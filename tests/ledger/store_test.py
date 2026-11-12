# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What the ledger's file says it is, and which files a load refuses."""

from __future__ import annotations

import contextlib
import functools
import json
import os
import sqlite3
import stat
from pathlib import Path
from typing import Any

import pytest
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.fee import FeeRate
from btclib.tx import TxOut
from typing_extensions import override

from btclib_wallet.ledger import APPLICATION_ID, FORMAT_VERSION, Ledger, crypto, store
from tests.ledger.conftest import LOOKAHEAD, XPRV, FakeChain, script_of, source
from tests.secret_free import assert_secret_free, windows


def _pragma(path: Path, name: str) -> int:
    db = sqlite3.connect(path)
    try:
        return int(db.execute(f"PRAGMA {name}").fetchone()[0])
    finally:
        db.close()


def _set_pragma(path: Path, name: str, value: int) -> None:
    db = sqlite3.connect(path)
    db.execute(f"PRAGMA {name} = {value}")
    db.close()


def test_a_new_file_says_what_it_is(chain: FakeChain, path: Path) -> None:
    """The application id and the format version, in SQLite's header."""
    Ledger.create(path, "regtest", chain).close()
    assert _pragma(path, "application_id") == APPLICATION_ID
    assert APPLICATION_ID.to_bytes(4, "big") == b"btlw"
    assert _pragma(path, "user_version") == FORMAT_VERSION == 2
    with Ledger.load(path, "regtest", chain) as ledger:
        assert ledger.tip is None
        assert ledger.sources == ()


@pytest.mark.skipif(os.name != "posix", reason="no POSIX permissions")
def test_a_new_file_is_its_owners_alone(chain: FakeChain, path: Path) -> None:
    """It holds private keys, so nobody else reads it."""
    Ledger.create(path, "regtest", chain).close()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_create_refuses_a_file_that_exists(chain: FakeChain, path: Path) -> None:
    """A file is never written over."""
    path.write_bytes(b"")
    with pytest.raises(BTClibValueError, match="the ledger file exists"):
        Ledger.create(path, "regtest", chain)
    with pytest.raises(BTClibTypeError, match="invalid path type"):
        Ledger.create(b"ledger", "regtest", chain)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid path type"):
        Ledger.load(1, "regtest", chain)  # type: ignore[arg-type]


def test_load_refuses_what_is_no_ledger_of_this_network(
    chain: FakeChain, path: Path, tmp_path: Path
) -> None:
    """A missing file, another program's, another network's."""
    with pytest.raises(BTClibValueError, match="cannot open the ledger file"):
        Ledger.load(tmp_path / "missing.sqlite", "regtest", chain)
    text = tmp_path / "text.sqlite"
    text.write_text("not a database, but long enough to be read as one " * 20)
    with pytest.raises(BTClibValueError, match="not a ledger file"):
        Ledger.load(text, "regtest", chain)
    other = tmp_path / "other.sqlite"
    sqlite3.connect(other).close()
    with pytest.raises(BTClibValueError, match="application id 0x0"):
        Ledger.load(other, "regtest", chain)
    # this package's header over no table
    headed = tmp_path / "headed.sqlite"
    _set_pragma(headed, "application_id", APPLICATION_ID)
    _set_pragma(headed, "user_version", FORMAT_VERSION)
    with pytest.raises(BTClibValueError, match="not a ledger file: no such table"):
        Ledger.load(headed, "regtest", chain)
    Ledger.create(path, "regtest", chain).close()
    with pytest.raises(BTClibValueError, match="a regtest ledger file, not a testnet"):
        Ledger.load(path, "testnet", chain)


def test_load_refuses_a_newer_format(chain: FakeChain, path: Path) -> None:
    """A release reads no format written by a later one."""
    Ledger.create(path, "regtest", chain).close()
    _set_pragma(path, "user_version", FORMAT_VERSION + 1)
    err_msg = f"ledger format {FORMAT_VERSION + 1} is newer"
    with pytest.raises(BTClibValueError, match=err_msg):
        Ledger.load(path, "regtest", chain)


def test_an_older_format_is_migrated_one_version_at_a_time(
    chain: FakeChain, path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each step of `_MIGRATIONS`, and a version with no step refused."""
    Ledger.create(path, "regtest", chain).close()
    ran: list[int] = []

    def step(db: sqlite3.Connection) -> None:
        ran.append(_pragma_of(db))
        db.execute("INSERT OR REPLACE INTO meta VALUES ('migrated', 'yes')")

    monkeypatch.setattr(store, "FORMAT_VERSION", FORMAT_VERSION + 2)
    steps = {FORMAT_VERSION: step, FORMAT_VERSION + 1: step}
    monkeypatch.setattr(store, "_MIGRATIONS", steps)
    Ledger.load(path, "regtest", chain).close()
    assert ran == [FORMAT_VERSION, FORMAT_VERSION + 1]
    assert _pragma(path, "user_version") == FORMAT_VERSION + 2
    _set_pragma(path, "user_version", 0)
    with pytest.raises(BTClibValueError, match="no migration from ledger format 0"):
        Ledger.load(path, "regtest", chain)


def _pragma_of(db: sqlite3.Connection) -> int:
    return int(db.execute("PRAGMA user_version").fetchone()[0])


def test_a_failed_migration_step_leaves_the_file_as_it_was(
    chain: FakeChain, path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The step's DDL is rolled back with it: one SQLite transaction."""
    Ledger.create(path, "regtest", chain).close()

    def step(db: sqlite3.Connection) -> None:
        db.execute("CREATE TABLE added (x INTEGER)")
        raise RuntimeError("the step failed")

    monkeypatch.setattr(store, "FORMAT_VERSION", FORMAT_VERSION + 1)
    monkeypatch.setattr(store, "_MIGRATIONS", {FORMAT_VERSION: step})
    with pytest.raises(RuntimeError, match="the step failed"):
        Ledger.load(path, "regtest", chain)
    assert _pragma(path, "user_version") == FORMAT_VERSION
    db = sqlite3.connect(path)
    try:
        query = "SELECT name FROM sqlite_master WHERE name = 'added'"
        assert db.execute(query).fetchall() == []
    finally:
        db.close()


def test_a_create_that_fails_leaves_no_file(
    chain: FakeChain, path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The network row refused, as on a full disk: nothing is left."""
    meta = "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    refusing = meta.replace("NOT NULL)", "NOT NULL CHECK (value <> 'regtest'))")
    assert store._SCHEMA[0] == meta
    monkeypatch.setattr(store, "_SCHEMA", (refusing, *store._SCHEMA[1:]))
    with pytest.raises(sqlite3.IntegrityError):
        Ledger.create(path, "regtest", chain)
    assert not path.exists()
    monkeypatch.undo()
    Ledger.create(path, "regtest", chain).close()
    assert _pragma(path, "user_version") == FORMAT_VERSION


def test_a_create_that_cannot_open_its_file_leaves_none(
    chain: FakeChain, path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The file made, then not opened: it is removed."""

    def refuse(path: Path, mode: str) -> sqlite3.Connection:
        raise BTClibValueError(f"cannot open the ledger file {path}")

    monkeypatch.setattr(store, "_connect", refuse)
    with pytest.raises(BTClibValueError, match="cannot open the ledger file"):
        Ledger.create(path, "regtest", chain)
    assert not path.exists()


def test_a_file_that_names_no_network_is_refused(chain: FakeChain, path: Path) -> None:
    """A ledger's header and tables with no network row."""
    Ledger.create(path, "regtest", chain).close()
    db = sqlite3.connect(path)
    with db:
        db.execute("DELETE FROM meta WHERE key = 'network'")
    db.close()
    with pytest.raises(
        BTClibValueError, match="not a ledger file: it names no network"
    ):
        Ledger.load(path, "regtest", chain)


def test_a_sources_repr_holds_no_private_key() -> None:
    """Its repr and its str leave the keys out, and show the descriptors."""
    wallet = source()
    held = store._Source(
        {branch: str(wallet.descriptor(branch)) for branch in wallet.branches},
        dict(wallet.prv_keys or {}),
        None,
        LOOKAHEAD,
        0,
        False,
    )
    assert XPRV in held.prv_keys.values()
    for text in (repr(held), str(held)):
        assert not [piece for piece in map(str, windows(XPRV)) if piece in text]
        assert held.descriptors[0] in text


@pytest.mark.parametrize(
    "column, damaged",
    [
        ("prv_keys", "substr(prv_keys, 1, length(prv_keys) - 1)"),
        ("descriptors", "'null'"),
        ("descriptors", "'[1]'"),
        ("prv_keys", "'[]'"),
        ("prv_keys", "'5'"),
    ],
)
def test_a_source_column_that_is_no_json_object_is_refused(
    chain: FakeChain, path: Path, column: str, damaged: str
) -> None:
    """A column that is no JSON object is refused, and no key leaves with it."""
    with Ledger.create(path, "regtest", chain) as ledger:
        ledger.add_source(source())
    db = sqlite3.connect(path)
    with db:
        db.execute(f"UPDATE sources SET {column} = {damaged}")  # noqa: S608
    db.close()
    err_msg = f"source 0's {column} is not a JSON object"
    with pytest.raises(BTClibValueError, match=err_msg) as e:
        Ledger.load(path, "regtest", chain)
    assert_secret_free(e.value, [XPRV])


_HELD = "is open in another ledger or program"


@pytest.mark.parametrize("opened", ["create", "load", "restore"])
def test_a_file_a_ledger_holds_opens_in_no_other(
    chain: FakeChain, path: Path, tmp_path: Path, opened: str
) -> None:
    """A ledger holds its file from its creation, load or restore to its close.

    Another load is refused at once, and so is a restore from the file,
    which leaves nothing at its path. Another SQLite connection reads
    nothing of it. Closed, the ledger lets the file go, and deletes the
    journal it opened.
    """
    backup = tmp_path / "backup.sqlite"
    with Ledger.create(path, "regtest", chain) as ledger:
        ledger.add_source(source())
        ledger.backup(backup)
    path.unlink()
    held = {
        "create": lambda: Ledger.create(path, "regtest", chain),
        "load": lambda: Ledger.load(backup, "regtest", chain),
        "restore": lambda: Ledger.restore(backup, path, "regtest", chain),
    }
    with held[opened]() as ledger:
        file = ledger._store._db.execute("PRAGMA database_list").fetchone()[2]
        sources = [str(wallet.descriptor(0)) for wallet in ledger.sources]
        with pytest.raises(BTClibValueError, match=_HELD):
            Ledger.load(file, "regtest", chain)
        copy = tmp_path / "copy.sqlite"
        with pytest.raises(BTClibValueError, match=_HELD):
            Ledger.restore(file, copy, "regtest", chain)
        assert not copy.exists()
        with (
            contextlib.closing(sqlite3.connect(file, timeout=0)) as other,
            pytest.raises(sqlite3.OperationalError, match="database is locked"),
        ):
            other.execute("SELECT count(*) FROM sources").fetchone()
    with Ledger.load(file, "regtest", chain) as again:
        assert [str(wallet.descriptor(0)) for wallet in again.sources] == sources
    assert not Path(f"{file}-journal").exists()


def test_another_constraint_on_a_new_source_is_no_ledgers(
    chain: FakeChain, path: Path
) -> None:
    """A constraint the file added refuses the source as no ledger's file.

    A unique index another program put on the lookahead is one: the
    ledger's own ids never collide.
    """
    with Ledger.create(path, "regtest", chain) as ledger:
        ledger.add_source(source())
    with contextlib.closing(sqlite3.connect(path)) as db, db:
        db.execute("CREATE UNIQUE INDEX one_lookahead ON sources(lookahead)")
    with Ledger.load(path, "regtest", chain) as ledger:
        err_msg = "not a ledger file: UNIQUE constraint failed: sources.lookahead"
        with pytest.raises(BTClibValueError, match=err_msg):
            ledger.add_source(source("wpkh({}/84h/1h/1h/{}/*)"))


# format 1's tables, as src/btclib_wallet/ledger/store.py wrote them at
# the v2026.11.11 tag: a file of that release is built from them here,
# not from this release's code
_FORMAT_1 = (
    "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    (
        "CREATE TABLE sources(id INTEGER PRIMARY KEY, descriptors TEXT NOT NULL,"
        " prv_keys TEXT NOT NULL, lookahead INTEGER NOT NULL,"
        " birth INTEGER NOT NULL, scanned INTEGER NOT NULL)"
    ),
    (
        "CREATE TABLE handed_out(source INTEGER NOT NULL, branch INTEGER NOT NULL,"
        " idx INTEGER NOT NULL, PRIMARY KEY(source, branch, idx))"
    ),
    (
        "CREATE TABLE txs(txid BLOB PRIMARY KEY, raw BLOB NOT NULL,"
        " state TEXT NOT NULL, height INTEGER, block_id BLOB, seq INTEGER NOT NULL)"
    ),
    "CREATE TABLE blocks(height INTEGER PRIMARY KEY, block_id BLOB NOT NULL)",
    (
        "CREATE TABLE labels(script BLOB PRIMARY KEY, label TEXT NOT NULL,"
        " purpose TEXT NOT NULL)"
    ),
)
# two sources, in the rows v2026.11.11's `Ledger.add_source` wrote
_FORMAT_1_SOURCES = {
    0: (source(), LOOKAHEAD),
    3: (source("wpkh({}/84h/1h/1h/{}/*)"), LOOKAHEAD + 2),
}


def _spending(chain: FakeChain) -> dict[str, Any]:
    """Return the readers a ledger spends with, all of `chain`."""
    return {
        "broadcaster": chain,
        "fee_estimator": chain,
        "relay_fee_reader": chain,
        "fallback_fee_rate": FeeRate.from_sats_per_vbyte(2),
    }


def _format_1_file(path: Path) -> None:
    """Write a ledger file of v2026.11.11, with the sources above."""
    db = sqlite3.connect(path)
    try:
        with db:
            db.execute(f"PRAGMA application_id = {APPLICATION_ID}")
            for statement in _FORMAT_1:
                db.execute(statement)
            db.execute("PRAGMA user_version = 1")
            db.execute("INSERT INTO meta VALUES ('network', 'regtest')")
            for source_id, (wallet, lookahead) in _FORMAT_1_SOURCES.items():
                descriptors = {
                    str(branch): str(wallet.descriptor(branch))
                    for branch in wallet.branches
                }
                db.execute(
                    "INSERT INTO sources VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        source_id,
                        json.dumps(descriptors),
                        json.dumps(dict(wallet.prv_keys or {})),
                        lookahead,
                        0,
                        1,
                    ),
                )
    finally:
        db.close()


def _keeps_the_format_1_sources(ledger: Ledger, chain: FakeChain) -> None:
    """Every source, with its id, its keys and its lookahead; then encrypted.

    The keys sign once encrypted and unlocked.
    """
    rows = ledger._store.sources()
    assert [
        (source_id, row.prv_keys, row.lookahead, row.encrypted)
        for source_id, row in rows
    ] == [
        (source_id, wallet.prv_keys, lookahead, None)
        for source_id, (wallet, lookahead) in _FORMAT_1_SOURCES.items()
    ]
    pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    ledger.encrypt("passphrase")
    assert all(row.prv_keys == {} for _, row in ledger._store.sources())
    chain.mine([chain.pay([TxOut(100_000, script_of(ledger.new_address(3)))])])
    ledger.sync()
    ledger.unlock_keys("passphrase", 60)
    other = source("wpkh({}/84h/1h/9h/{}/*)", (0,))
    psbt = ledger.fund([TxOut(30_000, other.script_pub_key(0, 0))]).psbt
    assert all(psbt_in.partial_sigs for psbt_in in ledger.sign(psbt).inputs)


def _layout(path: Path) -> dict[str, list[tuple[object, ...]]]:
    db = sqlite3.connect(path)
    try:
        tables = db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        return {
            name: db.execute(f"PRAGMA table_info({name})").fetchall()
            for (name,) in tables.fetchall()
        }
    finally:
        db.close()


def test_a_format_1_file_is_migrated(
    chain: FakeChain, path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """v2026.11.11's file loads, keeps its sources and takes a passphrase.

    It is migrated to this release's layout, the one a new file has.
    """
    monkeypatch.setattr(crypto, "_SCRYPT_N", 2**4)
    _format_1_file(path)
    with Ledger.load(path, "regtest", chain, **_spending(chain)) as ledger:
        _keeps_the_format_1_sources(ledger, chain)
    assert _pragma(path, "user_version") == FORMAT_VERSION
    new = tmp_path / "new.sqlite"
    Ledger.create(new, "regtest", chain).close()
    assert _layout(path) == _layout(new)


def test_a_format_1_transaction_has_no_comments_and_no_bump(
    chain: FakeChain, path: Path
) -> None:
    """Format 2's columns of a transaction v2026.11.11 wrote are empty."""
    _format_1_file(path)
    wallet, _ = _FORMAT_1_SOURCES[min(_FORMAT_1_SOURCES)]
    tx = chain.pay([TxOut(100_000, wallet.script_pub_key(0, 0))])
    db = sqlite3.connect(path)
    try:
        with db:
            db.execute(
                "INSERT INTO txs VALUES (?, ?, 'inactive', NULL, NULL, 0)",
                (tx.id, tx.serialize(include_witness=True)),
            )
    finally:
        db.close()
    with Ledger.load(path, "regtest", chain) as ledger:
        (wtx,) = ledger._store.txs("regtest")
        assert wtx.tx == tx
        assert (wtx.comment, wtx.comment_to) == (None, None)
        assert (wtx.replaces, wtx.replaced_by) == (None, None)


def test_a_format_1_backup_is_restored(
    chain: FakeChain, path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A backup v2026.11.11 wrote is restored, and the backup left as it was."""
    monkeypatch.setattr(crypto, "_SCRYPT_N", 2**4)
    backup = tmp_path / "backup.sqlite"
    _format_1_file(backup)
    with Ledger.restore(backup, path, "regtest", chain, **_spending(chain)) as ledger:
        _keeps_the_format_1_sources(ledger, chain)
    assert _pragma(path, "user_version") == FORMAT_VERSION
    assert _pragma(backup, "user_version") == 1


def test_a_format_1_file_of_another_network_is_left_at_format_1(
    chain: FakeChain, path: Path
) -> None:
    """The network is checked before any step, so v2026.11.11 still opens it."""
    _format_1_file(path)
    with pytest.raises(BTClibValueError, match="a regtest ledger file, not a testnet"):
        Ledger.load(path, "testnet", chain)
    assert _pragma(path, "user_version") == 1
    assert "master_key" not in _layout(path)


def test_a_file_being_migrated_opens_in_no_other_ledger(
    chain: FakeChain, path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The lock is taken before the file's version is read.

    A second load while the first reads the version is refused, so no
    two ledgers migrate one file.
    """
    _format_1_file(path)
    pragma = store._pragma
    refused: list[str] = []

    def then_another(db: sqlite3.Connection, name: str) -> int:
        if name == "user_version" and not refused:
            with pytest.raises(BTClibValueError, match=_HELD) as e:
                Ledger.load(path, "regtest", chain)
            refused.append(str(e.value))
        return pragma(db, name)

    monkeypatch.setattr(store, "_pragma", then_another)
    with Ledger.load(path, "regtest", chain) as ledger:
        assert len(ledger.sources) == len(_FORMAT_1_SOURCES)
    assert refused
    assert _pragma(path, "user_version") == FORMAT_VERSION


def test_v2026_11_11_refuses_a_file_of_this_release(
    chain: FakeChain, path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A release writing format 1, with no step, reads this one as newer."""
    Ledger.create(path, "regtest", chain).close()
    monkeypatch.setattr(store, "FORMAT_VERSION", 1)
    monkeypatch.setattr(store, "_MIGRATIONS", {})
    err_msg = "ledger format 2 is newer than this release's 1"
    with pytest.raises(BTClibValueError, match=err_msg):
        Ledger.load(path, "regtest", chain)


def _keeping(unread: list[str]) -> type[sqlite3.Connection]:
    """Return a connection that keeps every cursor it returns.

    At its close it adds to `unread` the statement of each cursor that
    still holds a row.
    """

    class Keeping(sqlite3.Connection):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self.kept: list[tuple[str, sqlite3.Cursor]] = []

        @override
        def execute(self, sql: str, parameters: Any = (), /) -> sqlite3.Cursor:
            cursor = super().execute(sql, parameters)
            self.kept.append((sql, cursor))
            return cursor

        @override
        def close(self) -> None:
            unread.extend(sql for sql, c in self.kept if c.fetchone() is not None)
            super().close()

    return Keeping


def test_every_statement_of_the_store_is_read_to_its_end(
    chain: FakeChain, path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No connection the store opens closes with a row left unread.

    SQLite refuses a commit while a statement that writes is unfinished,
    as `PRAGMA journal_mode` is until its row is read. CPython finishes
    an unread statement once its cursor is dropped, PyPy only once it
    collects the cursor, so every cursor is kept here, as PyPy may keep
    it: a load migrating a file, a label, a backup, a restore and a
    create, then an encryption and a new passphrase.
    """
    monkeypatch.setattr(crypto, "_SCRYPT_N", 2**4)
    _format_1_file(path)
    unread: list[str] = []
    connect = functools.partial(sqlite3.connect, factory=_keeping(unread))
    monkeypatch.setattr(sqlite3, "connect", connect)
    backup = tmp_path / "backup.sqlite"
    with Ledger.load(path, "regtest", chain, **_spending(chain)) as ledger:
        ledger.set_label(ledger.new_address(), "label")
        ledger.backup(backup)
    Ledger.restore(backup, tmp_path / "restored.sqlite", "regtest", chain).close()
    Ledger.create(tmp_path / "new.sqlite", "regtest", chain).close()
    assert not unread
    with Ledger.load(path, "regtest", chain, **_spending(chain)) as ledger:
        _keeps_the_format_1_sources(ledger, chain)
        ledger.change_passphrase("passphrase", "new passphrase")
    assert not unread
