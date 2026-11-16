# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What the ledger's file says it is, and which files a load refuses."""

from __future__ import annotations

import contextlib
import errno
import functools
import json
import operator
import os
import sqlite3
import stat
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest
from btclib.alias import Octets
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.fee import FeeRate
from btclib.script import ScriptPubKey
from btclib.tx import Tx, TxOut
from typing_extensions import override

from btclib_wallet._refusal import _exact, _exact_int, _quoted
from btclib_wallet.descriptors import parse
from btclib_wallet.fetch.history import (
    BlockRef,
    HistoryTx,
    ScriptHistory,
    history_scripts,
)
from btclib_wallet.ledger import (
    APPLICATION_ID,
    FORMAT_VERSION,
    MAX_LOOKAHEAD,
    Ledger,
    TxState,
    WalletTx,
    crypto,
    store,
)
from btclib_wallet.wallet import DescriptorWallet
from tests import raises_alone
from tests.ledger import (
    ClaimsInt,
    ClaimsStr,
    Conforming,
    ConformingBytes,
    ConformingStr,
)
from tests.ledger.conftest import LOOKAHEAD, XPRV, FakeChain, script_of, source
from tests.refused_value_test import HEX, SPELLINGS
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
    with pytest.raises(
        BTClibValueError, match="not a ledger file: application id an int of 0 bits"
    ):
        Ledger.load(other, "regtest", chain)
    # this package's header over no table
    headed = tmp_path / "headed.sqlite"
    _set_pragma(headed, "application_id", APPLICATION_ID)
    _set_pragma(headed, "user_version", FORMAT_VERSION)
    with pytest.raises(BTClibValueError, match="not a ledger file: OperationalError"):
        Ledger.load(headed, "regtest", chain)
    Ledger.create(path, "regtest", chain).close()
    with pytest.raises(
        BTClibValueError, match="^not a testnet ledger file: its network is regtest$"
    ):
        Ledger.load(path, "testnet", chain)


def test_load_refuses_a_newer_format(chain: FakeChain, path: Path) -> None:
    """A release reads no format written by a later one."""
    Ledger.create(path, "regtest", chain).close()
    _set_pragma(path, "user_version", FORMAT_VERSION + 1)
    err_msg = f"ledger format {_quoted(FORMAT_VERSION + 1)} is newer"
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
    with pytest.raises(
        BTClibValueError, match="no migration from ledger format an int of 0 bits"
    ):
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


def refuse_removal(monkeypatch: pytest.MonkeyPatch, folder: Path) -> None:
    """Refuse to remove a file in `folder`, as where it has no write permission.

    The error is the one the system raises there, its text and `filename`
    the file's path. A removal of a file elsewhere fails the test.
    """

    def refused(self: Path, missing_ok: bool = False) -> None:
        assert self.parent == folder
        raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), str(self))

    monkeypatch.setattr(Path, "unlink", refused)


def test_a_create_whose_file_cannot_be_removed_raises_its_failure(
    chain: FakeChain, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A key's hex in the path is in no error (issue #907).

    The create is interrupted after making its file, and the system
    refuses to remove that file: the interrupt is raised as it was, and
    the file is left.
    """
    folder = tmp_path / HEX
    folder.mkdir()
    target = folder / "ledger.sqlite"
    interrupt = KeyboardInterrupt()

    def interrupted(path: Path, mode: str) -> sqlite3.Connection:
        raise interrupt

    monkeypatch.setattr(store, "_connect", interrupted)
    refuse_removal(monkeypatch, folder)
    with pytest.raises(KeyboardInterrupt) as e:
        Ledger.create(target, "regtest", chain)
    raised = e.value
    assert id(raised) == id(interrupt)
    assert raised.__context__ is None
    assert_secret_free(raised, SPELLINGS)
    assert target.exists()


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


# Windows' SQLite loads the file with a directory at its journal, as
# every cell of os-windows.yml measured: no failure to name there
@pytest.mark.skipif(os.name == "nt", reason="no failure to open on Windows")
def test_a_file_sqlite_cannot_open_is_not_called_no_ledger(
    chain: FakeChain, path: Path
) -> None:
    """SQLite's operational failure at the open names the file, not its kind.

    A directory where the journal goes makes SQLite fail its read of
    what it takes for a hot journal. The ledger file is whole, so the
    refusal does not say it is no ledger file, and once the directory
    goes the file loads.
    """
    Ledger.create(path, "regtest", chain).close()
    journal = Path(f"{path}-journal")
    journal.mkdir()
    with pytest.raises(BTClibValueError, match="cannot open the ledger file") as e:
        Ledger.load(path, "regtest", chain)
    assert "not a ledger file" not in str(e.value)
    journal.rmdir()
    Ledger.load(path, "regtest", chain).close()


def _failing(statement: str, error: sqlite3.Error) -> type[sqlite3.Connection]:
    """Return a connection that raises `error` where it runs `statement`."""

    class Failing(sqlite3.Connection):
        @override
        def execute(self, sql: str, parameters: Any = (), /) -> sqlite3.Cursor:
            if sql == statement:
                raise error
            return super().execute(sql, parameters)

    return Failing


@pytest.mark.parametrize(
    "opened, statement, error, err_msg",
    [
        ("load", "BEGIN EXCLUSIVE", sqlite3.OperationalError, "cannot open the"),
        ("load", "BEGIN EXCLUSIVE", sqlite3.DatabaseError, "not a ledger file"),
        (
            "restore",
            "SELECT count(*) FROM sqlite_master",
            sqlite3.DatabaseError,
            "not a ledger file",
        ),
    ],
)
def test_an_error_with_no_sqlite_errorname_is_refused_as_the_others(
    chain: FakeChain,
    path: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    opened: str,
    statement: str,
    error: type[sqlite3.DatabaseError],
    err_msg: str,
) -> None:
    """An error that names no SQLite code is not taken for a held file.

    One built in Python carries no `sqlite_errorname`, so the open
    refuses it as it refuses any other error of its class.
    """
    Ledger.create(path, "regtest", chain).close()
    failure = error("failed")
    assert not hasattr(failure, "sqlite_errorname")
    connect = functools.partial(sqlite3.connect, factory=_failing(statement, failure))
    monkeypatch.setattr(sqlite3, "connect", connect)
    opens = {
        "load": lambda: Ledger.load(path, "regtest", chain),
        "restore": lambda: Ledger.restore(
            path, tmp_path / "restored.sqlite", "regtest", chain
        ),
    }
    with pytest.raises(BTClibValueError, match=err_msg) as e:
        opens[opened]()
    assert _HELD not in str(e.value)


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
        err_msg = "not a ledger file: IntegrityError"
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
    with pytest.raises(
        BTClibValueError, match="^not a testnet ledger file: its network is regtest$"
    ):
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
    err_msg = "ledger format an int of 2 bits is newer than this release's 1"
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


# what a load says of a lookahead `Ledger.add_source` refuses
_NO_LOOKAHEAD = (
    "^not a ledger file: source 0's lookahead is no int from 0 to MAX_LOOKAHEAD,"
    f" {MAX_LOOKAHEAD}$"
)


@pytest.mark.parametrize(
    "statement, value, err_msg",
    [
        (
            "UPDATE meta SET value = ? WHERE key = 'network'",
            HEX,
            "^not a regtest ledger file: its network is a value of 64 characters$",
        ),
        (
            "UPDATE sources SET descriptors = ?",
            json.dumps({HEX: "x"}),
            "^not a ledger file: source 0's descriptors are not keyed by branch$",
        ),
        (
            "UPDATE meta SET value = ? WHERE key = 'tip_height'",
            HEX,
            "^not a ledger file: a malformed tip$",
        ),
        (
            "UPDATE meta SET value = ? WHERE key = 'tip_id'",
            HEX.upper(),
            "^not a ledger file: a malformed tip$",
        ),
        (
            "UPDATE txs SET state = ?",
            HEX,
            "^not a ledger file: a transaction in no state$",
        ),
        (
            "UPDATE txs SET height = ?",
            HEX,
            "^not a ledger file: a transaction in a malformed block$",
        ),
        (
            "UPDATE txs SET block_id = ?",
            HEX,
            "^not a ledger file: a transaction in a malformed block$",
        ),
        (
            "UPDATE txs SET seq = ?",
            HEX,
            "^not a ledger file: a transaction with a malformed seq$",
        ),
        # past what an SQLite INTEGER holds: a column of INTEGER affinity
        # keeps the text as a REAL
        (
            "UPDATE meta SET value = ? WHERE key = 'tip_height'",
            str(2**63),
            "^not a ledger file: a malformed tip$",
        ),
        (
            "UPDATE txs SET height = ?",
            str(2**63),
            "^not a ledger file: a transaction in a malformed block$",
        ),
        (
            "UPDATE txs SET seq = ?",
            str(2**63),
            "^not a ledger file: a transaction with a malformed seq$",
        ),
        (
            "UPDATE meta SET value = ? WHERE key = 'tip_height'",
            str(-(2**63) - 1),
            "^not a ledger file: a malformed tip$",
        ),
        (
            "UPDATE txs SET height = ?",
            str(-(2**63) - 1),
            "^not a ledger file: a transaction in a malformed block$",
        ),
        (
            "UPDATE txs SET seq = ?",
            "-1",
            "^not a ledger file: a transaction with a malformed seq$",
        ),
        (
            "UPDATE meta SET value = ? WHERE key = 'tip_id'",
            HEX[:-1],
            "^not a ledger file: a malformed tip$",
        ),
        (
            "UPDATE sources SET lookahead = ?",
            HEX,
            _NO_LOOKAHEAD,
        ),
        (
            "UPDATE sources SET lookahead = ?",
            "1.5",
            _NO_LOOKAHEAD,
        ),
        (
            "UPDATE sources SET lookahead = ?",
            "-3",
            _NO_LOOKAHEAD,
        ),
        (
            "UPDATE sources SET lookahead = ?",
            str(MAX_LOOKAHEAD + 1),
            _NO_LOOKAHEAD,
        ),
    ],
    ids=[
        "network",
        "descriptors map key",
        "tip height",
        "tip id",
        "tx state",
        "tx height",
        "tx block id",
        "tx seq",
        "tip height of 2**63",
        "tx height of 2**63",
        "tx seq of 2**63",
        "tip height below -2**63",
        "tx height below -2**63",
        "negative tx seq",
        "tip id of odd length",
        "lookahead of text",
        "lookahead of a real",
        "negative lookahead",
        "lookahead above MAX_LOOKAHEAD",
    ],
)
def test_a_key_in_a_damaged_file_is_in_no_refusal(
    chain: FakeChain, path: Path, statement: str, value: str, err_msg: str
) -> None:
    """What `int`, `TxState` and the network check read is not quoted.

    `int` and `TxState` quote a value they refuse, so the file's value is
    checked before they read it, and refused by where it is (issue #900).
    """
    with Ledger.create(path, "regtest", chain) as ledger:
        ledger.add_source(source())
        chain.mine([chain.pay([TxOut(100_000, script_of(ledger.new_address()))])])
        ledger.sync()
    db = sqlite3.connect(path)
    with db:
        assert db.execute(statement, (value,)).rowcount > 0
    db.close()
    with raises_alone(BTClibValueError, err_msg) as e:
        Ledger.load(path, "regtest", chain)
    assert_secret_free(e.value, SPELLINGS)


@pytest.mark.parametrize("lookahead", [0, MAX_LOOKAHEAD], ids=["least", "largest"])
def test_a_lookahead_add_source_takes_loads(
    chain: FakeChain, path: Path, lookahead: int
) -> None:
    """The least and the largest lookahead `Ledger.add_source` takes load.

    The source has no ranged branch, so it watches one script whatever
    its lookahead.
    """
    single = source("wpkh({}/84h/1h/0h/{}/0)", (0,))
    with Ledger.create(path, "regtest", chain) as ledger:
        source_id = ledger.add_source(single, lookahead=lookahead)
    with Ledger.load(path, "regtest", chain) as again:
        assert again._lookahead == {source_id: lookahead}


@pytest.mark.parametrize("height", [2**63 - 1, -(2**63)], ids=["largest", "least"])
def test_a_height_an_sqlite_integer_holds_loads(
    chain: FakeChain, path: Path, height: int
) -> None:
    """Any height an SQLite INTEGER holds, and the largest seq, load."""
    with Ledger.create(path, "regtest", chain) as ledger:
        ledger.add_source(source())
        chain.mine([chain.pay([TxOut(100_000, script_of(ledger.new_address()))])])
        ledger.sync()
    largest = 2**63 - 1
    db = sqlite3.connect(path)
    with db:
        db.execute("UPDATE meta SET value = ? WHERE key = 'tip_height'", (str(height),))
        db.execute("UPDATE txs SET height = ?, seq = ?", (height, largest))
    db.close()
    with Ledger.load(path, "regtest", chain) as again:
        assert again.tip is not None
        assert again.tip.height == height
        [info] = again.transactions
        assert info.wallet_tx.seq == largest
        assert info.wallet_tx.block is not None
        assert info.wallet_tx.block.height == height


class _JumpChain(FakeChain):
    """A chain whose tip is `jump` once `held` holds that block's txs."""

    def __init__(self, jump: BlockRef) -> None:
        super().__init__()
        self.jump = jump
        self.held: list[Tx] | None = None

    @override
    def get_history(
        self, scripts: Iterable[Octets | ScriptPubKey], start_height: int = 0
    ) -> ScriptHistory:
        if self.held is None:
            return super().get_history(scripts, start_height)
        # read once after the jump, from the genesis the first sync left
        wanted = set(history_scripts(scripts))
        txs = tuple(
            HistoryTx(tx, self.jump) for tx in self.held if self._touches(tx, wanted)
        )
        return ScriptHistory(BlockRef(0, self.blocks[0][0]), self.jump, txs)


@pytest.mark.parametrize("confirmed", [False, True], ids=["tip", "confirmed tx"])
@pytest.mark.parametrize(
    "jump",
    [
        BlockRef(10**10, b"\x0b" * 32),
        BlockRef(5, b"\x0b" * 31),
        BlockRef(5, b"\x0b" * 33),
    ],
    ids=["height past 10 digits", "31-byte id", "33-byte id"],
)
def test_what_a_sync_writes_of_a_backends_block_loads_again(
    path: Path, jump: BlockRef, *, confirmed: bool
) -> None:
    """What a sync writes of a block a backend answers, a load reads back.

    A sync keeps the height and the id a backend answers: a height past
    10 digits, and, from a reader of the caller's own, any id.
    """
    chain = _JumpChain(jump)
    with Ledger.create(path, "regtest", chain) as ledger:
        ledger.add_source(source())
        ledger.sync()
        payment = chain.pay([TxOut(100_000, script_of(ledger.new_address()))])
        chain.held = [payment] if confirmed else []
        ledger.sync()
        synced = (ledger.tip, [info.wallet_tx for info in ledger.transactions])
    assert synced[0] == jump
    with Ledger.load(path, "regtest", chain) as again:
        assert (again.tip, [info.wallet_tx for info in again.transactions]) == synced
    if confirmed:
        [wtx] = synced[1]
        assert wtx.block == jump


def test_a_branch_past_10_digits_loads_again(chain: FakeChain, path: Path) -> None:
    """`add_source` writes a branch past 10 digits, and a load reads it."""
    prv_keys: dict[str, str] = {}
    branch = 10**12
    descriptor = parse(f"wpkh({XPRV}/84h/1h/0h/0/*)", "regtest", prv_keys)
    with Ledger.create(path, "regtest", chain) as ledger:
        ledger.add_source(DescriptorWallet({branch: descriptor}, prv_keys))
    with Ledger.load(path, "regtest", chain) as again:
        [wallet] = again.sources
        assert wallet.branches == (branch,)


def test_a_test_fails_that_binds_a_subclass() -> None:
    """What `tests/conftest.py` makes of a connection `sqlite3.connect` opens.

    `sqlite3` binds what each `__conform__` answers, where such a
    connection fails the test first.
    """
    values = (Conforming(1), ConformingStr("a"), ConformingBytes(b"a"))
    with contextlib.closing(sqlite3.Connection(":memory:")) as plain:
        row = plain.execute("SELECT ?, ?, ?, ?", (*values, memoryview(b"a")))
        assert row.fetchone() == ("conformed", "conformed", b"conformed", b"a")
    with contextlib.closing(sqlite3.connect(":memory:")) as db:
        db.execute("CREATE TABLE t(v)")
        with pytest.raises(pytest.fail.Exception, match="binds a Conforming$"):
            db.execute("INSERT INTO t VALUES (?)", (Conforming(1),))
        with pytest.raises(pytest.fail.Exception, match="binds a ConformingStr$"):
            db.executemany("INSERT INTO t VALUES (?)", [(ConformingStr("a"),)])
        with pytest.raises(pytest.fail.Exception, match="binds a ConformingBytes$"):
            db.execute("INSERT INTO t VALUES (?)", (ConformingBytes(b"a"),))
        with pytest.raises(pytest.fail.Exception, match="binds a memoryview$"):
            db.execute("INSERT INTO t VALUES (?)", (memoryview(b"a"),))
        with pytest.raises(pytest.fail.Exception, match="binds a bool$"):
            db.execute("INSERT INTO t VALUES (:v)", {"v": True})
        assert db.execute("SELECT count(*) FROM t").fetchone() == (0,)
        # a cursor's own execute is not the connection's, and is not checked
        row = db.cursor().execute("SELECT ?", (Conforming(1),)).fetchone()
        assert row == ("conformed",)


def _rows(path: Path, sql: str) -> list[tuple[object, ...]]:
    with contextlib.closing(sqlite3.connect(path)) as db:
        return db.execute(sql).fetchall()


def test_a_caller_s_int_or_str_is_written_as_the_value_it_holds(
    chain: FakeChain, path: Path
) -> None:
    """What `store` says it binds of a caller's arguments, read back.

    Each of the subclass's own methods would write another value.
    """
    wallet = source()
    with Ledger.create(path, "regtest", chain) as ledger:
        ledger.add_source(wallet, Conforming(3), lookahead=Conforming(2))
        address = ledger.new_address(Conforming(0), Conforming(1))
        ledger.new_address(0, 0, label=ConformingStr("a"))
        ledger.set_label(address, ConformingStr("b"))
    assert _rows(path, "SELECT lookahead, birth FROM sources") == [(2, 3)]
    assert _rows(path, "SELECT * FROM handed_out ORDER BY branch") == [
        (0, 0, 0),
        (0, 1, 0),
    ]
    assert sorted(_rows(path, "SELECT label FROM labels")) == [("a",), ("b",)]
    with Ledger.load(path, "regtest", chain) as again:
        assert again.label_of(address) == "b"
        assert again.new_address(0, 1) == wallet.address(1, 1)


def test_a_value_is_copied_by_its_type_whatever_its_class_claims() -> None:
    """`_exact` and `_exact_int` read the type, and never `__class__`.

    `isinstance` reads `__class__`, which can claim another type, or
    raise.
    """

    def no_class(_self: object) -> type:
        raise RuntimeError("no __class__")

    claims_bytes: Any = property(lambda _self: bytes)

    class ClaimsBytes:
        __class__ = claims_bytes

    class RaisesClass(int):
        __class__ = property(no_class)

    claimant = ClaimsBytes()
    # what isinstance reads of each, which a copy must not ask
    assert isinstance(ClaimsInt("a"), int)
    assert isinstance(ClaimsStr(b"a"), str)
    assert isinstance(claimant, bytes)
    with pytest.raises(RuntimeError, match="no __class__"):
        isinstance(RaisesClass(5), bool)
    copies = (_exact(ClaimsInt("a")), _exact(ClaimsStr(b"a")), _exact(RaisesClass(5)))
    assert [(type(held), held) for held in copies] == [
        (str, "a"),
        (bytes, b"a"),
        (int, 5),
    ]
    assert _exact(claimant) is claimant
    held = _exact_int(RaisesClass(5))
    assert (type(held), held) == (int, 5)


def test_a_subclass_is_bound_as_the_value_it_holds_not_as_it_answers() -> None:
    """What `_exact` reads of each, and what its own methods answer.

    The tests that read a ledger's file back rest on the difference.
    """
    number, text, octets = Conforming(1), ConformingStr("a"), ConformingBytes(b"a")
    assert (int(number), number.__index__(), str(number)) == (99, 98, "97")
    arithmetic = (
        number | 0,
        0 | number,
        number + 0,
        0 + number,
        number * 1,
        1 * number,
    )
    assert arithmetic == (99,) * 6
    assert str(text) == "str"
    # operator.add is `+`, the dispatch under test, either way round
    texts = (
        operator.add(text, ""),
        operator.add("", text),
        text[:],
        text * 1,
        1 * text,
    )
    assert (texts, len(text)) == (("wrong",) * 5, 0)
    assert (bytes(octets), octets.hex()) == (b"bytes", "beef")
    assert octets.__buffer__(0).tobytes() == b"buffer"
    octet_copies = (octets + b"", b"" + octets, octets[:], octets * 1, 1 * octets)
    assert (octet_copies, len(octets)) == ((b"wrong",) * 5, 0)
    for value, exact in ((number, 1), (text, "a"), (octets, b"a"), (True, 1)):
        held = _exact(value)
        assert (type(held), held) == (type(exact), exact)
    # an empty copy is still the exact type, not the subclass
    empties = (Conforming(0), ConformingStr(""), ConformingBytes(b""))
    for empty, copy in zip(empties, (0, "", b""), strict=True):
        copied = _exact(empty)
        assert (type(copied), copied) == (type(copy), copy)
    other = 5.0
    # the very object, which `==` would not tell from a copy
    assert _exact(other) is other  # sourcery skip: compare-via-equals


def test_the_store_writes_the_value_held_whatever_reaches_it(
    ledger: Ledger, chain: FakeChain, path: Path
) -> None:
    """The store's own read, under the ledger's, which hands it the value.

    Each of the subclass's own methods would write another value, a 0 and
    an empty one included, and bytes whose `__class__` claims str are
    copied as bytes.
    """
    held = ledger._store
    wallet = source("wpkh({}/84h/1h/9h/{}/*)")
    source_id = held.next_source_id()
    descriptors = {branch: str(wallet.descriptor(branch)) for branch in wallet.branches}
    added = store._Source(descriptors, {}, None, Conforming(2), Conforming(3), False)
    held.add_source(source_id, added)
    held.add_handed_out([(Conforming(source_id), Conforming(0), 0)])
    held.set_label(b"\x51", ConformingStr("b"), "send")
    tx = chain.pay([TxOut(1_000, script_of(ledger.new_address()))])
    block = BlockRef(Conforming(0), ConformingBytes(b""))
    comments = (ConformingStr("c"), ConformingStr(""))
    wtx = WalletTx(tx, TxState.CONFIRMED, block, 0, *comments, None, None)
    other = chain.pay([TxOut(2_000, script_of(ledger.new_address()))])
    claimed = BlockRef(1, ClaimsStr(b"\x01"))
    claiming = WalletTx(other, TxState.CONFIRMED, claimed, 1, None, None, None, None)
    held.upsert_txs([wtx, claiming])
    ledger.close()
    sources = _rows(path, "SELECT id, lookahead, birth FROM sources ORDER BY id")
    assert sources[-1] == (source_id, 2, 3)
    assert (source_id, 0, 0) in _rows(path, "SELECT * FROM handed_out")
    assert _rows(path, "SELECT label FROM labels WHERE script = x'51'") == [("b",)]
    sql = "SELECT height, block_id, comment, comment_to FROM txs ORDER BY seq"
    assert _rows(path, sql) == [(0, b"", "c", ""), (1, b"\x01", None, None)]


class _ConformingChain(FakeChain):
    """A reader answering each height and block id as a subclass of its own."""

    @override
    def get_history(
        self, scripts: Iterable[Octets | ScriptPubKey], start_height: int = 0
    ) -> ScriptHistory:
        # the ledger asks from a height this reader answered
        answer = super().get_history(scripts, _exact_int(start_height))

        def theirs(block: BlockRef) -> BlockRef:
            return BlockRef(Conforming(block.height), ConformingBytes(block.block_id))

        return ScriptHistory(
            theirs(answer.start),
            theirs(answer.tip),
            tuple(
                HistoryTx(
                    entry.tx, None if entry.block is None else theirs(entry.block)
                )
                for entry in answer.txs
            ),
        )


def test_a_reader_s_heights_and_ids_are_written_as_the_values_they_hold(
    path: Path,
) -> None:
    """What `store` says it binds of a reader's answers, read back.

    A reorganization drops the block of the old tip by its height.
    """
    chain = _ConformingChain()
    with Ledger.create(path, "regtest", chain) as ledger:
        ledger.add_source(source())
        payment = chain.pay([TxOut(100_000, script_of(ledger.new_address()))])
        [block_id] = chain.mine([payment])
        chain.mine(count=2)
        ledger.sync()
        chain.invalidate(2)
        ledger.sync()
    assert _rows(path, "SELECT height, block_id FROM blocks") == [(1, block_id)]
    assert _rows(path, "SELECT height, block_id FROM txs") == [(1, block_id)]
    tip = _rows(path, "SELECT value FROM meta WHERE key LIKE 'tip_%' ORDER BY key")
    assert tip == [("1",), (block_id.hex(),)]
    with Ledger.load(path, "regtest", chain) as again:
        assert again.tip == BlockRef(1, block_id)
        [info] = again.transactions
        assert info.wallet_tx.block == BlockRef(1, block_id)
