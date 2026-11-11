# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What the ledger's file says it is, and which files a load refuses."""

from __future__ import annotations

import os
import sqlite3
import stat
from pathlib import Path

import pytest
from btclib.exceptions import BTClibTypeError, BTClibValueError

from btclib_wallet.ledger import APPLICATION_ID, FORMAT_VERSION, Ledger, store
from tests.ledger.conftest import LOOKAHEAD, XPRV, FakeChain, source
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
    assert _pragma(path, "user_version") == FORMAT_VERSION == 1
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
    with pytest.raises(BTClibValueError, match="ledger format 2 is newer"):
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

    monkeypatch.setattr(store, "FORMAT_VERSION", 3)
    monkeypatch.setattr(store, "_MIGRATIONS", {1: step, 2: step})
    Ledger.load(path, "regtest", chain).close()
    assert ran == [1, 2]
    assert _pragma(path, "user_version") == 3
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

    monkeypatch.setattr(store, "FORMAT_VERSION", 2)
    monkeypatch.setattr(store, "_MIGRATIONS", {1: step})
    with pytest.raises(RuntimeError, match="the step failed"):
        Ledger.load(path, "regtest", chain)
    assert _pragma(path, "user_version") == 1
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


def test_a_source_id_another_ledger_took_meanwhile_is_refused(
    chain: FakeChain, path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two ledgers on one file, the second adding between the first's two steps.

    The first reads the next id, the second writes a source under it,
    and the first's write is refused, not raised as SQLite's error. The
    file keeps the second's source.
    """
    with (
        Ledger.create(path, "regtest", chain) as first,
        Ledger.load(path, "regtest", chain) as second,
    ):
        write = first._store.add_source

        def between(source_id: int, written: store._Source) -> None:
            assert second.add_source(source("wpkh({}/84h/1h/1h/{}/*)")) == source_id
            write(source_id, written)

        monkeypatch.setattr(first._store, "add_source", between)
        with pytest.raises(BTClibValueError, match="source 0 was written by another"):
            first.add_source(source())
    with Ledger.load(path, "regtest", chain) as ledger:
        assert len(ledger.sources) == 1
