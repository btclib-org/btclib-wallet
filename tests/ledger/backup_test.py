# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A `Ledger`'s backup, what it holds, and the restore that reads it.

The cases follow Core's test/functional/wallet_backup.py at
bitcoin/bitcoin@f0de87f040, the v32.1 tag: backups taken before more
rounds of payments restore the balances the original reaches (lines
209-257), a backup onto the wallet's own file is refused (lines
263-271), and a restore from a missing or foreign file, or onto a wallet
that exists, is refused (lines 94-119). Wallet names and directories are
the caller's: a `Ledger` takes paths.
"""

from __future__ import annotations

import os
import platform
import re
import sqlite3
import stat
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.tx import TxOut

from btclib_wallet.exceptions import FetchError
from btclib_wallet.ledger import APPLICATION_ID, FORMAT_VERSION, Ledger, store
from tests import raises_alone
from tests.ledger.conftest import LOOKAHEAD, FakeChain, script_of, source
from tests.refused_value_test import KEY, SPELLINGS
from tests.secret_free import assert_secret_free

_PYPY = platform.python_implementation() == "PyPy"
# what a copy SQLite refuses to write raises: PyPy's `Connection.backup`
# calls `.decode` on a C string where SQLite reports a failure (ISS
# btclib-org/btclib-wallet#763)
_COPY_REFUSALS: tuple[type[Exception], ...] = (
    (BTClibValueError, AttributeError) if _PYPY else (BTClibValueError,)
)


def _answers(ledger: Ledger) -> tuple[Any, ...]:
    """Return what a load answers from, without a read of the backend."""
    return (
        ledger.balances(),
        ledger.utxos(0),
        ledger.transactions,
        ledger.tip,
        [str(wallet.descriptor(0)) for wallet in ledger.sources],
    )


def _synced(ledger: Ledger) -> tuple[Any, ...]:
    """Return what a sync answers, whatever order it saw transactions in.

    `seq` is the order the ledger first saw each transaction in: a
    restored ledger reads in one sync what the original read over many,
    and need not see it in the same order.
    """
    return (
        ledger.balances(),
        sorted(ledger.utxos(0), key=lambda u: (u.outpoint.tx_id, u.outpoint.vout)),
        {
            info.wallet_tx.tx.id: replace(
                info, wallet_tx=replace(info.wallet_tx, seq=0)
            )
            for info in ledger.transactions
        },
        ledger.tip,
    )


def _round(ledger: Ledger, chain: FakeChain) -> None:
    """Receive at a new address, spend part of it with change, mine."""
    payment = chain.pay([TxOut(100_000, script_of(ledger.new_address()))])
    chain.mine([payment])
    ledger.sync()
    other = source("wpkh({}/84h/1h/9h/{}/*)", (0,))
    ledger.spend([TxOut(30_000, other.script_pub_key(0, 0))])
    chain.mine(list(chain.mempool.values()))
    ledger.sync()


def test_a_backup_holds_what_the_file_holds(
    ledger: Ledger, chain: FakeChain, tmp_path: Path
) -> None:
    """Loaded, the copy answers what the ledger answers."""
    _round(ledger, chain)
    backup = tmp_path / "ledger.bak"
    ledger.backup(backup)
    with Ledger.load(backup, "regtest", chain) as copy:
        assert _answers(copy) == _answers(ledger)
    db = sqlite3.connect(backup)
    try:
        assert db.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID
        assert db.execute("PRAGMA user_version").fetchone()[0] == FORMAT_VERSION
    finally:
        db.close()


@pytest.mark.skipif(os.name != "posix", reason="no POSIX permissions")
def test_a_backup_is_its_owners_alone(ledger: Ledger, tmp_path: Path) -> None:
    """It holds the private keys the file holds."""
    backup = tmp_path / "ledger.bak"
    ledger.backup(backup)
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600


def test_a_backup_refuses_anything_at_its_path(
    ledger: Ledger, path: Path, tmp_path: Path
) -> None:
    """The ledger's own file, a link to it, a directory, another file."""
    other = tmp_path / "other.bak"
    other.write_bytes(b"kept")
    link = tmp_path / "link.bak"
    link.symlink_to(path)
    original = path.read_bytes()
    for target in (path, f"{tmp_path}/./{path.name}", link, tmp_path, other):
        with pytest.raises(BTClibValueError, match="the ledger file exists"):
            ledger.backup(target)
    assert path.read_bytes() == original
    assert other.read_bytes() == b"kept"
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "ledger.sqlite",
        "ledger.sqlite-journal",
        "link.bak",
        "other.bak",
    ]
    with pytest.raises(BTClibTypeError, match="invalid path type"):
        ledger.backup(b"ledger.bak")  # type: ignore[arg-type]


@pytest.mark.parametrize("parent", ["missing", "a file"])
def test_a_file_the_system_cannot_make_is_refused_by_its_class(
    ledger: Ledger, chain: FakeChain, tmp_path: Path, parent: str
) -> None:
    """A key's hex in the path is in no refusal (issue #821).

    The system's `OSError` holds the path, so the refusal names its class
    alone and chains nothing: under a missing directory, and under a file,
    which POSIX and Windows refuse as different classes.
    """
    backup = tmp_path / "ledger.bak"
    ledger.backup(backup)
    if parent == "a file":
        (tmp_path / parent).write_bytes(b"")
    target = tmp_path / parent / KEY.hex()
    for call in (
        lambda: ledger.backup(target),
        lambda: Ledger.create(target, "regtest", chain),
        lambda: Ledger.restore(backup, target, "regtest", chain),
    ):
        with raises_alone(BTClibValueError, r"^cannot make the ledger file: \w+$") as e:
            call()
        assert_secret_free(e.value, SPELLINGS)
        assert not target.exists()


def test_a_backup_that_cannot_open_its_file_leaves_none(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The file made, then not opened: it is removed."""

    def refuse(path: Path, mode: str) -> sqlite3.Connection:
        raise BTClibValueError(f"cannot open the ledger file {path}")

    monkeypatch.setattr(store, "_connect", refuse)
    backup = tmp_path / "ledger.bak"
    with pytest.raises(BTClibValueError, match="cannot open the ledger file"):
        ledger.backup(backup)
    assert not backup.exists()


# the path is the caller's and SQLite's text is not relayed
_COPY_REFUSED = "^cannot copy the ledger file: OperationalError$"


def test_a_copy_that_cannot_write_names_the_copy_and_leaves_none(
    ledger: Ledger, chain: FakeChain, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A write SQLite refuses, as on a full disk: the backup is not blamed.

    The new file is opened read-only, so SQLite refuses the first page
    written, on a backup and on a restore alike. `_COPY_REFUSALS` says
    what PyPy raises instead; the file is removed all the same.
    """
    backup = tmp_path / "ledger.bak"
    ledger.backup(backup)
    connect = store._connect

    def read_only(path: Path, mode: str) -> sqlite3.Connection:
        return connect(path, "ro")

    monkeypatch.setattr(store, "_connect", read_only)
    second = tmp_path / "second.bak"
    with pytest.raises(_COPY_REFUSALS) as refused:
        ledger.backup(second)
    assert _PYPY or re.match(_COPY_REFUSED, str(refused.value))
    assert not second.exists()
    restored = tmp_path / "restored.sqlite"
    with pytest.raises(_COPY_REFUSALS) as refused:
        Ledger.restore(backup, restored, "regtest", chain)
    assert _PYPY or re.match(_COPY_REFUSED, str(refused.value))
    assert not restored.exists()


@pytest.mark.parametrize("secure_delete", [0, 1])
def test_a_backup_keeps_the_old_bytes_of_freed_pages(
    ledger: Ledger, tmp_path: Path, secure_delete: int
) -> None:
    """A row deleted from the file is in the backup's freed pages.

    Unless the delete zeroed them: `PRAGMA secure_delete`, which the
    ledger's connection turns on, so the test sets it either way. The
    ledger holds the file, so the row is written through its connection.
    """
    secret = b"a deleted secret " * 300
    db = ledger._store._db
    db.execute(f"PRAGMA secure_delete = {secure_delete}").fetchall()
    with db:
        db.execute("CREATE TABLE scratch(x BLOB)")
        db.execute("INSERT INTO scratch VALUES (?)", (secret,))
    with db:
        db.execute("DELETE FROM scratch")
    backup = tmp_path / "ledger.bak"
    ledger.backup(backup)
    kept = b"a deleted secret " * 10 in backup.read_bytes()
    assert kept is not bool(secure_delete)


def test_a_restored_ledger_syncs_on_from_its_tip(
    ledger: Ledger, chain: FakeChain, path: Path, tmp_path: Path
) -> None:
    """Rounds of payments after the backup, and the restore answers the same.

    Each round hands out a receive and a change address past what the
    backup holds, and the rounds go past the window the backup watches
    on each branch: the restored ledger finds them as each payment it
    finds moves its window on.
    """
    _round(ledger, chain)
    backup = tmp_path / "ledger.bak"
    ledger.backup(backup)
    backup_tip = ledger.tip
    assert backup_tip is not None
    for _ in range(LOOKAHEAD + 2):
        _round(ledger, chain)
    expected = _synced(ledger)
    ledger.close()
    path.unlink()

    restored_path = tmp_path / "restored.sqlite"
    restored = Ledger.restore(backup, restored_path, "regtest", chain)
    last = restored.sources[0].script_pub_key(0, LOOKAHEAD + 2)
    with restored:
        assert restored.tip == backup_tip
        assert restored.position_of(last) is None
        chain.reads.clear()
        restored.sync()
        assert chain.reads[0] == backup_tip.height
        assert _synced(restored) == expected
        assert restored.position_of(last) == (0, 0, LOOKAHEAD + 2)
    # the backup is read, not changed: it restores again
    with Ledger.restore(backup, tmp_path / "again.sqlite", "regtest", chain) as again:
        assert again.tip == backup_tip


def test_a_restore_is_refused_and_leaves_nothing(
    ledger: Ledger, chain: FakeChain, path: Path, tmp_path: Path
) -> None:
    """A missing backup, a foreign file, a file at the path, another network."""
    backup = tmp_path / "ledger.bak"
    ledger.backup(backup)
    target = tmp_path / "restored.sqlite"

    with pytest.raises(BTClibValueError, match="cannot open the ledger file"):
        Ledger.restore(tmp_path / "missing.bak", target, "regtest", chain)
    assert not target.exists()

    text = tmp_path / "text.bak"
    text.write_text("not a database, but long enough to be read as one " * 20)
    with pytest.raises(BTClibValueError, match="not a ledger file"):
        Ledger.restore(text, target, "regtest", chain)
    assert not target.exists()

    foreign = tmp_path / "foreign.bak"
    db = sqlite3.connect(foreign)
    with db:
        db.execute("CREATE TABLE t(x INTEGER)")
    db.close()
    with pytest.raises(BTClibValueError, match="not a ledger file: application id 0"):
        Ledger.restore(foreign, target, "regtest", chain)
    assert not target.exists()

    with pytest.raises(BTClibValueError, match="a regtest ledger file, not a testnet"):
        Ledger.restore(backup, target, "testnet", chain)
    assert not target.exists()

    original = path.read_bytes()
    with pytest.raises(BTClibValueError, match="the ledger file exists"):
        Ledger.restore(backup, path, "regtest", chain)
    assert path.read_bytes() == original

    with pytest.raises(BTClibTypeError, match="invalid backup type"):
        Ledger.restore(b"ledger.bak", target, "regtest", chain)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid path type"):
        Ledger.restore(backup, 1, "regtest", chain)  # type: ignore[arg-type]
    assert not target.exists()


def test_a_restore_past_the_backends_blocks_fails_at_the_sync(
    ledger: Ledger, chain: FakeChain, tmp_path: Path
) -> None:
    """A backend without the block the backup was synced to says so.

    `BitcoinCoreFetcher` raises `FetchError` on a block a pruned node no
    longer has; Core refuses such a restore at load (wallet_backup.py
    lines 190-194). The restore reads no backend, so the refusal is the
    first sync's, and that sync writes nothing.
    """
    _round(ledger, chain)
    backup = tmp_path / "ledger.bak"
    ledger.backup(backup)
    restored_path = tmp_path / "restored.sqlite"
    with Ledger.restore(backup, restored_path, "regtest", chain) as restored:
        expected = _answers(restored)
        chain.mine(count=3)

        def pruned() -> None:
            raise FetchError("block 2 has no undo data: the node pruned it")

        chain.on_read.append(pruned)
        with pytest.raises(FetchError, match="pruned"):
            restored.sync()
        assert _answers(restored) == expected
    with Ledger.load(restored_path, "regtest", chain) as reloaded:
        assert _answers(reloaded) == expected
