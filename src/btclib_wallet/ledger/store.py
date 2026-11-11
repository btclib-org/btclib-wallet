# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The file a `Ledger` lives in: SQLite, through the standard library.

Two integers in SQLite's own header say what the file is, as Bitcoin
Core's wallet does (src/wallet/sqlite.cpp at bitcoin/bitcoin@f0de87f040,
the v32.1 tag). `PRAGMA
application_id` is `APPLICATION_ID`, the same in every file this package
writes, so another program's SQLite file is refused before any table is
read. Core writes its network magic there instead, so a Core wallet file
is refused too. `PRAGMA user_version` is the format version,
`FORMAT_VERSION` for the files this release writes. A file of a newer
version is refused. A file of an older version is migrated one version
at a time, each step in its own SQLite transaction, by the steps
`_MIGRATIONS` holds. The network is a row of the `meta` table, checked
when the file is opened.

The file holds everything a load answers from: the sources, the
positions handed out, every transaction with its state and block, the
blocks synced through, and the tip. Each source's private keys are
written in plain text, as an unencrypted Core wallet writes its own:
ISS btclib-org/btclib-wallet#717 encrypts them. SQLite's rollback
journal and its freed pages can keep old bytes after a write.

Every write a sync makes is one SQLite transaction, so a process killed
mid-write leaves the file as the last whole sync left it.

A backup is a new file written through SQLite's backup API, as Core's
`SQLiteDatabase::Backup` writes one (src/wallet/sqlite.cpp:356-381 at
bitcoin/bitcoin@f0de87f040): a copy of every page of the file as one
read sees it, freed pages included. So it holds what the file holds,
private keys included, and the old bytes its freed pages keep.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from os import PathLike
from pathlib import Path
from urllib.parse import quote

from btclib.exceptions import BTClibValueError
from btclib.tx import Tx

from btclib_wallet.fetch.fetcher import tx_for_network
from btclib_wallet.fetch.history import BlockRef
from btclib_wallet.ledger.records import TxState, WalletTx

__all__ = ["APPLICATION_ID", "FORMAT_VERSION"]

# "btlw" in ASCII, big-endian: what `PRAGMA application_id` reads in a
# file this package wrote
APPLICATION_ID = 0x62746C77

# the format this release writes; a file carries it in `PRAGMA user_version`
FORMAT_VERSION = 1

_SCHEMA = (
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
)

# the step that takes a file from the version of its key to the next one
_MIGRATIONS: dict[int, Callable[[sqlite3.Connection], None]] = {}


@dataclass(frozen=True)
class _Source:
    """A source as the file holds it.

    `descriptors` is the text of each branch's descriptor, `prv_keys` the
    mapping `descriptors.parse` fills. `birth` is the height its history
    is read from, and `scanned` whether that read is done. The repr
    leaves `prv_keys` out: its values are private keys.
    """

    descriptors: dict[int, str]
    prv_keys: dict[str, str] = field(repr=False)
    lookahead: int
    birth: int
    scanned: bool


@dataclass(frozen=True)
class _SyncWrite:
    """What one sync writes, in one SQLite transaction."""

    upserted: tuple[WalletTx, ...]
    deleted: tuple[bytes, ...]
    fork_height: int | None
    blocks: tuple[BlockRef, ...]
    tip: BlockRef
    scanned: tuple[int, ...]
    handed_out: tuple[tuple[int, int, int], ...]


def _connect(path: str | PathLike[str], mode: str) -> sqlite3.Connection:
    """Open the file, `rw` refusing a missing one and `rwc` creating it."""
    uri = f"file:{quote(str(Path(path)))}?mode={mode}"
    try:
        return sqlite3.connect(uri, uri=True)
    except sqlite3.OperationalError as e:
        raise BTClibValueError(f"cannot open the ledger file {path}: {e}") from None


def _check_and_migrate(db: sqlite3.Connection, network: str) -> None:
    """Refuse a file that is not a ledger of `network`; migrate an older one."""
    application_id = _pragma(db, "application_id")
    version = _pragma(db, "user_version")
    if application_id != APPLICATION_ID:
        err_msg = f"not a ledger file: application id {application_id:#x}"
        raise BTClibValueError(err_msg)
    if version > FORMAT_VERSION:
        err_msg = f"ledger format {version} is newer than this release's"
        err_msg += f" {FORMAT_VERSION}"
        raise BTClibValueError(err_msg)
    while version < FORMAT_VERSION:
        if version not in _MIGRATIONS:
            raise BTClibValueError(f"no migration from ledger format {version}")
        # an explicit BEGIN: the sqlite3 module opens a transaction before
        # a DML statement alone, so a step's DDL would commit as it runs
        with db:
            db.execute("BEGIN")
            _MIGRATIONS[version](db)
            version += 1
            db.execute(f"PRAGMA user_version = {version}")
    row = db.execute("SELECT value FROM meta WHERE key = 'network'").fetchone()
    if row is None:
        raise BTClibValueError("not a ledger file: it names no network")
    if row[0] != network:
        raise BTClibValueError(f"a {row[0]} ledger file, not a {network} one")


def _decoded(text: str, source_id: int, column: str) -> dict[str, str]:
    """Return a source's column as the JSON object it holds.

    The decoder's error keeps the whole text, private keys included, so
    the refusal is raised outside the `except`, where no `__context__`
    holds it.
    """
    try:
        decoded: object = json.loads(text)
    except ValueError:
        decoded = None
    if not isinstance(decoded, dict):
        err_msg = f"not a ledger file: source {source_id}'s {column}"
        err_msg += " is not a JSON object"
        raise BTClibValueError(err_msg)
    return decoded


def _pragma(db: sqlite3.Connection, name: str) -> int:
    """Return the integer a pragma reads."""
    return int(db.execute(f"PRAGMA {name}").fetchone()[0])


def _new_file(path: str | PathLike[str]) -> None:
    """Make an empty file at `path`, refusing anything there.

    A directory and a link are refused too. The file is its owner's
    alone where the system has POSIX permissions.
    """
    try:
        Path(path).touch(mode=0o600, exist_ok=False)
    except OSError as e:
        # Windows refuses to make a file over a directory as a
        # PermissionError, not a FileExistsError
        if not (isinstance(e, FileExistsError) or Path(path).exists()):
            raise
        raise BTClibValueError(f"the ledger file exists: {path}") from None


def _copy(db: sqlite3.Connection, path: str | PathLike[str]) -> None:
    """Write the pages of `db` into a new file at `path`.

    A copy that fails after making the file removes it. A failure of
    SQLite's is refused naming `path`, SQLite's own text saying what
    failed, as a full disk or a file it cannot write.
    """
    _new_file(path)
    target: sqlite3.Connection | None = None
    try:
        target = _connect(path, "rw")
        db.backup(target)
    except BaseException as e:
        if target is not None:
            target.close()
        Path(path).unlink(missing_ok=True)
        if isinstance(e, sqlite3.DatabaseError):
            raise BTClibValueError(f"cannot copy into {path}: {e}") from None
        raise
    target.close()


def _copy_backup(backup: str | PathLike[str], path: str | PathLike[str]) -> None:
    """Copy the file at `backup` into a new file at `path`.

    Read-only on `backup`; a missing `backup` and one SQLite cannot read
    are refused before anything is made at `path`, and `_copy` says the
    rest. What the copy holds is `_Store.open`'s to check.
    """
    source = _connect(backup, "ro")
    try:
        try:
            source.execute("SELECT count(*) FROM sqlite_master").fetchone()
        except sqlite3.DatabaseError as e:
            raise BTClibValueError(f"not a ledger file: {e}") from None
        _copy(source, path)
    finally:
        source.close()


class _Store:
    """The open file, read and written in the shapes the ledger uses."""

    def __init__(self, db: sqlite3.Connection) -> None:
        self._db = db

    @classmethod
    def create(cls, path: str | PathLike[str], network: str) -> _Store:
        """Write a new file for `network`, refusing one that exists.

        The file is made readable and writable by its owner alone, where
        the system has POSIX permissions; SQLite gives its journal the
        same permissions. The header, the tables and the network are
        written in one SQLite transaction. A create that fails after
        making the file removes it, so nothing is left at `path`.
        """
        _new_file(path)
        db: sqlite3.Connection | None = None
        try:
            db = _connect(path, "rw")
            # an explicit BEGIN, as for a migration step: the pragmas and
            # the DDL would otherwise commit as each runs
            with db:
                db.execute("BEGIN")
                db.execute(f"PRAGMA application_id = {APPLICATION_ID}")
                db.execute(f"PRAGMA user_version = {FORMAT_VERSION}")
                for statement in _SCHEMA:
                    db.execute(statement)
                db.execute("INSERT INTO meta VALUES ('network', ?)", (network,))
        except BaseException:
            if db is not None:
                db.close()
            Path(path).unlink(missing_ok=True)
            raise
        return cls(db)

    @classmethod
    def open(cls, path: str | PathLike[str], network: str) -> _Store:
        """Open a file of this package for `network`, migrating an older one."""
        db = _connect(path, "rw")
        try:
            _check_and_migrate(db, network)
        except sqlite3.DatabaseError as e:
            db.close()
            raise BTClibValueError(f"not a ledger file: {e}") from None
        except BaseException:
            # a refusal, or a migration step that failed: the file is
            # closed either way
            db.close()
            raise
        return cls(db)

    def close(self) -> None:
        """Close the file."""
        self._db.close()

    def backup(self, path: str | PathLike[str]) -> None:
        """Write a copy of the file into a new file at `path`."""
        _copy(self._db, path)

    def sources(self) -> list[tuple[int, _Source]]:
        """Return every source, in the order it was added."""
        rows = self._db.execute(
            "SELECT id, descriptors, prv_keys, lookahead, birth, scanned"
            " FROM sources ORDER BY id"
        )
        return [
            (
                source_id,
                _Source(
                    {
                        int(b): text
                        for b, text in _decoded(
                            descriptors, source_id, "descriptors"
                        ).items()
                    },
                    _decoded(prv_keys, source_id, "prv_keys"),
                    lookahead,
                    birth,
                    bool(scanned),
                ),
            )
            for source_id, descriptors, prv_keys, lookahead, birth, scanned in rows
        ]

    def handed_out(self) -> list[tuple[int, int, int]]:
        """Return every position handed out, as source, branch and index."""
        rows = self._db.execute(
            "SELECT source, branch, idx FROM handed_out ORDER BY source, branch, idx"
        )
        return [(source, branch, index) for source, branch, index in rows]

    def txs(self, network: str) -> list[WalletTx]:
        """Return every transaction, its outputs labelled for `network`."""
        rows = self._db.execute(
            "SELECT raw, state, height, block_id, seq FROM txs ORDER BY seq"
        )
        return [
            WalletTx(
                tx_for_network(Tx.parse(raw), network),
                TxState(state),
                None if height is None else BlockRef(height, block_id),
                seq,
            )
            for raw, state, height, block_id, seq in rows
        ]

    def blocks(self) -> dict[int, bytes]:
        """Return the id of each block synced through, by height."""
        rows = self._db.execute("SELECT height, block_id FROM blocks")
        return dict(rows.fetchall())

    def tip(self) -> BlockRef | None:
        """Return the block the ledger is synced to, None before any sync."""
        rows = dict(
            self._db.execute(
                "SELECT key, value FROM meta WHERE key IN ('tip_height', 'tip_id')"
            ).fetchall()
        )
        if not rows:
            return None
        return BlockRef(int(rows["tip_height"]), bytes.fromhex(rows["tip_id"]))

    def add_source(self, source: _Source) -> int:
        """Write a source, and return its id."""
        source_id = int(
            self._db.execute("SELECT COALESCE(MAX(id) + 1, 0) FROM sources").fetchone()[
                0
            ]
        )
        with self._db:
            self._db.execute(
                "INSERT INTO sources VALUES (?, ?, ?, ?, ?, ?)",
                (
                    source_id,
                    json.dumps({str(b): t for b, t in source.descriptors.items()}),
                    json.dumps(dict(source.prv_keys)),
                    source.lookahead,
                    source.birth,
                    int(source.scanned),
                ),
            )
        return source_id

    def add_handed_out(self, positions: Iterable[tuple[int, int, int]]) -> None:
        """Write positions handed out."""
        with self._db:
            self._insert_handed_out(positions)

    def _insert_handed_out(self, positions: Iterable[tuple[int, int, int]]) -> None:
        self._db.executemany(
            "INSERT OR IGNORE INTO handed_out VALUES (?, ?, ?)", list(positions)
        )

    def upsert_txs(self, txs: Iterable[WalletTx]) -> None:
        """Write transactions, replacing any of the same id."""
        with self._db:
            self._upsert_txs(txs)

    def _upsert_txs(self, txs: Iterable[WalletTx]) -> None:
        self._db.executemany(
            "INSERT OR REPLACE INTO txs VALUES (?, ?, ?, ?, ?, ?)",
            [
                (
                    wtx.tx.id,
                    wtx.tx.serialize(include_witness=True),
                    wtx.state.value,
                    None if wtx.block is None else wtx.block.height,
                    None if wtx.block is None else wtx.block.block_id,
                    wtx.seq,
                )
                for wtx in txs
            ],
        )

    def delete_txs(self, txids: Iterable[bytes]) -> None:
        """Delete transactions by id."""
        with self._db:
            self._db.executemany(
                "DELETE FROM txs WHERE txid = ?", [(txid,) for txid in txids]
            )

    def write_sync(self, write: _SyncWrite) -> None:
        """Write what a sync decided, in one SQLite transaction."""
        with self._db:
            if write.fork_height is not None:
                self._db.execute(
                    "DELETE FROM blocks WHERE height > ?", (write.fork_height,)
                )
            self._db.executemany(
                "INSERT OR REPLACE INTO blocks VALUES (?, ?)",
                [(block.height, block.block_id) for block in write.blocks],
            )
            self._db.executemany(
                "DELETE FROM txs WHERE txid = ?", [(txid,) for txid in write.deleted]
            )
            self._upsert_txs(write.upserted)
            self._db.executemany(
                "UPDATE sources SET scanned = 1 WHERE id = ?",
                [(source,) for source in write.scanned],
            )
            self._insert_handed_out(write.handed_out)
            _write_tip(self._db, write.tip)


def _write_tip(db: sqlite3.Connection, tip: BlockRef) -> None:
    """Write the tip into `meta`."""
    rows: Mapping[str, str] = {
        "tip_height": str(tip.height),
        "tip_id": tip.block_id.hex(),
    }
    db.executemany("INSERT OR REPLACE INTO meta VALUES (?, ?)", list(rows.items()))
