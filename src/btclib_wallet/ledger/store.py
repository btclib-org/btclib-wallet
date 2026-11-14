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
positions handed out, every transaction with its state, block, comments
and the bump that links it to another, the blocks synced through, the
tip, and the labels. Each source's private keys are written in plain
text, as an unencrypted Core wallet writes its own, until
`Ledger.encrypt` encrypts them. In an encrypted file a source
that holds private keys is written as what a locked ledger reads: its
descriptors as `descriptors.normalized` writes them, which derive every
script with no private key, and no key. The descriptors it was added
with and their private keys are one ciphertext beside them, and the
master key that ciphertext is under is the `master_key` table's.
`crypto` says how each is encrypted.

Every connection turns SQLite's `secure_delete` on, so what a write
replaces or deletes is overwritten with zeros, in the file and in its
freed pages, as the measurement on ISS btclib-org/btclib-wallet#623
asks. SECURITY.md's *A ledger's keys at rest* says what that leaves
outside the file. That holds in SQLite's rollback-journal mode, which
every connection that writes sets: in WAL mode the pages a write
replaces stay in the main file until a checkpoint, `secure_delete` or
not. So a file another program set to WAL goes back to the rollback
journal when it is opened, and one another connection has open and has
read, which keeps it in WAL mode, is refused. The journal is truncated
at the end of each transaction, not deleted: under the lock below, a
journal in `DELETE` mode keeps the pages it saved until the file is
closed. A journal a killed process left is rolled back at the load and
stays whole until the ledger's first write truncates it, or its close
deletes it.

**One ledger per file.** A ledger holds its file's exclusive lock from
`create`, `load` or `restore` until `close`, as Core holds a wallet's
(`SQLiteDatabase::Open`, src/wallet/sqlite.cpp:289-299 at
bitcoin/bitcoin@f0de87f040). So another SQLite connection neither reads
nor writes the file meanwhile: a load of a file another ledger holds is
refused at once, and so is a restore from it. Two ledgers on one file
would each write rows over the other's with what it read at its load.

The lock is SQLite's, a POSIX advisory lock where the system has one.
A program reading the file directly, as `cp` does, is not refused. And
a plain open and close of the file in the process that holds it, as
`shutil.copyfile` makes, releases the lock (sqlite.org/howtocorrupt.html,
section 2.2), so that another ledger can then open it and the two
corrupt it. While a ledger holds the file, copy it with
`Ledger.backup`. A ledger never closed keeps its file locked until its
connection is collected.

Every write a sync makes is one SQLite transaction, so a process killed
mid-write leaves the file as the last whole sync left it.

A backup is a new file written through SQLite's backup API, as Core's
`SQLiteDatabase::Backup` writes one (src/wallet/sqlite.cpp:356-381 at
bitcoin/bitcoin@f0de87f040): a copy of every page of the file as one
read sees it, freed pages included, which `secure_delete` keeps
zeroed. So it holds what the file holds: private keys in plain text
where the ledger is not encrypted, and only their ciphertext where it
is.
"""

from __future__ import annotations

import contextlib
import json
import re
import sqlite3
import sys
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from os import PathLike
from pathlib import Path
from typing import TypeGuard
from urllib.parse import quote

from btclib.exceptions import BTClibValueError
from btclib.network import NETWORKS
from btclib.tx import Tx

from btclib_wallet._refusal import _label, _message_text, _quoted
from btclib_wallet.fetch.fetcher import tx_for_network
from btclib_wallet.fetch.history import BlockRef
from btclib_wallet.ledger.crypto import _assert_cost, _MasterKey
from btclib_wallet.ledger.records import TxState, WalletTx

__all__ = ["APPLICATION_ID", "FORMAT_VERSION"]

# "btlw" in ASCII, big-endian: what `PRAGMA application_id` reads in a
# file this package wrote
APPLICATION_ID = 0x62746C77

# the format this release writes; a file carries it in `PRAGMA user_version`
FORMAT_VERSION = 2

# format 1's tables, as v2026.11.11 wrote them: a new file is written as
# format 1 and taken through `_MIGRATIONS`, so that it and a migrated file
# are one layout
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
    (
        "CREATE TABLE labels(script BLOB PRIMARY KEY, label TEXT NOT NULL,"
        " purpose TEXT NOT NULL)"
    ),
)


def _to_format_2(db: sqlite3.Connection) -> None:
    """Take format 1 to 2: encryption, and a transaction's comments and bump.

    A source's ciphertext column and the master key: every source keeps
    its id and its keys in plain text, with no ciphertext, and the file
    has no master key, so it is unencrypted, as format 1 is. A
    transaction's `comment`, `comment_to`, `replaces` and `replaced_by`
    columns: every transaction has none of them, as in format 1.
    """
    db.execute("ALTER TABLE sources ADD COLUMN encrypted BLOB")
    db.execute(
        "CREATE TABLE master_key(id INTEGER PRIMARY KEY CHECK (id = 0),"
        " kdf TEXT NOT NULL, n INTEGER NOT NULL, r INTEGER NOT NULL,"
        " p INTEGER NOT NULL, salt BLOB NOT NULL, encrypted BLOB NOT NULL)"
    )
    for column in (
        "comment TEXT",
        "comment_to TEXT",
        "replaces BLOB",
        "replaced_by BLOB",
    ):
        db.execute(f"ALTER TABLE txs ADD COLUMN {column}")


# the step that takes a file from the version of its key to the next one
_MIGRATIONS: dict[int, Callable[[sqlite3.Connection], None]] = {1: _to_format_2}


@dataclass(frozen=True)
class _Source:
    """A source as the file holds it.

    `descriptors` is the text of each branch's descriptor, `prv_keys` the
    mapping `descriptors.parse` fills. `encrypted` is None where the keys
    are in `prv_keys`; in an encrypted file it is the ciphertext of the
    descriptors the source was added with and their keys, and
    `prv_keys` is empty. `birth` is the height its history is read
    from, and `scanned` whether that read is done. The repr leaves
    `prv_keys` out: its values are private keys.
    """

    descriptors: dict[int, str]
    prv_keys: dict[str, str] = field(repr=False)
    encrypted: bytes | None = field(repr=False)
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
    """Open the file, `rw` refusing a missing one and `ro` reading it only.

    An `rw` connection holds the file, as the module's docstring says,
    and is closed by `_release`. A file another connection holds is
    refused at once: `timeout=0` waits for no lock.
    """
    uri = f"file:{quote(str(Path(path)))}?mode={mode}"
    # each refusal of SQLite's failure is raised after the `except` block
    # that sees it, so that it chains nothing
    db = None
    with contextlib.suppress(sqlite3.OperationalError):
        db = sqlite3.connect(uri, uri=True, timeout=0)
    if db is None:
        raise BTClibValueError("cannot open the ledger file: OperationalError")
    # each pragma's row is read: SQLite refuses a commit while a statement
    # that writes is unfinished, and PyPy finishes an unread one only when
    # it collects its cursor
    db.execute("PRAGMA secure_delete = ON").fetchall()
    if mode != "ro":
        refusal = None
        try:
            # in exclusive locking mode the lock a transaction takes is
            # kept after it ends
            db.execute("PRAGMA locking_mode = EXCLUSIVE").fetchall()
            db.execute("BEGIN EXCLUSIVE")
            db.execute("COMMIT")
            db.execute("PRAGMA journal_mode = TRUNCATE").fetchall()
        except sqlite3.DatabaseError as e:
            if isinstance(e, sqlite3.OperationalError):
                refusal = _database_refusal(e, "cannot open the ledger file")
            else:
                refusal = _database_refusal(e, "not a ledger file")
        # closed after the block, where no exception is handled
        if refusal is not None:
            db.close()
            raise BTClibValueError(refusal)
    return db


def _database_refusal(e: sqlite3.DatabaseError, what: str) -> str:
    """Return what a refusal says of a failure of SQLite's.

    A file whose lock another connection holds is said to be held. An
    error with no `sqlite_errorname` is not that one: not every
    `sqlite3.DatabaseError` carries one. Any other failure is `what` and
    the class of SQLite's error, whose text is not relayed.
    """
    if getattr(e, "sqlite_errorname", None) == "SQLITE_BUSY":
        return "the ledger file is open in another ledger or program"
    return f"{what}: {type(e).__name__}"


def _release(db: sqlite3.Connection) -> None:
    """Close an `rw` connection, and with it the file's journal.

    In exclusive locking mode SQLite deletes the journal this connection
    opened at close in `DELETE` mode only, and leaves it empty in
    `TRUNCATE` mode. A switch that fails leaves that empty journal, and
    the file is closed all the same.
    """
    with contextlib.suppress(sqlite3.Error):
        db.execute("PRAGMA journal_mode = DELETE").fetchall()
    db.close()


def _check_and_migrate(db: sqlite3.Connection, network: str) -> None:
    """Refuse a file that is not a ledger of `network`; migrate an older one."""
    application_id = _pragma(db, "application_id")
    version = _pragma(db, "user_version")
    if application_id != APPLICATION_ID:
        err_msg = f"not a ledger file: application id {_quoted(application_id)}"
        raise BTClibValueError(err_msg)
    _assert_not_newer(version)
    # every format has `meta`: a file of another network is refused before
    # a step runs, and left at its version
    row = db.execute("SELECT value FROM meta WHERE key = 'network'").fetchone()
    if row is None:
        raise BTClibValueError("not a ledger file: it names no network")
    if row[0] != network:
        # the file's network after a colon, where no article stands before
        # what `_label` writes of one it does not know
        err_msg = f"not a {_label(network, NETWORKS)} ledger file: its network is"
        err_msg += f" {_label(row[0], NETWORKS)}"
        raise BTClibValueError(err_msg)
    while version < FORMAT_VERSION:
        # an explicit BEGIN: the sqlite3 module opens a transaction before
        # a DML statement alone, so a step's DDL would commit as it runs
        with db:
            db.execute("BEGIN")
            if version not in _MIGRATIONS:
                raise BTClibValueError(
                    f"no migration from ledger format {_quoted(version)}"
                )
            _MIGRATIONS[version](db)
            version += 1
            db.execute(f"PRAGMA user_version = {version}")


def _assert_not_newer(version: int) -> None:
    """Refuse a file of a format a later release writes."""
    if version > FORMAT_VERSION:
        err_msg = f"ledger format {_quoted(version)} is newer than this release's"
        err_msg += f" {FORMAT_VERSION}"
        raise BTClibValueError(err_msg)


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
        err_msg = f"not a ledger file: source {_quoted(source_id)}'s {column}"
        err_msg += " is not a JSON object"
        raise BTClibValueError(err_msg)
    return decoded


# a branch as the file writes it: the decimal `str` writes of an int that
# is not negative, which `add_source` takes with no upper bound
_BRANCH = re.compile(r"0|[1-9][0-9]*")
# a height: any int an SQLite INTEGER holds, since a sync writes what a
# backend answers, a negative height included. A sync writes its tip's
# height into `blocks` too, in the transaction that writes the tip's text
# into `meta`, so that text is in the range as well
_INTEGERS = range(-(2**63), 2**63)
_HEIGHT = re.compile(r"-?(0|[1-9][0-9]{0,18})")
# a block id: any bytes, as `hex` writes them into the tip's text
_HEX = re.compile(r"(?:[0-9a-f]{2})*")
_STATES = {state.value: state for state in TxState}


def _is_branch(key: object) -> bool:
    """Return whether a key of a descriptors map is a branch `int` can read.

    The interpreter's limit on the digits of an int holds for `str` and
    `int` alike: a key past it is none `str` wrote, and `int` would raise
    on it.
    """
    limit = sys.get_int_max_str_digits()
    return (
        isinstance(key, str)
        and _BRANCH.fullmatch(key) is not None
        and (limit == 0 or len(key) <= limit)
    )


def _branches(value: object, source_id: int) -> dict[int, str]:
    """Return a source's descriptors by branch, from the object the file holds.

    `int` quotes the literal it refuses, and a key of the file can be
    anything, so a key that is not a branch is refused here, by the
    source alone, before `int` reads it (issue #900).
    """
    if not isinstance(value, dict) or not all(_is_branch(b) for b in value):
        err_msg = f"not a ledger file: source {_quoted(source_id)}'s descriptors"
        err_msg += " are not keyed by branch"
        raise BTClibValueError(err_msg)
    return {int(b): text for b, text in value.items()}


def _height(value: object) -> TypeGuard[int]:
    """Return whether a column holds a height as the file writes it."""
    return type(value) is int and value in _INTEGERS


def _counted(value: object) -> TypeGuard[int]:
    """Return whether a column holds a seq as the file writes it.

    Each seq the ledger writes counts on from 0: one past the highest it
    holds, or 0 where it holds none.
    """
    return _height(value) and value >= 0


def _tx_block(height: object, block_id: object) -> BlockRef | None:
    """Return the block a transaction's row confirms it in, None for none.

    `BlockRef` checks nothing, so a row is read where its height and its
    block id are as `_upsert_txs` writes them: both None, or a height and
    the bytes of an id, of whatever length the backend answered.
    """
    if height is None and block_id is None:
        return None
    if not (_height(height) and isinstance(block_id, bytes)):
        raise BTClibValueError("not a ledger file: a transaction in a malformed block")
    return BlockRef(height, block_id)


def _tx_state(value: object) -> TxState:
    """Return the state a transaction's row holds.

    `TxState` quotes a value it does not know, so one is refused here.
    """
    state = _STATES.get(value) if isinstance(value, str) else None
    if state is None:
        raise BTClibValueError("not a ledger file: a transaction in no state")
    return state


def _encrypted(value: object, source_id: int) -> bytes | None:
    """Return a source's ciphertext, None where it has none."""
    if value is not None and not isinstance(value, bytes):
        err_msg = f"not a ledger file: source {_quoted(source_id)}'s encrypted keys"
        err_msg += " are no blob"
        raise BTClibValueError(err_msg)
    return value


def _pragma(db: sqlite3.Connection, name: str) -> int:
    """Return the integer a pragma reads."""
    return int(db.execute(f"PRAGMA {name}").fetchone()[0])


def _new_file(path: str | PathLike[str]) -> None:
    """Make an empty file at `path`, refusing anything there.

    A directory and a link are refused too. The file is its owner's
    alone where the system has POSIX permissions.

    A failure of the system is refused by the class of its `OSError`,
    raised after the `except` block: the error's own text and `filename`
    are the caller's path, which can hold anything.
    """
    failure = None
    try:
        Path(path).touch(mode=0o600, exist_ok=False)
    except OSError as e:
        # Windows refuses to make a file over a directory as a
        # PermissionError, not a FileExistsError
        if isinstance(e, FileExistsError) or Path(path).exists():
            failure = "the ledger file exists"
        else:
            failure = f"cannot make the ledger file: {type(e).__name__}"
    if failure is not None:
        raise BTClibValueError(failure)


def _copy(db: sqlite3.Connection, path: str | PathLike[str]) -> None:
    """Write the pages of `db` into a new file at `path`.

    A copy that fails after making the file removes it. A failure of
    SQLite's is refused by the class of SQLite's error, whose text is not
    relayed.
    """
    _new_file(path)
    target: sqlite3.Connection | None = None
    failure: str
    try:
        target = _connect(path, "rw")
        db.backup(target)
    except sqlite3.DatabaseError as e:
        failure = f"cannot copy the ledger file: {type(e).__name__}"
    except BaseException:
        _undo_copy(target, path)
        raise
    else:
        _release(target)
        return
    # undone after the block, where no exception is handled
    _undo_copy(target, path)
    raise BTClibValueError(failure)


def _undo_copy(target: sqlite3.Connection | None, path: str | PathLike[str]) -> None:
    """Close the copy where it was opened, and remove its file."""
    if target is not None:
        _release(target)
    Path(path).unlink(missing_ok=True)


def _copy_backup(backup: str | PathLike[str], path: str | PathLike[str]) -> None:
    """Copy the file at `backup` into a new file at `path`.

    Read-only on `backup`; a missing `backup` and one SQLite cannot read
    are refused before anything is made at `path`, and `_copy` says the
    rest. What the copy holds is `_Store.open`'s to check.
    """
    source = _connect(backup, "ro")
    try:
        refusal = None
        try:
            source.execute("SELECT count(*) FROM sqlite_master").fetchone()
        except sqlite3.DatabaseError as e:
            refusal = _database_refusal(e, "not a ledger file")
        if refusal is not None:
            raise BTClibValueError(refusal)
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
                for statement in _SCHEMA:
                    db.execute(statement)
                for version in range(1, FORMAT_VERSION):
                    _MIGRATIONS[version](db)
                db.execute(f"PRAGMA user_version = {FORMAT_VERSION}")
                db.execute("INSERT INTO meta VALUES ('network', ?)", (network,))
        except BaseException:
            if db is not None:
                _release(db)
            Path(path).unlink(missing_ok=True)
            raise
        return cls(db)

    @classmethod
    def open(cls, path: str | PathLike[str], network: str) -> _Store:
        """Open a file of this package for `network`, migrating an older one."""
        db = _connect(path, "rw")
        failure = None
        try:
            _check_and_migrate(db, network)
        except sqlite3.DatabaseError as e:
            failure = f"not a ledger file: {type(e).__name__}"
        except BaseException:
            # a refusal, or a migration step that failed: the file is
            # closed either way
            _release(db)
            raise
        # closed after the block, where no exception is handled
        if failure is not None:
            _release(db)
            raise BTClibValueError(failure)
        return cls(db)

    def close(self) -> None:
        """Close the file, and let another ledger open it."""
        _release(self._db)

    def backup(self, path: str | PathLike[str]) -> None:
        """Write a copy of the file into a new file at `path`."""
        _copy(self._db, path)

    def sources(self) -> list[tuple[int, _Source]]:
        """Return every source, in the order it was added."""
        rows = self._db.execute(
            "SELECT id, descriptors, prv_keys, encrypted, lookahead, birth, scanned"
            " FROM sources ORDER BY id"
        )
        return [
            (
                source_id,
                _Source(
                    _branches(
                        _decoded(descriptors, source_id, "descriptors"), source_id
                    ),
                    _decoded(prv_keys, source_id, "prv_keys"),
                    _encrypted(encrypted, source_id),
                    lookahead,
                    birth,
                    bool(scanned),
                ),
            )
            for source_id, descriptors, prv_keys, encrypted, lookahead, birth, scanned in (
                rows
            )
        ]

    def master_key(self) -> _MasterKey | None:
        """Return the encrypted master key, None in a file not encrypted."""
        row = self._db.execute(
            "SELECT kdf, n, r, p, salt, encrypted FROM master_key"
        ).fetchone()
        if row is None:
            return None
        kdf, n, r, p, salt, encrypted = row
        if kdf != "scrypt":
            raise BTClibValueError(
                f"not a ledger file: unknown kdf, {_message_text(kdf)}"
            )
        if not all(isinstance(v, int) for v in (n, r, p)) or not all(
            isinstance(v, bytes) for v in (salt, encrypted)
        ):
            raise BTClibValueError("not a ledger file: a malformed master key")
        _assert_cost(n, r, p)
        return _MasterKey(n, r, p, salt, encrypted)

    def handed_out(self) -> list[tuple[int, int, int]]:
        """Return every position handed out, as source, branch and index."""
        rows = self._db.execute(
            "SELECT source, branch, idx FROM handed_out ORDER BY source, branch, idx"
        )
        return list(rows)

    def txs(self, network: str) -> list[WalletTx]:
        """Return every transaction, its outputs labelled for `network`."""
        rows = self._db.execute(
            "SELECT raw, state, height, block_id, seq, comment, comment_to,"
            " replaces, replaced_by FROM txs ORDER BY seq"
        )
        txs: list[WalletTx] = []
        for (
            raw,
            state,
            height,
            block_id,
            seq,
            comment,
            comment_to,
            replaces,
            replaced_by,
        ) in rows:
            # `WalletTx` checks nothing either
            if not _counted(seq):
                raise BTClibValueError(
                    "not a ledger file: a transaction with a malformed seq"
                )
            txs.append(
                WalletTx(
                    tx_for_network(Tx.parse(raw), network),
                    _tx_state(state),
                    _tx_block(height, block_id),
                    seq,
                    comment,
                    comment_to,
                    replaces,
                    replaced_by,
                )
            )
        return txs

    def blocks(self) -> dict[int, bytes]:
        """Return the id of each block synced through, by height."""
        rows = self._db.execute("SELECT height, block_id FROM blocks")
        return dict(rows.fetchall())

    def tip(self) -> BlockRef | None:
        """Return the block the ledger is synced to, None before any sync."""
        if not (
            rows := dict(
                self._db.execute(
                    "SELECT key, value FROM meta WHERE key IN ('tip_height', 'tip_id')"
                ).fetchall()
            )
        ):
            return None
        height, block_id = rows.get("tip_height"), rows.get("tip_id")
        # `int` quotes the literal it refuses: a tip is read where it is
        # spelled as `_write_tip` writes it, and refused otherwise
        if not (
            isinstance(height, str)
            and _HEIGHT.fullmatch(height)
            and int(height) in _INTEGERS
            and isinstance(block_id, str)
            and _HEX.fullmatch(block_id)
        ):
            raise BTClibValueError("not a ledger file: a malformed tip")
        return BlockRef(int(height), bytes.fromhex(block_id))

    def labels(self) -> dict[bytes, tuple[str, str]]:
        """Return the label and the purpose of each script given one."""
        rows = self._db.execute("SELECT script, label, purpose FROM labels")
        return {script: (label, purpose) for script, label, purpose in rows}

    def set_label(self, script: bytes, label: str, purpose: str) -> None:
        """Write a script's label and purpose, replacing any it had."""
        with self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO labels VALUES (?, ?, ?)",
                (script, label, purpose),
            )

    def next_source_id(self) -> int:
        """Return the id the next source written gets."""
        return int(
            self._db.execute("SELECT COALESCE(MAX(id) + 1, 0) FROM sources").fetchone()[
                0
            ]
        )

    def add_source(self, source_id: int, source: _Source) -> None:
        """Write a source under the id `next_source_id` returned."""
        with self._db:
            # refused inside the transaction, which it rolls back, and
            # after `suppress`, so that it chains nothing
            written = False
            with contextlib.suppress(sqlite3.IntegrityError):
                self._db.execute(
                    "INSERT INTO sources (id, descriptors, prv_keys, encrypted,"
                    " lookahead, birth, scanned) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        source_id,
                        _descriptors_text(source.descriptors),
                        json.dumps(dict(source.prv_keys)),
                        source.encrypted,
                        source.lookahead,
                        source.birth,
                        int(source.scanned),
                    ),
                )
                written = True
            if not written:
                raise BTClibValueError("not a ledger file: IntegrityError")

    def encrypt(
        self,
        master_key: _MasterKey,
        sources: Mapping[int, tuple[Mapping[int, str], bytes]],
    ) -> None:
        """Write the master key, and each source's ciphertext for its keys.

        `sources` maps a source's id to the descriptors a locked ledger
        reads and the ciphertext; it is written in one SQLite
        transaction with the master key.
        """
        with self._db:
            # refused inside the transaction, as `add_source` refuses
            written = False
            with contextlib.suppress(sqlite3.IntegrityError):
                self._db.execute(
                    "INSERT INTO master_key VALUES (0, 'scrypt', ?, ?, ?, ?, ?)",
                    _master_key_row(master_key),
                )
                written = True
            if not written:
                raise BTClibValueError("not a ledger file: IntegrityError")
            self._db.executemany(
                "UPDATE sources SET descriptors = ?, prv_keys = '{}', encrypted = ?"
                " WHERE id = ?",
                [
                    (_descriptors_text(descriptors), encrypted, source_id)
                    for source_id, (descriptors, encrypted) in sources.items()
                ],
            )

    def set_master_key(self, master_key: _MasterKey) -> None:
        """Write the master key encrypted under a new passphrase."""
        with self._db:
            self._db.execute(
                "UPDATE master_key SET n = ?, r = ?, p = ?, salt = ?, encrypted = ?",
                _master_key_row(master_key),
            )

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
            "INSERT OR REPLACE INTO txs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    wtx.tx.id,
                    wtx.tx.serialize(include_witness=True),
                    wtx.state.value,
                    None if wtx.block is None else wtx.block.height,
                    None if wtx.block is None else wtx.block.block_id,
                    wtx.seq,
                    wtx.comment,
                    wtx.comment_to,
                    wtx.replaces,
                    wtx.replaced_by,
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


def _master_key_row(master_key: _MasterKey) -> tuple[int, int, int, bytes, bytes]:
    """Return the master key's columns after its id and kdf."""
    return (
        master_key.n,
        master_key.r,
        master_key.p,
        master_key.salt,
        master_key.encrypted,
    )


def _descriptors_text(descriptors: Mapping[int, str]) -> str:
    """Return the JSON object a source's descriptors are written as."""
    return json.dumps({str(b): t for b, t in descriptors.items()})


def _write_tip(db: sqlite3.Connection, tip: BlockRef) -> None:
    """Write the tip into `meta`."""
    rows: Mapping[str, str] = {
        "tip_height": str(tip.height),
        "tip_id": tip.block_id.hex(),
    }
    db.executemany("INSERT OR REPLACE INTO meta VALUES (?, ?)", list(rows.items()))
