# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A set of descriptor wallets, their transactions and coins, kept current.

`Ledger` is what Bitcoin Core calls a wallet: a set of descriptors, which
`add_source` grows as `importdescriptors` does, and every transaction
that pays to or spends from their scripts. It answers what Core's wallet
RPCs answer of them -- `balances` (`getbalances`, and `getbalance`'s
`trusted`), `utxos` (`listunspent`), `transaction` and `transactions`
(`gettransaction`, `listtransactions`) -- and spends from them. It reads
the chain only when its caller calls `sync`; nothing runs between calls.

**What a source is.** A `DescriptorWallet`, one descriptor per branch:
branch 0 receives and branch 1, where there is one, takes change. The
ledger watches each ranged branch from index 0 up to the next index it
would hand out plus `lookahead`, that last one left out: with nothing
handed out and a lookahead of 3, indexes 0, 1 and 2. `LOOKAHEAD` is
Core's `DEFAULT_KEYPOOL_SIZE` (src/wallet/scriptpubkeyman.h at
bitcoin/bitcoin@f0de87f040, the v32.1 tag). An output paid to a position
marks it handed out, as Core's `MarkUnusedAddresses` does, which moves
the window on. Ownership is computed from the scripts each time it is
asked, so a source added later makes an output of a transaction already
held the ledger's with no read of the chain
(test/functional/wallet_balance.py:283-307 at the same commit).

**The sync.** `HistoryReader` says how two answers are read together,
and `sync` follows it. It asks again from the height of the tip it last
synced to. Where the answer starts from that tip, its blocks extend what
is held. Where it starts from another block, a reorganization replaced
that tip: `sync` asks again from the height of each block it holds below
it, highest first, until an answer starts from a block it holds. The
blocks above that one are disconnected, and their transactions are what
the new answer says they are. A source whose history has not been read
yet is read from its birth height, and so is a position that a payment
the sync finds brings into the window. A position that `new_address` or
`fund` brings into the window is read from the tip on, at the next sync:
a payment to it in an earlier block is not found, as Core's
`TopUpWithDB` reads no earlier block either: it hands the new scripts to
`TopUpCallback`, which only caches them
(src/wallet/scriptpubkeyman.cpp:1109-1169 and
src/wallet/wallet.cpp:4560-4571 at bitcoin/bitcoin@f0de87f040, the v32.1
tag).

The mempool part of the answers replaces the one the ledger held. A
transaction that was in the mempool or in a block and is in neither
now is kept as `TxState.INACTIVE`, not dropped: the mempool replaced it,
refused it or evicted it (test/functional/wallet_balance.py:174-180 and
214-225).

**What is checked of an unconfirmed transaction** (ISS
btclib-org/btclib-wallet#642). A backend can report a mempool
transaction that spends the ledger's coins with a signature that does
not verify, to have the user replace it. So each input of a transaction
in no block that spends an output the ledger owns is verified with
btclib's script engine, against every output the transaction spends that
the ledger holds. The check runs at the end of each sync, against the
scripts the windows reach once that sync has moved them, and again
whenever the scripts watched grow: by `add_source`, `new_address` or
`fund`. A transaction that fails leaves the ledger with its unconfirmed
descendants, or is kept out. Where the transaction spending an output
arrives before the transaction paying it, the input cannot be checked
yet: it is checked when that parent arrives. A taproot input commits to
every output the transaction spends, so a spend of a taproot output of
the ledger beside an output the ledger does not hold fails the check.
What stays unverified: an incoming unconfirmed transaction spends no
coin of the ledger, so nothing of it is checked; a spend of the ledger's
coin whose parent the backend has not reported, until it does; and a
transaction a backend reports in a block, since a `HistoryReader`
answers no proof that the block holds it (ISS
btclib-org/btclib-wallet#737).

**Balances.** Core's `GetBalance` and `CachedTxIsTrusted`
(src/wallet/receive.cpp:205-295 at bitcoin/bitcoin@f0de87f040, the v32.1
tag), and its `HowSpent` (src/wallet/wallet.cpp:810-830). A transaction
is trusted where it is
confirmed, or in the mempool with every input spending a trusted output
of the ledger. A coinbase is immature until 100 blocks are built on top
of its own.

**The spender.** `fund` selects among the trusted, unlocked, unspent
coins that are confirmed or in the mempool, with `select_coins`, and
pays the change to source 0: to the next address of its branch 1 not
handed out, or of its branch 0 where it has no branch 1, or to the one
address of that branch where its descriptor is not ranged. The fee
rate is the caller's where given, refused below the node's minimum relay
rate; else the backend's estimate, else `fallback_fee_rate`, raised to
the node's mempool minimum. A spend with no rate, no estimate and no fallback is
refused, as Core's is with `-fallbackfee=0`. `spend` funds, signs and
records the transaction as inactive before it broadcasts it, so one the
node refuses stays, and counts as `nonmempool`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, replace
from os import PathLike
from types import TracebackType
from typing import Self

from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.fee import FeeRate
from btclib.network import validated_network_name
from btclib.script.engine import verify_input
from btclib.script.script_pub_key import ScriptPubKey
from btclib.script.witness import Witness
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from btclib.tx.limits import COINBASE_MATURITY
from btclib.tx.tx_in import input_weight
from btclib.utils import assert_type, is_integer

from btclib_wallet.bip32.bip32 import fingerprint
from btclib_wallet.coin_selection import Candidate, select_coins
from btclib_wallet.descriptors import parse
from btclib_wallet.exceptions import FetchError
from btclib_wallet.fetch.broadcaster import Broadcaster
from btclib_wallet.fetch.fee_estimator import FeeEstimator
from btclib_wallet.fetch.fetcher import tx_for_network
from btclib_wallet.fetch.history import BlockRef, HistoryReader, ScriptHistory
from btclib_wallet.fetch.relay_fees import RelayFeeReader
from btclib_wallet.ledger.records import (
    Balances,
    SyncResult,
    TxDetail,
    TxInfo,
    TxState,
    Utxo,
    WalletTx,
)
from btclib_wallet.ledger.store import _Source, _Store, _SyncWrite
from btclib_wallet.psbt.psbt import Psbt, extract_tx, finalize
from btclib_wallet.psbt.psbt_in import PsbtIn
from btclib_wallet.psbt.psbt_size import estimated_input_sizes, miniscript_sizer
from btclib_wallet.psbt_signer import SoftwareSigner
from btclib_wallet.tx_builder import FundedPsbt, build_psbt
from btclib_wallet.wallet.descriptor_wallet import DescriptorWallet

__all__ = ["LOOKAHEAD", "Ledger"]

# Core's DEFAULT_KEYPOOL_SIZE: how many indexes past the next one to
# hand out the ledger watches on each ranged branch
LOOKAHEAD = 1000

# Core's DEFAULT_TX_CONFIRM_TARGET (src/wallet/wallet.h at
# bitcoin/bitcoin@f0de87f040, the v32.1 tag): the target a fee estimate
# is asked for
_CONFIRMATION_TARGET = 6

# Core's DEFAULT_CONSOLIDATE_FEERATE (the same file), 10 sat/vB: the rate
# coin selection weighs spending an input now against spending it later
_LONG_TERM_FEE_RATE = FeeRate(sats_per_kvbyte=10_000)

# how many times `sync` reads again after the tip moved between two reads
_SYNC_ATTEMPTS = 3

# where an output of the ledger is: its source, branch and index
_Position = tuple[int, int, int]


class _TipMovedError(Exception):
    """Two reads of one sync answered for different tips."""


@dataclass
class _Windows:
    """The windows of one sync's reads, grown by the positions paid to.

    `end` is each branch's first index not watched, `scripts` the
    position of each script watched, `handed` the positions handed out.
    """

    end: dict[tuple[int, int], int]
    scripts: dict[bytes, _Position]
    handed: set[_Position]


@dataclass(frozen=True)
class _Read:
    """What the reads of one sync answered, before anything is written."""

    answers: tuple[ScriptHistory, ...]
    tip: BlockRef
    fork_height: int | None
    used: frozenset[_Position]
    scanned: frozenset[int]


class Ledger:
    """A set of descriptor wallets, their transactions, and their file.

    Made by `create` or `load`, never directly. The reader is the backend
    `sync` reads the chain from. The broadcaster, the fee estimator and
    the relay fee reader are what `fund` and `spend` use, each where the
    backend has it.
    """

    def __init__(
        self,
        store: _Store,
        network: str,
        reader: HistoryReader,
        broadcaster: Broadcaster | None,
        fee_estimator: FeeEstimator | None,
        relay_fee_reader: RelayFeeReader | None,
        fallback_fee_rate: FeeRate | None,
    ) -> None:
        self.network = network
        self.fallback_fee_rate = fallback_fee_rate
        self._store = store
        self._reader = reader
        self._broadcaster = broadcaster
        self._fee_estimator = fee_estimator
        self._relay_fee_reader = relay_fee_reader
        self._sources: dict[int, DescriptorWallet] = {}
        self._lookahead: dict[int, int] = {}
        self._birth: dict[int, int] = {}
        self._unscanned: set[int] = set()
        self._handed: set[_Position] = set()
        self._scripts: dict[bytes, _Position] = {}
        self._window: dict[tuple[int, int], int] = {}
        self._locked: set[OutPoint] = set()
        self._txs: dict[bytes, WalletTx] = {}
        self._blocks: dict[int, bytes] = {}
        self._tip: BlockRef | None = None

    @classmethod
    def create(
        cls,
        path: str | PathLike[str],
        network: str,
        reader: HistoryReader,
        *,
        broadcaster: Broadcaster | None = None,
        fee_estimator: FeeEstimator | None = None,
        relay_fee_reader: RelayFeeReader | None = None,
        fallback_fee_rate: FeeRate | None = None,
    ) -> Ledger:
        """Return a new ledger, with no source, in a new file at `path`.

        Core's `createwallet`. A file already at `path` is refused.
        """
        assert_type(path, (str, PathLike), "path")
        assert_type(fallback_fee_rate, (FeeRate, type(None)), "fallback_fee_rate")
        network = validated_network_name(network)
        store = _Store.create(path, network)
        return cls(
            store,
            network,
            reader,
            broadcaster,
            fee_estimator,
            relay_fee_reader,
            fallback_fee_rate,
        )

    @classmethod
    def load(
        cls,
        path: str | PathLike[str],
        network: str,
        reader: HistoryReader,
        *,
        broadcaster: Broadcaster | None = None,
        fee_estimator: FeeEstimator | None = None,
        relay_fee_reader: RelayFeeReader | None = None,
        fallback_fee_rate: FeeRate | None = None,
    ) -> Ledger:
        """Return the ledger the file at `path` holds, reading no backend.

        Core's `loadwallet`. `store` says which files are refused.
        """
        assert_type(path, (str, PathLike), "path")
        assert_type(fallback_fee_rate, (FeeRate, type(None)), "fallback_fee_rate")
        network = validated_network_name(network)
        store = _Store.open(path, network)
        ledger = cls(
            store,
            network,
            reader,
            broadcaster,
            fee_estimator,
            relay_fee_reader,
            fallback_fee_rate,
        )
        for source_id, source in store.sources():
            wallet = DescriptorWallet(
                {
                    branch: parse(text, network, source.prv_keys)
                    for branch, text in source.descriptors.items()
                },
                source.prv_keys or None,
            )
            ledger._attach(source_id, wallet, source)
        for position in store.handed_out():
            ledger._hand_out(position)
        ledger._txs = {wtx.tx.id: wtx for wtx in store.txs(network)}
        ledger._blocks = store.blocks()
        ledger._tip = store.tip()
        ledger._extend_windows()
        return ledger

    def close(self) -> None:
        """Close the file; the ledger answers nothing after this."""
        self._store.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    # -- the sources ------------------------------------------------------

    def add_source(
        self,
        wallet: DescriptorWallet,
        birth_height: int | None = 0,
        *,
        lookahead: int = LOOKAHEAD,
    ) -> int:
        """Add a wallet of descriptors, and return its source id.

        Core's `importdescriptors`. `birth_height` is where the next
        `sync` reads its history from, and `None` reads none before the
        tip the ledger holds, as Core's `timestamp: "now"` does;
        `fetch.start_height_for_time` turns a birth time into a height.
        The wallet is written to the file whole, its private keys
        included, and `load` builds it again from its descriptors and
        keys.
        """
        assert_type(wallet, DescriptorWallet, "wallet")
        if birth_height is not None:
            _assert_height(birth_height, "birth_height")
        _assert_height(lookahead, "lookahead")
        if wallet.network != self.network:
            err_msg = f"a {wallet.network} wallet in a {self.network} ledger"
            raise BTClibValueError(err_msg)
        scanned = birth_height is None
        birth = birth_height
        if birth is None:
            birth = 0 if self._tip is None else self._tip.height
        source = _Source(
            {branch: str(wallet.descriptor(branch)) for branch in wallet.branches},
            dict(wallet.prv_keys or {}),
            lookahead,
            birth,
            scanned,
        )
        source_id = self._store.add_source(source)
        self._attach(source_id, wallet, source)
        self._extend_windows()
        return source_id

    def _attach(
        self, source_id: int, wallet: DescriptorWallet, source: _Source
    ) -> None:
        """Hold a source read from the file or just added."""
        self._sources[source_id] = wallet
        self._lookahead[source_id] = source.lookahead
        self._birth[source_id] = source.birth
        if not source.scanned:
            self._unscanned.add(source_id)

    @property
    def sources(self) -> tuple[DescriptorWallet, ...]:
        """The wallets of the ledger, in source id order."""
        return tuple(self._sources[i] for i in sorted(self._sources))

    def _source(self, source: int) -> DescriptorWallet:
        """Return the source of an id, refusing an unknown one."""
        if not is_integer(source):
            raise BTClibTypeError(f"invalid source type: {type(source).__name__}")
        if source not in self._sources:
            raise BTClibValueError(f"no source {source}")
        return self._sources[source]

    def _next_index(self, source: int, branch: int) -> int:
        """Return the index after the highest handed out on a branch."""
        return _next_index(self._handed, source, branch)

    def _hand_out(self, position: _Position) -> str:
        """Record a position as handed out, and return its address."""
        source, branch, index = position
        self._handed.add(position)
        return self._sources[source].address(branch, index)

    def _windows_for(
        self, handed: set[_Position]
    ) -> tuple[dict[tuple[int, int], int], dict[bytes, _Position]]:
        """Return the windows and the scripts that `handed` makes reached."""
        window = dict(self._window)
        scripts = dict(self._scripts)
        for source, wallet in self._sources.items():
            for branch in wallet.branches:
                end = 1
                if wallet.descriptor(branch).is_ranged:
                    end = _next_index(handed, source, branch) + self._lookahead[source]
                start = window.get((source, branch), 0)
                for index in range(start, end):
                    script = wallet.script_pub_key(branch, index).script
                    scripts.setdefault(script, (source, branch, index))
                window[(source, branch)] = max(start, end)
        return window, scripts

    def _extend_windows(self) -> None:
        """Watch every position the lookahead reaches, and check again.

        A script newly watched can make an output that a held transaction
        spends the ledger's: each unconfirmed transaction is checked
        again, and one that fails is deleted from the file.
        """
        self._window, self._scripts = self._windows_for(self._handed)
        txs = dict(self._txs)
        _drop_unverified(txs, self._scripts)
        gone = [txid for txid in self._txs if txid not in txs]
        if gone:
            self._store.delete_txs(gone)
            self._txs = txs

    def _new_position(self, source: int, branch: int) -> _Position:
        """Return the position the next address of a branch is at."""
        wallet = self._source(source)
        if not is_integer(branch):
            raise BTClibTypeError(f"invalid branch type: {type(branch).__name__}")
        if branch not in wallet.branches:
            raise BTClibValueError(f"invalid branch: {branch}")
        if not wallet.descriptor(branch).is_ranged:
            return source, branch, 0
        return source, branch, self._next_index(source, branch)

    def new_address(self, source: int = 0, branch: int = 0) -> str:
        """Hand out the next address of a branch, and remember it.

        Core's `getnewaddress`. The next index is one past the highest
        handed out or paid to. A branch whose descriptor is not ranged
        has one address, which is handed out every time.
        """
        position = self._new_position(source, branch)
        address = self._hand_out(position)
        self._store.add_handed_out([position])
        self._extend_windows()
        return address

    def new_change_address(self, source: int = 0) -> str:
        """Hand out the next address of the change branch, branch 1.

        Core's `getrawchangeaddress`. A source with no branch 1 is
        refused.
        """
        return self.new_address(source, 1)

    def position_of(self, script_pub_key: ScriptPubKey) -> tuple[int, int, int] | None:
        """Return the source, branch and index paying to a script, or None.

        The answer is one of the positions the ledger watches.
        """
        assert_type(script_pub_key, ScriptPubKey, "script_pub_key")
        return self._scripts.get(script_pub_key.script)

    # -- the sync ---------------------------------------------------------

    @property
    def tip(self) -> BlockRef | None:
        """The block the ledger is synced to, None before any sync.

        Core's `lastprocessedblock`.
        """
        return self._tip

    def sync(self) -> SyncResult:
        """Read the chain from the tip the ledger holds, and record it.

        The module docstring says how. A tip that moves between the reads
        of one sync starts it again, at most three times in all, and then
        raises `FetchError`. A backend's own `FetchError` is raised as it
        comes, and nothing is written. A ledger with no source is refused,
        having no script to ask about.
        """
        if not self._sources:
            raise BTClibValueError("no source: add one before the sync")
        for _ in range(_SYNC_ATTEMPTS):
            try:
                read = self._read()
            except _TipMovedError:
                continue
            return self._apply(read)
        raise FetchError("the chain tip moved during every read of the sync")

    def _read(self) -> _Read:
        """Read what a sync needs: the main answer, then the new scripts."""
        scripts = frozenset(self._scripts)
        fork_height: int | None = None
        if self._tip is None:
            start = min(self._birth.values(), default=0)
            main = self._history(scripts, start)
        else:
            main = self._history(scripts, self._tip.height)
            if main.start != self._tip:
                main, fork_height = self._walk_down(scripts, self._tip)
        answers = [main]
        scanned = frozenset(self._unscanned)
        pending: dict[int, set[bytes]] = {}
        # the first sync reads every source from the lowest birth already
        if self._tip is not None:
            for script, (source, _, _) in self._scripts.items():
                if source in scanned:
                    pending.setdefault(source, set()).add(script)
        # positions the answers pay to, which move the windows on: a copy
        # of the ledger's windows grows as they are found, and the scripts
        # it reaches are read in turn
        windows = _Windows(dict(self._window), dict(self._scripts), set(self._handed))
        pending.update(self._grow(windows, answers))
        while pending:
            for source, source_scripts in sorted(pending.items()):
                answer = self._history(source_scripts, self._birth[source])
                if answer.tip != main.tip:
                    raise _TipMovedError
                answers.append(answer)
            pending = self._grow(windows, answers)
        used = frozenset(windows.handed - self._handed)
        return _Read(tuple(answers), main.tip, fork_height, used, scanned)

    def _grow(
        self, windows: _Windows, answers: Sequence[ScriptHistory]
    ) -> dict[int, set[bytes]]:
        """Mark the positions the answers pay to, and return the new scripts.

        A ranged branch watches `lookahead` indexes past each position
        paid to.
        """
        used: set[_Position] = set()
        for answer in answers:
            for entry in answer.txs:
                for tx_out in entry.tx.vout:
                    position = windows.scripts.get(_script(tx_out))
                    if position is not None and position not in windows.handed:
                        used.add(position)
        new: dict[int, set[bytes]] = {}
        for source, branch, index in sorted(used):
            windows.handed.add((source, branch, index))
            wallet = self._sources[source]
            if not wallet.descriptor(branch).is_ranged:
                continue
            end = index + 1 + self._lookahead[source]
            for i in range(windows.end[(source, branch)], end):
                script = wallet.script_pub_key(branch, i).script
                windows.scripts.setdefault(script, (source, branch, i))
                new.setdefault(source, set()).add(script)
            windows.end[(source, branch)] = max(windows.end[(source, branch)], end)
        return new

    def _history(self, scripts: Iterable[bytes], start: int) -> ScriptHistory:
        """Ask the reader, from `start` or from its tip where that is lower."""
        return self._reader.get_history(sorted(scripts), start)

    def _walk_down(
        self, scripts: frozenset[bytes], tip: BlockRef
    ) -> tuple[ScriptHistory, int]:
        """Find the highest block held below `tip` that is still on the chain.

        Asked from each block held below the tip, highest first, and from
        height 0 last, where none of them is on the chain any more: the
        fork height is then -1.
        """
        heights = sorted((h for h in self._blocks if h < tip.height), reverse=True)
        for height in heights:
            answer = self._history(scripts, height)
            if answer.start == BlockRef(height, self._blocks[height]):
                return answer, height
        return self._history(scripts, 0), -1

    def _apply(self, read: _Read) -> SyncResult:
        """Write what the reads answered, and return what changed."""
        txs, blocks = _disconnected(self._txs, self._blocks, read.fork_height)
        confirmed: dict[bytes, tuple[Tx, BlockRef]] = {}
        mempool: dict[bytes, Tx] = {}
        for answer in read.answers:
            for entry in answer.txs:
                if entry.block is None:
                    mempool[entry.tx.id] = entry.tx
                else:
                    confirmed[entry.tx.id] = (entry.tx, entry.block)
                    blocks[entry.block.height] = entry.block.block_id
        blocks[read.tip.height] = read.tip.block_id
        handed = tuple(sorted(read.used - self._handed))
        window, scripts = self._windows_for(self._handed | read.used)
        _admit(txs, confirmed, mempool)
        _drop_unverified(txs, scripts)
        upserted = tuple(wtx for txid, wtx in txs.items() if self._txs.get(txid) != wtx)
        deleted = tuple(txid for txid in self._txs if txid not in txs)
        self._store.write_sync(
            _SyncWrite(
                upserted,
                deleted,
                read.fork_height,
                tuple(
                    BlockRef(h, b)
                    for h, b in blocks.items()
                    if self._blocks.get(h) != b
                ),
                read.tip,
                tuple(sorted(read.scanned)),
                handed,
            )
        )
        self._txs = txs
        self._blocks = blocks
        self._tip = read.tip
        self._unscanned -= read.scanned
        self._handed |= read.used
        self._window, self._scripts = window, scripts
        changed = frozenset(wtx.tx.id for wtx in upserted) | frozenset(deleted)
        return SyncResult(read.tip, read.fork_height, changed)

    # -- what the ledger answers -------------------------------------------

    def _owned(self, tx_out: TxOut) -> bool:
        return tx_out.script_pub_key.script in self._scripts

    def _depth(self, wtx: WalletTx) -> int:
        """Core's `GetTxDepthInMainChain`: confirmations, 0 in no block."""
        if wtx.block is None or self._tip is None:
            return 0
        return self._tip.height - wtx.block.height + 1

    def _is_immature(self, wtx: WalletTx) -> bool:
        """Core's `IsTxImmatureCoinBase`: an orphan, at depth 0, is too.

        src/wallet/wallet.cpp:3392-3410 at bitcoin/bitcoin@f0de87f040, the
        v32.1 tag.
        """
        return wtx.tx.is_coinbase and self._depth(wtx) <= COINBASE_MATURITY

    def _debit(self, tx: Tx) -> int:
        """Return what the transaction spends of the ledger's own outputs."""
        total = 0
        for tx_in in tx.vin:
            prevout = _prevout(tx_in, self._txs)
            if prevout is not None and self._owned(prevout):
                total += prevout.value
        return total

    def _is_trusted(self, wtx: WalletTx, trusted: set[bytes]) -> bool:
        """Core's `CachedTxIsTrusted`."""
        if wtx.tx.id in trusted or wtx.state is TxState.CONFIRMED:
            return True
        if wtx.state is not TxState.MEMPOOL or self._debit(wtx.tx) == 0:
            return False
        for tx_in in wtx.tx.vin:
            parent = self._txs.get(tx_in.prev_out.tx_id)
            if parent is None:
                return False
            if not self._owned(parent.tx.vout[tx_in.prev_out.vout]):
                return False
            if parent.tx.id not in trusted and not self._is_trusted(parent, trusted):
                return False
            trusted.add(parent.tx.id)
        return True

    def _spends(self) -> dict[OutPoint, list[WalletTx]]:
        """Return the ledger's transactions spending each outpoint."""
        spends: dict[OutPoint, list[WalletTx]] = {}
        for wtx in self._txs.values():
            if wtx.tx.is_coinbase:
                continue
            for tx_in in wtx.tx.vin:
                spends.setdefault(tx_in.prev_out, []).append(wtx)
        return spends

    def _outputs(self) -> Iterable[tuple[WalletTx, int, TxOut]]:
        """Yield every output of the ledger: its transaction, index, output."""
        for wtx in sorted(self._txs.values(), key=lambda w: w.seq):
            for vout, tx_out in enumerate(wtx.tx.vout):
                if self._owned(tx_out):
                    yield wtx, vout, tx_out

    def balances(
        self, min_depth: int = 0, *, include_nonmempool: bool = True
    ) -> Balances:
        """Return Core's balance buckets, in satoshi.

        `getbalances` is the defaults. `getbalance` with `minconf` is the
        `trusted` bucket of `balances(minconf, include_nonmempool=False)`.
        """
        _assert_height(min_depth, "min_depth")
        assert_type(include_nonmempool, bool, "include_nonmempool")
        spends = self._spends()
        trusted_set: set[bytes] = set()
        trusted = pending = immature = nonmempool = 0
        for wtx, vout, tx_out in self._outputs():
            how = _how_spent(spends.get(OutPoint(wtx.tx.id, vout), []))
            if how in (TxState.CONFIRMED, TxState.MEMPOOL):
                continue
            nonmempool_spent = how is TxState.INACTIVE
            if nonmempool_spent and not include_nonmempool:
                continue
            is_trusted = self._is_trusted(wtx, trusted_set)
            if self._is_immature(wtx) and wtx.state is TxState.CONFIRMED:
                immature += tx_out.value
            elif is_trusted and self._depth(wtx) >= min_depth:
                trusted += tx_out.value
            elif not is_trusted and wtx.state is TxState.MEMPOOL:
                pending += tx_out.value
            else:
                continue
            if nonmempool_spent:
                nonmempool -= tx_out.value
        return Balances(trusted, pending, immature, nonmempool)

    def utxos(
        self,
        min_depth: int = 1,
        *,
        include_immature_coinbase: bool = False,
        include_locked: bool = False,
        include_unsafe: bool = True,
    ) -> tuple[Utxo, ...]:
        """Return the unspent outputs, as Core's `AvailableCoins` filters them.

        `listunspent` is the defaults. An output is left out where a
        transaction of the ledger spends it, in any state; where its own
        transaction is in no block and not in the mempool; where it is
        locked, unless `include_locked`; where it is an immature coinbase,
        unless `include_immature_coinbase`; and where its transaction is
        not trusted and `include_unsafe` is False.
        """
        _assert_height(min_depth, "min_depth")
        assert_type(include_immature_coinbase, bool, "include_immature_coinbase")
        assert_type(include_locked, bool, "include_locked")
        assert_type(include_unsafe, bool, "include_unsafe")
        spends = self._spends()
        trusted_set: set[bytes] = set()
        found: list[Utxo] = []
        for wtx, vout, tx_out in self._outputs():
            outpoint = OutPoint(wtx.tx.id, vout)
            depth = self._depth(wtx)
            safe = self._is_trusted(wtx, trusted_set)
            skipped = (
                (self._is_immature(wtx) and not include_immature_coinbase)
                or (depth == 0 and wtx.state is not TxState.MEMPOOL)
                or (not safe and not include_unsafe)
                or depth < min_depth
                or (outpoint in self._locked and not include_locked)
                or outpoint in spends
            )
            if not skipped:
                source, branch, index = self._scripts[tx_out.script_pub_key.script]
                found.append(Utxo(outpoint, tx_out, depth, safe, source, branch, index))
        return tuple(found)

    def lock(self, outpoint: OutPoint) -> None:
        """Keep an output out of `fund` and `spend`, until `unlock`.

        Core's `lockunspent`, not persistent: a lock is not in the file.
        """
        assert_type(outpoint, OutPoint, "outpoint")
        self._locked.add(outpoint)

    def unlock(self, outpoint: OutPoint) -> None:
        """Let a locked output be spent again."""
        assert_type(outpoint, OutPoint, "outpoint")
        self._locked.discard(outpoint)

    @property
    def locked(self) -> frozenset[OutPoint]:
        """The outputs locked, Core's `listlockunspent`."""
        return frozenset(self._locked)

    def transaction(self, txid: bytes) -> TxInfo:
        """Return what `gettransaction` reports of a transaction held.

        `txid` is in display order, as `Tx.id` returns it.
        """
        assert_type(txid, bytes, "txid")
        if txid not in self._txs:
            raise BTClibValueError(f"not a ledger transaction: {txid.hex()}")
        return self._info(self._txs[txid], set())

    @property
    def transactions(self) -> tuple[TxInfo, ...]:
        """Every transaction held, in the order it was recorded.

        Core's `listtransactions`, one `TxInfo` per transaction.
        """
        trusted: set[bytes] = set()
        ordered = sorted(self._txs.values(), key=lambda wtx: wtx.seq)
        return tuple(self._info(wtx, trusted) for wtx in ordered)

    def _info(self, wtx: WalletTx, trusted: set[bytes]) -> TxInfo:
        """Return Core's `gettransaction` figures of a transaction.

        Its details are `CachedTxGetAmounts` with the change left out
        (src/wallet/receive.cpp:165-191 at bitcoin/bitcoin@f0de87f040, the
        v32.1 tag): where the transaction spends the ledger's coins, each
        output that is not change is sent, the ledger's own included, and
        each output of the ledger is received.
        """
        tx = wtx.tx
        debit = self._debit(tx)
        immature = self._is_immature(wtx)
        details: list[TxDetail] = []
        credit = 0
        for vout, tx_out in enumerate(tx.vout):
            owned = self._owned(tx_out)
            if owned and not immature:
                credit += tx_out.value
            if debit and owned and self._scripts[_script(tx_out)][1] != 0:
                continue
            if debit:
                details.append(TxDetail("send", vout, -tx_out.value))
            if owned:
                details.append(TxDetail(self._category(wtx), vout, tx_out.value))
        fee = None
        amount = credit - debit
        if debit:
            fee = debit - sum(tx_out.value for tx_out in tx.vout)
            amount += fee
        return TxInfo(
            wtx,
            amount,
            fee,
            self._depth(wtx),
            self._is_trusted(wtx, trusted),
            tuple(details),
        )

    def _category(self, wtx: WalletTx) -> str:
        """Core's category of an output received."""
        if not wtx.tx.is_coinbase:
            return "receive"
        if wtx.state is not TxState.CONFIRMED:
            return "orphan"
        return "immature" if self._is_immature(wtx) else "generate"

    # -- the spender ------------------------------------------------------

    def _fee_rate(self, fee_rate: FeeRate | None) -> FeeRate:
        """Return the rate a spend pays, as the module docstring says."""
        assert_type(fee_rate, (FeeRate, type(None)), "fee_rate")
        relay = None
        if self._relay_fee_reader is not None:
            relay = self._relay_fee_reader.get_relay_fees()
        if fee_rate is not None:
            if relay is not None and fee_rate < relay.min_relay:
                err_msg = f"fee rate {fee_rate.sats_per_kvbyte} sat/kvB is below"
                err_msg += f" the minimum relay rate {relay.min_relay.sats_per_kvbyte}"
                raise BTClibValueError(err_msg)
            return fee_rate
        rate = None
        if self._fee_estimator is not None:
            try:
                rate = self._fee_estimator.estimate_fee(_CONFIRMATION_TARGET).rate
            except FetchError:
                rate = None
        if rate is None:
            rate = self.fallback_fee_rate
        if rate is None:
            err_msg = "no fee estimate and no fallback fee rate: name a fee rate"
            raise BTClibValueError(err_msg)
        if relay is not None:
            rate = max(rate, relay.mempool_min)
        return rate

    def _psbt_in(self, parent: Tx, vout: int) -> PsbtIn:
        """Return the input map spending an output of the ledger, updated."""
        outpoint = OutPoint(parent.id, vout)
        psbt = Psbt.from_tx(Tx(vin=[TxIn(outpoint)], vout=[parent.vout[vout]]))
        position = self._scripts[_script(parent.vout[vout])]
        return self._updated(psbt, 0, position, parent).inputs[0]

    def _updated(self, psbt: Psbt, i: int, position: _Position, parent: Tx) -> Psbt:
        """Return the psbt with input `i` told what the position is."""
        psbt = deepcopy(psbt)
        psbt.inputs[i].non_witness_utxo = parent
        source, branch, index = position
        return self._sources[source].update_psbt_input(psbt, i, branch, index)

    @staticmethod
    def _weight(psbt_in: PsbtIn) -> int:
        """Return the weight the input will add once signed."""
        tx_in = TxIn(OutPoint(psbt_in.previous_tx_id, psbt_in.output_index or 0))
        script_sig_size, stack = estimated_input_sizes(
            psbt_in, tx_in, sizer=miniscript_sizer
        )
        witness = Witness([b"\x00" * size for size in stack]) if stack else None
        return input_weight(b"\x00" * script_sig_size, witness)

    def fund(
        self, outputs: Sequence[TxOut], fee_rate: FeeRate | None = None
    ) -> FundedPsbt:
        """Return the unsigned psbt paying `outputs` from the ledger's coins.

        Core's `fundrawtransaction`. The coins, the rate and the change
        address are the module docstring's; the change address is handed
        out only where the psbt pays to it. A ledger with no source 0 is
        refused.
        """
        assert_type(outputs, Sequence, "outputs")
        for tx_out in outputs:
            assert_type(tx_out, TxOut, "outputs")
        rate = self._fee_rate(fee_rate)
        candidates: dict[OutPoint, tuple[Candidate, PsbtIn]] = {}
        for utxo in self.utxos(0, include_unsafe=False):
            psbt_in = self._psbt_in(
                self._txs[utxo.outpoint.tx_id].tx, utxo.outpoint.vout
            )
            candidate = Candidate(utxo.outpoint, utxo.tx_out, self._weight(psbt_in))
            candidates[utxo.outpoint] = (candidate, psbt_in)
        change_branch = 1 if 1 in self._source(0).branches else 0
        change_position = self._new_position(0, change_branch)
        _, branch, index = change_position
        change_script = self._sources[0].script_pub_key(branch, index)
        # what spending the change will weigh: an input spending an output
        # of a stand-in parent, the change being no transaction's yet
        stand_in = Tx(
            vin=[TxIn(OutPoint(b"\x01" * 32, 0))], vout=[TxOut(0, change_script)]
        )
        psbt = Psbt.from_tx(
            Tx(vin=[TxIn(OutPoint(stand_in.id, 0))], vout=[stand_in.vout[0]])
        )
        change_weight = self._weight(
            self._updated(psbt, 0, change_position, stand_in).inputs[0]
        )
        selection = select_coins(
            [candidate for candidate, _ in candidates.values()],
            list(outputs),
            rate,
            _LONG_TERM_FEE_RATE,
            change_script.script,
            change_weight,
        )
        funded = build_psbt(
            [candidates[c.outpoint][1] for c in selection.selected],
            list(outputs),
            rate,
            change_script.script,
            sizer=miniscript_sizer,
        )
        if funded.change_index is not None:
            self._hand_out(change_position)
            self._store.add_handed_out([change_position])
            self._extend_windows()
            psbt = self._sources[0].update_psbt_output(
                funded.psbt, funded.change_index, branch, index
            )
            funded = FundedPsbt(psbt, funded.fee, funded.change_index)
        return funded

    def sign(self, psbt: Psbt) -> Psbt:
        """Return the psbt with every signature the ledger's keys can add.

        Core's `signrawtransactionwithwallet`, over a psbt: each input
        spending an output the ledger holds is updated with its source's
        scripts and key origins first. A source signs with the extended
        private keys it was added with.
        """
        assert_type(psbt, Psbt, "psbt")
        for i, tx_in in enumerate(psbt.tx.vin):
            held = _prevout(tx_in, self._txs)
            if held is not None and self._owned(held):
                position = self._scripts[_script(held)]
                parent = self._txs[tx_in.prev_out.tx_id].tx
                psbt = self._updated(psbt, i, position, parent)
        for signer in self._signers():
            psbt = signer.sign_psbt(psbt)
        return psbt

    def _signers(self) -> list[SoftwareSigner]:
        """Return a signer per master fingerprint the sources hold keys of."""
        accounts: dict[bytes, dict[tuple[int, ...], str]] = {}
        for wallet in self._sources.values():
            prv_keys = wallet.prv_keys or {}
            for branch in wallet.branches:
                for key in wallet.descriptor(branch).key_expressions:
                    if key.xkey not in prv_keys:
                        continue
                    path: tuple[int, ...] = ()
                    if key.origin is None:
                        master = fingerprint(key.xkey)
                    else:
                        master = key.origin.master_fingerprint
                        path = tuple(key.origin.der_path)
                    accounts.setdefault(master, {})[path] = prv_keys[key.xkey]
        return [
            SoftwareSigner.from_accounts(master, dict(held.items()))
            for master, held in accounts.items()
        ]

    def spend(self, outputs: Sequence[TxOut], fee_rate: FeeRate | None = None) -> Tx:
        """Pay `outputs` from the ledger's coins, and broadcast the payment.

        Core's `send`. The transaction is recorded as inactive before it
        is broadcast, and as in the mempool once the broadcaster accepts
        it. A refusal is raised as the broadcaster raises it, and leaves
        the transaction in the ledger as inactive.
        """
        if self._broadcaster is None:
            raise BTClibValueError("no broadcaster: the ledger cannot send")
        funded = self.fund(outputs, fee_rate)
        tx = tx_for_network(extract_tx(finalize(self.sign(funded.psbt))), self.network)
        seq = max((wtx.seq for wtx in self._txs.values()), default=-1) + 1
        wtx = WalletTx(tx, TxState.INACTIVE, None, seq)
        self._store.upsert_txs([wtx])
        self._txs[tx.id] = wtx
        self._broadcaster.broadcast(tx)
        wtx = replace(wtx, state=TxState.MEMPOOL)
        self._store.upsert_txs([wtx])
        self._txs[tx.id] = wtx
        return tx


def _script(tx_out: TxOut) -> bytes:
    return tx_out.script_pub_key.script


def _assert_height(value: int, name: str) -> None:
    """Refuse what is not a non-negative integer."""
    if not is_integer(value):
        raise BTClibTypeError(f"invalid {name} type: {type(value).__name__}")
    if value < 0:
        raise BTClibValueError(f"negative {name}: {value}")


def _next_index(handed: set[_Position], source: int, branch: int) -> int:
    """Return the index after the highest handed out on a branch."""
    indexes = [i for s, b, i in handed if (s, b) == (source, branch)]
    return max(indexes, default=-1) + 1


def _prevout(tx_in: TxIn, txs: Mapping[bytes, WalletTx]) -> TxOut | None:
    """Return the output an input spends, where the ledger holds it."""
    parent = txs.get(tx_in.prev_out.tx_id)
    if parent is None or tx_in.prev_out.vout >= len(parent.tx.vout):
        return None
    return parent.tx.vout[tx_in.prev_out.vout]


def _disconnected(
    txs: Mapping[bytes, WalletTx], blocks: Mapping[int, bytes], fork_height: int | None
) -> tuple[dict[bytes, WalletTx], dict[int, bytes]]:
    """Return copies with the blocks above `fork_height` taken out.

    A transaction confirmed in one of them is inactive until the answers
    say where it is now.
    """
    txs = dict(txs)
    if fork_height is None:
        return txs, dict(blocks)
    for txid, wtx in txs.items():
        if wtx.block is not None and wtx.block.height > fork_height:
            txs[txid] = replace(wtx, state=TxState.INACTIVE, block=None)
    return txs, {h: b for h, b in blocks.items() if h <= fork_height}


def _admit(
    txs: dict[bytes, WalletTx],
    confirmed: Mapping[bytes, tuple[Tx, BlockRef]],
    mempool: Mapping[bytes, Tx],
) -> None:
    """Set each transaction's state from what the answers listed."""
    for txid, wtx in txs.items():
        if wtx.state is TxState.MEMPOOL and txid not in mempool:
            txs[txid] = replace(wtx, state=TxState.INACTIVE)
    seq = max((wtx.seq for wtx in txs.values()), default=-1) + 1
    for txid, (tx, block) in confirmed.items():
        if txid in txs:
            txs[txid] = replace(txs[txid], state=TxState.CONFIRMED, block=block)
        else:
            txs[txid] = WalletTx(tx, TxState.CONFIRMED, block, seq)
            seq += 1
    for tx in _parents_first(mempool):
        held = txs.get(tx.id)
        if held is not None:
            txs[tx.id] = replace(held, state=TxState.MEMPOOL, block=None)
        else:
            txs[tx.id] = WalletTx(tx, TxState.MEMPOOL, None, seq)
            seq += 1


# -- ISS btclib-org/btclib-wallet#642 --------------------------------------


def _inputs_verify(
    tx: Tx, txs: Mapping[bytes, WalletTx], scripts: Mapping[bytes, _Position]
) -> bool:
    """Whether every input spending an output of the ledger verifies."""
    prevouts = [_prevout(tx_in, txs) for tx_in in tx.vin]
    for i, prevout in enumerate(prevouts):
        if prevout is None or prevout.script_pub_key.script not in scripts:
            continue
        spent = [p or TxOut(0, b"") for p in prevouts]
        try:
            verify_input(spent, tx, i)
        except BTClibValueError:
            return False
    return True


def _drop_unverified(
    txs: dict[bytes, WalletTx], scripts: Mapping[bytes, _Position]
) -> None:
    """Remove each transaction in no block whose own inputs do not verify.

    Its unconfirmed descendants go with it. Parents are checked first, so
    a spender is checked against the parents that stay.
    """
    unconfirmed = {
        txid: wtx.tx for txid, wtx in txs.items() if wtx.state is not TxState.CONFIRMED
    }
    for tx in _parents_first(unconfirmed):
        if tx.id in txs and not _inputs_verify(tx, txs, scripts):
            _remove_with_descendants(tx.id, txs)


def _how_spent(spenders: Sequence[WalletTx]) -> TxState | None:
    """Core's `HowSpent`: the strongest state of the spenders, None if none."""
    states = {wtx.state for wtx in spenders}
    for state in (TxState.CONFIRMED, TxState.MEMPOOL, TxState.INACTIVE):
        if state in states:
            return state
    return None


def _parents_first(txs: Mapping[bytes, Tx]) -> list[Tx]:
    """Return the transactions with each after those it spends.

    A depth-first walk on a stack of its own, so that a chain of any
    length orders with no recursion.
    """
    ordered: list[Tx] = []
    placed: set[bytes] = set()
    for root in txs.values():
        # each entry is a transaction and whether its parents are placed
        stack = [(root, False)]
        while stack:
            tx, parents_placed = stack.pop()
            if parents_placed:
                ordered.append(tx)
                continue
            if tx.id in placed:
                continue
            placed.add(tx.id)
            stack.append((tx, True))
            for tx_in in reversed(tx.vin):
                parent = txs.get(tx_in.prev_out.tx_id)
                if parent is not None and parent.id not in placed:
                    stack.append((parent, False))
    return ordered


def _remove_with_descendants(txid: bytes, txs: dict[bytes, WalletTx]) -> None:
    """Remove a transaction and every unconfirmed one spending its outputs."""
    doomed = {txid}
    new = doomed
    while new:
        new = {
            child_id
            for child_id, child in txs.items()
            if child_id not in doomed
            and child.state is not TxState.CONFIRMED
            and any(tx_in.prev_out.tx_id in doomed for tx_in in child.tx.vin)
        }
        doomed |= new
    for gone in doomed:
        del txs[gone]
