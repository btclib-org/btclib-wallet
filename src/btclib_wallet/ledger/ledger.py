# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A set of descriptor wallets, their transactions and coins, kept current.

`Ledger` is what Bitcoin Core calls a wallet: a set of descriptors, which
`add_source` grows as `importdescriptors` does, and every transaction
that pays to or spends from their scripts. It answers what Core's wallet
RPCs answer of them -- `balances` (`getbalances`, and `getbalance`'s
`trusted`), `utxos` (`listunspent`), `transaction` and `transactions`
(`gettransaction`, `listtransactions`) -- and spends from them. It keeps
labels on addresses, as the last paragraph says. It reads the chain only
when its caller calls `sync`; nothing runs between calls.

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
the sync finds brings into the window. A position that comes into the
window between two syncs is read from the tip on, at the next sync: a
payment to it in an earlier block is not found, as Core's `TopUpWithDB`
reads no earlier block either: it hands the new scripts to
`TopUpCallback`, which only caches them
(src/wallet/scriptpubkeyman.cpp:1109-1169 and
src/wallet/wallet.cpp:4560-4571 at bitcoin/bitcoin@f0de87f040, the v32.1
tag).

The mempool part of the answers replaces the one the ledger held. A
transaction that was in the mempool or in a block and is in neither
now is kept as `TxState.INACTIVE`, not dropped: the mempool replaced it,
refused it or evicted it (test/functional/wallet_balance.py:174-180 and
214-225). A coinbase (*Abandon*) and a transaction a block conflicts
with (*Conflicts*) are the exceptions.

**Conflicts.** A transaction in a block that spends an input of a
transaction in no block makes that one `TxState.CONFLICTED` with the
block, and each of its descendants not in a block, as Core's
`MarkConflicted` does (src/wallet/wallet.cpp:1235-1252 and 1372-1400 at
bitcoin/bitcoin@f0de87f040, the v32.1 tag). Where several blocks
conflict with one transaction, the lowest is its block. Its
confirmations are minus the depth of that block. A reorganization that
disconnects the block makes it inactive again, as Core's
`blockDisconnected` does (:1599-1644). The ledger holds only what its
`HistoryReader` answers, so a conflict is found only where the
conflicting transaction touches the ledger's scripts: a payment to the
ledger whose input a block spends in a transaction paying elsewhere goes
inactive, not conflicted.

**Abandon.** `abandon` marks an inactive transaction `ABANDONED`, and
each inactive descendant, in the file, as Core's `AbandonTransaction`
does (:1342-1370). A sync that finds an abandoned transaction in the
mempool or a block clears its own mark only, and a conflict replaces
it. A coinbase a reorganization takes out of its block is abandoned, as
Core's `blockDisconnected` leaves it. An abandoned or conflicted
transaction counts in no balance and gives no coin, and the coins it
spends count and can be spent again.

**Resubmission.** `resubmit` broadcasts again each transaction in no
block that is neither conflicted nor abandoned, as Core does on load
and from time to time (:2147-2180). Here it runs only when its caller
calls it: the ledger broadcasts nothing that `spend`, `bump` or
`resubmit` was not called for.

**What is checked of an unconfirmed transaction** (ISS
btclib-org/btclib-wallet#642). A backend can report a mempool
transaction that spends the ledger's coins with a signature that does
not verify, to have the user replace it. So each input of a transaction
in no block that spends an output the ledger owns is verified with
btclib's script engine, against every output the transaction spends that
the ledger holds. The check runs at the end of each sync, against the
scripts the windows reach once that sync has moved them, and again
whenever the scripts watched grow between two syncs. A transaction that
fails leaves the ledger with its unconfirmed descendants, or is kept
out. A taproot input commits to every output the transaction spends, so
a spend of a taproot output of the ledger beside an output the ledger
does not hold fails the check. What stays unverified: an incoming
unconfirmed transaction spends no coin of the ledger, so nothing of it
is checked; a spend of the ledger's coin whose parent the backend has
not reported, until it does; and a transaction a backend reports in a
block, since a `HistoryReader` answers no proof that the block holds it
(ISS btclib-org/btclib-wallet#737).

**Balances.** Core's `GetBalance` and `CachedTxIsTrusted`
(src/wallet/receive.cpp:205-295 at bitcoin/bitcoin@f0de87f040, the v32.1
tag), and its `HowSpent` (src/wallet/wallet.cpp:810-830). A transaction
is trusted where it is
confirmed, or in the mempool with every input spending a trusted output
of the ledger. A coinbase is immature until 100 blocks are built on top
of its own.

**The spender.** `fund` selects among the safe, unlocked, unspent coins
that are confirmed or in the mempool, with `select_coins`, safe as
`Ledger.utxos` defines it: trusted, and while unconfirmed neither a bump
nor replaced by one. It pays the change to source 0: to the next address
of its branch 1 not handed out, or of its branch 0 where it has no
branch 1, or to the one address of that branch where its descriptor is
not ranged. The fee rate is the caller's where given, refused below the
node's minimum relay rate; else the backend's estimate, else
`fallback_fee_rate`, raised to the node's mempool minimum. A spend with
no rate, no estimate and no fallback is refused, as Core's is with
`-fallbackfee=0`. `spend` funds, signs and records the transaction as
inactive before it broadcasts it, so one the node refuses stays, and
counts as `nonmempool`. Its comments are kept with it, as
`sendtoaddress` keeps `comment` and `comment_to`. Each input signals
BIP125 replaceability, as Core's wallet does by default
(`DEFAULT_WALLET_RBF`, src/wallet/wallet.h:132 at
bitcoin/bitcoin@f0de87f040, the v32.1 tag); `replaceable=False` gives it
the sequence Core gives an input that does not signal
(src/wallet/spend.cpp:1303-1311).

**Fee bumping.** `bump_psbt` is Core's `psbtbumpfee`, and `bump` its
`bumpfee`: it signs, records and broadcasts what `bump_psbt` returns
(src/wallet/feebumper.cpp and src/wallet/rpc/spend.cpp:962-1178 at the
same commit). The replacement spends every input of the transaction it
replaces, and pays its outputs or those the caller names. Its change
goes to the output `original_change_index` names, or else to the
transaction's own change, which is change as *Labels* reads it and
Core's `OutputIsChange` reads it (feebumper.cpp:258), or else to a new
change address. Where every output is change,
they are paid as one output and the fee is taken from it, as Core takes
it (feebumper.cpp:267-279). What the inputs hold over them is a new
change output of at least Core's `min_viable_change` at
`DEFAULT_DISCARD_FEE` (src/wallet/spend.cpp:1187-1192), and otherwise
fee, which the output then pays that much less of.
Where the inputs fall short, confirmed coins are added, the largest
first, where Core runs its coin selection over what is short, the
replaced transaction's inputs preset (`SelectCoins`,
src/wallet/spend.cpp:811-845): `select_coins` takes no preset input.
Neither adds an unconfirmed one (feebumper.cpp:313-314). With no rate of
the caller's, the
rate is the replaced transaction's own, one sat/kvB more, plus the
larger of the node's incremental rate and `WALLET_INCREMENTAL_RELAY_FEE`,
raised to the rate for `conf_target` where that is higher: the
backend's estimate, else `fallback_fee_rate`, either raised to the
node's mempool minimum (`EstimateFeeRate`, feebumper.cpp:120-145, and
`GetMinimumFeeRate`, src/wallet/fees.cpp:32-88). Whatever the rate, the
replacement's fee must be at least the replaced one's plus the node's
incremental rate over the replacement's estimated size, as the node's
`PaysForRBF` asks (src/policy/rbf.cpp:100-125); it is checked here
before anything is signed, so a watch-only ledger's psbt is checked too.
`bump` records the link both ways, carries the comments across, and
marks the replaced transaction inactive once the broadcaster takes the
replacement, where it was in the mempool: an abandoned one stays
abandoned. While unconfirmed, neither one's coins are safe, as Core's
`AvailableCoins` has it (src/wallet/spend.cpp:366-395), so `fund`
spends none of them.

What a bump does not see: a descendant in the mempool that pays no
script of the ledger, which Core refuses (feebumper.cpp:31-36), and an
input spending an output the ledger does not hold, which Core's
`psbtbumpfee` values from the chain (test/functional/wallet_bumpfee.py:
412-417) and which is refused here.

**Labels.** Core's address book (src/wallet/wallet.h:238-278 at
bitcoin/bitcoin@f0de87f040, the v32.1 tag). A label is kept by script,
in the file, on an address of the ledger or of anybody else on its
network. Its purpose is `receive` where the ledger watches the script
when the label is set, and `send` otherwise, as `setlabel` sets it
(src/wallet/rpc/addresses.cpp:146-150). Until one is set, an address of
branch 0 has the label "" once it or a later index of its branch is
handed out or paid to, or where its descriptor is not ranged, as Core
labels each receiving address it hands out, imports, sees paid or skips
below one paid (src/wallet/wallet.cpp:1275-1280 and 3849-3865, and
src/wallet/scriptpubkeyman.cpp:1171-1197). `new_address` on a ranged
branch 0 sets the label it is given, "" where it is given none, over any
label the address had, with the purpose `receive`, as Core's
`GetNewDestination` does (src/wallet/wallet.cpp:2640-2654). An address
of another branch has no label until one is set. Change is an output to
the ledger's script with no label, as Core's `ScriptIsChange` reads it
(src/wallet/receive.cpp:52-72), so a label makes a change address a
receiving one. A script with no address, as `pk()` pays to, has no
label, is change, and is in no answer about labels or groupings. The
name `*` is refused, as `LabelFromValue` refuses it
(src/wallet/rpc/util.cpp:101-110). What an address or a label received
is Core's `GetReceived` (src/wallet/rpc/coins.cpp:21-77): every output
paying the ledger's scripts, change included, in each transaction deep
enough. `address_groupings` is `GetAddressBalances` and
`GetAddressGroupings` (src/wallet/receive.cpp:297-416).

**Encryption.** `encrypt` encrypts the private keys of every source
under a passphrase, as Core's `encryptwallet` does, and leaves the
ledger locked; the descriptors, the transactions and everything else
the file holds stay plain, so a locked ledger syncs, answers, hands out
addresses and funds a psbt. `unlock_keys` decrypts them for a number of
seconds, `lock_keys` locks them again, and `change_passphrase` encrypts
the master key under a new passphrase. While locked, `sign` and `spend`
are refused, and so is `add_source` of a wallet holding private keys,
whose keys need the master key to be encrypted. `crypto` says how the
keys are encrypted and `store` what the file holds.

What a ledger holds of its keys while unlocked is the master key, in a
buffer zeroed as *The relock* and `change_passphrase` say. An unlock
and a signature decrypt the keys into a buffer zeroed once they are
parsed, or at once where the tag fails. Copies remain, as `crypto`
says.

**The relock.** `lock_keys` and `close` zero the master key at once,
even under a call running in another thread. The timeout is kept on the
monotonic clock, as Core's relock runs on its scheduler's steady clock
(src/scheduler.h:49-54 at bitcoin/bitcoin@f0de87f040, the v32.1 tag):
a change of the system's time neither shortens nor lengthens an unlock.
Nothing runs between calls: the master key is zeroed by the first call
of a public method or property that starts after the timeout while no
call of the ledger runs, in any thread, and outlives its timeout in
memory until that call. So a call running as the timeout lapses keeps
the key to its end, and a `spend` signs what it funded. A public member
another one calls, as `spend` calls `fund` and `sign` and `fund` calls
`utxos`, starts while its caller runs, so it zeroes nothing. Core's
relock likewise waits for the wallet lock, which a call such as
`sendtoaddress` holds to its end (src/wallet/rpc/encrypt.cpp:104 and
src/wallet/rpc/spend.cpp:301 and 322 at the same commit).
"""

from __future__ import annotations

import functools
import json
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, replace
from math import ceil
from os import PathLike
from pathlib import Path
from types import TracebackType
from typing import Concatenate, ParamSpec, Self, TypeVar

from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.fee import FeeRate, dust_threshold, fee_from_vsize
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
from btclib_wallet.descriptors import normalized, parse
from btclib_wallet.exceptions import FetchError
from btclib_wallet.fetch.balance import script_pub_key_for_network
from btclib_wallet.fetch.broadcaster import Broadcaster
from btclib_wallet.fetch.fee_estimator import FeeEstimator, valid_confirmation_target
from btclib_wallet.fetch.fetcher import tx_for_network
from btclib_wallet.fetch.history import BlockRef, HistoryReader, ScriptHistory
from btclib_wallet.fetch.relay_fees import RelayFeeReader, RelayFees
from btclib_wallet.ledger.crypto import (
    _cipher,
    _master_key,
    _MasterKey,
    _new_key,
    _opened,
    _sealed,
    _unlocked,
    _wipe,
    _WrongKeyError,
)
from btclib_wallet.ledger.records import (
    Balances,
    BumpedPsbt,
    GroupedAddress,
    SyncResult,
    TxDetail,
    TxInfo,
    TxState,
    Utxo,
    WalletTx,
)
from btclib_wallet.ledger.store import _copy_backup, _Source, _Store, _SyncWrite
from btclib_wallet.psbt.psbt import Psbt, extract_tx, finalize
from btclib_wallet.psbt.psbt_in import PsbtIn
from btclib_wallet.psbt.psbt_size import estimated_input_sizes, miniscript_sizer
from btclib_wallet.psbt_signer import SoftwareSigner
from btclib_wallet.tx_builder import (
    DEFAULT_MAX_FEE,
    DEFAULT_MAX_FEE_RATE,
    FundedPsbt,
    _assert_fee_within,
    _ShortfallError,
    build_psbt,
)
from btclib_wallet.wallet.descriptor_wallet import DescriptorWallet

__all__ = ["LOOKAHEAD", "MAX_UNLOCK_TIME", "Ledger"]

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

# the longest `unlock_keys` keeps the keys unlocked, in seconds: Core's
# MAX_SLEEP_TIME (src/wallet/rpc/encrypt.cpp:63-67 at
# bitcoin/bitcoin@f0de87f040, the v32.1 tag)
MAX_UNLOCK_TIME = 100_000_000

_LOCKED = "the ledger is locked: unlock its keys first"
_LOCKED_DURING = "the ledger was locked while the call ran: unlock its keys again"

# the sequence of an input that signals BIP125 replaceability, and of one
# that does not: Core's MAX_BIP125_RBF_SEQUENCE (src/util/rbf.h:12 at
# bitcoin/bitcoin@f0de87f040, the v32.1 tag) and
# CTxIn::MAX_SEQUENCE_NONFINAL (src/primitives/transaction.h:83)
_RBF_SEQUENCE = 0xFFFFFFFD
_NON_RBF_SEQUENCE = 0xFFFFFFFE

# Core's WALLET_INCREMENTAL_RELAY_FEE (src/wallet/wallet.h:124): the least
# rise in rate a bump adds where its caller names no rate, unless the
# node's incremental rate is higher
_WALLET_INCREMENTAL_FEE_RATE = FeeRate(sats_per_kvbyte=5_000)

# Core's DEFAULT_DISCARD_FEE (src/wallet/wallet.h:108): the rate change
# is weighed at, to say whether it is worth creating
_DISCARD_FEE_RATE = FeeRate(sats_per_kvbyte=10_000)

# Core's MAX_MONEY, in satoshi (src/consensus/amount.h:26)
_MAX_MONEY = 21_000_000 * 100_000_000

# Core's DEFAULT_INCREMENTAL_RELAY_FEE (src/policy/policy.h:48): the
# node's incremental rate where the ledger has no relay fee reader to ask
_INCREMENTAL_RELAY_FEE_RATE = FeeRate(sats_per_kvbyte=100)

_P = ParamSpec("_P")
_R = TypeVar("_R")


def _relocking(
    method: Callable[Concatenate[Ledger, _P], _R],
) -> Callable[Concatenate[Ledger, _P], _R]:
    """Zero the master key before `method` runs, as *The relock* says.

    *The relock* is a paragraph of the module's docstring. This
    decorator wraps every public method and property of `Ledger` but
    the constructors `create`, `load` and `restore`. The count of calls
    running and the check of the timeout are under one lock, so that the
    count is exact where threads run without the GIL.
    """

    @functools.wraps(method)
    def relocked(ledger: Ledger, /, *args: _P.args, **kwargs: _P.kwargs) -> _R:
        with ledger._calls:
            if ledger._running == 0:
                ledger._relock_if_due()
            ledger._running += 1
        try:
            return method(ledger, *args, **kwargs)
        finally:
            with ledger._calls:
                ledger._running -= 1

    return relocked


# where an output of the ledger is: its source, branch and index
_Position = tuple[int, int, int]

# Core's two purposes of an address book entry, its own address's and
# anybody else's
_RECEIVE = "receive"
_SEND = "send"
# the third purpose `listlabels` accepts, which nothing here sets
_REFUND = "refund"


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

    Made by `create`, `load` or `restore`, never directly. The reader is
    the backend `sync` reads the chain from. The broadcaster, the fee
    estimator and the relay fee reader are what `fund` and `spend` use,
    each where the backend has it.
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
        self._labels: dict[bytes, tuple[str, str]] = {}
        self._txs: dict[bytes, WalletTx] = {}
        self._blocks: dict[int, bytes] = {}
        self._tip: BlockRef | None = None
        self._master_key: _MasterKey | None = None
        self._encrypted: dict[int, bytes] = {}
        self._key: bytearray | None = None
        # the lock the master key is zeroed, let go of and set under, with
        # the times it locks at, which `_holds` reads
        self._key_lock = threading.Lock()
        # when the keys lock: as `unlocked_until` reports it, and as
        # *The relock* decides it
        self._unlocked_until = 0
        self._relock_at = 0.0
        # how many public members are running, in every thread, and the
        # lock `_relocking` reads and writes it under
        self._running = 0
        self._calls = threading.Lock()

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
        try:
            ledger._master_key = store.master_key()
            if ledger._master_key is not None:
                # an encrypted file needs the cipher, refused here if missing
                _cipher()
            for source_id, source in store.sources():
                ledger._hold_keys(source_id, source)
                wallet = _wallet(source.descriptors, network, source.prv_keys)
                ledger._attach(source_id, wallet, source)
            # no address is asked for: a script `pk()` pays to has none
            ledger._handed.update(store.handed_out())
            ledger._txs = {wtx.tx.id: wtx for wtx in store.txs(network)}
            ledger._blocks = store.blocks()
            ledger._tip = store.tip()
            ledger._labels = store.labels()
            ledger._extend_windows()
        except BaseException:
            # what the file holds was refused: it is closed, as `_Store.open`
            # closes one it refuses
            store.close()
            raise
        return ledger

    @classmethod
    def restore(
        cls,
        backup: str | PathLike[str],
        path: str | PathLike[str],
        network: str,
        reader: HistoryReader,
        *,
        broadcaster: Broadcaster | None = None,
        fee_estimator: FeeEstimator | None = None,
        relay_fee_reader: RelayFeeReader | None = None,
        fallback_fee_rate: FeeRate | None = None,
    ) -> Ledger:
        """Copy the backup at `backup` into a new file at `path`, and load it.

        Core's `restorewallet`, which copies the backup and loads the copy
        (`RestoreWallet`, src/wallet/wallet.cpp:459-536 at
        bitcoin/bitcoin@f0de87f040, the v32.1 tag). A missing backup, a
        file already at `path`, and a backup that is no ledger file of
        `network` are refused, with nothing left at `path`. The ledger
        reads no backend here: its next `sync` reads from the tip the
        backup holds. On a node that pruned blocks from that tip up,
        `BitcoinCoreFetcher` fails that sync with a `FetchError`, where
        Core refuses the restore itself.
        """
        assert_type(backup, (str, PathLike), "backup")
        assert_type(path, (str, PathLike), "path")
        assert_type(fallback_fee_rate, (FeeRate, type(None)), "fallback_fee_rate")
        network = validated_network_name(network)
        _copy_backup(backup, path)
        try:
            return cls.load(
                path,
                network,
                reader,
                broadcaster=broadcaster,
                fee_estimator=fee_estimator,
                relay_fee_reader=relay_fee_reader,
                fallback_fee_rate=fallback_fee_rate,
            )
        except BaseException:
            Path(path).unlink(missing_ok=True)
            raise

    @_relocking
    def backup(self, path: str | PathLike[str]) -> None:
        """Write a copy of the ledger's file into a new file at `path`.

        Core's `backupwallet`. Anything at `path` is refused, the ledger's
        own file included, and nothing is written there. `store` says what
        the copy holds; `restore` reads it.
        """
        assert_type(path, (str, PathLike), "path")
        self._store.backup(path)

    @_relocking
    def close(self) -> None:
        """Lock the keys and close the file; the ledger answers nothing then."""
        self._drop_key()
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

    @_relocking
    def add_source(
        self,
        wallet: DescriptorWallet,
        birth_height: int | None = 0,
        *,
        lookahead: int = LOOKAHEAD,
        label: str | None = None,
    ) -> int:
        """Add a wallet of descriptors, and return its source id.

        Core's `importdescriptors`. `birth_height` is where the next
        `sync` reads its history from, and `None` reads none before the
        tip the ledger holds, as Core's `timestamp: "now"` does;
        `fetch.start_height_for_time` turns a birth time into a height.
        The wallet is written to the file whole, its private keys
        included, and `load` builds it again from its descriptors and
        keys. In an encrypted ledger its keys are written encrypted, as
        `store` says, and a wallet holding keys is refused while the
        ledger is locked, where a lock in another thread zeroed the
        master key while its keys were encrypted, and where its scripts
        need a private key at every index (a hardened ``/*h``), which a
        locked ledger could not derive. `label` is set on the one address
        of branch 0, where its script has one, and refused where that
        branch is ranged or missing, as Core refuses a label on a ranged
        descriptor (src/wallet/rpc/backup.cpp:213-216 at
        bitcoin/bitcoin@f0de87f040, the v32.1 tag).
        """
        assert_type(wallet, DescriptorWallet, "wallet")
        if birth_height is not None:
            _assert_height(birth_height, "birth_height")
        _assert_height(lookahead, "lookahead")
        if wallet.network != self.network:
            err_msg = f"a {wallet.network} wallet in a {self.network} ledger"
            raise BTClibValueError(err_msg)
        if label is not None:
            _assert_label(label)
            if 0 not in wallet.branches or wallet.descriptor(0).is_ranged:
                raise BTClibValueError("a label needs one address on branch 0")
        scanned = birth_height is None
        birth = birth_height
        if birth is None:
            birth = 0 if self._tip is None else self._tip.height
        descriptors = {
            branch: str(wallet.descriptor(branch)) for branch in wallet.branches
        }
        prv_keys = dict(wallet.prv_keys or {})
        source_id = self._store.next_source_id()
        encrypted = None
        if self._master_key is not None and prv_keys:
            descriptors, encrypted = self._sealed_source(wallet, source_id)
            wallet = _wallet(descriptors, self.network, {})
            prv_keys = {}
        source = _Source(descriptors, prv_keys, encrypted, lookahead, birth, scanned)
        self._store.add_source(source_id, source)
        if encrypted is not None:
            self._encrypted[source_id] = encrypted
        self._attach(source_id, wallet, source)
        self._extend_windows()
        if label is not None:
            script = wallet.script_pub_key(0, 0).script
            if self._address(script):
                self._write_label(script, label)
        return source_id

    def _sealed_source(
        self, wallet: DescriptorWallet, source_id: int
    ) -> tuple[dict[int, str], bytes]:
        """Return a wallet's watched descriptors, and its keys encrypted.

        A locked ledger is refused, and so is one whose master key
        `lock_keys` or `close` in another thread zeroed while the keys
        were encrypted: they may be under zeros.
        """
        key = self._assert_unlocked()
        descriptors = _watched(wallet)
        encrypted = _sealed(key, _plaintext(wallet), _aad(source_id))
        if not self._holds(key):
            raise BTClibValueError(_LOCKED_DURING)
        return descriptors, encrypted

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
    @_relocking
    def sources(self) -> tuple[DescriptorWallet, ...]:
        """The wallets of the ledger, in source id order.

        In an encrypted ledger a wallet added with private keys is the
        watch-only one `store` says the file holds.
        """
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
        if gone := [txid for txid in self._txs if txid not in txs]:
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

    @_relocking
    def new_address(
        self, source: int = 0, branch: int = 0, *, label: str | None = None
    ) -> str:
        """Hand out the next address of a branch, and remember it.

        Core's `getnewaddress`. The next index is one past the highest
        handed out or paid to. A branch whose descriptor is not ranged
        has one address, which is handed out every time. `label` is set
        on the address, replacing any it had. On a ranged branch 0, one
        not given is "", as the module docstring says.
        """
        if label is not None:
            _assert_label(label)
        position = self._new_position(source, branch)
        address = self._hand_out(position)
        self._store.add_handed_out([position])
        self._extend_windows()
        receiving = branch == 0 and self._sources[source].descriptor(0).is_ranged
        if label is None and receiving:
            label = ""
        if label is not None:
            self._write_label(
                self._sources[source].script_pub_key(branch, position[2]).script, label
            )
        return address

    @_relocking
    def new_change_address(self, source: int = 0) -> str:
        """Hand out the next address of the change branch, branch 1.

        Core's `getrawchangeaddress`. A source with no branch 1 is
        refused.
        """
        return self.new_address(source, 1)

    @_relocking
    def position_of(self, script_pub_key: ScriptPubKey) -> tuple[int, int, int] | None:
        """Return the source, branch and index paying to a script, or None.

        The answer is one of the positions the ledger watches.
        """
        assert_type(script_pub_key, ScriptPubKey, "script_pub_key")
        return self._scripts.get(script_pub_key.script)

    # -- the labels -------------------------------------------------------

    def _script_of(self, address: str) -> bytes:
        """Return the script of an address of the ledger's network."""
        return script_pub_key_for_network(address, self.network).script

    def _write_label(self, script: bytes, label: str) -> None:
        """Set a script's label, its purpose read from what is watched now."""
        purpose = _RECEIVE if script in self._scripts else _SEND
        self._store.set_label(script, label, purpose)
        self._labels[script] = (label, purpose)

    @_relocking
    def set_label(self, address: str, label: str) -> None:
        """Set the label of an address, the ledger's or anybody else's.

        Core's `setlabel`. A label the address had is replaced.
        """
        script = self._script_of(address)
        _assert_label(label)
        self._write_label(script, label)

    def _receive_ends(self) -> dict[int, int]:
        """Return the next index of each source's branch 0, by source id."""
        return {source: self._next_index(source, 0) for source in self._sources}

    def _entry(self, script: bytes, ends: Mapping[int, int]) -> tuple[str, str] | None:
        """Return a script's label and purpose, None where it has no label.

        `ends` is what `_receive_ends` returns. A caller asking of many
        scripts reads it once: each read scans every position handed out.
        """
        if script in self._labels:
            return self._labels[script]
        position = self._scripts.get(script)
        if position is None or position[1] != 0:
            return None
        source_id, _, index = position
        ranged = self._sources[source_id].descriptor(0).is_ranged
        if ranged and index >= ends[source_id]:
            return None
        return ("", _RECEIVE) if self._address(script) else None

    def _address_book(self) -> dict[bytes, tuple[str, str]]:
        """Return the label and purpose of each script that has a label."""
        book: dict[bytes, tuple[str, str]] = {}
        ends = self._receive_ends()
        for script in self._scripts.keys() | self._labels.keys():
            entry = self._entry(script, ends)
            if entry is not None:
                book[script] = entry
        return book

    def _address(self, script: bytes) -> str:
        """Return the address of a script, "" where it has none."""
        return ScriptPubKey(script, self.network).address

    def _has_address(self, tx_out: TxOut) -> bool:
        """Whether the output pays the ledger a script with an address."""
        return self._owned(tx_out) and self._address(_script(tx_out)) != ""

    @_relocking
    def label_of(self, address: str) -> str | None:
        """Return the label of an address, None where it has none.

        The `labels` that Core's `getaddressinfo` reports
        (src/wallet/rpc/addresses.cpp:550-555 at bitcoin/bitcoin@f0de87f040,
        the v32.1 tag).
        """
        entry = self._entry(self._script_of(address), self._receive_ends())
        return None if entry is None else entry[0]

    @_relocking
    def labels(self, purpose: str | None = None) -> tuple[str, ...]:
        """Return each label in use, sorted, Core's `listlabels`.

        A `purpose`, `receive` or `send`, keeps the labels of the
        addresses of that purpose.
        """
        assert_type(purpose, (str, type(None)), "purpose")
        if purpose not in (None, "", _RECEIVE, _SEND, _REFUND):
            raise BTClibValueError(f"invalid purpose: {purpose}")
        purpose = purpose or None
        return tuple(
            sorted(
                {
                    label
                    for label, entry_purpose in self._address_book().values()
                    if purpose in (None, entry_purpose)
                }
            )
        )

    @_relocking
    def addresses_by_label(self, label: str) -> dict[str, str]:
        """Return the purpose of each address with the label.

        Core's `getaddressesbylabel`. A label no address has is refused.
        """
        _assert_label(label)
        if not (
            found := {
                self._address(script): purpose
                for script, (entry_label, purpose) in self._address_book().items()
                if entry_label == label
            }
        ):
            raise BTClibValueError(f"no address has the label {label}")
        return found

    # -- the sync ---------------------------------------------------------

    @property
    @_relocking
    def tip(self) -> BlockRef | None:
        """The block the ledger is synced to, None before any sync.

        Core's `lastprocessedblock`.
        """
        return self._tip

    @_relocking
    def sync(self) -> SyncResult:
        """Read the chain from the tip the ledger holds, and record it.

        The module docstring says how. A tip that moves between the reads
        of one sync starts it again, at most `_SYNC_ATTEMPTS` times in
        all, and then raises `FetchError`. A backend's own `FetchError` is
        raised as it comes, and nothing is written. A ledger with no
        source is refused, having no script to ask about.
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
        # merged, not replaced: an unscanned source keeps its whole window
        for source, grown in self._grow(windows, answers).items():
            pending.setdefault(source, set()).update(grown)
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
        _mark_conflicts(txs)
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

    def _is_change(self, tx_out: TxOut, ends: Mapping[int, int]) -> bool:
        """Whether the output pays the ledger a script with no label."""
        return self._owned(tx_out) and self._entry(_script(tx_out), ends) is None

    def _depth(self, wtx: WalletTx) -> int:
        """Core's `GetTxDepthInMainChain`: confirmations, 0 in no block.

        A conflicted transaction's depth is minus its block's.
        """
        if wtx.block is None or self._tip is None:
            return 0
        depth = self._tip.height - wtx.block.height + 1
        return -depth if wtx.state is TxState.CONFLICTED else depth

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
            prevout = _prevout(tx_in, self._txs)
            if prevout is None or not self._owned(prevout):
                return False
            parent = self._txs[tx_in.prev_out.tx_id]
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

    @_relocking
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

    @_relocking
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
        transaction of the ledger that is neither abandoned nor
        conflicted spends it; where its own transaction is in no block
        and not in the mempool, a conflicted one included; where it is
        locked, unless `include_locked`; where it is an immature coinbase,
        unless `include_immature_coinbase`; and where it is not safe and
        `include_unsafe` is False. An output is safe where its transaction
        is trusted and, while in no block, neither a bump nor replaced by
        one.
        """
        _assert_height(min_depth, "min_depth")
        assert_type(include_immature_coinbase, bool, "include_immature_coinbase")
        assert_type(include_locked, bool, "include_locked")
        assert_type(include_unsafe, bool, "include_unsafe")
        spends = self._spends()
        found: list[Utxo] = []
        trusted_set: set[bytes] = set()
        for wtx, vout, tx_out in self._outputs():
            outpoint = OutPoint(wtx.tx.id, vout)
            depth = self._depth(wtx)
            safe = self._is_trusted(wtx, trusted_set) and (
                depth != 0 or (wtx.replaces is None and wtx.replaced_by is None)
            )
            skipped = (
                (self._is_immature(wtx) and not include_immature_coinbase)
                or (depth <= 0 and wtx.state is not TxState.MEMPOOL)
                or (not safe and not include_unsafe)
                or depth < min_depth
                or (outpoint in self._locked and not include_locked)
                or _how_spent(spends.get(outpoint, [])) is not None
            )
            if not skipped:
                source, branch, index = self._scripts[tx_out.script_pub_key.script]
                found.append(Utxo(outpoint, tx_out, depth, safe, source, branch, index))
        return tuple(found)

    @_relocking
    def lock(self, outpoint: OutPoint) -> None:
        """Keep an output out of `fund` and `spend`, until `unlock`.

        Core's `lockunspent`, not persistent: a lock is not in the file.
        """
        assert_type(outpoint, OutPoint, "outpoint")
        self._locked.add(outpoint)

    @_relocking
    def unlock(self, outpoint: OutPoint) -> None:
        """Let a locked output be spent again."""
        assert_type(outpoint, OutPoint, "outpoint")
        self._locked.discard(outpoint)

    @property
    @_relocking
    def locked(self) -> frozenset[OutPoint]:
        """The outputs locked, Core's `listlockunspent`."""
        return frozenset(self._locked)

    @_relocking
    def transaction(self, txid: bytes) -> TxInfo:
        """Return what `gettransaction` reports of a transaction held.

        `txid` is in display order, as `Tx.id` returns it.
        """
        return self._info(self._held(txid), set(), self._spends(), self._receive_ends())

    def _held(self, txid: bytes) -> WalletTx:
        """Return a transaction held, refusing an id of none."""
        assert_type(txid, bytes, "txid")
        if txid not in self._txs:
            raise BTClibValueError(f"not a ledger transaction: {txid.hex()}")
        return self._txs[txid]

    @property
    @_relocking
    def transactions(self) -> tuple[TxInfo, ...]:
        """Every transaction held, in the order it was recorded.

        Core's `listtransactions`, one `TxInfo` per transaction.
        """
        trusted: set[bytes] = set()
        spends = self._spends()
        ends = self._receive_ends()
        ordered = sorted(self._txs.values(), key=lambda wtx: wtx.seq)
        return tuple(self._info(wtx, trusted, spends, ends) for wtx in ordered)

    def _info(
        self,
        wtx: WalletTx,
        trusted: set[bytes],
        spends: Mapping[OutPoint, Sequence[WalletTx]],
        ends: Mapping[int, int],
    ) -> TxInfo:
        """Return Core's `gettransaction` figures of a transaction.

        Its details are `CachedTxGetAmounts` with the change left out
        (src/wallet/receive.cpp:165-191 at bitcoin/bitcoin@f0de87f040, the
        v32.1 tag): where the transaction spends the ledger's coins, each
        output that is not change is sent, the ledger's own included, and
        each output of the ledger is received. A conflicted transaction
        lists no output received, as Core's `ListTransactions` lists none
        below depth 0 (src/wallet/rpc/transactions.cpp:355).
        """
        tx = wtx.tx
        debit = self._debit(tx)
        immature = self._is_immature(wtx)
        depth = self._depth(wtx)
        details: list[TxDetail] = []
        credit = 0
        for vout, tx_out in enumerate(tx.vout):
            owned = self._owned(tx_out)
            if owned and not immature:
                credit += tx_out.value
            if debit and self._is_change(tx_out, ends):
                continue
            if debit:
                details.append(TxDetail("send", vout, -tx_out.value))
            if owned and depth >= 0:
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
            depth,
            self._is_trusted(wtx, trusted),
            tuple(details),
            frozenset(
                other.tx.id
                for tx_in in tx.vin
                for other in spends.get(tx_in.prev_out, ())
                if other.tx.id != tx.id
            ),
        )

    def _category(self, wtx: WalletTx) -> str:
        """Core's category of an output received."""
        if not wtx.tx.is_coinbase:
            return "receive"
        if wtx.state is not TxState.CONFIRMED:
            return "orphan"
        return "immature" if self._is_immature(wtx) else "generate"

    @_relocking
    def received_by_address(
        self,
        address: str,
        min_depth: int = 1,
        *,
        include_immature_coinbase: bool = False,
    ) -> int:
        """Return what the address received, in satoshi.

        Core's `getreceivedbyaddress`, as the module docstring says. An
        address the ledger does not watch is refused.
        """
        script = self._script_of(address)
        _assert_height(min_depth, "min_depth")
        assert_type(include_immature_coinbase, bool, "include_immature_coinbase")
        if script not in self._scripts:
            raise BTClibValueError(f"not an address of the ledger: {address}")
        return self._received({script}, min_depth, include_immature_coinbase)

    @_relocking
    def received_by_label(
        self,
        label: str,
        min_depth: int = 1,
        *,
        include_immature_coinbase: bool = False,
    ) -> int:
        """Return what the ledger's addresses with the label received.

        Core's `getreceivedbylabel`. A label no address has is refused,
        and so is one that only addresses of others have.
        """
        _assert_label(label)
        _assert_height(min_depth, "min_depth")
        assert_type(include_immature_coinbase, bool, "include_immature_coinbase")
        scripts = {
            script
            for script, (entry_label, _) in self._address_book().items()
            if entry_label == label
        }
        if not scripts:
            raise BTClibValueError(f"no address has the label {label}")
        if not (owned := scripts & self._scripts.keys()):
            raise BTClibValueError(f"no address of the ledger has the label {label}")
        return self._received(owned, min_depth, include_immature_coinbase)

    def _received(
        self, scripts: set[bytes], min_depth: int, include_immature_coinbase: bool
    ) -> int:
        """Core's `GetReceived`: what the scripts received, deep enough.

        A coinbase in no block is left out at any depth asked.
        """
        total = 0
        for wtx in self._txs.values():
            depth = self._depth(wtx)
            if (
                depth < min_depth
                or (wtx.tx.is_coinbase and depth < 1)
                or (self._is_immature(wtx) and not include_immature_coinbase)
            ):
                continue
            total += sum(o.value for o in wtx.tx.vout if _script(o) in scripts)
        return total

    @property
    @_relocking
    def address_groupings(self) -> tuple[tuple[GroupedAddress, ...], ...]:
        """The ledger's addresses, grouped as spent together.

        Core's `listaddressgroupings`. Addresses whose outputs one
        transaction spends are in one group, with the change it pays;
        each address paid is in a group, alone where nothing joins it.
        A script with no address is left out. The groups and the addresses
        in each are sorted by address.
        """
        merged: dict[bytes, set[bytes]] = {}
        ends = self._receive_ends()
        for wtx in self._txs.values():
            tx = wtx.tx
            prevouts = [_prevout(tx_in, self._txs) for tx_in in tx.vin]
            spent = [
                _script(prevout)
                for prevout in prevouts
                if prevout is not None and self._has_address(prevout)
            ]
            if spent:
                spent += [
                    _script(o)
                    for o in tx.vout
                    if self._is_change(o, ends) and self._has_address(o)
                ]
            groups = [spent] + [[_script(o)] for o in tx.vout if self._has_address(o)]
            for group in groups:
                joined = set(group)
                for script in group:
                    joined |= merged.get(script, set())
                for script in joined:
                    merged[script] = joined
        balances = self._address_balances()
        found = []
        for joined_scripts in {frozenset(scripts) for scripts in merged.values()}:
            entries = []
            for script in joined_scripts:
                entry = self._entry(script, ends)
                entries.append(
                    GroupedAddress(
                        self._address(script),
                        balances.get(script, 0),
                        None if entry is None else entry[0],
                    )
                )
            found.append(tuple(sorted(entries, key=lambda e: e.address)))
        return tuple(sorted(found, key=lambda group: group[0].address))

    def _address_balances(self) -> dict[bytes, int]:
        """Core's `GetAddressBalances`: what each script holds unspent.

        An output counts where its transaction is trusted and no immature
        coinbase. Trusted is confirmed unless it spends the ledger's coins,
        which is Core's depth check here too.
        """
        spends = self._spends()
        trusted: set[bytes] = set()
        balances: dict[bytes, int] = {}
        for wtx, vout, tx_out in self._outputs():
            if not self._is_trusted(wtx, trusted) or self._is_immature(wtx):
                continue
            spent = _how_spent(spends.get(OutPoint(wtx.tx.id, vout), []))
            value = 0 if spent is not None else tx_out.value
            script = _script(tx_out)
            balances[script] = balances.get(script, 0) + value
        return balances

    # -- the spender ------------------------------------------------------

    def _fee_rate(self, fee_rate: FeeRate | None) -> FeeRate:
        """Return the rate a spend pays, as the module docstring says."""
        assert_type(fee_rate, (FeeRate, type(None)), "fee_rate")
        relay = self._relay_fees()
        if fee_rate is not None:
            if relay is not None and fee_rate < relay.min_relay:
                err_msg = f"fee rate {fee_rate.sats_per_kvbyte} sat/kvB is below"
                err_msg += f" the minimum relay rate {relay.min_relay.sats_per_kvbyte}"
                raise BTClibValueError(err_msg)
            return fee_rate
        rate = self._estimated(_CONFIRMATION_TARGET, relay)
        if rate is None:
            err_msg = "no fee estimate and no fallback fee rate: name a fee rate"
            raise BTClibValueError(err_msg)
        return rate

    def _estimated(self, target: int, relay: RelayFees | None) -> FeeRate | None:
        """Return the estimate for `target`, else the fallback, else None.

        Raised to the node's mempool minimum, where the ledger reads it.
        """
        rate = None
        if self._fee_estimator is not None:
            try:
                rate = self._fee_estimator.estimate_fee(target).rate
            except FetchError:
                rate = None
        if rate is None:
            rate = self.fallback_fee_rate
        if rate is not None and relay is not None:
            rate = max(rate, relay.mempool_min)
        return rate

    def _relay_fees(self) -> RelayFees | None:
        """Return the node's relay fee floors, None with no reader to ask."""
        if self._relay_fee_reader is None:
            return None
        return self._relay_fee_reader.get_relay_fees()

    def _psbt_in(self, parent: Tx, vout: int, sequence: int) -> PsbtIn:
        """Return the input map spending an output of the ledger, updated."""
        outpoint = OutPoint(parent.id, vout)
        psbt = Psbt.from_tx(Tx(vin=[TxIn(outpoint)], vout=[parent.vout[vout]]))
        position = self._scripts[_script(parent.vout[vout])]
        psbt_in = self._updated(psbt, 0, position, parent).inputs[0]
        psbt_in.sequence = sequence
        return psbt_in

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

    @_relocking
    def fund(
        self,
        outputs: Sequence[TxOut],
        fee_rate: FeeRate | None = None,
        *,
        replaceable: bool = True,
    ) -> FundedPsbt:
        """Return the unsigned psbt paying `outputs` from the ledger's coins.

        Core's `fundrawtransaction`. The coins, the rate, the change
        address and the sequence `replaceable` chooses are the module
        docstring's; the change address is handed out only where the psbt
        pays to it. A ledger with no source 0 is refused.
        """
        assert_type(outputs, Sequence, "outputs")
        for tx_out in outputs:
            assert_type(tx_out, TxOut, "outputs")
        assert_type(replaceable, bool, "replaceable")
        rate = self._fee_rate(fee_rate)
        sequence = _RBF_SEQUENCE if replaceable else _NON_RBF_SEQUENCE
        candidates: dict[OutPoint, tuple[Candidate, PsbtIn]] = {}
        for utxo in self.utxos(0, include_unsafe=False):
            psbt_in = self._psbt_in(
                self._txs[utxo.outpoint.tx_id].tx, utxo.outpoint.vout, sequence
            )
            candidate = Candidate(utxo.outpoint, utxo.tx_out, self._weight(psbt_in))
            candidates[utxo.outpoint] = (candidate, psbt_in)
        change_position, change_script = self._new_change()
        change_weight = self._change_spend_weight(change_position, change_script)
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
            psbt = self._paid_new_change(
                funded.psbt, funded.change_index, change_position
            )
            funded = FundedPsbt(psbt, funded.fee, funded.change_index)
        return funded

    def _new_change(self) -> tuple[_Position, ScriptPubKey]:
        """Return the position the change of a spend goes to, and its script.

        The module docstring says which; it is not handed out until a psbt
        pays to it.
        """
        change_branch = 1 if 1 in self._source(0).branches else 0
        position = self._new_position(0, change_branch)
        _, branch, index = position
        return position, self._sources[0].script_pub_key(branch, index)

    def _change_spend_weight(self, position: _Position, script: ScriptPubKey) -> int:
        """Return what an input spending the change will weigh.

        An input spending an output of a stand-in parent, the change being
        no transaction's yet.
        """
        stand_in = Tx(vin=[TxIn(OutPoint(b"\x01" * 32, 0))], vout=[TxOut(0, script)])
        psbt = Psbt.from_tx(
            Tx(vin=[TxIn(OutPoint(stand_in.id, 0))], vout=[stand_in.vout[0]])
        )
        return self._weight(self._updated(psbt, 0, position, stand_in).inputs[0])

    def _paid_new_change(self, psbt: Psbt, i: int, position: _Position) -> Psbt:
        """Hand out the position output `i` pays, and update the output."""
        self._hand_out(position)
        self._store.add_handed_out([position])
        self._extend_windows()
        source, branch, index = position
        return self._sources[source].update_psbt_output(psbt, i, branch, index)

    @_relocking
    def sign(self, psbt: Psbt) -> Psbt:
        """Return the psbt with every signature the ledger's keys can add.

        Core's `signrawtransactionwithwallet`, over a psbt: each input
        spending an output the ledger holds is updated with its source's
        scripts and key origins first. A source signs with the extended
        private keys it was added with. A locked ledger is refused.
        """
        assert_type(psbt, Psbt, "psbt")
        if self._master_key is not None:
            self._assert_unlocked()
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
        for wallet in self._signing_wallets():
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

    def _signing_wallets(self) -> list[DescriptorWallet]:
        """Return each source as it signs, an encrypted one decrypted."""
        key = self._key
        if key is None:
            if self._master_key is not None:
                raise BTClibValueError(_LOCKED_DURING)
            return list(self._sources.values())
        return [
            self._decrypted(key, source_id) if source_id in self._encrypted else wallet
            for source_id, wallet in self._sources.items()
        ]

    def _decrypted(self, key: bytearray, source_id: int) -> DescriptorWallet:
        """Return a source as it was added, its keys decrypted under `key`.

        A `key` zeroed in place, as `lock_keys` and a new `unlock_keys`
        zero the one held, from another thread while this ran, is refused
        as a ledger locked during the call, not as a damaged file.
        """
        try:
            plaintext = _opened(key, self._encrypted[source_id], _aad(source_id))
        except _WrongKeyError:
            if not any(key):
                raise BTClibValueError(_LOCKED_DURING) from None
            err_msg = f"not a ledger file: source {source_id}'s keys do not decrypt"
            raise BTClibValueError(err_msg) from None
        try:
            held = json.loads(plaintext)
        finally:
            _wipe(plaintext)
        return _wallet(
            {int(b): t for b, t in held["descriptors"].items()},
            self.network,
            held["prv_keys"],
        )

    @_relocking
    def spend(
        self,
        outputs: Sequence[TxOut],
        fee_rate: FeeRate | None = None,
        *,
        comment: str | None = None,
        comment_to: str | None = None,
        replaceable: bool = True,
    ) -> Tx:
        """Pay `outputs` from the ledger's coins, and broadcast the payment.

        Core's `send`, and `sendtoaddress` for its `comment` and
        `comment_to`, which are kept with the transaction. The
        transaction is recorded as inactive before it is broadcast, and
        as in the mempool once the broadcaster accepts it. A refusal is
        raised as the broadcaster raises it, and leaves the transaction in
        the ledger as inactive. Each position of the ledger it pays other
        than the change is handed out once the broadcaster accepts it, as
        Core's wallet marks the scripts a transaction pays used when the
        mempool reports it (src/wallet/wallet.cpp:1263-1280 at
        bitcoin/bitcoin@f0de87f040, the v32.1 tag); the change is handed
        out by the call that builds the psbt, as Core keeps its change
        address once it creates the transaction
        (src/wallet/spend.cpp:1432-1434).
        """
        assert_type(comment, (str, type(None)), "comment")
        assert_type(comment_to, (str, type(None)), "comment_to")
        if self._broadcaster is None:
            raise BTClibValueError("no broadcaster: the ledger cannot send")
        if self._master_key is not None:
            self._assert_unlocked()
        funded = self.fund(outputs, fee_rate, replaceable=replaceable)
        tx = tx_for_network(extract_tx(finalize(self.sign(funded.psbt))), self.network)
        self._commit(self._broadcaster, tx, comment, comment_to, None)
        return tx

    def _commit(
        self,
        broadcaster: Broadcaster,
        tx: Tx,
        comment: str | None,
        comment_to: str | None,
        replaced: WalletTx | None,
    ) -> None:
        """Record a transaction as inactive, broadcast it, then as in mempool.

        Core's `CommitTransaction`. Where it replaces `replaced`, both are
        linked in the same write, as `feebumper::CommitTransaction` marks
        the original whether or not the node takes the replacement
        (src/wallet/feebumper.cpp:352-381 at bitcoin/bitcoin@f0de87f040,
        the v32.1 tag); once the node takes it, the original left its
        mempool, and is inactive.
        """
        seq = max((wtx.seq for wtx in self._txs.values()), default=-1) + 1
        replaces = None if replaced is None else replaced.tx.id
        wtx = WalletTx(
            tx, TxState.INACTIVE, None, seq, comment, comment_to, replaces, None
        )
        written = [wtx]
        if replaced is not None:
            replaced = replace(replaced, replaced_by=tx.id)
            written.append(replaced)
        self._store.upsert_txs(written)
        self._txs.update((w.tx.id, w) for w in written)
        broadcaster.broadcast(tx)
        written = [replace(wtx, state=TxState.MEMPOOL)]
        if replaced is not None and replaced.state is TxState.MEMPOOL:
            written.append(replace(replaced, state=TxState.INACTIVE))
        self._store.upsert_txs(written)
        self._txs.update((w.tx.id, w) for w in written)
        self._hand_out_paid([tx])

    # -- fee bumping ------------------------------------------------------

    @_relocking
    def bump_psbt(
        self,
        txid: bytes,
        fee_rate: FeeRate | None = None,
        *,
        conf_target: int | None = None,
        outputs: Sequence[TxOut] | None = None,
        original_change_index: int | None = None,
        replaceable: bool = True,
    ) -> BumpedPsbt:
        """Return the unsigned replacement of a transaction, at a higher fee.

        Core's `psbtbumpfee`; the module docstring says what the
        replacement spends and pays. `fee_rate` is its rate, or
        `conf_target` the target the estimate is asked for; not both.
        `outputs` replaces the transaction's outputs, or
        `original_change_index` names the output whose script takes the
        change; not both either. `replaceable` is `fund`'s. `txid` is in
        display order.

        Refused, in Core's order but for the fee of a replacement at the
        caller's rate, which Core checks before it funds the replacement
        and the ledger checks on the funded one (src/wallet/feebumper.cpp:
        24-118 and 160-330 at bitcoin/bitcoin@f0de87f040, the v32.1 tag):
        a locked
        ledger, as Core refuses a locked wallet's `psbtbumpfee`
        (src/wallet/rpc/spend.cpp:1109); a change index out of range; an
        input spending an output the ledger does not hold, or a coin
        spent in a block, as a confirmed or conflicted transaction's are,
        or in no block and no mempool; a transaction with a descendant
        the ledger holds that is neither abandoned nor conflicted, and
        one already bumped; a rate below the node's mempool minimum; a
        replacement the confirmed coins cannot fund, or whose fee is above
        `build_psbt`'s ceilings; and one whose fee is under the replaced
        one's plus the incremental rate over its size. An abandoned
        transaction is bumped, as Core bumps one.
        """
        _assert_bump_arguments(
            fee_rate, conf_target, outputs, original_change_index, replaceable
        )
        if self._master_key is not None:
            self._assert_unlocked()
        wtx = self._held(txid)
        tx = wtx.tx
        if original_change_index is not None and original_change_index >= len(tx.vout):
            err_msg = f"change index {original_change_index} is out of range"
            raise BTClibValueError(err_msg)
        sequence = _RBF_SEQUENCE if replaceable else _NON_RBF_SEQUENCE
        inputs = self._original_inputs(tx, sequence)
        self._assert_bumpable(wtx)
        old_fee = self._debit(tx) - sum(tx_out.value for tx_out in tx.vout)
        relay = self._relay_fees()
        rate = self._bump_rate(fee_rate, conf_target, wtx, old_fee, relay)
        txouts = list(tx.vout) if outputs is None else list(outputs)
        funded, updates = self._replacement(
            tx, inputs, txouts, original_change_index, rate, sequence
        )
        vsize = funded.psbt.vsize_estimate(miniscript_sizer)
        incremental = (
            _INCREMENTAL_RELAY_FEE_RATE if relay is None else relay.incremental
        )
        _assert_replaces(old_fee, funded.fee, vsize, incremental)
        psbt = funded.psbt
        for i, position, new in updates:
            if new:
                psbt = self._paid_new_change(psbt, i, position)
            else:
                source, branch, index = position
                psbt = self._sources[source].update_psbt_output(psbt, i, branch, index)
        return BumpedPsbt(psbt, txid, old_fee, funded.fee, funded.change_index)

    def _replacement(
        self,
        tx: Tx,
        inputs: list[PsbtIn],
        txouts: list[TxOut],
        original_change_index: int | None,
        rate: FeeRate,
        sequence: int,
    ) -> tuple[FundedPsbt, list[tuple[int, _Position, bool]]]:
        """Return the replacement of `tx` paying `txouts`, and what to update.

        What to update is each output paying the ledger's change: its
        index, its position, and whether that is the new change's,
        handed out only once the replacement is checked.
        """
        change: TxOut | None = None
        recipients: list[TxOut] = []
        ends = self._receive_ends()
        for i, tx_out in enumerate(txouts):
            if original_change_index is None:
                is_change = self._is_change(tx_out, ends)
            else:
                is_change = i == original_change_index
            if is_change:
                change = tx_out
            else:
                recipients.append(tx_out)
        new_position, new_script = self._new_change()
        spent = {tx_in.prev_out for tx_in in tx.vin}
        # BIP125's rule 2: no unconfirmed input is added
        coins = [
            u for u in self.utxos(1, include_unsafe=False) if u.outpoint not in spent
        ]
        coins.sort(key=lambda u: u.tx_out.value, reverse=True)
        added = [
            self._psbt_in(self._txs[u.outpoint.tx_id].tx, u.outpoint.vout, sequence)
            for u in coins
        ]
        updates: list[tuple[int, _Position, bool]] = []
        if recipients or change is None:
            script = new_script if change is None else change.script_pub_key
            funded = _with_inputs_added(
                inputs,
                added,
                lambda ins: build_psbt(
                    ins, recipients, rate, script.script, sizer=miniscript_sizer
                ),
            )
            position = self._scripts.get(script.script)
            if funded.change_index is not None and change is None:
                updates.append((funded.change_index, new_position, True))
            elif funded.change_index is not None and position is not None:
                updates.append((funded.change_index, position, False))
            return funded, updates
        # every output is change: one output, the fee taken from it
        value = sum(tx_out.value for tx_out in txouts)
        weight = self._change_spend_weight(new_position, new_script)
        least_change = _least_change(new_script, weight)
        funded = _with_inputs_added(
            inputs,
            added,
            lambda ins: _fee_from_change(
                ins, change, value, rate, new_script, least_change
            ),
        )
        position = self._scripts.get(_script(change))
        if position is not None:
            updates.append((0, position, False))
        if funded.change_index is not None:
            updates.append((funded.change_index, new_position, True))
        return funded, updates

    def _original_inputs(self, tx: Tx, sequence: int) -> list[PsbtIn]:
        """Return the input maps of what `tx` spends, refusing a spent coin.

        Core's `CreateRateBumpTransaction` finds each coin in the chain
        and the mempool, and refuses one it does not find
        (src/wallet/feebumper.cpp:188-209 at bitcoin/bitcoin@f0de87f040,
        the v32.1 tag). Here a coin is found where its transaction is
        confirmed or in the mempool, and no confirmed transaction of the
        ledger spends it.
        """
        in_blocks = {
            tx_in.prev_out
            for wtx in self._txs.values()
            if wtx.state is TxState.CONFIRMED and not wtx.tx.is_coinbase
            for tx_in in wtx.tx.vin
        }
        inputs = []
        for i, tx_in in enumerate(tx.vin):
            outpoint = tx_in.prev_out
            prevout = _prevout(tx_in, self._txs)
            if prevout is None or not self._owned(prevout):
                err_msg = f"input {i} spends an output the ledger does not hold"
                raise BTClibValueError(err_msg)
            parent = self._txs[outpoint.tx_id]
            if (
                parent.state not in (TxState.CONFIRMED, TxState.MEMPOOL)
                or outpoint in in_blocks
            ):
                err_msg = f"{outpoint.tx_id.hex()}:{outpoint.vout} is already spent"
                raise BTClibValueError(err_msg)
            inputs.append(self._psbt_in(parent.tx, outpoint.vout, sequence))
        return inputs

    def _assert_bumpable(self, wtx: WalletTx) -> None:
        """Refuse what Core's `PreconditionChecks` refuses that the ledger sees.

        src/wallet/feebumper.cpp:24-58 at bitcoin/bitcoin@f0de87f040, the
        v32.1 tag; the module docstring says what is not seen. A confirmed
        or conflicted transaction is not asked about: it spends a coin
        spent in a block, or one of a conflicted parent, which
        `_original_inputs` refuses first, as Core's coin lookup refuses
        it before these checks (test/functional/wallet_bumpfee.py:667-674).
        """
        spends = self._spends()
        tx = wtx.tx
        for vout in range(len(tx.vout)):
            if _how_spent(spends.get(OutPoint(tx.id, vout), [])) is not None:
                raise BTClibValueError("the transaction has descendants in the ledger")
        if wtx.replaced_by is not None:
            err_msg = f"cannot bump transaction {tx.id.hex()}, which was already"
            err_msg += f" bumped by transaction {wtx.replaced_by.hex()}"
            raise BTClibValueError(err_msg)

    def _bump_rate(
        self,
        fee_rate: FeeRate | None,
        conf_target: int | None,
        wtx: WalletTx,
        old_fee: int,
        relay: RelayFees | None,
    ) -> FeeRate:
        """Return the rate a replacement pays, as the module docstring says.

        A rate of the caller's below the node's mempool minimum is refused,
        as Core's `CheckFeeRate` refuses it (src/wallet/feebumper.cpp:68-76
        at bitcoin/bitcoin@f0de87f040, the v32.1 tag).
        """
        if fee_rate is not None:
            if relay is not None and fee_rate < relay.mempool_min:
                err_msg = f"fee rate {fee_rate.sats_per_kvbyte} sat/kvB is below"
                err_msg += " the mempool's minimum"
                err_msg += f" {relay.mempool_min.sats_per_kvbyte}"
                raise BTClibValueError(err_msg)
            return fee_rate
        incremental = (
            _INCREMENTAL_RELAY_FEE_RATE if relay is None else relay.incremental
        )
        # the replaced rate rounded down, as `CFeeRate(old_fee, size)` is
        old_rate = old_fee * 1000 // wtx.tx.vsize
        rate = FeeRate(
            sats_per_kvbyte=old_rate
            + 1
            + max(incremental, _WALLET_INCREMENTAL_FEE_RATE).sats_per_kvbyte
        )
        target = _CONFIRMATION_TARGET if conf_target is None else conf_target
        estimate = self._estimated(target, relay)
        return rate if estimate is None else max(rate, estimate)

    @_relocking
    def bump(
        self,
        txid: bytes,
        fee_rate: FeeRate | None = None,
        *,
        conf_target: int | None = None,
        outputs: Sequence[TxOut] | None = None,
        original_change_index: int | None = None,
        replaceable: bool = True,
    ) -> Tx:
        """Replace a transaction with one paying a higher fee, and broadcast it.

        Core's `bumpfee`: `bump_psbt`'s replacement, signed, recorded and
        broadcast as `spend` does it, with the comments of the transaction
        it replaces. A ledger holding no private key is refused, as Core
        refuses a wallet without them (src/wallet/rpc/spend.cpp:1040-1042
        at bitcoin/bitcoin@f0de87f040, the v32.1 tag): `bump_psbt` is
        its route. The module docstring says how the two are linked.
        """
        if self._broadcaster is None:
            raise BTClibValueError("no broadcaster: the ledger cannot send")
        if not self._encrypted and not any(w.prv_keys for w in self._sources.values()):
            err_msg = "no private key in the ledger: bump_psbt returns the"
            raise BTClibValueError(f"{err_msg} replacement to sign elsewhere")
        bumped = self.bump_psbt(
            txid,
            fee_rate,
            conf_target=conf_target,
            outputs=outputs,
            original_change_index=original_change_index,
            replaceable=replaceable,
        )
        tx = tx_for_network(extract_tx(finalize(self.sign(bumped.psbt))), self.network)
        replaced = self._txs[txid]
        self._commit(
            self._broadcaster, tx, replaced.comment, replaced.comment_to, replaced
        )
        return tx

    def _hand_out_paid(self, txs: Iterable[Tx]) -> None:
        """Hand out each position of the ledger the transactions pay."""
        paid = {
            self._scripts[_script(o)] for tx in txs for o in tx.vout if self._owned(o)
        }
        if new := sorted(paid - self._handed):
            # no address is asked for, as `load` asks none
            self._handed.update(new)
            self._store.add_handed_out(new)
            self._extend_windows()

    # -- abandon and resubmit ---------------------------------------------

    @_relocking
    def abandon(self, txid: bytes) -> None:
        """Abandon an inactive transaction, and its inactive descendants.

        Core's `abandontransaction`: the coins they spend count, and can
        be spent, again. The mark is written to the file. A transaction
        confirmed, conflicted or in the mempool is refused, and an
        abandoned one is left as it is. `txid` is in display order.
        """
        wtx = self._held(txid)
        if wtx.state in (TxState.CONFIRMED, TxState.CONFLICTED, TxState.MEMPOOL):
            err_msg = f"a {wtx.state.value} transaction cannot be abandoned:"
            raise BTClibValueError(f"{err_msg} {txid.hex()}")
        txs = dict(self._txs)
        _abandon(txid, txs)
        self._store.upsert_txs(w for t, w in txs.items() if self._txs[t] != w)
        self._txs = txs

    @_relocking
    def resubmit(self) -> dict[bytes, FetchError]:
        """Broadcast again what is in the mempool or inactive; return refusals.

        Core's `ResubmitWalletTransactions`, run only when the caller
        calls it: each transaction in the mempool or inactive, in the
        order it was recorded. One the broadcaster accepts is in the
        mempool, and hands out what it pays, as `spend` says; where it is
        a bump, the transaction it replaces is inactive, as *Fee bumping*
        in the module docstring says. One it refuses keeps its state
        unless a replacement of it is accepted, and its refusal is
        returned under its id rather than raised, so that one refusal
        does not hold back the others.
        """
        if self._broadcaster is None:
            raise BTClibValueError("no broadcaster: the ledger cannot send")
        refused: dict[bytes, FetchError] = {}
        accepted: list[Tx] = []
        written: dict[bytes, WalletTx] = {}
        for wtx in sorted(self._txs.values(), key=lambda w: w.seq):
            if wtx.state not in (TxState.MEMPOOL, TxState.INACTIVE):
                continue
            try:
                self._broadcaster.broadcast(wtx.tx)
            except FetchError as e:
                refused[wtx.tx.id] = e
                continue
            accepted.append(wtx.tx)
            written[wtx.tx.id] = replace(wtx, state=TxState.MEMPOOL)
            if wtx.replaces is not None:
                replaced = written.get(wtx.replaces) or self._txs.get(wtx.replaces)
                if replaced is not None and replaced.state is TxState.MEMPOOL:
                    written[wtx.replaces] = replace(replaced, state=TxState.INACTIVE)
        self._store.upsert_txs(written.values())
        self._txs.update(written)
        self._hand_out_paid(accepted)
        return refused

    # -- encryption ---------------------------------------------------------

    @_relocking
    def encrypt(self, passphrase: str) -> None:
        """Encrypt the private keys of every source, and lock them.

        Core's `encryptwallet`, which refuses a wallet holding no private
        key, an encrypted wallet and an empty passphrase, in that order
        (src/wallet/rpc/encrypt.cpp:255-275 at bitcoin/bitcoin@f0de87f040,
        the v32.1 tag). A source whose scripts need a private key at every
        index, a hardened ``/*h``, is refused too: a locked ledger could
        not derive them. The keys and the master key are written in one
        SQLite transaction, so a process killed in it leaves the file
        as it was.
        """
        assert_type(passphrase, str, "passphrase")
        keyed = {
            source_id: wallet
            for source_id, wallet in self._sources.items()
            if wallet.prv_keys
        }
        if not keyed and not self._encrypted:
            raise BTClibValueError("no private key in the ledger: nothing to encrypt")
        if self._master_key is not None:
            raise BTClibValueError("the ledger is encrypted already")
        if not passphrase:
            raise BTClibValueError("the passphrase is empty")
        watched = {source_id: _watched(wallet) for source_id, wallet in keyed.items()}
        key = _new_key()
        try:
            master_key = _master_key(passphrase, key)
            encrypted = {
                source_id: _sealed(key, _plaintext(wallet), _aad(source_id))
                for source_id, wallet in keyed.items()
            }
            self._store.encrypt(
                master_key,
                {
                    source_id: (watched[source_id], encrypted[source_id])
                    for source_id in keyed
                },
            )
        finally:
            _wipe(key)
        self._master_key = master_key
        self._encrypted = encrypted
        for source_id, descriptors in watched.items():
            self._sources[source_id] = _wallet(descriptors, self.network, {})

    @_relocking
    def unlock_keys(self, passphrase: str, timeout: int) -> None:
        """Decrypt the keys, and keep them for `timeout` seconds.

        Core's `walletpassphrase`: an unencrypted ledger, a negative
        timeout and an empty passphrase are refused, a timeout above
        `MAX_UNLOCK_TIME` is that, and a call while unlocked sets the
        timeout anew (src/wallet/rpc/encrypt.cpp:48-89). A wrong
        passphrase is refused, and so is a source whose keys the right
        one does not decrypt.
        """
        assert_type(passphrase, str, "passphrase")
        if not is_integer(timeout):
            raise BTClibTypeError(f"invalid timeout type: {type(timeout).__name__}")
        master_key = self._current_master_key()
        if timeout < 0:
            raise BTClibValueError(f"negative timeout: {timeout}")
        timeout = min(timeout, MAX_UNLOCK_TIME)
        if not passphrase:
            raise BTClibValueError("the passphrase is empty")
        key = _unlocked(passphrase, master_key)
        if key is None:
            raise BTClibValueError("the passphrase is wrong")
        try:
            # every source is decrypted once, as Core's `Unlock` checks
            # its keys: a damaged ciphertext is refused here, not at a sign
            for source_id in self._encrypted:
                self._decrypted(key, source_id)
        except BaseException:
            _wipe(key)
            raise
        # the key and the times it locks at are set as one, so that a
        # `lock_keys` in another thread finds both or neither
        with self._key_lock:
            if self._key is not None:
                _wipe(self._key)
            self._key = key
            self._unlocked_until = _now() + timeout
            self._relock_at = _monotonic() + timeout

    @_relocking
    def lock_keys(self) -> None:
        """Lock the keys: zero the master key held. Core's `walletlock`."""
        self._assert_encrypted()
        self._drop_key()

    @_relocking
    def change_passphrase(self, old: str, new: str) -> None:
        """Encrypt the master key under `new`.

        Core's `walletpassphrasechange`: an unencrypted ledger, an empty
        passphrase and a wrong `old` are refused
        (src/wallet/rpc/encrypt.cpp:137-170). A change done leaves the
        ledger locked or unlocked as it was. A change refused past the
        check of an empty passphrase, a wrong `old` among the refusals,
        locks the ledger, as Core's `ChangeWalletPassphrase` locks the
        wallet before it reads `old` (src/wallet/wallet.cpp:653).

        The master key is read from the file at each change and unlock,
        so after another ledger on the file changed the passphrase, the
        new one is asked for here too. A change written over one this
        ledger did not read is refused, and writes nothing.
        """
        assert_type(old, str, "old")
        assert_type(new, str, "new")
        self._assert_encrypted()
        if not old or not new:
            raise BTClibValueError("the passphrase is empty")
        try:
            self._encrypt_master_key(old, new)
        except BaseException:
            self._drop_key()
            raise

    def _encrypt_master_key(self, old: str, new: str) -> None:
        """Write the master key `old` decrypts encrypted under `new`."""
        master_key = self._current_master_key()
        key = _unlocked(old, master_key)
        if key is None:
            raise BTClibValueError("the passphrase is wrong")
        try:
            new_master_key = _master_key(new, key)
        finally:
            _wipe(key)
        self._store.set_master_key(master_key, new_master_key)
        self._master_key = new_master_key

    @property
    @_relocking
    def unlocked_until(self) -> int | None:
        """When the keys lock, in seconds since the epoch.

        Core's `unlocked_until`: 0 while locked, None where the ledger is
        not encrypted. It is wall-clock time, as Core reports it
        (src/wallet/rpc/encrypt.cpp:89 at bitcoin/bitcoin@f0de87f040, the
        v32.1 tag); when the keys lock is decided as the module's *The
        relock* says.
        """
        return None if self._master_key is None else self._unlocked_until

    def _hold_keys(self, source_id: int, source: _Source) -> None:
        """Hold a source's ciphertext read from the file, if it has one.

        A ciphertext with no master key to decrypt it is refused, and so
        are keys in plain text in an encrypted file.
        """
        err_msg = f"not a ledger file: source {source_id}'s keys"
        if source.prv_keys and self._master_key is not None:
            raise BTClibValueError(f"{err_msg} are plain in an encrypted file")
        if source.encrypted is not None:
            if self._master_key is None:
                raise BTClibValueError(f"{err_msg} have no master key")
            self._encrypted[source_id] = source.encrypted

    def _current_master_key(self) -> _MasterKey:
        """Return the master key as the file holds it now.

        Another ledger on the file may have changed the passphrase since
        this one loaded it: the passphrase asked for is the file's.
        """
        self._assert_encrypted()
        master_key = self._store.master_key()
        if master_key is None:
            raise BTClibValueError("not a ledger file: its master key is gone")
        self._master_key = master_key
        return master_key

    def _assert_encrypted(self) -> None:
        """Refuse a ledger not encrypted."""
        if self._master_key is None:
            raise BTClibValueError("the ledger is not encrypted")

    def _assert_unlocked(self) -> bytearray:
        """Return the master key, refusing a locked ledger."""
        self._assert_encrypted()
        if self._key is None:
            raise BTClibValueError(_LOCKED)
        return self._key

    def _relock_if_due(self) -> None:
        """Zero the master key held where its timeout has passed."""
        if self._key is not None and _monotonic() >= self._relock_at:
            self._drop_key()

    def _holds(self, key: bytearray) -> bool:
        """Whether `key` is the master key held, and so was never zeroed.

        `_drop_key` and `unlock_keys` zero a key and let go of it under
        one lock, and a key let go is never held again. So a key held
        when this reads it, under that lock, was whole for anything that
        read it before.
        """
        with self._key_lock:
            return self._key is key

    def _drop_key(self) -> None:
        """Zero the master key held, if any."""
        with self._key_lock:
            if self._key is not None:
                _wipe(self._key)
            self._key = None
            self._unlocked_until = 0
            self._relock_at = 0.0


def _assert_bump_arguments(
    fee_rate: FeeRate | None,
    conf_target: int | None,
    outputs: Sequence[TxOut] | None,
    original_change_index: int | None,
    replaceable: bool,
) -> None:
    """Refuse what `Ledger.bump_psbt` is handed before the ledger is read."""
    assert_type(fee_rate, (FeeRate, type(None)), "fee_rate")
    if conf_target is not None:
        valid_confirmation_target(conf_target)
    if outputs is not None:
        assert_type(outputs, Sequence, "outputs")
        for tx_out in outputs:
            assert_type(tx_out, TxOut, "outputs")
    if original_change_index is not None:
        _assert_height(original_change_index, "original_change_index")
    assert_type(replaceable, bool, "replaceable")
    if fee_rate is not None and conf_target is not None:
        raise BTClibValueError("name a fee rate or a confirmation target, not both")
    if outputs is not None and not outputs:
        raise BTClibValueError("no outputs: name at least one")
    if outputs is not None and original_change_index is not None:
        err_msg = (
            "outputs and original_change_index are incompatible:"
            " name new outputs, or the change output to reuse"
        )
        raise BTClibValueError(err_msg)


def _with_inputs_added(
    inputs: Sequence[PsbtIn],
    added: Sequence[PsbtIn],
    build: Callable[[list[PsbtIn]], FundedPsbt],
) -> FundedPsbt:
    """Return what `build` funds from `inputs` and the first of `added`.

    An input of `added` is taken, in order, only where those taken so far
    fall short.
    """
    spending = list(inputs)
    pending = list(added)
    while True:
        try:
            return build(spending)
        except _ShortfallError as e:
            if not pending:
                err_msg = "the confirmed coins cannot fund the replacement"
                raise BTClibValueError(f"{err_msg}: {e}") from None
            spending.append(pending.pop(0))


def _least_change(script: ScriptPubKey, spend_weight: int) -> int:
    """Return the least change Core's spender creates, subtracting the fee.

    `min_viable_change`, the larger of one satoshi over what spending the
    change costs and the change's dust threshold, both at the discard
    rate (src/wallet/spend.cpp:1187-1192 at bitcoin/bitcoin@f0de87f040,
    the v32.1 tag). The discard rate is `_DISCARD_FEE_RATE`, where Core
    takes the lower of that and its estimate for the longest target it
    tracks, not below the dust relay rate (`GetDiscardRate`,
    src/wallet/fees.cpp:90-100): a `FeeEstimator` answers the target it
    is asked for, and names no longest target.
    """
    spend_fee = fee_from_vsize(ceil(spend_weight / 4), _DISCARD_FEE_RATE)
    return max(spend_fee + 1, dust_threshold(script.script, _DISCARD_FEE_RATE))


def _fee_from_change(
    inputs: Sequence[PsbtIn],
    change: TxOut,
    value: int,
    rate: FeeRate,
    new_script: ScriptPubKey,
    least_change: int,
) -> FundedPsbt:
    """Return the psbt paying `value` to `change`'s script, less the fee.

    Core's bump where every output is change: one recipient, `value`,
    with its fee subtracted (src/wallet/feebumper.cpp:267-279 at
    bitcoin/bitcoin@f0de87f040, the v32.1 tag). It is output 0. What the
    inputs hold over `value` is new change, output 1, where it is at
    least `least_change`, as `SelectionResult::GetChange` makes it
    (src/wallet/coinselection.cpp:1043-1060). Otherwise it is fee, and
    counts toward what the rate asks: the recipient pays only the rest,
    as `CreateTransactionInternal` reduces it (src/wallet/spend.cpp:
    1356-1385). An amount left under the dust threshold is refused, as
    Core refuses it.
    """
    # psbts at no fee rate: the fee of each is what the inputs hold over
    # its outputs, and a shortfall is refused by the first. They have no
    # fee ceiling: what the first holds over may be change, and the fee
    # this returns is checked against the ceilings below
    no_rate = FeeRate(sats_per_kvbyte=0)
    outputs = [TxOut(value, change.script_pub_key)]
    probe = _probe(inputs, outputs, no_rate)
    if probe.fee >= least_change:
        outputs.append(TxOut(probe.fee, new_script))
        probe = _probe(inputs, outputs, no_rate)
    psbt = probe.psbt
    vsize = psbt.vsize_estimate(miniscript_sizer)
    fee = fee_from_vsize(vsize, rate)
    amount = value - (fee - probe.fee)
    if amount < dust_threshold(_script(change)):
        reason = "to pay the fee" if amount < 0 else "to send after the fee"
        err_msg = f"the amount, {value} satoshi, is too small {reason}, {fee}"
        raise BTClibValueError(err_msg)
    _assert_fee_within(fee, vsize, DEFAULT_MAX_FEE, DEFAULT_MAX_FEE_RATE)
    psbt.outputs[0].amount = amount
    psbt.assert_valid()
    return FundedPsbt(psbt, fee, 1 if len(outputs) > 1 else None)


def _probe(
    inputs: Sequence[PsbtIn], outputs: list[TxOut], no_rate: FeeRate
) -> FundedPsbt:
    """Return `build_psbt`'s psbt at `no_rate`, with no change and no ceiling.

    Its ceilings are Core's `MAX_MONEY` (src/consensus/amount.h:26 at
    bitcoin/bitcoin@f0de87f040, the v32.1 tag), which no fee exceeds,
    and that much per virtual byte.
    """
    return build_psbt(
        list(inputs),
        outputs,
        no_rate,
        None,
        sizer=miniscript_sizer,
        max_fee=_MAX_MONEY,
        max_fee_rate=FeeRate(sats_per_kvbyte=_MAX_MONEY * 1000),
    )


def _assert_replaces(old_fee: int, fee: int, vsize: int, incremental: FeeRate) -> None:
    """Refuse a replacement the node refuses for its fee.

    BIP125's rules 3 and 4, as Core's `PaysForRBF` checks them
    (src/policy/rbf.cpp:100-125 at bitcoin/bitcoin@f0de87f040, the v32.1
    tag): the fee is at least the replaced one's plus the incremental
    rate over the replacement's virtual size.
    """
    least = old_fee + fee_from_vsize(vsize, incremental)
    if fee < least:
        err_msg = f"insufficient total fee {fee} satoshi, must be at least {least}"
        err_msg += f" (old fee {old_fee} + incremental fee {least - old_fee})"
        raise BTClibValueError(err_msg)


def _now() -> int:
    """Return the time, in seconds since the epoch."""
    return int(time.time())


def _monotonic() -> float:
    """Return the monotonic clock, in seconds."""
    return time.monotonic()


def _aad(source_id: int) -> bytes:
    """Return the associated data of a source's ciphertext."""
    return f"btclib-wallet ledger source {source_id}".encode()


def _wallet(
    descriptors: Mapping[int, str], network: str, prv_keys: Mapping[str, str]
) -> DescriptorWallet:
    """Return the wallet of a source's descriptors and keys."""
    keys = dict(prv_keys)
    return DescriptorWallet(
        {branch: parse(text, network, keys) for branch, text in descriptors.items()},
        keys or None,
    )


def _watched(wallet: DescriptorWallet) -> dict[int, str]:
    """Return the descriptors of a wallet that derive with no private key.

    `descriptors.normalized`, refused where a script still needs one:
    each branch's first is derived with no key.
    """
    watched = {
        branch: normalized(wallet.descriptor(branch), wallet.prv_keys)
        for branch in wallet.branches
    }
    try:
        for descriptor in watched.values():
            DescriptorWallet(descriptor)
    except BTClibValueError:
        err_msg = "a descriptor needs a private key at every index:"
        raise BTClibValueError(f"{err_msg} a locked ledger cannot watch it") from None
    return {branch: str(descriptor) for branch, descriptor in watched.items()}


def _plaintext(wallet: DescriptorWallet) -> bytes:
    """Return what a source's ciphertext encrypts: its descriptors and keys."""
    return json.dumps(
        {
            "descriptors": {
                str(branch): str(wallet.descriptor(branch))
                for branch in wallet.branches
            },
            "prv_keys": dict(wallet.prv_keys or {}),
        }
    ).encode()


def _script(tx_out: TxOut) -> bytes:
    return tx_out.script_pub_key.script


def _assert_label(label: str) -> None:
    """Refuse what is not a label, and the name `*`."""
    if not isinstance(label, str):
        raise BTClibTypeError(f"invalid label type: {type(label).__name__}")
    if label == "*":
        raise BTClibValueError("invalid label name: *")


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

    A transaction confirmed in one of them, or conflicted by one, is
    inactive until the answers say where it is now; a coinbase is
    abandoned, as Core's `blockDisconnected` leaves it, since it can be
    in no mempool.
    """
    txs = dict(txs)
    if fork_height is None:
        return txs, dict(blocks)
    for txid, wtx in txs.items():
        if wtx.block is not None and wtx.block.height > fork_height:
            state = TxState.ABANDONED if wtx.tx.is_coinbase else TxState.INACTIVE
            txs[txid] = replace(wtx, state=state, block=None)
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


def _mark_conflicts(txs: dict[bytes, WalletTx]) -> None:
    """Mark conflicted each transaction a block conflicts with.

    A transaction in no block is conflicted with the lowest block holding
    a transaction that spends one of its inputs, or that one of its
    parents is conflicted with. Parents are marked first, so that a child
    finds them marked. Nothing here clears a conflict: `_disconnected`
    does, when the block goes.
    """
    spent_in: dict[OutPoint, BlockRef] = {}
    for wtx in txs.values():
        if (
            wtx.state is TxState.CONFIRMED
            and wtx.block is not None
            and not wtx.tx.is_coinbase
        ):
            for tx_in in wtx.tx.vin:
                spent_in[tx_in.prev_out] = wtx.block
    unconfirmed = {
        txid: wtx.tx for txid, wtx in txs.items() if wtx.state is not TxState.CONFIRMED
    }
    for tx in _parents_first(unconfirmed):
        if blocks := [
            block
            for tx_in in tx.vin
            for block in (
                spent_in.get(tx_in.prev_out),
                _conflicting_block(txs.get(tx_in.prev_out.tx_id)),
            )
            if block is not None
        ]:
            block = min(blocks, key=lambda b: b.height)
            txs[tx.id] = replace(txs[tx.id], state=TxState.CONFLICTED, block=block)


def _conflicting_block(wtx: WalletTx | None) -> BlockRef | None:
    """Return the block a transaction is conflicted with, None if none."""
    if wtx is None or wtx.state is not TxState.CONFLICTED:
        return None
    return wtx.block


def _abandon(txid: bytes, txs: dict[bytes, WalletTx]) -> None:
    """Mark a transaction abandoned, and its descendants.

    As Core's `RecursiveUpdateTxState` walks them: the walk marks an
    inactive transaction and goes on to its children, and stops at any
    other.
    """
    children: dict[bytes, list[bytes]] = {}
    for child_id, child in txs.items():
        for tx_in in child.tx.vin:
            children.setdefault(tx_in.prev_out.tx_id, []).append(child_id)
    todo = [txid]
    while todo:
        wtx = txs[todo.pop()]
        if wtx.state is TxState.INACTIVE:
            txs[wtx.tx.id] = replace(wtx, state=TxState.ABANDONED)
            todo.extend(children.get(wtx.tx.id, ()))


def _how_spent(spenders: Sequence[WalletTx]) -> TxState | None:
    """Core's `HowSpent`: the strongest state of the spenders, None if none.

    An abandoned or a conflicted spender counts as none.
    """
    states = {wtx.state for wtx in spenders}
    return next(
        (
            state
            for state in (TxState.CONFIRMED, TxState.MEMPOOL, TxState.INACTIVE)
            if state in states
        ),
        None,
    )


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
