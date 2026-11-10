# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What a `Ledger` holds and answers, one frozen record each.

`TxState` is the state Bitcoin Core gives a wallet transaction
(src/wallet/transaction.h:33-81 at bitcoin/bitcoin@f0de87f040, the v32.1
tag), with the abandoned flag of Core's inactive state as a state of its
own.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from btclib.tx import OutPoint, Tx, TxOut

from btclib_wallet.fetch.history import BlockRef

__all__ = [
    "Balances",
    "SyncResult",
    "TxDetail",
    "TxInfo",
    "TxState",
    "Utxo",
    "WalletTx",
]


class TxState(Enum):
    """Where a wallet transaction is.

    `INACTIVE` is a transaction neither in a block of the chain nor in
    the last mempool read: one the mempool replaced, refused or evicted,
    or one a reorganization took out of a block and the mempool did not
    take back. It is kept, not dropped. `ABANDONED` is an inactive
    transaction its caller abandoned, or a descendant of one
    (`Ledger.abandon`), or a coinbase a reorganization took out of its
    block. `CONFLICTED` is a transaction that a transaction
    in a block conflicts with, by spending one of its inputs or an input
    of one of its ancestors.
    """

    CONFIRMED = "confirmed"
    MEMPOOL = "mempool"
    INACTIVE = "inactive"
    ABANDONED = "abandoned"
    CONFLICTED = "conflicted"


@dataclass(frozen=True)
class WalletTx:
    """A transaction the ledger holds, its state, and its order.

    `block` is the block that confirms it where `state` is `CONFIRMED`,
    the block that conflicts with it where `state` is `CONFLICTED`, and
    `None` otherwise. `seq` is the order the ledger first recorded it in.
    """

    tx: Tx
    state: TxState
    block: BlockRef | None
    seq: int


@dataclass(frozen=True)
class Balances:
    """Core's balance buckets, in satoshi, as `getbalances` reports them.

    `nonmempool` is negative: the coins counted in another bucket that a
    wallet transaction outside the mempool spends.
    """

    trusted: int
    untrusted_pending: int
    immature: int
    nonmempool: int


@dataclass(frozen=True)
class Utxo:
    """An unspent output of the ledger, as `listunspent` reports it.

    `safe` is Core's: the transaction is trusted. `source`, `branch` and
    `index` are the position of the source that pays to the output.
    """

    outpoint: OutPoint
    tx_out: TxOut
    confirmations: int
    safe: bool
    source: int
    branch: int
    index: int


@dataclass(frozen=True)
class TxDetail:
    """One line of `gettransaction`'s details.

    `category` is Core's: `send` for an output paid to someone else by a
    transaction spending the ledger's coins, and for an output the ledger
    receives `receive`, or for a coinbase `immature`, `generate` or
    `orphan`. `amount` is negative for `send`.
    """

    category: str
    vout: int
    amount: int


@dataclass(frozen=True)
class TxInfo:
    """What `gettransaction` reports of a wallet transaction, in satoshi.

    `amount` is what the transaction adds to the ledger with its fee
    left out, as Core's `amount` leaves it; a coinbase adds nothing until
    it matures, and an orphaned one, in no block, nothing at all. Its
    `details` still list what it pays. `fee` is what it pays, and
    `None` unless it spends one of the ledger's coins. `confirmations`
    is 0 for a transaction in no block, and minus the depth of the
    conflicting block for a conflicted one. `wallet_conflicts` is Core's
    `walletconflicts`: the ids of the other transactions of the ledger
    that spend one of its inputs, whatever their state.
    """

    wallet_tx: WalletTx
    amount: int
    fee: int | None
    confirmations: int
    trusted: bool
    details: tuple[TxDetail, ...]
    wallet_conflicts: frozenset[bytes]


@dataclass(frozen=True)
class SyncResult:
    """What one `Ledger.sync` did.

    `tip` is the block the ledger is synced to. `fork_height` is the
    height of the last block the ledger held that is still on the chain
    where a reorganization replaced the blocks above it, and `None`
    where none did. It is -1 where no block the ledger held below its tip
    is still on the chain, as where the backend now follows another
    chain: the ledger then asked from height 0, and every block it held
    was disconnected. `changed` holds the id of every transaction that
    entered the ledger, left it, or changed state or block.
    """

    tip: BlockRef
    fork_height: int | None
    changed: frozenset[bytes]
