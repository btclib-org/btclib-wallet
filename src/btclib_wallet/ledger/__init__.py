# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The ledger: descriptor wallets, their transactions and coins, and a file.

What `wallet`'s wallets leave out -- the transactions, the coins, the
balances, a spender and a file that outlives the process -- is here,
one layer above them and above `fetch`:

- `ledger` is `Ledger`, which holds a set of descriptor wallets, syncs
  them from a `HistoryReader` when its caller calls `sync`, answers Bitcoin
  Core's wallet questions of them, and spends from them;
- `records` is what it answers in;
- `store` is its SQLite file and how the file says what it is;
- `crypto` is what its private keys are encrypted with.
"""

from btclib_wallet.ledger.ledger import LOOKAHEAD, MAX_UNLOCK_TIME, Ledger
from btclib_wallet.ledger.records import (
    Balances,
    GroupedAddress,
    SyncResult,
    TxDetail,
    TxInfo,
    TxState,
    Utxo,
    WalletTx,
)
from btclib_wallet.ledger.store import APPLICATION_ID, FORMAT_VERSION

__all__ = [
    "APPLICATION_ID",
    "FORMAT_VERSION",
    "LOOKAHEAD",
    "MAX_UNLOCK_TIME",
    "Balances",
    "GroupedAddress",
    "Ledger",
    "SyncResult",
    "TxDetail",
    "TxInfo",
    "TxState",
    "Utxo",
    "WalletTx",
]
