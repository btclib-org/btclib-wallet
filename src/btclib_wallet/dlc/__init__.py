# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Discreet log contracts: the transactions and signatures of a DLC.

https://github.com/discreetlogcontracts/dlcspecs

`transactions` and `signing` make it up:

- `transactions` is the funding transaction, the contract execution
  transactions (CETs) and the refund transaction, built from the terms
  two parties agree on, with the fee each of them pays;
- `signing`, which imports it, is the adaptor signatures that make a CET
  spendable by whoever holds the oracle's attestation, the signature of
  the refund, and the witnesses that complete each transaction.

The flat surface is this package's: the names are read off
`btclib_wallet.dlc`, the modules being where they are written.
"""

from btclib_wallet.dlc.signing import (
    adaptor_sign,
    complete_cet,
    complete_funding_tx,
    complete_spend,
    sig_hash,
    sign,
    verify_adaptor,
)
from btclib_wallet.dlc.transactions import (
    CET_SEQUENCE,
    DUST_LIMIT,
    Dlc,
    DlcParty,
    DlcTransactions,
    FundingInput,
    build_cet,
    build_funding_tx,
    build_refund_tx,
    build_transactions,
    closing_fee,
    funding_fee,
    funding_script,
    funding_script_pub_key,
)

__all__ = [
    "CET_SEQUENCE",
    "DUST_LIMIT",
    "Dlc",
    "DlcParty",
    "DlcTransactions",
    "FundingInput",
    "adaptor_sign",
    "build_cet",
    "build_funding_tx",
    "build_refund_tx",
    "build_transactions",
    "closing_fee",
    "complete_cet",
    "complete_funding_tx",
    "complete_spend",
    "funding_fee",
    "funding_script",
    "funding_script_pub_key",
    "sig_hash",
    "sign",
    "verify_adaptor",
]
