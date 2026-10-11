# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Discreet log contracts: transactions, signatures and oracle data.

https://github.com/discreetlogcontracts/dlcspecs

`oracle`, `transactions` and `signing` are the modules: each says what it
holds.

The flat surface is this package's: the names are read off
`btclib_wallet.dlc`, the modules being where they are written.
"""

from btclib_wallet.dlc.oracle import (
    PLAIN_SHA256,
    TAGGED,
    DigitDecompositionEventDescriptor,
    EnumEventDescriptor,
    OracleAnnouncement,
    OracleAttestation,
    OracleEvent,
    outcome_message,
    sign_announcement,
    sign_attestation,
    verify_announcement,
    verify_attestation,
)
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
    "PLAIN_SHA256",
    "TAGGED",
    "DigitDecompositionEventDescriptor",
    "Dlc",
    "DlcParty",
    "DlcTransactions",
    "EnumEventDescriptor",
    "FundingInput",
    "OracleAnnouncement",
    "OracleAttestation",
    "OracleEvent",
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
    "outcome_message",
    "sig_hash",
    "sign",
    "sign_announcement",
    "sign_attestation",
    "verify_adaptor",
    "verify_announcement",
    "verify_attestation",
]
