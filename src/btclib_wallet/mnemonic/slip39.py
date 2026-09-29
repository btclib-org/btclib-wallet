# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The BIP32 master key of a set of SLIP-0039 shares.

https://github.com/satoshilabs/slips/blob/master/slip-0039.md.

The shares and the master secret they recover are
`btclib_mnemonics.slip39`'s. SLIP-0039 backs up the BIP32 seed itself,
so the master secret is handed straight to ``rootxprv_from_seed``.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

import btclib_mnemonics.slip39
from btclib.network import network_from_name

from btclib_wallet.bip32 import rootxprv_from_seed

# under TYPE_CHECKING, so that the alias annotates the signatures below
# without this module binding a name of btclib_mnemonics'
if TYPE_CHECKING:
    from btclib_mnemonics.mnemonic import Mnemonic

__all__ = [
    "mxprv_from_mnemonics",
]


def mxprv_from_mnemonics(
    mnemonics: Sequence[Mnemonic],
    passphrase: str | None = None,
    network: str = "mainnet",
) -> str:
    """Return BIP32 root master extended private key from SLIP-0039 shares.

    The master secret is the BIP32 seed, so there is no stretching step
    between the two: SLIP-0039 backs up the seed itself.

    None is the empty passphrase; any other value is handed on to be
    checked, so a falsy one of another type is refused rather than read
    as the empty passphrase. A refusal of
    `btclib_mnemonics.slip39.master_secret_from_mnemonics` leaves as
    `btclib_mnemonics`' own class.
    """
    passphrase = "" if passphrase is None else passphrase
    seed = btclib_mnemonics.slip39.master_secret_from_mnemonics(mnemonics, passphrase)
    version = network_from_name(network).bip32_prv
    return rootxprv_from_seed(seed, version)
