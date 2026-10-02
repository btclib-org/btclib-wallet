# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The BIP32 master key of a BIP39 mnemonic.

https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki.

The sentence, its entropy and its seed are `btclib_mnemonics.bip39`'s;
what is here is the step BIP39 hands to BIP32, the seed becoming a root
extended private key.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import btclib_mnemonics.bip39
from btclib.network import network_from_name

from btclib_wallet.bip32 import rootxprv_from_seed

# under TYPE_CHECKING, so that the alias annotates the signatures below
# without this module binding a name of btclib_mnemonics'
if TYPE_CHECKING:
    from btclib_mnemonics.mnemonic import Mnemonic

__all__ = [
    "mxprv_from_mnemonic",
]


def mxprv_from_mnemonic(
    mnemonic: Mnemonic,
    passphrase: str | None = None,
    network: str = "mainnet",
    verify_checksum: bool = True,
) -> str:
    """Return BIP32 root master extended private key from BIP39 mnemonic.

    The seed is `btclib_mnemonics.bip39.seed_from_mnemonic`'s, None being
    the empty passphrase, and a refusal of that function's leaves as
    `btclib_mnemonics`' own class.
    """
    passphrase = "" if passphrase is None else passphrase
    seed = btclib_mnemonics.bip39.seed_from_mnemonic(
        mnemonic, passphrase, verify_checksum
    )
    version = network_from_name(network).bip32_prv
    return rootxprv_from_seed(seed, version)
