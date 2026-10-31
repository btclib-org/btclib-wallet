# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The master keys of an Electrum mnemonic.

The sentence, its version and its seed are `bip39_slip39.electrum`'s.
What is here is what Electrum derives from them: the BIP32 master key a
versioned mnemonic names, and the master public key of a pre-2.0 one.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import bip39_slip39.electrum
from btclib.exceptions import BTClibValueError
from btclib.network import network_from_name
from ecc.curves.curve import mult, secp256k1
from ecc.curves.sec_point import bytes_from_point, scalar_from_prv_key

from btclib_wallet.bip32 import derive, rootxprv_from_seed
from btclib_wallet.bip32.der_path import HARDENED_OFFSET

# under TYPE_CHECKING, so that the alias annotates the signatures below
# without this module binding a name of bip39_slip39's
if TYPE_CHECKING:
    from bip39_slip39.mnemonic import Mnemonic

__all__ = [
    "mxprv_from_mnemonic",
    "old_master_pub_key_from_mnemonic",
]


def mxprv_from_mnemonic(
    mnemonic: Mnemonic, passphrase: str | None = None, network: str = "mainnet"
) -> str:
    """Return BIP32 master extended private key from Electrum mnemonic.

    The derivation path is "m" for a "standard" mnemonic and "m/0h"
    for a "segwit" one. The version is
    `bip39_slip39.electrum.version_from_mnemonic`'s and the seed
    `bip39_slip39.electrum.seed_from_mnemonic`'s, None being the empty
    passphrase; a refusal of either leaves as `bip39_slip39`'s own class.
    """
    version, _ = bip39_slip39.electrum.version_from_mnemonic(mnemonic)
    if version not in {"standard", "segwit"}:
        err_msg = f"unmanaged electrum mnemonic version: {version}"
        if version == "old":
            # the pre-2.0 scheme has no BIP32 master key to return: its keys
            # hang off the master public key by an addition of its own, not
            # by a chain code, so there is no xprv this could answer with
            err_msg += "; use old_master_pub_key_from_mnemonic"
        raise BTClibValueError(err_msg)

    passphrase = "" if passphrase is None else passphrase
    seed = bip39_slip39.electrum.seed_from_mnemonic(mnemonic, passphrase)
    if version == "standard":
        xversion = network_from_name(network).bip32_prv
        return rootxprv_from_seed(seed, xversion)
    xversion = network_from_name(network).slip132_p2wpkh_prv
    rootxprv = rootxprv_from_seed(seed, xversion)
    return derive(rootxprv, HARDENED_OFFSET)  # "m/0h"


def old_master_pub_key_from_mnemonic(
    mnemonic: Mnemonic, passphrase: str | None = None
) -> str:
    """Return the pre-2.0 Electrum master public key, as Electrum writes it.

    Electrum's Old_KeyStore.mpk_from_seed: the uncompressed SEC point of
    the stretched key with its 04 prefix cut off, so 128 hex characters
    of x and then y. That string is what a pre-2.0 wallet file holds
    under "master_public_key", which is what makes it the value a vector
    can be taken from. The stretched key is
    `bip39_slip39.electrum.old_master_prv_key_from_mnemonic`'s, which
    refuses a passphrase: the pre-2.0 scheme has none.
    """
    prv_key = bip39_slip39.electrum.old_master_prv_key_from_mnemonic(
        mnemonic, passphrase
    )
    # scalar_from_prv_key and not mult alone: mult reduces the scalar mod n
    # and would answer for a stretch that landed outside 1..n-1, where
    # electrum's ECPrivkey raises. A 2**-128 disagreement, and refusing
    # is the side that costs nothing
    point = mult(scalar_from_prv_key(prv_key, secp256k1), secp256k1.G, secp256k1)
    return bytes_from_point(point, secp256k1, compressed=False)[1:].hex()
