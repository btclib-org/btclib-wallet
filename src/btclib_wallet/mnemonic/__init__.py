# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Module btclib_wallet.mnemonic.

The master key of a BIP39, SLIP39 or Electrum mnemonic, one module per
scheme. The schemes themselves -- entropy, sentence and seed -- are
`btclib_mnemonics`', and what is here is where a seed meets BIP32:
`bip39.mxprv_from_mnemonic`, `slip39.mxprv_from_mnemonics`,
`electrum.mxprv_from_mnemonic` and
`electrum.old_master_pub_key_from_mnemonic`.

The modules are named here because none is exported by importing
the package alone: `import btclib_wallet.mnemonic` followed by
`btclib_wallet.mnemonic.bip39.mxprv_from_mnemonic(...)` raises
AttributeError until something else in the process happens to import the
submodule.
"""

from btclib_wallet.mnemonic import bip39, electrum, slip39

__all__ = [
    "bip39",
    "electrum",
    "slip39",
]
