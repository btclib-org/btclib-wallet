# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing the two BIP32 wire decoders.

`btclib_wallet.bip32.bip32.BIP32KeyData` is an xprv or xpub, pasted by a
watch-only wallet's user or read out of a device; `.parse` is its 78
raw octets and `.b58decode` is the Base58Check text an xprv or xpub is
ordinarily spelled as, both decoding the same fixed-width record.
`btclib_wallet.bip32.key_origin.BIP32KeyOrigin` is the smaller record a
psbt's `bip32_derivs` field and a descriptor's `[fingerprint/path]`
prefix carry: a four-octet master fingerprint and a derivation path of
4-octet indexes. All three are wire records handed over by a
counterparty rather than computed locally, which is what this harness
is for.

`String`, which `.b58decode` and `bip322.Sig.b64decode` alike take,
already admits bytes -- `str | bytes | bytearray | memoryview` -- so
`data` reaches `.b58decode` unmodified rather than through a decode step
`.parse` and `.b64decode` elsewhere in this tree do not need either.

A crash on hostile bytes is a defect in one of the three decoders,
never in this harness: `data` is unconstrained bytes handed straight to
each entry point. `BTClibException` is what all three answer a
truncated, non-canonical or wrong-length record with, so that family is
caught below as the expected outcome. An `IndexError`, a
`RecursionError` or an uncaught assertion is not, and propagates to
atheris as the finding it is.

The seed corpus is BIP32's own first test vector's master extended
key, in both spellings and both decoders' native shape -- the xprv and
the xpub text, and the xpub's own 78 raw octets -- plus one
`BIP32KeyOrigin` serialized from a synthetic fingerprint and a
three-level hardened path.
"""

from __future__ import annotations

import contextlib
import sys

import atheris
from btclib.exceptions import BTClibException

from btclib_wallet.bip32.bip32 import BIP32KeyData
from btclib_wallet.bip32.key_origin import BIP32KeyOrigin

# tests/fuzz_corpus_test.py reads this by ast.literal_eval, never by
# importing the module -- atheris below is CI-only and undeclared in
# pyproject.toml, so the test must not execute this file
ENTRY_POINTS = (
    "btclib_wallet.bip32.bip32:BIP32KeyData.parse",
    "btclib_wallet.bip32.bip32:BIP32KeyData.b58decode",
    "btclib_wallet.bip32.key_origin:BIP32KeyOrigin.parse",
)


def fuzz_target(data: bytes) -> None:
    """Parse `data` as an extended key, its text spelling, and a key origin.

    `BTClibException` is swallowed as each entry point's own refusal of
    malformed input; any other exception propagates, which is how atheris
    tells a defect in one of the three from the domain of input each
    already rejects.
    """
    with contextlib.suppress(BTClibException):
        BIP32KeyData.parse(data)
    with contextlib.suppress(BTClibException):
        BIP32KeyData.b58decode(data)
    with contextlib.suppress(BTClibException):
        BIP32KeyOrigin.parse(data)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
