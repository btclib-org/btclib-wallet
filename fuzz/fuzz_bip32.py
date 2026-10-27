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

A crash on hostile bytes is a defect in one of the three decoders or in
what reads their answer, never in this harness: `data` is unconstrained
bytes handed straight to each entry point. `BTClibException` and
`EccException` are what all three answer a truncated, non-canonical or
wrong-length record with, so that family is caught below as the expected
outcome. An `IndexError`, a `RecursionError` or an uncaught assertion is
not, and propagates to atheris as the finding it is.

The seed corpus is BIP32's own first test vector's master extended
key, in both spellings and both decoders' native shape -- the xprv and
the xpub text, and the xpub's own 78 raw octets -- plus one
`BIP32KeyOrigin` serialized from a synthetic fingerprint and a
three-level hardened path.

**What a decoder accepts is then written back.** The octets each decoder
reads have one encoding, so what it accepts must write back to `data`
itself: `serialize` for the 78 octets and the key origin, `b58encode` for
the text. `.b58decode` strips ASCII whitespace from a `str` and from no
bytes, and `data` is bytes. Each key then derives its child at index 0
through `derive_`, and a private key also gives its public one through
`xpub_from_xprv_`. Those two may refuse with the same two families, as
`derive_` does at depth 255; any other exception propagates, and so does an
exception from writing the key back. A different write raises
`AssertionError`.
"""

from __future__ import annotations

import contextlib
import sys

import atheris
from btclib.exceptions import BTClibException
from ecc.exceptions import EccException

from btclib_wallet.bip32.bip32 import BIP32KeyData, derive_, xpub_from_xprv_
from btclib_wallet.bip32.key_origin import BIP32KeyOrigin

# tests/fuzz_corpus_test.py reads this by ast.literal_eval. It also loads
# this module with a placeholder for the CI-only atheris, so the corpus
# runs the very assertions the fuzz target runs.
ENTRY_POINTS = (
    "btclib_wallet.bip32.bip32:BIP32KeyData.parse",
    "btclib_wallet.bip32.bip32:BIP32KeyData.b58decode",
    "btclib_wallet.bip32.key_origin:BIP32KeyOrigin.parse",
)


def _use_key(key: BIP32KeyData) -> None:
    """Derive a child of `key`, and its public key where it is private."""
    with contextlib.suppress(BTClibException, EccException):
        derive_(key, 0)
    if key.is_private:
        with contextlib.suppress(BTClibException, EccException):
            xpub_from_xprv_(key)


def fuzz_target(data: bytes) -> None:
    """Parse `data` as an extended key, its text spelling, and a key origin.

    A `BTClibException` or `EccException` from a decoder is its refusal
    of malformed input and is swallowed; the module docstring says what
    is checked after an input is accepted.
    """
    try:
        key = BIP32KeyData.parse(data)
    except (BTClibException, EccException):
        pass
    else:
        if key.serialize() != data:
            raise AssertionError("extended key does not serialize back to its input")
        _use_key(key)
    try:
        key = BIP32KeyData.b58decode(data)
    except (BTClibException, EccException):
        pass
    else:
        if key.b58encode().encode("ascii") != data:
            raise AssertionError("extended key does not encode back to its input")
        _use_key(key)
    try:
        origin = BIP32KeyOrigin.parse(data)
    except (BTClibException, EccException):
        return
    if origin.serialize() != data:
        raise AssertionError("key origin does not serialize back to its input")


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
