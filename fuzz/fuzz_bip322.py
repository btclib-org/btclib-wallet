# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib_wallet.bip322.Sig.b64decode`.

A BIP322 signature is pasted by whoever claims to have made it, and
`b64decode` is what a verifier runs on it first: the three-character
prefix picks which of three unrelated serializations follows -- a
witness stack, a whole transaction, or a psbt -- and the base64 behind
it is decoded and handed to that payload's own parser before anything
is verified. Reading the signature is therefore ahead of judging it,
which is what puts it here rather than beside `verify`.

A crash here on hostile bytes is a defect in `b64decode` or `b64encode`,
never in this harness: `data` is unconstrained bytes handed straight to
it, the `String` it takes being bytes as readily as text, and the ascii
decode inside it answering a byte outside ascii with the library's own
exception. `BTClibException` and `EccException` are what it answers a
bad armor and a malformed payload alike with, so that family is caught
below as the expected outcome. An `IndexError`, a `RecursionError` or an
uncaught assertion is not, and propagates to atheris as the finding it
is.

The seed corpus is one signature per prefix `b64decode` dispatches on,
taken from the vendored `tests/_data/generated-test-vectors.json`:
`smp`, `ful` and `pof`. The `pof` seed reaches `Psbt.parse`, this
tree's own decoder and `fuzz_psbt.py`'s subject; `smp` and `ful` reach
`Witness.parse` and `Tx.parse`, which stay btclib's. The legacy variant
is not among the seeds, being `ecc.bms`'s compact signature rather than
anything this method decodes.

**What `b64decode` accepts is then written back.** A signature has more
than one spelling: ASCII whitespace around it is stripped, a simple one
may come without its prefix, and a proof of funds may hold its map
records in any order. So the check is a fixed point rather than `data`
itself: the text `b64encode` writes decodes to a signature that writes
the same text. An exception from `b64encode`, or from decoding what it
wrote, propagates, and a different text raises `AssertionError`.
"""

from __future__ import annotations

import sys

import atheris
from btclib.exceptions import BTClibException
from ecc.exceptions import EccException

from btclib_wallet.bip322 import Sig

# tests/fuzz_corpus_test.py reads this by ast.literal_eval. It also loads
# this module with a placeholder for the CI-only atheris, so the corpus
# runs the very assertions the fuzz target runs.
ENTRY_POINTS = ("btclib_wallet.bip322:Sig.b64decode",)


def fuzz_target(data: bytes) -> None:
    """Parse `data` as the base64 armor of a BIP322 signature.

    A `BTClibException` or `EccException` from `b64decode` is its refusal
    of malformed input and is swallowed; the module docstring says what
    is checked after an input is accepted.
    """
    try:
        sig = Sig.b64decode(data)
    except (BTClibException, EccException):
        return
    armored = sig.b64encode()
    if Sig.b64decode(armored).b64encode() != armored:
        raise AssertionError("signature armor is not a fixed point")


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
