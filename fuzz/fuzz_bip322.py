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

A crash here on hostile bytes is a defect in `b64decode` itself, never in
this harness: `data` is unconstrained bytes handed straight to it, the
`String` it takes being bytes as readily as text, and the ascii decode
inside it answering a byte outside ascii with the library's own
exception. `BTClibException` is what it answers a bad armor and a
malformed payload alike with, so that family is caught below as the
expected outcome. An `IndexError`, a `RecursionError` or an uncaught
assertion is not, and propagates to atheris as the finding it is.

The seed corpus is one signature per prefix `b64decode` dispatches on,
taken from the vendored `tests/_data/generated-test-vectors.json`:
`smp`, `ful` and `pof`. The `pof` seed reaches `Psbt.parse`, this
tree's own decoder and `fuzz_psbt.py`'s subject; `smp` and `ful` reach
`Witness.parse` and `Tx.parse`, which stay btclib's. The legacy variant
is not among the seeds, being `ecc.bms`'s compact signature rather than
anything this method decodes.
"""

from __future__ import annotations

import contextlib
import sys

import atheris
from btclib.exceptions import BTClibException

from btclib_wallet.bip322 import Sig

# tests/fuzz_corpus_test.py reads this by ast.literal_eval, never by
# importing the module -- atheris below is CI-only and undeclared in
# pyproject.toml, so the test must not execute this file
ENTRY_POINTS = ("btclib_wallet.bip322:Sig.b64decode",)


def fuzz_target(data: bytes) -> None:
    """Parse `data` as the base64 armor of a BIP322 signature.

    `BTClibException` is swallowed as `b64decode`'s own refusal of
    malformed input; any other exception propagates, which is how
    atheris tells a defect in `b64decode` from the domain of input it
    already rejects.
    """
    with contextlib.suppress(BTClibException):
        Sig.b64decode(data)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
