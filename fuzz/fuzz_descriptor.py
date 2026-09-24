# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib_wallet.descriptors.descriptors.parse`.

An output descriptor is what a wallet is handed to watch somebody else's
keys: it arrives in a file, in an rpc argument or pasted, and parsing it
builds a tree of nested function calls, key expressions and derivation
paths out of text nobody signed. That is a recursive grammar over a
stranger's own input, which is what this harness is for. `parse` reads a
key expression's extended key through `key_expression.py`'s own call to
`BIP32KeyData.b58decode`, and a `wsh(...)` or `tr(...)` script through
`miniscript.parse`, so a corpus of real descriptors drives both readers
too; each also has its own direct entry point in the Hypothesis property
suite, `tests/fuzz_test.py`.

**A descriptor is text, so the octets are decoded here and the decode is
total.** `errors="replace"` is what makes it so: no input is filtered out
before `parse` sees it, and octets that are not utf-8 arrive as the
replacement character, which is outside BIP380's INPUT_CHARSET and
refused as any other character outside it would be. A decode that could
raise would make the harness answer for the decoder rather than for the
parser.

A crash on hostile text is a defect in `parse` itself, never in this
harness: nothing validates or normalizes between the decode and the call.
`BTClibException` is what `parse` answers a character outside the
charset, an unknown function, a bad key and a checksum that does not
match with, so that family is caught below as the expected outcome. An
`IndexError`, a `RecursionError` or an uncaught assertion is not, and
propagates to atheris as the finding it is.

`network` and `prv_keys` are left at their defaults: both are the
caller's own arguments rather than anything the descriptor says.

The seed corpus is two of BIP380's own descriptors, as
`tests/_data/descriptor_checksums.json` carries them, each with its own
checksum appended: unlike a seed with the checksum stripped, a mutation
almost never reaches past `strip_checksum` on one that carries it, so
one seed of each shape would spend the fuzzer's budget differently, and
a seed here keeps its checksum because a stranger pasting a descriptor
does too.
"""

from __future__ import annotations

import contextlib
import sys

import atheris
from btclib.exceptions import BTClibException

from btclib_wallet.descriptors import descriptors

# tests/fuzz_corpus_test.py reads this by ast.literal_eval, never by
# importing the module -- atheris below is CI-only and undeclared in
# pyproject.toml, so the test must not execute this file
ENTRY_POINTS = ("btclib_wallet.descriptors.descriptors:parse",)


def fuzz_target(data: bytes) -> None:
    """Parse `data`, decoded as text, as an output descriptor.

    `BTClibException` is swallowed as `parse`'s own refusal of malformed
    input; any other exception propagates, which is how atheris tells a
    defect in `parse` from the domain of input it already rejects.
    """
    with contextlib.suppress(BTClibException):
        descriptors.parse(data.decode("utf-8", errors="replace"))


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
