# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib_wallet.psbt.psbt.Psbt`'s two decoders.

A psbt travels between wallets that do not trust each other -- that is
what it is for -- and every one of them parses what the last one wrote
before any signature in it has been looked at. Its own maps are
length-prefixed keys and values whose types decide how the value is read,
which is a deserializer taking a stranger's own numbers, and BIP174's
file form wraps the whole of it in base64 that anybody can paste.

`parse` is the octets and `b64decode` is the armor in front of them, so
this harness runs both against the same input: neither is reachable from
the other, `b64decode` refusing what is not canonical base64 before
`parse` ever sees it. `Psbt.parse` dispatches to `PsbtIn.parse`,
`PsbtOut.parse` and the map and Taproot-tree readers of
`psbt_utils.py` for every record a psbt carries, so a corpus of real
psbts drives those readers too; each also has its own direct entry point
in the Hypothesis property suite, `tests/fuzz_test.py`.

A psbt that parses is then used. It is serialized, and the
serialization has to be a fixed point: `serialize(parse(serialize(p)))
== serialize(p)`. The bytes need not come back as they arrived, because
`PsbtIn.serialize` drops the signing fields of a finalized input
(`_DROPPED_ONCE_FINALIZED` in `psbt_in.py`). The psbt is then read the
way a wallet reads it next: `to_dict`, `prevouts`, `assert_signable`
and `finalize`, whose result has to serialize to a fixed point too.

A crash here on hostile bytes is a defect in the parser, in `serialize`
or in one of those readers, never in this harness: `data` is
unconstrained bytes handed straight to each entry point, `b64decode`
taking bytes as the ascii it decodes them from. `BTClibException` and
`EccException` are what the entry points and the readers answer input
they refuse with, so that family is caught below as the expected
outcome. `parse` has already validated the psbt, so nothing is caught
around `serialize`, the second `parse` and `to_dict`: a refusal from
any of them is a finding. An `IndexError`, a `RecursionError` or a
failed check of this harness propagates to atheris as the finding it
is.

The seed corpus holds, as octets, every valid psbt of
`tests/psbt/_data/bip174_test_vectors.json` and
`bip371_test_vectors.json`, and the first BIP174 one also as the base64
it is published as. The fuzzer thus starts from witness utxos, partial
signatures, scripts, BIP32 derivations and the Taproot records, rather
than having to build each by mutation. It also holds the psbt with a
final script witness that `tests/psbt/_data/rust-psbt/bip174.json`
expects from "Workflow A (step 7)", and the two psbts that crashed
rust-bitcoin's combiner, `tests/psbt/_data/psbt_fuzz1.hex` and
`psbt_fuzz2.hex`.
"""

from __future__ import annotations

import contextlib
import sys

import atheris
from btclib.exceptions import BTClibException
from ecc.exceptions import EccException

from btclib_wallet.psbt.psbt import Psbt, finalize, prevouts

# tests/fuzz_corpus_test.py reads this by ast.literal_eval. It also loads
# this module with a placeholder for the CI-only atheris, and runs
# fuzz_target on every seed.
ENTRY_POINTS = (
    "btclib_wallet.psbt.psbt:Psbt.parse",
    "btclib_wallet.psbt.psbt:Psbt.b64decode",
)


def _assert_fixed_point(psbt: Psbt) -> None:
    """Serialize `psbt`, parse that, and serialize it again unchanged."""
    serialized = psbt.serialize()
    if Psbt.parse(serialized).serialize() != serialized:
        raise AssertionError("psbt serialization is not a fixed point")


def _use(psbt: Psbt) -> None:
    """Serialize an accepted psbt, then read it as a wallet would."""
    _assert_fixed_point(psbt)
    psbt.to_dict()
    with contextlib.suppress(BTClibException, EccException):
        prevouts(psbt)
    with contextlib.suppress(BTClibException, EccException):
        psbt.assert_signable()
    try:
        finalized = finalize(psbt)
    except (BTClibException, EccException):
        return
    _assert_fixed_point(finalized)


def fuzz_target(data: bytes) -> None:
    """Parse `data` as psbt octets, then as the base64 armor of some.

    Each psbt either one accepts is used; the module docstring says what
    is caught and what propagates.
    """
    try:
        psbt = Psbt.parse(data)
    except (BTClibException, EccException):
        pass
    else:
        _use(psbt)
    try:
        psbt = Psbt.b64decode(data)
    except (BTClibException, EccException):
        pass
    else:
        _use(psbt)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
