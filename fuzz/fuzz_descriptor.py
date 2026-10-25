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

A crash on hostile text is a defect in `parse` or in the printer, never in
this harness: nothing validates or normalizes between the decode and the
call. `BTClibException` and `EccException` are what `parse`
answers a character outside the charset, an unknown function, a bad key
and a checksum that does not match with, so that family is caught below
as the expected outcome. An `IndexError`, a `RecursionError` or an
uncaught assertion is not, and propagates to atheris as the finding it
is.

`network` is left at its default. `prv_keys` collects the private material
the parser reads, for the script round trip below.

**What `parse` accepts prints to a normal form that preserves the parsed
input.** Reading the printed text must recover the same descriptor tree,
including key origins, derivation paths and wildcards. The comparison
walks the dataclasses' compared fields, not their printers. An x-only
key's SEC parity is ignored, because its printed form keeps only x.
The walk is iterative so a deep miniscript needs no recursive equality.

The normal form can differ from the text. Among other things it
writes public keys for private ones, hex in lowercase, numbers without
leading zeros, no checksum, the sugared fragment names (`pk(K)` for
`c:pk_k(K)`) and every hardened step in the symbol of the key's last
hardened step. The assertions below read the printed text again: a second
`parse` that refuses it, recovers another tree, or prints it differently is
a defect in the printer or the parser and propagates to atheris as a finding.

**Every embedded miniscript whose keys derive at index 0 also makes a
script round trip.** The private material read from the input is supplied
for hardened derivation, and a hash160-to-key mapping lets `from_script`
read `pk_h()` fragments. A key that cannot derive at that index leaves
this check unasked: a public extended key cannot take a hardened step.
Once the keys derive, a failure to compile or decode propagates.

The decoded expression must compile to the same bytes, rather than have
the original tree: scripts carry no origins or derivation paths, and
different associations of `and_v()` can compile to the same script.

The seed corpus: each `bipNNN_*` seed is one of BIP NNN's examples, from
BIP380 to BIP387 and BIP390, with its checksum.
`ms_*` are miniscript fragments inside `wsh()` composed here from keys of
the BIPs' examples, `own_*` a descriptor composed here, and `pk` and
`wpkh` come from `tests/_data/descriptor_checksums.json`. The checksum is
the BIP's own in `bip380_raw`, the file's in `pk` and `wpkh`, and
BIP380's `descsum_create`'s in the rest. A
seed keeps its checksum because a stranger pasting a descriptor does
too, at a cost: a mutation of it almost never reaches past
`strip_checksum`.
`tests/fuzz_corpus_test.py` holds each seed to the round trip above.
"""

from __future__ import annotations

import sys
from dataclasses import fields, is_dataclass, replace

import atheris
from btclib.exceptions import BTClibException
from btclib.hashes import hash160
from ecc.exceptions import EccException

from btclib_wallet.descriptors import descriptors, miniscript
from btclib_wallet.descriptors.key_expression import KeyExpression

# tests/fuzz_corpus_test.py reads this by ast.literal_eval. Its descriptor
# tests also load this module with a placeholder for the CI-only atheris,
# so the corpus runs the very assertions the fuzz target runs.
ENTRY_POINTS = ("btclib_wallet.descriptors.descriptors:parse",)


def _same_tree(left: object, right: object) -> bool:
    """Compare parsed descriptor fields without recursive equality."""
    pending = [(left, right)]
    while pending:
        left, right = pending.pop()
        if type(left) is not type(right):
            return False
        if isinstance(left, KeyExpression) and left.x_only and left.pub_key:
            left = replace(left, pub_key=b"\x02" + left.pub_key[1:])
        if isinstance(right, KeyExpression) and right.x_only and right.pub_key:
            right = replace(right, pub_key=b"\x02" + right.pub_key[1:])
        if is_dataclass(left):
            pending.extend(
                (getattr(left, field.name), getattr(right, field.name))
                for field in fields(left)
                if field.compare
            )
        elif isinstance(left, tuple) and isinstance(right, tuple):
            if len(left) != len(right):
                return False
            pending.extend(zip(left, right, strict=True))
        elif left != right:
            return False
    return True


def _assert_miniscript_round_trips(
    parsed: descriptors.Descriptor, prv_keys: dict[str, str]
) -> None:
    """Compile and decode each derivable miniscript inside a descriptor."""
    pending: list[object] = [parsed]
    while pending:
        value = pending.pop()
        if isinstance(value, miniscript.Miniscript):
            key_hashes: dict[bytes, bytes] = {}
            try:
                for key in value.key_expressions:
                    sec = key.sec(0, parsed.network, prv_keys)
                    if value.context == miniscript.TAPSCRIPT:
                        sec = sec[1:]
                    key_hashes[hash160(sec)] = sec
            except (BTClibException, EccException):
                continue
            script = value.script(0, parsed.network, prv_keys)
            decoded = miniscript.from_script(script, value.context, key_hashes)
            if decoded.script() != script:
                raise AssertionError("miniscript script round trip changes the script")
        elif is_dataclass(value):
            pending.extend(
                getattr(value, field.name) for field in fields(value) if field.compare
            )
        elif isinstance(value, tuple):
            pending.extend(value)


def fuzz_target(data: bytes) -> None:
    """Parse `data` as an output descriptor and print it back.

    A `BTClibException` or `EccException` from parsing `data` ends
    the run; the module docstring says what propagates.
    """
    prv_keys: dict[str, str] = {}
    try:
        parsed = descriptors.parse(
            data.decode("utf-8", errors="replace"), prv_keys=prv_keys
        )
    except (BTClibException, EccException):
        return
    printed = str(parsed)
    reparsed = descriptors.parse(printed)
    if not _same_tree(parsed, reparsed):
        raise AssertionError("descriptor print changes the parsed input")
    reprinted = str(reparsed)
    if reprinted != printed:
        msg = f"{printed!r} parses and prints as {reprinted!r}"
        raise AssertionError(msg)
    _assert_miniscript_round_trips(parsed, prv_keys)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
