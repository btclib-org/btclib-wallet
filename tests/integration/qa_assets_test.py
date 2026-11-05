# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The fuzz corpora of Bitcoin Core and rust-bitcoin, replayed here.

`bitcoin-core/qa-assets` holds, per Core fuzz target, the inputs that
target's fuzzers found interesting, and `rust-bitcoin/qa-assets` does the
same for rust-bitcoin's. Where the target reads a psbt or a descriptor,
the same input goes to this package's parser for it. A
parser may refuse it with an exception of the families
`tests/exception_family_test.py` holds; any other exception is a defect.
btclib replays the directories its own parsers read, in its own
`tests/integration/qa_assets_test.py`, and leaves these to this package.

A source is skipped unless its variable names its checkout,
`BTCLIB_QA_ASSETS` for Core's and `BTCLIB_RUST_BITCOIN_QA_ASSETS` for
rust-bitcoin's:

    BTCLIB_QA_ASSETS=/path/to/qa-assets uv run pytest \
        tests/integration/qa_assets_test.py -n 0

`qa-assets.yml` runs it weekly against both repositories' default
branch, sparse-checking out the directories `TARGETS` names.

`TARGETS` is the table from a qa-assets directory to the parser that
reads it. `reading` says how the source's own target reads the input: a
file of `src/test/fuzz/` in `bitcoin/bitcoin`, or of
`fuzz/fuzz_targets/` in `rust-bitcoin/rust-bitcoin`. A Core
`_deserialize` target reads an object off the front of the input and
ignores what follows (`SpanReader{buffer} >> obj`), while `parse` on bytes
refuses trailing bytes; so those rows hand `parse` a `BytesIO`, which it
leaves where the object ends. Each parser that takes `check_validity` is
replayed with it on and off.

The `psbt` row is replayed as Core's target draws it. That target does
not read its input as a psbt: `FuzzedDataProvider`'s
`ConsumeRandomLengthString` draws a string from it, two backslashes
standing for one and a backslash before any other octet ending the
string, and `DecodeRawPSBT` reads that string as the whole of a psbt. A
second draw, from what the first left, is the psbt the target merges
into it. `_draws` is that draw, and both strings go to `Psbt.parse`.

rust-bitcoin's `bitcoin_0_32_deserialize_psbt` hands the input to
bitcoin 0.32's `Psbt::deserialize`, which reads a psbt off the front and
ignores what follows, as Core's `_deserialize` targets do; so its row
hands `parse` a `BytesIO` too.

`descriptor_parse` hands `parse` the input as text, one character per
octet, as Core's `std::string` holds it. Core parses each input twice,
with a checksum required and without; `parse` verifies a checksum where
there is one and requires none, which is the second, the first adding
only the refusal of an input without one. Core's target skips what
`IsTooExpensive` names, to spend its fuzzing time elsewhere; this replay
reads every input, and `pyproject.toml`'s `timeout` bounds each test.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

import pytest

from btclib_wallet.descriptors import descriptors
from btclib_wallet.psbt.psbt import Psbt
from btclib_wallet.psbt.psbt_in import PsbtIn
from btclib_wallet.psbt.psbt_out import PsbtOut
from tests.exception_family_test import EXCEPTIONS

pytestmark = pytest.mark.integration

# a parser and the way to ask it: (octets, check_validity)
Parser = Callable[[bytes, bool], object]

_BACKSLASH = ord("\\")


def _draw(data: bytes, start: int) -> tuple[bytes, int]:
    """Return a `ConsumeRandomLengthString` draw from `start`, and its end."""
    drawn = bytearray()
    position = start
    while position < len(data):
        octet = data[position]
        position += 1
        if octet == _BACKSLASH and position < len(data):
            octet = data[position]
            position += 1
            if octet != _BACKSLASH:
                break
        drawn.append(octet)
    return bytes(drawn), position


def _draws(data: bytes) -> tuple[bytes, ...]:
    """Return the psbt Core's `psbt` target draws, and the one it merges."""
    first, position = _draw(data, 0)
    second, _ = _draw(data, position)
    return first, second


def _whole(data: bytes) -> tuple[bytes, ...]:
    """Return the input, which the target reads as it is."""
    return (data,)


@dataclass(frozen=True)
class Target:
    """A qa-assets directory, how its target reads it, and the parser here."""

    directory: str
    reading: str
    parse: Parser
    # what the target hands its parser, out of one input
    subjects: Callable[[bytes], tuple[bytes, ...]] = _whole
    # the values of `check_validity` to replay with
    validity: tuple[bool, ...] = (True, False)
    # whose qa-assets holds the directory
    source: str = "bitcoin-core"


def _front(parse: Callable[..., object]) -> Parser:
    """Return `parse` reading off the front of a stream of the octets."""
    return lambda data, check_validity: parse(
        BytesIO(data), check_validity=check_validity
    )


def _psbt(data: bytes, check_validity: bool) -> object:
    """Return the psbt the octets are, nothing after it."""
    return Psbt.parse(data, check_validity=check_validity)


def _psbt_base64(data: bytes, check_validity: bool) -> object:
    """Return the psbt the octets are the base64 text of."""
    return Psbt.b64decode(data, check_validity=check_validity)


def _descriptor(data: bytes, check_validity: bool) -> object:
    """Return the descriptor the octets spell, one character each."""
    return descriptors.parse(data.decode("latin-1"))


TARGETS = (
    Target(
        "partially_signed_transaction_deserialize",
        "deserialize.cpp: PartiallySignedTransaction",
        _front(Psbt.parse),
    ),
    Target(
        "psbt_input_deserialize",
        "deserialize.cpp: PSBTInput of a version 0 psbt",
        _front(PsbtIn.parse),
    ),
    Target(
        "psbt_output_deserialize",
        "deserialize.cpp: PSBTOutput of a version 0 psbt",
        _front(PsbtOut.parse),
    ),
    Target(
        "psbt_base64_decode",
        "base_encode_decode.cpp: DecodeBase64PSBT on the input as a string",
        _psbt_base64,
    ),
    Target(
        "psbt",
        "psbt.cpp: DecodeRawPSBT on each of two ConsumeRandomLengthString draws",
        _psbt,
        subjects=_draws,
    ),
    Target(
        "bitcoin_0_32_deserialize_psbt",
        "bitcoin_0_32/deserialize_psbt.rs: Psbt::deserialize,"
        " a psbt off the front of the input",
        _front(Psbt.parse),
        source="rust-bitcoin",
    ),
    Target(
        "descriptor_parse",
        "descriptor_parse.cpp: Parse on the input as a string, on mainnet",
        _descriptor,
        validity=(True,),
    ),
)


# the environment variable that names a checkout, per source
_CHECKOUTS = {
    "bitcoin-core": "BTCLIB_QA_ASSETS",
    "rust-bitcoin": "BTCLIB_RUST_BITCOIN_QA_ASSETS",
}


@pytest.mark.parametrize(
    "target", TARGETS, ids=lambda target: f"{target.source}-{target.directory}"
)
def test_corpus_is_refused_in_the_libraries_own_exceptions(target: Target) -> None:
    """Every input is parsed, or refused in one of the families."""
    variable = _CHECKOUTS[target.source]
    checkout = os.environ.get(variable)
    if not checkout:
        # the prefix is what integration-bitcoind.yml exempts from its
        # check that the tests ran
        pytest.skip(f"set {variable} to a {target.source} qa-assets checkout")
    inputs = sorted((Path(checkout) / "fuzz_corpora" / target.directory).iterdir())
    # a renamed or emptied directory would otherwise pass by replaying nothing
    assert inputs, f"{target.directory} holds no input"

    defects = []
    for path in inputs:
        data = path.read_bytes()
        for subject in target.subjects(data):
            for check_validity in target.validity:
                try:
                    target.parse(subject, check_validity)
                except EXCEPTIONS:
                    pass
                except Exception as exc:  # noqa: BLE001 -- any other is the finding
                    defects.append(
                        f"{path.name} ({len(data)} octets),"
                        f" check_validity={check_validity}: {exc!r}"
                    )
    assert not defects, "\n".join([target.reading, *defects])
