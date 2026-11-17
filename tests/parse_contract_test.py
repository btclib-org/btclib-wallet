# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the parse contract every `parse` in this package owes its caller.

btclib's contract, which `btclib.utils` states: a field is as long as its
encoding says, a complete octet string is one whole object, and a caller's
stream is the caller's. What the tests hold every parser to is that none
of the three depends on `check_validity`, which is an opinion about what
the bytes mean and not about where they end.

The inventory at the top is what those tests run over, and the last test
is what makes it a promise rather than a list: it walks the package for
every public class carrying a `parse` and fails unless each one is either
in the inventory or in a table of exclusions naming its reason. A parser
added here and forgotten in the inventory would otherwise be held to
nothing.
"""

from __future__ import annotations

from collections.abc import Callable
from io import BytesIO
from typing import Any

import pytest
from btclib.exceptions import BTClibValueError
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from ecc.curves import mult

from btclib_wallet.dlc import oracle
from btclib_wallet.psbt import Psbt, PsbtIn, PsbtOut
from tests import public_classes_with
from tests.exception_family_test import RUNTIME_ERRORS, TYPE_ERRORS, VALUE_ERRORS

# what btclib promises to raise, and the whole of it: a truncated buffer
# has to be refused as one of these three, each with ecc's class
# of its kind beside it (issue btclib-org/btclib#2282), and never as an
# IndexError or a struct error from underneath the library
_CONTRACT_EXCEPTIONS = (*VALUE_ERRORS, *RUNTIME_ERRORS, *TYPE_ERRORS)

_TX_ID = "01" * 32


def _psbt() -> Psbt:
    """Return the psbt of a one-input one-output transaction, maps and all."""
    return Psbt.from_tx(
        Tx(1, 0x12345678, [TxIn(OutPoint(_TX_ID, 0), b"", 0xFFFFFFFF)], [TxOut(1, b"")])
    )


_ORACLE_KEY = 7
_ORACLE_NONCE = 11
_ORACLE_EVENT = oracle.OracleEvent(
    nonces=(mult(_ORACLE_NONCE)[0].to_bytes(32, "big"),),
    maturity_epoch=1,
    descriptor=oracle.EnumEventDescriptor(outcomes=("a", "b")),
    event_id="e",
)
_ORACLE_ANNOUNCEMENT = oracle.sign_announcement(_ORACLE_EVENT, _ORACLE_KEY)
_ORACLE_ATTESTATION = oracle.sign_attestation(
    _ORACLE_ANNOUNCEMENT, ("a",), _ORACLE_KEY, (_ORACLE_NONCE,)
)

# every object with a fixed-width field in it or a length of its own,
# with the class whose `parse` reads it back: (name, class, serialization).
# The class and not the bound method, so that the inventory says which
# parsers are covered -- see the completeness test at the end of this file
_CASES: list[tuple[str, type[Any], bytes]] = [
    ("psbt", Psbt, _psbt().serialize()),
    ("psbt_in", PsbtIn, PsbtIn(redeem_script=b"\x51").serialize()),
    ("psbt_out", PsbtOut, PsbtOut(redeem_script=b"\x51").serialize()),
    ("oracle_event", oracle.OracleEvent, _ORACLE_EVENT.serialize()),
    (
        "oracle_announcement",
        oracle.OracleAnnouncement,
        _ORACLE_ANNOUNCEMENT.serialize(),
    ),
    ("oracle_attestation", oracle.OracleAttestation, _ORACLE_ATTESTATION.serialize()),
]

_IDS = [case[0] for case in _CASES]
_PARSE_AND_BYTES = [(case[1].parse, case[2]) for case in _CASES]


@pytest.mark.parametrize("parse, serialization", _PARSE_AND_BYTES, ids=_IDS)
@pytest.mark.parametrize("check_validity", [True, False], ids=["checked", "unchecked"])
def test_no_prefix_of_an_encoding_is_an_object(
    parse: Callable[..., Any], serialization: bytes, *, check_validity: bool
) -> None:
    """Every truncation is refused, at every offset and either way.

    `BytesIO.read` answers with what is left rather than raising, and
    `int.from_bytes` takes a short answer, so an unchecked parser turns
    each of these prefixes into an object that serializes back longer
    than the buffer it came from: distinct buffers, including malformed
    ones, mapping to one canonical object.
    """
    for size in range(len(serialization)):
        with pytest.raises(_CONTRACT_EXCEPTIONS):
            parse(serialization[:size], check_validity=check_validity)


@pytest.mark.parametrize("parse, serialization", _PARSE_AND_BYTES, ids=_IDS)
@pytest.mark.parametrize("check_validity", [True, False], ids=["checked", "unchecked"])
def test_octets_are_one_whole_object(
    parse: Callable[..., Any], serialization: bytes, *, check_validity: bool
) -> None:
    """Bytes after the object are refused, hex-string included."""
    assert parse(serialization, check_validity=check_validity)

    for trailing in (b"\x00", b"junk"):
        with pytest.raises(BTClibValueError, match="bytes after the"):
            parse(serialization + trailing, check_validity=check_validity)
        with pytest.raises(BTClibValueError, match="bytes after the"):
            parse((serialization + trailing).hex(), check_validity=check_validity)


@pytest.mark.parametrize("parse, serialization", _PARSE_AND_BYTES, ids=_IDS)
def test_a_stream_is_the_callers(
    parse: Callable[..., Any], serialization: bytes
) -> None:
    """A stream may carry more, and is left on the byte after the object.

    This is the half of the contract that makes the other half safe to
    enforce: a transaction is read out of the very stream its block is
    read from, so what follows the object in a stream is not the parser's
    to complain about -- or to consume.
    """
    stream = BytesIO(serialization + b"junk")
    assert parse(stream)
    assert stream.read() == b"junk"


# what a parser of this library is *not* held to, and why. A name here is
# a decision, which is the difference between an exclusion and an
# oversight -- the test below fails on either
_EXCLUDED = {
    "btclib_wallet.bip21.Bip21": (
        "a bitcoin: URI is text and not octets: it has no fixed-width"
        " field, nothing can follow it in a stream, and its own grammar"
        " is what tests/bip21_test.py holds it to"
    ),
}


def test_every_parser_is_covered_or_named_an_exclusion() -> None:
    """The inventory is a promise only if omission is what fails.

    A parser added to the package and forgotten here is the failure this
    catches: the tests above would go on passing on the parsers they were
    given, and the new one would be held to nothing.

    `public_classes_with` is the walk, and it is `tests/__init__.py`'s
    because `serialization_boundary_test.py` holds these same parsers to
    a different contract -- where the bytes end is not what type the
    argument is. A private class is skipped there.
    """
    covered = {f"{cls.__module__}.{cls.__qualname__}" for _, cls, _ in _CASES}
    assert not covered & _EXCLUDED.keys()
    assert public_classes_with("parse") == covered | _EXCLUDED.keys()
