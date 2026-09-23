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
from btclib.exceptions import BTClibRuntimeError, BTClibTypeError, BTClibValueError
from btclib.tx import OutPoint, Tx, TxIn, TxOut

from btclib_wallet.bip32 import BIP32KeyData, BIP32KeyOrigin
from btclib_wallet.psbt import Psbt, PsbtIn, PsbtOut
from tests import public_classes_with

# what btclib promises to raise, and the whole of it: a truncated buffer
# has to be refused as one of these three, and never as an IndexError or a
# struct error from underneath the library
_CONTRACT_EXCEPTIONS = (BTClibValueError, BTClibRuntimeError, BTClibTypeError)

_TX_ID = "01" * 32
_XPRV = (
    "xprv9s21ZrQH143K2ZP8tyNiUtgoezZosUkw9hhir2JFzDhcUWKz8qFYk3cxdgSFo"
    "CMzt8E2Ubi1nXw71TLhwgCfzqFHfM5Snv4zboSebePRmLS"
)


def _psbt() -> Psbt:
    """Return the psbt of a one-input one-output transaction, maps and all."""
    return Psbt.from_tx(
        Tx(1, 0x12345678, [TxIn(OutPoint(_TX_ID, 0), b"", 0xFFFFFFFF)], [TxOut(1, b"")])
    )


# every object with a fixed-width field in it or a length of its own,
# with the class whose `parse` reads it back: (name, class, serialization).
# The class and not the bound method, so that the inventory says which
# parsers are covered -- see the completeness test at the end of this file
_CASES: list[tuple[str, type[Any], bytes]] = [
    ("bip32_key", BIP32KeyData, BIP32KeyData.b58decode(_XPRV).serialize()),
    ("psbt", Psbt, _psbt().serialize()),
    ("psbt_in", PsbtIn, PsbtIn(redeem_script=b"\x51").serialize()),
    ("psbt_out", PsbtOut, PsbtOut(redeem_script=b"\x51").serialize()),
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


def test_a_fixed_size_object_reports_its_own_length() -> None:
    """A buffer that is the object reports the buffer, not a field of it.

    Whatever `check_validity` says, which is what a semantic check would
    have gated.
    """
    key_bytes = BIP32KeyData.b58decode(_XPRV).serialize()

    err_msg = "invalid decoded length: 70 instead of 78"
    with pytest.raises(BTClibValueError, match=err_msg):
        BIP32KeyData.parse(key_bytes[:70], check_validity=False)


def test_a_key_origin_is_a_fingerprint_and_then_indexes() -> None:
    """The fingerprint is four octets wide, whatever the origin means.

    Deferred to `check_validity`, a slice of a shorter buffer answered with
    whatever was there and the object serialized back longer than what it
    was parsed from. The remainder was already unconditional:
    `indexes_from_der_path` refuses what is not a whole number of 4-octet
    indexes, whatever `check_validity` says, so this is the other half of
    one boundary.

    Its own test rather than a line in the inventory above, because none of
    the three generic properties applies to a key origin, and that is worth
    saying once: four octets are a valid key origin with an empty path, so
    a prefix of a longer encoding *is* an object; the record carries no
    length and consumes the whole buffer, so nothing can trail it -- four
    junk octets are one more index; and `parse` takes `Octets` rather than
    `BinaryData`, so there is no stream to leave alone.
    """
    for check_validity in (True, False):
        for raw in (b"", b"\x00", b"\x00\x00\x00"):
            err_msg = "not enough data for the master fingerprint"
            with pytest.raises(BTClibValueError, match=err_msg):
                BIP32KeyOrigin.parse(raw, check_validity=check_validity)

    # and what the refusal must not take with it: the shortest key origin
    # there is, and one with a path
    assert BIP32KeyOrigin.parse(b"\xde\xad\xbe\xef").description == "deadbeef"
    key_origin = BIP32KeyOrigin("deadbeef", "m/44h/0h")
    assert BIP32KeyOrigin.parse(key_origin.serialize()) == key_origin


# what a parser of this library is *not* held to, and why. A name here is
# a decision, which is the difference between an exclusion and an
# oversight -- the test below fails on either
_EXCLUDED = {
    "btclib_wallet.bip21.Bip21": (
        "a bitcoin: URI is text and not octets: it has no fixed-width"
        " field, nothing can follow it in a stream, and its own grammar"
        " is what tests/bip21_test.py holds it to"
    ),
    "btclib_wallet.bip32.key_origin.BIP32KeyOrigin": (
        "a four-octet prefix of it is a valid key origin with an empty"
        " path, and the record has no length of its own, so two of the"
        " three properties are false of it by design; the boundary it does"
        " owe its caller is the test above"
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
    argument is. A private class is skipped there, which is what leaves
    `_BIP32KeyData` out here; its public subclass is in the inventory.
    """
    covered = {f"{cls.__module__}.{cls.__qualname__}" for _, cls, _ in _CASES}
    assert not covered & _EXCLUDED.keys()
    assert public_classes_with("parse") == covered | _EXCLUDED.keys()
