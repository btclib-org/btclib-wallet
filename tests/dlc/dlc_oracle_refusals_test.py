# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests of what `btclib_wallet.dlc.oracle` refuses and of its edges."""

from __future__ import annotations

from dataclasses import replace
from io import BytesIO
from typing import Any

import pytest
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib_ecc.curves import mult, secp256k1
from btclib_ecc.hashes import tagged_hash

from btclib_wallet.dlc import oracle
from tests.exception_family_test import VALUE_ERRORS

_KEY = 7
_NONCES = (11, 13, 17)


def _replace(obj: Any, **changes: Any) -> Any:
    """Return obj with fields changed, whatever the type of the new values."""
    return replace(obj, **changes)


def _x(k: int) -> bytes:
    return mult(k)[0].to_bytes(32, "big")


_ENUM = oracle.EnumEventDescriptor(outcomes=("a", "b"))
_DIGITS = oracle.DigitDecompositionEventDescriptor(
    base=2, is_signed=True, unit="btc", precision=-2, nb_digits=2
)
_EVENT = oracle.OracleEvent(
    nonces=(_x(_NONCES[0]),), maturity_epoch=1, descriptor=_ENUM, event_id="e"
)
_DIGITS_EVENT = _replace(
    _EVENT, nonces=tuple(_x(k) for k in _NONCES), descriptor=_DIGITS
)
_ANNOUNCEMENT = oracle.sign_announcement(_EVENT, _KEY)
_DIGITS_ANNOUNCEMENT = oracle.sign_announcement(_DIGITS_EVENT, _KEY)
_ATTESTATION = oracle.sign_attestation(_ANNOUNCEMENT, ("a",), _KEY, _NONCES[:1])


@pytest.mark.parametrize("scheme", [oracle.TAGGED, oracle.PLAIN_SHA256])
def test_a_signed_announcement_verifies_under_its_scheme_only(scheme: Any) -> None:
    """A signed announcement verifies under its scheme only."""
    announcement = oracle.sign_announcement(_EVENT, _KEY, scheme=scheme)
    assert oracle.verify_announcement(announcement, scheme=scheme)
    other = oracle.PLAIN_SHA256 if scheme == oracle.TAGGED else oracle.TAGGED
    assert not oracle.verify_announcement(announcement, scheme=other)


def test_a_scheme_is_a_known_string() -> None:
    """A scheme is a known string."""
    with pytest.raises(BTClibTypeError):
        oracle.verify_announcement(_ANNOUNCEMENT, scheme=None)  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError, match="unknown announcement"):
        oracle.verify_announcement(_ANNOUNCEMENT, scheme="md5")  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError, match="unknown announcement"):
        oracle.sign_announcement(_EVENT, _KEY, scheme="md5")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "obj",
    [_ENUM, _DIGITS, _EVENT, _DIGITS_EVENT, _ANNOUNCEMENT, _ATTESTATION],
    ids=lambda o: type(o).__name__,
)
def test_serialize_does_not_depend_on_the_check_for_a_valid_object(obj: Any) -> None:
    """Serialize does not depend on the check for a valid object."""
    assert obj.serialize() == obj.serialize(check_validity=False)


@pytest.mark.parametrize(
    "parse, obj",
    [
        (oracle.OracleEvent.parse, _EVENT),
        (oracle.OracleAnnouncement.parse, _ANNOUNCEMENT),
        (oracle.OracleAttestation.parse, _ATTESTATION),
    ],
    ids=["event", "announcement", "attestation"],
)
def test_parse_round_trips_octets_and_a_stream(parse: Any, obj: Any) -> None:
    """Parse round trips octets and a stream."""
    data = obj.serialize()
    assert parse(data) == obj
    assert parse(data.hex()) == obj
    assert parse(BytesIO(data)) == obj


def test_a_digit_decomposition_event_round_trips() -> None:
    """A digit decomposition event round trips."""
    assert oracle.OracleEvent.parse(_DIGITS_EVENT.serialize()) == _DIGITS_EVENT


def test_the_check_is_what_check_validity_gates() -> None:
    """A syntactically complete event that means nothing parses unchecked."""
    event = _replace(_EVENT, nonces=(_x(11), _x(11)))
    data = event.serialize(check_validity=False)
    with pytest.raises(BTClibValueError, match="do not fit"):
        oracle.OracleEvent.parse(data)
    assert oracle.OracleEvent.parse(data, check_validity=False) == event
    with pytest.raises(BTClibValueError, match="do not fit"):
        event.serialize()


def test_the_wire_refuses_what_is_not_minimal_or_not_typed() -> None:
    """The wire refuses what is not minimal or not typed."""
    data = _EVENT.serialize()
    # the type 55330 written in five octets where three are minimal
    longer = b"\xfe" + (55330).to_bytes(4, "big") + data[3:]
    with pytest.raises(BTClibValueError, match="minimally"):
        oracle.OracleEvent.parse(longer)
    # and in the long forms a value is small enough for the short one
    for form, size in ((b"\xfd", 2), (b"\xfe", 4), (b"\xff", 8)):
        padded = form + (1).to_bytes(size, "big")
        with pytest.raises(BTClibValueError, match="minimally"):
            oracle.OracleEvent.parse(padded)
    # an announcement where an event is expected
    with pytest.raises(BTClibValueError, match="unexpected TLV type"):
        oracle.OracleEvent.parse(_ANNOUNCEMENT.serialize())
    with pytest.raises(BTClibValueError, match="unexpected TLV type"):
        oracle.OracleAttestation.parse(_ANNOUNCEMENT.serialize())


def test_a_long_form_bigsize_is_read() -> None:
    """A length of 253 octets or more is written in the long forms."""
    event = _replace(_EVENT, event_id="x" * 300)
    assert oracle.OracleEvent.parse(event.serialize()) == event
    event = _replace(_EVENT, event_id="x" * 70000)
    assert oracle.OracleEvent.parse(event.serialize()) == event


def test_a_string_that_is_not_utf8_is_refused() -> None:
    """A string that is not utf8 is refused."""
    data = bytearray(_EVENT.serialize())
    assert data[-2:] == b"\x01e"
    data[-1] = 0xFF
    with pytest.raises(BTClibValueError, match="not UTF-8"):
        oracle.OracleEvent.parse(bytes(data))


def test_a_value_longer_than_its_fields_is_refused() -> None:
    """Octets inside a TLV past its last field are not skipped."""
    data = _EVENT.serialize()
    padded = data[:3] + bytes([data[3] + 1]) + data[4:] + b"\x00"
    with pytest.raises(BTClibValueError, match="trailing octets"):
        oracle.OracleEvent.parse(padded)


def test_a_flag_that_is_not_a_bool_is_refused() -> None:
    """A flag that is not a bool is refused."""
    data = bytearray(_DIGITS.serialize())
    # type (3), length (1), base (2), then the flag
    data[3 + 1 + 2] = 2
    reader = oracle._Reader(BytesIO(bytes(data)))
    with pytest.raises(BTClibValueError, match="is_signed"):
        oracle._read_descriptor(reader)


def test_a_descriptor_of_no_known_type_is_refused() -> None:
    """A descriptor of no known type is refused."""
    reader = oracle._Reader(BytesIO(b"\x01\x00"))
    with pytest.raises(BTClibValueError, match="unexpected TLV type"):
        oracle._read_descriptor(reader)


def test_a_descriptor_with_octets_past_its_fields_is_refused() -> None:
    """A descriptor with octets past its fields is refused."""
    data = _ENUM.serialize()
    padded = data[:3] + bytes([data[3] + 1]) + data[4:] + b"\x00"
    reader = oracle._Reader(BytesIO(padded))
    with pytest.raises(BTClibValueError, match="trailing octets"):
        oracle._read_descriptor(reader)


@pytest.mark.parametrize(
    "bad, err",
    [
        (_replace(_ENUM, outcomes=()), "1 to 65535"),
        (_replace(_ENUM, outcomes=("a", "a")), "not distinct"),
        (_replace(_ENUM, outcomes=["a"]), "type"),
        (_replace(_ENUM, outcomes=("é".encode(),)), "type"),
        (_replace(_ENUM, outcomes=("é",)), "NFC"),
        (_replace(_ENUM, outcomes=("\ud800",)), "UTF-8"),
        (_replace(_DIGITS, base=1), "base out of range"),
        (_replace(_DIGITS, base=0x10000), "base out of range"),
        (_replace(_DIGITS, base="2"), "type"),
        (_replace(_DIGITS, base=True), "type"),
        (_replace(_DIGITS, is_signed=1), "type"),
        (_replace(_DIGITS, unit=b"btc"), "type"),
        (_replace(_DIGITS, precision=2**31), "precision out of range"),
        (_replace(_DIGITS, nb_digits=0), "digits out of range"),
        (_replace(_DIGITS, nb_digits=0xFFFF), "more nonces than an event"),
        (_replace(_EVENT, nonces=[]), "type"),
        (_replace(_EVENT, nonces=("x",)), "type"),
        (_replace(_EVENT, nonces=(bytes(31),)), "32 octets"),
        (_replace(_EVENT, nonces=(bytes(32),)), "not a point"),
        (_replace(_EVENT, nonces=()), "do not fit"),
        (_replace(_EVENT, maturity_epoch=-1), "maturity out of range"),
        (_replace(_EVENT, descriptor=None), "type"),
        (_replace(_EVENT, descriptor=_replace(_ENUM, outcomes=())), "1 to 65535"),
        (_replace(_EVENT, event_id=None), "type"),
        (_replace(_ANNOUNCEMENT, signature=bytes(63)), "64 octets"),
        (_replace(_ANNOUNCEMENT, public_key=bytes(32)), "not a point"),
        (_replace(_ANNOUNCEMENT, event=None), "type"),
        (_replace(_ATTESTATION, event_id=None), "type"),
        (_replace(_ATTESTATION, public_key=bytes(31)), "32 octets"),
        (_replace(_ATTESTATION, signatures=[]), "type"),
        (_replace(_ATTESTATION, outcomes=["a"]), "type"),
        (_replace(_ATTESTATION, signatures=(bytes(65),)), "64 octets"),
        (_replace(_ATTESTATION, outcomes=(1,)), "type"),
        (_replace(_ATTESTATION, outcomes=("a", "b")), "differ in number"),
        (_replace(_ATTESTATION, signatures=(bytes(64),) * 65536), "too many"),
    ],
)
def test_assert_valid_refuses(bad: Any, err: str) -> None:
    """Assert valid refuses."""
    with pytest.raises((BTClibValueError, BTClibTypeError), match=err):
        bad.assert_valid()
    with pytest.raises((BTClibValueError, BTClibTypeError), match=err):
        bad.serialize()


def test_serialize_unchecked_refuses_what_has_no_encoding() -> None:
    """Serialize unchecked refuses what has no encoding."""
    for bad in (
        _replace(_ENUM, outcomes=("a",) * 65536),
        _replace(_DIGITS, base=0x10000),
        _replace(_DIGITS, precision=2**31),
        _replace(_DIGITS, nb_digits=0x10000),
        _replace(_EVENT, maturity_epoch=2**32),
        _replace(_EVENT, nonces=(_x(11),) * 65536),
        _replace(_ATTESTATION, signatures=(bytes(64),) * 65536),
    ):
        with pytest.raises(BTClibValueError, match="out of range"):
            bad.serialize(check_validity=False)


def test_a_nonce_may_not_repeat() -> None:
    """A nonce may not repeat."""
    bad = _replace(
        _DIGITS_EVENT, nonces=(_x(_NONCES[0]), _x(_NONCES[0]), _x(_NONCES[1]))
    )
    with pytest.raises(BTClibValueError, match="not distinct"):
        bad.assert_valid()


def test_a_string_is_nfc_everywhere_it_is_taken() -> None:
    """Refuse a string that is not NFC, in every field and function."""
    decomposed = "e\u0301"
    composed = "\u00e9"
    assert oracle.outcome_message(composed) != oracle.outcome_message("e")
    with pytest.raises(BTClibValueError, match="NFC"):
        oracle.outcome_message(decomposed)
    for bad in (
        _replace(_EVENT, event_id=decomposed),
        _replace(_EVENT, descriptor=_replace(_ENUM, outcomes=("a", decomposed))),
        _replace(_DIGITS_EVENT, descriptor=_replace(_DIGITS, unit=decomposed)),
        _replace(_ATTESTATION, event_id=decomposed),
        _replace(_ATTESTATION, outcomes=(decomposed,)),
    ):
        with pytest.raises(BTClibValueError, match="NFC"):
            bad.assert_valid()
    with pytest.raises(BTClibValueError, match="NFC"):
        oracle.sign_attestation(_ANNOUNCEMENT, (decomposed,), _KEY, _NONCES[:1])


def test_the_outcome_message_is_the_tagged_hash_of_the_text() -> None:
    """The outcome message is the tagged hash of the text."""
    assert oracle.outcome_message("a") == tagged_hash(
        b"DLC/oracle/attestation/v0", b"a"
    )


def test_the_signing_functions_refuse_the_wrong_types() -> None:
    """The signing functions refuse the wrong types."""
    with pytest.raises(BTClibTypeError):
        oracle.sign_announcement(None, _KEY)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError):
        oracle.verify_announcement(None)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError):
        oracle.verify_attestation(None, _ATTESTATION)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError):
        oracle.verify_attestation(_ANNOUNCEMENT, None)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError):
        oracle.sign_attestation(None, ("a",), _KEY, _NONCES[:1])  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError):
        oracle.sign_attestation(_ANNOUNCEMENT, ["a"], _KEY, _NONCES[:1])  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError):
        oracle.sign_attestation(_ANNOUNCEMENT, (1,), _KEY, _NONCES[:1])  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError):
        oracle.sign_attestation(_ANNOUNCEMENT, ("a",), _KEY, [11])  # type: ignore[arg-type]


def test_the_signing_functions_check_the_object_they_are_given() -> None:
    """The signing functions check the object they are given."""
    bad = _replace(_ANNOUNCEMENT, signature=bytes(63))
    with pytest.raises(BTClibValueError, match="64 octets"):
        oracle.sign_attestation(bad, ("a",), _KEY, _NONCES[:1])
    with pytest.raises(BTClibValueError, match="64 octets"):
        oracle.verify_attestation(bad, _ATTESTATION)
    with pytest.raises(BTClibValueError, match="64 octets"):
        oracle.verify_announcement(bad)
    with pytest.raises(BTClibValueError, match="not distinct"):
        oracle.sign_announcement(
            _replace(_EVENT, descriptor=_replace(_ENUM, outcomes=("a", "a"))), _KEY
        )
    with pytest.raises(BTClibValueError, match="64 octets"):
        oracle.verify_attestation(
            _ANNOUNCEMENT, _replace(_ATTESTATION, signatures=(bytes(63),))
        )


def test_an_attestation_is_signed_only_with_what_was_committed() -> None:
    """An attestation is signed only with what was committed."""
    with pytest.raises(BTClibValueError, match="outcomes are not"):
        oracle.sign_attestation(_ANNOUNCEMENT, ("c",), _KEY, _NONCES[:1])
    with pytest.raises(BTClibValueError, match="key is not"):
        oracle.sign_attestation(_ANNOUNCEMENT, ("a",), _OTHER, _NONCES[:1])
    with pytest.raises(BTClibValueError, match="nonces are not"):
        oracle.sign_attestation(_ANNOUNCEMENT, ("a",), _KEY, (_OTHER,))
    with pytest.raises(BTClibValueError, match="nonces are not"):
        oracle.sign_attestation(_ANNOUNCEMENT, ("a",), _KEY, ())


_ORDER = secp256k1.n
_SECRET = _ORDER + 0xABCDEF
_SECRET_BYTES = bytes.fromhex("ab" * 31)
_OTHER = 0x5EC12E7C0DE5EC12E7C0DE5EC12E7C0DE


@pytest.mark.parametrize(
    "call",
    [
        lambda: oracle.sign_attestation(_ANNOUNCEMENT, ("a",), _KEY, (_OTHER,)),
        lambda: oracle.sign_attestation(_ANNOUNCEMENT, ("a",), _OTHER, _NONCES[:1]),
        lambda: oracle.sign_attestation(_ANNOUNCEMENT, ("a",), _SECRET, _NONCES[:1]),
        lambda: oracle.sign_attestation(_ANNOUNCEMENT, ("a",), _KEY, (_SECRET,)),
        lambda: oracle.sign_attestation(_ANNOUNCEMENT, ("a",), _KEY, (_SECRET_BYTES,)),
        lambda: oracle.sign_attestation(
            _ANNOUNCEMENT, ("a",), _SECRET_BYTES, _NONCES[:1]
        ),
        lambda: oracle.sign_announcement(_EVENT, _SECRET),
        lambda: oracle.sign_announcement(_EVENT, _SECRET_BYTES),
    ],
    ids=[
        "other nonce",
        "other key",
        "key out of range",
        "nonce out of range",
        "nonce of the wrong size",
        "key of the wrong size",
        "announcement key out of range",
        "announcement key of the wrong size",
    ],
)
def test_a_refusal_prints_no_secret(call: Any) -> None:
    """A refusal that read a key or a nonce does not print it."""
    with pytest.raises(VALUE_ERRORS) as excinfo:
        call()
    message = str(excinfo.value)
    for secret in (_OTHER, _SECRET):
        assert str(secret) not in message
        assert f"{secret:x}" not in message
    assert _SECRET_BYTES.hex() not in message
    assert repr(_SECRET_BYTES) not in message


@pytest.mark.parametrize(
    "outcomes, fits",
    [
        (("+", "1", "0"), True),
        (("-", "0", "1"), True),
        (("1", "1", "0"), False),
        (("+", "2", "0"), False),
        (("+", "1"), False),
        (("+", "01", "0"), False),
    ],
)
def test_a_signed_digit_decomposition_has_a_sign_and_digits(
    outcomes: tuple[str, ...], fits: bool
) -> None:
    """A signed digit decomposition has a sign and digits."""
    sign = oracle.sign_attestation
    if fits:
        att = sign(_DIGITS_ANNOUNCEMENT, outcomes, _KEY, _NONCES)
        assert oracle.verify_attestation(_DIGITS_ANNOUNCEMENT, att)
    else:
        with pytest.raises(BTClibValueError, match="outcomes are not"):
            sign(_DIGITS_ANNOUNCEMENT, outcomes, _KEY, _NONCES[: len(outcomes)])


def test_an_unsigned_digit_decomposition_has_digits_only() -> None:
    """An unsigned digit decomposition has digits only."""
    descriptor = _replace(_DIGITS, is_signed=False, base=16)
    event = _replace(
        _DIGITS_EVENT, descriptor=descriptor, nonces=_DIGITS_EVENT.nonces[:2]
    )
    announcement = oracle.sign_announcement(event, _KEY)
    att = oracle.sign_attestation(announcement, ("15", "0"), _KEY, _NONCES[:2])
    assert oracle.verify_attestation(announcement, att)
    with pytest.raises(BTClibValueError, match="outcomes are not"):
        oracle.sign_attestation(announcement, ("16", "0"), _KEY, _NONCES[:2])


def test_verify_attestation_answers_false_for_every_mismatch() -> None:
    """Verify attestation answers false for every mismatch."""
    assert oracle.verify_attestation(_ANNOUNCEMENT, _ATTESTATION)
    other_key = oracle.sign_announcement(_EVENT, _KEY + 1)
    for bad in (
        _replace(_ATTESTATION, event_id="f"),
        _replace(_ATTESTATION, public_key=other_key.public_key),
        _replace(_ATTESTATION, outcomes=("c",)),
        _replace(_ATTESTATION, outcomes=("b",)),
        _replace(_ATTESTATION, signatures=(_ATTESTATION.signatures[0][::-1],)),
        _replace(_ATTESTATION, signatures=(), outcomes=()),
    ):
        assert not oracle.verify_attestation(_ANNOUNCEMENT, bad)


def test_an_event_announced_under_another_key_verifies() -> None:
    """An event announced under another key and nonces is attested."""
    peer_key, peer_nonce = _KEY + 1, 23
    event = _replace(_EVENT, nonces=(_x(peer_nonce),))
    resigned = oracle.sign_announcement(event, peer_key)
    assert resigned.public_key != _ANNOUNCEMENT.public_key
    assert oracle.verify_announcement(resigned)
    forged = oracle.sign_attestation(resigned, ("a",), peer_key, (peer_nonce,))
    assert oracle.verify_attestation(resigned, forged)
    assert not oracle.verify_attestation(_ANNOUNCEMENT, forged)


def test_an_attestation_of_another_key_is_not_the_announced_oracles() -> None:
    """Another key's attestation is refused against the oracle's announcement.

    The forger re-signs the oracle's event and reuses its nonces; its own
    announcement verifies and accepts the attestation.
    """
    resigned = oracle.sign_announcement(_EVENT, _KEY + 1)
    assert oracle.verify_announcement(resigned)
    forged = oracle.sign_attestation(resigned, ("a",), _KEY + 1, _NONCES[:1])
    assert oracle.verify_attestation(resigned, forged)
    assert not oracle.verify_attestation(_ANNOUNCEMENT, forged)


def test_verify_attestation_does_not_check_the_announcements_signature() -> None:
    """Verify attestation does not check the announcement's signature."""
    unsigned = _replace(_ANNOUNCEMENT, signature=bytes(64))
    assert not oracle.verify_announcement(unsigned)
    assert oracle.verify_attestation(unsigned, _ATTESTATION)


def test_a_nonce_signing_two_outcomes_is_not_an_attestation_of_the_other() -> None:
    """A nonce signing two outcomes is not an attestation of the other."""
    other = oracle.sign_attestation(_ANNOUNCEMENT, ("b",), _KEY, _NONCES[:1])
    assert oracle.verify_attestation(_ANNOUNCEMENT, other)
    swapped = _replace(_ATTESTATION, signatures=other.signatures)
    assert not oracle.verify_attestation(_ANNOUNCEMENT, swapped)


def test_the_widest_bigsize_is_written_and_read_back() -> None:
    """The widest bigsize is written and read back."""
    wide = oracle._bigsize(2**33)
    assert wide == b"\xff" + (2**33).to_bytes(8, "big")
    assert oracle._Reader(BytesIO(wide)).bigsize() == 2**33


def test_parse_without_the_check_keeps_what_is_complete() -> None:
    """Parse without the check keeps what is complete."""
    bad_announcement = _replace(
        _ANNOUNCEMENT, signature=bytes(64), public_key=bytes(32)
    )
    data = bad_announcement.serialize(check_validity=False)
    with pytest.raises(BTClibValueError, match="not a point"):
        oracle.OracleAnnouncement.parse(data)
    parsed_announcement = oracle.OracleAnnouncement.parse(data, check_validity=False)
    assert parsed_announcement == bad_announcement

    bad_attestation = _replace(_ATTESTATION, public_key=bytes(32))
    data = bad_attestation.serialize(check_validity=False)
    with pytest.raises(BTClibValueError, match="not a point"):
        oracle.OracleAttestation.parse(data)
    parsed_attestation = oracle.OracleAttestation.parse(data, check_validity=False)
    assert parsed_attestation == bad_attestation
