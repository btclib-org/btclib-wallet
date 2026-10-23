# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests of `btclib_wallet.dlc.oracle` against vectors and by property.

The dlcspecs vectors carry each announcement twice, in the fields of its
JSON and inside the serialized offer message. Each file is tested under
the scheme `btclib_wallet.dlc.oracle` says it signs under.
`bitcoin_s_oracle_vectors.json` holds announcements and attestations that
bitcoin-s's own tests check. No dlcspecs vector holds an attestation, so
those are tested by bitcoin-s's, and by signing outcomes with committed
nonces.
"""

from __future__ import annotations

import dataclasses
from typing import Any
from unicodedata import normalize

import pytest
from btclib.exceptions import BTClibValueError
from ecc.curves import mult
from hypothesis import given, settings
from hypothesis import strategies as st

from btclib_wallet import dlc
from tests import load

_FILES = [
    "enum_3_of_3_test.json",
    "enum_3_of_5_test.json",
    "enum_and_numerical_3_of_5_test.json",
    "enum_and_numerical_5_of_5_test.json",
    "enum_and_numerical_with_diff_3_of_5_test.json",
    "enum_and_numerical_with_diff_5_of_5_test.json",
    "enum_single_oracle_test.json",
    "single_oracle_numerical_hyperbola_test.json",
    "single_oracle_numerical_test.json",
    "three_of_five_oracle_numerical_with_diff_test.json",
    "three_of_three_oracle_numerical_test.json",
    "three_of_three_oracle_numerical_with_diff_test.json",
    "two_of_five_oracle_numerical_test.json",
    "two_of_five_oracle_numerical_with_diff_test.json",
]
_BITCOIN_S = load("dlc", "_data", "bitcoin_s_oracle_vectors.json")


def _announcements_of(node: Any) -> list[dict[str, Any]]:
    """Return every announcement object under a vector's JSON node."""
    if isinstance(node, dict):
        if "announcementSignature" in node:
            return [node]
        return [a for v in node.values() for a in _announcements_of(v)]
    if isinstance(node, list):
        return [a for v in node for a in _announcements_of(v)]
    return []


def _descriptor(fields: dict[str, Any]) -> dlc.EnumEventDescriptor | Any:
    if "enumEvent" in fields:
        return dlc.EnumEventDescriptor(outcomes=tuple(fields["enumEvent"]["outcomes"]))
    digits = fields["digitDecompositionEvent"]
    return dlc.DigitDecompositionEventDescriptor(
        base=digits["base"],
        is_signed=digits["isSigned"],
        unit=digits["unit"],
        precision=digits["precision"],
        nb_digits=digits["nbDigits"],
    )


def _from_fields(fields: dict[str, Any]) -> dlc.OracleAnnouncement:
    event = fields["oracleEvent"]
    return dlc.OracleAnnouncement(
        signature=bytes.fromhex(fields["announcementSignature"]),
        public_key=bytes.fromhex(fields["oraclePublicKey"]),
        event=dlc.OracleEvent(
            nonces=tuple(bytes.fromhex(n) for n in event["oracleNonces"]),
            maturity_epoch=event["eventMaturityEpoch"],
            descriptor=_descriptor(event["eventDescriptor"]),
            event_id=event["eventId"],
        ),
    )


@pytest.mark.parametrize("name", _FILES)
def test_announcements_of_the_vectors(name: str) -> None:
    """Round-trip every announcement, and verify it under its own scheme."""
    vector = load("dlc", "_data", "test_vectors", name)
    offer = bytes.fromhex(vector["offer_message"]["serialized"])
    found = _announcements_of(vector["offer_message"]["message"])
    assert found
    for fields in found:
        announcement = _from_fields(fields)
        wire = announcement.serialize()
        assert wire in offer
        assert dlc.OracleAnnouncement.parse(wire) == announcement
        assert dlc.verify_announcement(announcement, scheme=dlc.PLAIN_SHA256)
        assert not dlc.verify_announcement(announcement)


def _bitcoin_s() -> tuple[dict[str, Any], dict[str, Any]]:
    announcements = {
        k: dlc.OracleAnnouncement.parse(bytes.fromhex(v))
        for k, v in _BITCOIN_S["announcements"].items()
    }
    attestations = {
        k: dlc.OracleAttestation.parse(bytes.fromhex(v))
        for k, v in _BITCOIN_S["attestations"].items()
    }
    return announcements, attestations


def test_announcements_of_bitcoin_s_verify_under_the_default() -> None:
    """Verify under TAGGED, and not under PLAIN_SHA256, and round-trip."""
    announcements, _ = _bitcoin_s()
    for name, announcement in announcements.items():
        assert dlc.verify_announcement(announcement)
        assert not dlc.verify_announcement(announcement, scheme=dlc.PLAIN_SHA256)
        assert announcement.serialize().hex() == _BITCOIN_S["announcements"][name]


def test_attestations_of_bitcoin_s() -> None:
    """Verify the valid attestations against their own announcement only."""
    announcements, attestations = _bitcoin_s()
    valid = {
        "validEnumAttestation": "enumAnnouncement",
        "validUnsignedDigitDecompAttestation": "unsignedDigitDecompAnnouncement",
        "validSignedDigitDecompAttestation": "signedDigitDecompAnnouncement",
        "validOutOfOrderNoncesAttestation": "outOfOrderNoncesAnnouncement",
    }
    for name, attestation in attestations.items():
        assert attestation.serialize().hex() == _BITCOIN_S["attestations"][name]
        for announcement_name, announcement in announcements.items():
            expected = valid.get(name) == announcement_name
            assert dlc.verify_attestation(announcement, attestation) is expected


# --- by property ------------------------------------------------------------

_PRV = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
_SCALARS = st.integers(min_value=1, max_value=2**255)


def _event(nonce_keys: list[int], descriptor: Any) -> dlc.OracleEvent:
    return dlc.OracleEvent(
        nonces=tuple(mult(k)[0].to_bytes(32, "big") for k in nonce_keys),
        maturity_epoch=1_700_000_000,
        descriptor=descriptor,
        event_id="event",
    )


@st.composite
def _digit_case(draw: st.DrawFn) -> tuple[Any, tuple[str, ...], list[int]]:
    base = draw(st.integers(min_value=2, max_value=16))
    is_signed = draw(st.booleans())
    nb_digits = draw(st.integers(min_value=1, max_value=4))
    descriptor = dlc.DigitDecompositionEventDescriptor(
        base=base, is_signed=is_signed, unit="u", precision=0, nb_digits=nb_digits
    )
    digits = [str(draw(st.integers(0, base - 1))) for _ in range(nb_digits)]
    outcomes = ([draw(st.sampled_from("+-"))] if is_signed else []) + digits
    keys = draw(
        st.lists(
            _SCALARS,
            min_size=descriptor.nonce_count,
            max_size=descriptor.nonce_count,
            unique=True,
        )
    )
    return descriptor, tuple(outcomes), keys


@settings(max_examples=40)
@given(case=_digit_case(), scheme=st.sampled_from([dlc.TAGGED, dlc.PLAIN_SHA256]))
def test_a_signed_digit_attestation_verifies(
    case: tuple[Any, tuple[str, ...], list[int]], scheme: str
) -> None:
    """Sign digits with the committed nonces, and verify the attestation."""
    descriptor, outcomes, keys = case
    announcement = dlc.sign_announcement(
        _event(keys, descriptor),
        _PRV,
        scheme=scheme,  # type: ignore[arg-type]
    )
    assert dlc.verify_announcement(announcement, scheme=scheme)  # type: ignore[arg-type]
    attestation = dlc.sign_attestation(announcement, outcomes, _PRV, tuple(keys))
    assert dlc.verify_attestation(announcement, attestation)
    assert dlc.OracleAttestation.parse(attestation.serialize()) == attestation
    # another outcome, and the signatures in another order
    other = tuple(
        str((int(o) + 1) % descriptor.base) if o.isdigit() else o for o in outcomes
    )
    moved = dataclasses.replace(attestation, outcomes=other)
    assert not dlc.verify_attestation(announcement, moved)
    if len(keys) > 1:
        swapped = dataclasses.replace(
            attestation, signatures=attestation.signatures[::-1]
        )
        assert not dlc.verify_attestation(announcement, swapped)


# printable names that are NFC and cannot compose with one another, so that
# the descriptor takes every draw
_NAME_CHARS = st.characters(codec="utf-8", categories=["Lu", "Ll", "Nd"]).filter(
    lambda c: normalize("NFC", c) == c
)


@settings(max_examples=40)
@given(
    nonce=_SCALARS,
    other_offset=st.integers(min_value=1, max_value=2**200),
    names=st.lists(
        st.text(alphabet=_NAME_CHARS, min_size=1, max_size=8),
        min_size=2,
        max_size=5,
        unique=True,
    ),
)
def test_an_enum_attestation_verifies_only_its_own(
    nonce: int, other_offset: int, names: list[str]
) -> None:
    """Fail an attestation for another outcome, nonce or event."""
    other_nonce = nonce + other_offset
    descriptor = dlc.EnumEventDescriptor(outcomes=tuple(names))
    announcement = dlc.sign_announcement(_event([nonce], descriptor), _PRV)
    attestation = dlc.sign_attestation(announcement, (names[0],), _PRV, (nonce,))
    assert dlc.verify_attestation(announcement, attestation)
    wrong_outcome = dataclasses.replace(attestation, outcomes=(names[1],))
    assert not dlc.verify_attestation(announcement, wrong_outcome)
    # a signature of the same outcome with another nonce
    foreign = dlc.sign_attestation(
        dlc.sign_announcement(_event([other_nonce], descriptor), _PRV),
        (names[0],),
        _PRV,
        (other_nonce,),
    )
    assert not dlc.verify_attestation(announcement, foreign)
    renamed = dataclasses.replace(attestation, event_id="another")
    assert not dlc.verify_attestation(announcement, renamed)
    with pytest.raises(BTClibValueError):
        dlc.sign_attestation(announcement, (names[0],), _PRV, (other_nonce,))
