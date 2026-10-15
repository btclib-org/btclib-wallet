# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""DLC oracle announcements and attestations, parsed and checked offline.

https://github.com/discreetlogcontracts/dlcspecs/blob/master/Oracle.md
https://github.com/discreetlogcontracts/dlcspecs/blob/master/Messaging.md

An oracle announces an event before it happens: the nonces it will sign
with, when it will attest, and what the outcomes are. After the event it
attests with one BIP340 signature per nonce. Nothing here asks the oracle
anything: `OracleAnnouncement.parse` and `OracleAttestation.parse` read
the TLVs, and `verify_announcement` and `verify_attestation` check them.

**An announcement's signature has two schemes**, named by the caller:

- `TAGGED`, the default, is the specification's: a BIP340 signature over
  the tagged hash `DLC/oracle/announcement/v0` of the serialized
  `oracle_event`, header included, which is what bitcoin-s does.
- `PLAIN_SHA256` is the plain sha256 of the `oracle_event`'s value,
  header excluded, which is what every announcement of the dlcspecs
  vectors carries.

A signature under one scheme is not valid under the other.

**The caller pins the oracle's key.** `verify_announcement` checks the
signature against the key the announcement carries, and
`verify_attestation` against that same key, so an event announced under
anyone's key, with nonces of their own, verifies and is attested. A caller
compares `announcement.public_key` with the oracle's key it already trusts,
and checks the announcement with `verify_announcement` before checking an
attestation against it: `verify_attestation` does not check the
announcement's signature.

**An attestation signs each outcome** as a BIP340 signature, with the
nonce the announcement committed to, of the tagged hash
`DLC/oracle/attestation/v0` of the outcome's UTF-8 text. The signatures
and the outcomes are in the order of the nonces. A signed digit
decomposition has the sign, `+` or `-`, first, and then each digit in
base 10, however large the base.

**The base of a digit decomposition is a `u16` on the wire**, where
Messaging.md says `bigsize`: the dlcspecs vectors and bitcoin-s write
two octets.

**Strings are NFC** UTF-8, and a string that is not is refused: that is
Messaging.md's `string` type, and Oracle.md has each outcome normalized
before it is signed, so that one outcome is not signed under two
spellings.

**An enum's outcomes are distinct.** An outcome is signed by its text, so
a repeated one names no second outcome: the specification is silent, and
this package refuses it.

**Every class checks itself** in `assert_valid`. `parse` and `serialize`
call it unless `check_validity` is false; the signing and verifying
functions always call it on the objects they are given. `parse` checks how
long each value is, and where it ends, whatever `check_validity` says.

**A nonce signs one message.** `sign_attestation` takes the nonces' secret
keys, and two signatures with one nonce reveal the oracle's key. A
refusal never prints a key or a nonce.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO
from typing import Literal

from btclib.alias import BinaryData, Integer
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import (
    assert_no_trailing,
    assert_type,
    bytesio_from_binarydata,
    is_integer,
    read_exactly,
)
from btclib_ecc.curves import mult, scalar_from_prv_key
from btclib_ecc.ecc import dlc_oracle, ssa
from btclib_ecc.hashes import tagged_hash

__all__ = [
    "PLAIN_SHA256",
    "TAGGED",
    "DigitDecompositionEventDescriptor",
    "EnumEventDescriptor",
    "OracleAnnouncement",
    "OracleAttestation",
    "OracleEvent",
    "outcome_message",
    "sign_announcement",
    "sign_attestation",
    "verify_announcement",
    "verify_attestation",
]

_Scheme = Literal["tagged", "sha256"]
TAGGED: _Scheme = "tagged"
PLAIN_SHA256: _Scheme = "sha256"

_ENUM_TYPE = 55302
_DIGITS_TYPE = 55306
_EVENT_TYPE = 55330
_ANNOUNCEMENT_TYPE = 55332
_ATTESTATION_TYPE = 55400

_ANNOUNCEMENT_TAG = b"DLC/oracle/announcement/v0"
_ATTESTATION_TAG = b"DLC/oracle/attestation/v0"

_U16 = 0xFFFF
_U32 = 0xFFFFFFFF
_I32 = 0x80000000


# --- the wire ---------------------------------------------------------------


def _int_bytes(value: int, size: int, what: str, *, signed: bool) -> bytes:
    try:
        return value.to_bytes(size, "big", signed=signed)
    except OverflowError:
        raise BTClibValueError(f"{what} out of range") from None


def _bigsize(value: int) -> bytes:
    if value < 0xFD:
        return bytes([value])
    if value <= _U16:
        return b"\xfd" + value.to_bytes(2, "big")
    if value <= _U32:
        return b"\xfe" + value.to_bytes(4, "big")
    return b"\xff" + value.to_bytes(8, "big")


def _string(text: str) -> bytes:
    data = text.encode()
    return _bigsize(len(data)) + data


def _tlv(tlv_type: int, payload: bytes) -> bytes:
    return _bigsize(tlv_type) + _bigsize(len(payload)) + payload


class _Reader:
    """The octets of one value, read from the front and read to the end."""

    def __init__(self, stream: BytesIO) -> None:
        self.stream = stream

    def take(self, size: int) -> bytes:
        return read_exactly(self.stream, size, "oracle TLV")

    def uint(self, size: int) -> int:
        return int.from_bytes(self.take(size), "big")

    def bigsize(self) -> int:
        first = self.take(1)[0]
        if first < 0xFD:
            return first
        size, floor = {0xFD: (2, 0xFD), 0xFE: (4, 0x10000)}.get(first, (8, 0x100000000))
        value = self.uint(size)
        if value < floor:
            raise BTClibValueError("bigsize is not minimally encoded")
        return value

    def string(self) -> str:
        data = self.take(self.bigsize())
        try:
            return data.decode()
        except UnicodeDecodeError:
            raise BTClibValueError("a string is not UTF-8") from None

    def tlv(self, *types: int) -> tuple[int, _Reader]:
        """Return the type and the reader of the value of the next TLV."""
        tlv_type = self.bigsize()
        if tlv_type not in types:
            raise BTClibValueError(f"unexpected TLV type {tlv_type}")
        return tlv_type, _Reader(BytesIO(self.take(self.bigsize())))

    def end(self) -> None:
        if self.stream.read(1):
            raise BTClibValueError("trailing octets in an oracle TLV")


def _assert_string(value: object, what: str) -> None:
    assert_type(value, str, what)
    try:
        value.encode()  # type: ignore[attr-defined]
    except UnicodeEncodeError:
        raise BTClibValueError(f"{what} is not UTF-8") from None
    if unicodedata.normalize("NFC", value) != value:  # type: ignore[arg-type]
        raise BTClibValueError(f"{what} is not NFC normalized")


def _assert_int(value: object, what: str, *, low: int, high: int) -> None:
    if not is_integer(value):
        raise BTClibTypeError(f"invalid {what} type: {type(value).__name__}")
    if not low <= value <= high:  # type: ignore[operator]
        raise BTClibValueError(f"{what} out of range")


def _assert_x_only(value: object, what: str) -> None:
    assert_type(value, bytes, what)
    if len(value) != 32:  # type: ignore[arg-type]
        raise BTClibValueError(f"{what} is not 32 octets")
    try:
        ssa.point_from_bip340pub_key_var(value)  # type: ignore[arg-type]
    except ValueError:
        raise BTClibValueError(f"{what} is not a point") from None


def _assert_signature(value: object, what: str) -> None:
    assert_type(value, bytes, what)
    if len(value) != 64:  # type: ignore[arg-type]
        raise BTClibValueError(f"{what} is not 64 octets")


# --- the event --------------------------------------------------------------


@dataclass(frozen=True, kw_only=True)
class EnumEventDescriptor:
    """An event with a list of outcomes, one of which the oracle signs."""

    outcomes: tuple[str, ...]

    def assert_valid(self) -> None:
        """Refuse no outcomes, too many, or outcomes not NFC or repeated."""
        assert_type(self.outcomes, tuple, "outcomes")
        if not 1 <= len(self.outcomes) <= _U16:
            raise BTClibValueError("an enum event has 1 to 65535 outcomes")
        for outcome in self.outcomes:
            _assert_string(outcome, "outcome")
        if len(set(self.outcomes)) != len(self.outcomes):
            raise BTClibValueError("the outcomes are not distinct")

    @property
    def nonce_count(self) -> int:
        """Return how many nonces the oracle commits to."""
        return 1

    def _payload(self) -> bytes:
        count = _int_bytes(len(self.outcomes), 2, "count of outcomes", signed=False)
        return count + b"".join(_string(o) for o in self.outcomes)

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the TLV of the descriptor."""
        if check_validity:
            self.assert_valid()
        return _tlv(_ENUM_TYPE, self._payload())


@dataclass(frozen=True, kw_only=True)
class DigitDecompositionEventDescriptor:
    """An event with a number, signed digit by digit."""

    base: int
    is_signed: bool
    unit: str
    precision: int
    nb_digits: int

    def assert_valid(self) -> None:
        """Refuse a base, a count of digits or a unit that cannot be signed."""
        _assert_int(self.base, "base", low=2, high=_U16)
        assert_type(self.is_signed, bool, "is_signed")
        _assert_string(self.unit, "unit")
        _assert_int(self.precision, "precision", low=-_I32, high=_I32 - 1)
        _assert_int(self.nb_digits, "number of digits", low=1, high=_U16)
        # the event writes its count of nonces as a u16, a sign included
        if self.nonce_count > _U16:
            raise BTClibValueError("the digits need more nonces than an event holds")

    @property
    def nonce_count(self) -> int:
        """Return how many nonces the oracle commits to."""
        return self.nb_digits + int(self.is_signed)

    def _payload(self) -> bytes:
        return (
            _int_bytes(self.base, 2, "base", signed=False)
            + bytes([int(self.is_signed)])
            + _string(self.unit)
            + _int_bytes(self.precision, 4, "precision", signed=True)
            + _int_bytes(self.nb_digits, 2, "number of digits", signed=False)
        )

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the TLV of the descriptor."""
        if check_validity:
            self.assert_valid()
        return _tlv(_DIGITS_TYPE, self._payload())


_EventDescriptor = EnumEventDescriptor | DigitDecompositionEventDescriptor


def _read_descriptor(reader: _Reader) -> _EventDescriptor:
    tlv_type, body = reader.tlv(_ENUM_TYPE, _DIGITS_TYPE)
    descriptor: _EventDescriptor
    if tlv_type == _ENUM_TYPE:
        count = body.uint(2)
        descriptor = EnumEventDescriptor(
            outcomes=tuple(body.string() for _ in range(count))
        )
    else:
        base = body.uint(2)
        flag = body.uint(1)
        if flag > 1:
            raise BTClibValueError("is_signed is not a bool")
        unit = body.string()
        precision = int.from_bytes(body.take(4), "big", signed=True)
        descriptor = DigitDecompositionEventDescriptor(
            base=base,
            is_signed=bool(flag),
            unit=unit,
            precision=precision,
            nb_digits=body.uint(2),
        )
    body.end()
    return descriptor


@dataclass(frozen=True, kw_only=True)
class OracleEvent:
    """What an oracle commits to before an event: its nonces and outcomes."""

    nonces: tuple[bytes, ...]
    maturity_epoch: int
    descriptor: _EventDescriptor
    event_id: str

    def assert_valid(self) -> None:
        """Refuse an event whose nonces do not fit its descriptor."""
        assert_type(self.nonces, tuple, "nonces")
        for nonce in self.nonces:
            _assert_x_only(nonce, "nonce")
        _assert_int(self.maturity_epoch, "maturity", low=0, high=_U32)
        assert_type(
            self.descriptor,
            (EnumEventDescriptor, DigitDecompositionEventDescriptor),
            "descriptor",
        )
        self.descriptor.assert_valid()
        _assert_string(self.event_id, "event id")
        if len(self.nonces) != self.descriptor.nonce_count:
            raise BTClibValueError("the nonces do not fit the descriptor")
        if len(set(self.nonces)) != len(self.nonces):
            raise BTClibValueError("the nonces are not distinct")

    def _payload(self) -> bytes:
        return (
            _int_bytes(len(self.nonces), 2, "count of nonces", signed=False)
            + b"".join(self.nonces)
            + _int_bytes(self.maturity_epoch, 4, "maturity", signed=False)
            + self.descriptor.serialize(check_validity=False)
            + _string(self.event_id)
        )

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the `oracle_event` TLV."""
        if check_validity:
            self.assert_valid()
        return _tlv(_EVENT_TYPE, self._payload())

    @classmethod
    def _read(cls, reader: _Reader) -> OracleEvent:
        _, body = reader.tlv(_EVENT_TYPE)
        count = body.uint(2)
        nonces = tuple(body.take(32) for _ in range(count))
        maturity = body.uint(4)
        descriptor = _read_descriptor(body)
        event = cls(
            nonces=nonces,
            maturity_epoch=maturity,
            descriptor=descriptor,
            event_id=body.string(),
        )
        body.end()
        return event

    @classmethod
    def parse(cls, data: BinaryData, *, check_validity: bool = True) -> OracleEvent:
        """Return the event of its TLV.

        Octets are one event and bytes after it are refused. A stream is
        left on the byte after the event.
        """
        stream = bytesio_from_binarydata(data)
        event = cls._read(_Reader(stream))
        assert_no_trailing(data, stream, "oracle event")
        if check_validity:
            event.assert_valid()
        return event


# --- the announcement -------------------------------------------------------


def _announcement_message(event: OracleEvent, scheme: _Scheme) -> bytes:
    if scheme == TAGGED:
        return tagged_hash(_ANNOUNCEMENT_TAG, event.serialize(check_validity=False))
    return sha256(event._payload()).digest()


def _assert_scheme(scheme: object) -> None:
    assert_type(scheme, str, "scheme")
    if scheme not in (TAGGED, PLAIN_SHA256):
        raise BTClibValueError("unknown announcement signature scheme")


@dataclass(frozen=True, kw_only=True)
class OracleAnnouncement:
    """An oracle's event, with its key and the signature of that event.

    Whether the signature is valid is `verify_announcement`'s to say, under
    the scheme the caller names. Whose key it is, is the caller's to pin: see
    the module docstring.
    """

    signature: bytes
    public_key: bytes
    event: OracleEvent

    def assert_valid(self) -> None:
        """Refuse a signature not 64 octets, a non-point key or a bad event."""
        _assert_signature(self.signature, "announcement signature")
        _assert_x_only(self.public_key, "oracle public key")
        assert_type(self.event, OracleEvent, "event")
        self.event.assert_valid()

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the `oracle_announcement` TLV."""
        if check_validity:
            self.assert_valid()
        return _tlv(
            _ANNOUNCEMENT_TYPE,
            self.signature
            + self.public_key
            + self.event.serialize(check_validity=False),
        )

    @classmethod
    def parse(
        cls, data: BinaryData, *, check_validity: bool = True
    ) -> OracleAnnouncement:
        """Return the announcement of its TLV.

        Octets are one announcement and bytes after it are refused. A
        stream is left on the byte after the announcement.
        """
        stream = bytesio_from_binarydata(data)
        _, body = _Reader(stream).tlv(_ANNOUNCEMENT_TYPE)
        assert_no_trailing(data, stream, "oracle announcement")
        signature = body.take(64)
        public_key = body.take(32)
        event = OracleEvent._read(body)
        body.end()
        announcement = cls(signature=signature, public_key=public_key, event=event)
        if check_validity:
            announcement.assert_valid()
        return announcement


def sign_announcement(
    event: OracleEvent,
    prv_key: Integer,
    *,
    scheme: _Scheme = TAGGED,
) -> OracleAnnouncement:
    """Return the announcement of event, signed by the oracle's key."""
    assert_type(event, OracleEvent, "event")
    event.assert_valid()
    _assert_scheme(scheme)
    q, x_q = ssa.gen_keys(scalar_from_prv_key(prv_key))
    sig = ssa.sign_(_announcement_message(event, scheme), q)
    return OracleAnnouncement(
        signature=sig.serialize(),
        public_key=x_q.to_bytes(32, "big"),
        event=event,
    )


def verify_announcement(
    announcement: OracleAnnouncement, *, scheme: _Scheme = TAGGED
) -> bool:
    """Return whether the announcement's signature is valid under the scheme.

    It is checked against `announcement.public_key`, which the caller pins as
    the module docstring says.
    """
    assert_type(announcement, OracleAnnouncement, "announcement")
    announcement.assert_valid()
    _assert_scheme(scheme)
    return ssa.verify_(
        _announcement_message(announcement.event, scheme),
        announcement.public_key,
        announcement.signature,
    )


# --- the attestation --------------------------------------------------------


def outcome_message(outcome: str) -> bytes:
    """Return the 32 octets the oracle signs to attest an outcome."""
    _assert_string(outcome, "outcome")
    return tagged_hash(_ATTESTATION_TAG, outcome.encode())


def _outcomes_fit(descriptor: _EventDescriptor, outcomes: tuple[str, ...]) -> bool:
    """Return whether outcomes are what the descriptor lets an oracle sign."""
    if len(outcomes) != descriptor.nonce_count:
        return False
    if isinstance(descriptor, EnumEventDescriptor):
        return outcomes[0] in descriptor.outcomes
    digits = outcomes[1:] if descriptor.is_signed else outcomes
    if descriptor.is_signed and outcomes[0] not in ("+", "-"):
        return False
    allowed = {str(d) for d in range(descriptor.base)}
    return all(d in allowed for d in digits)


@dataclass(frozen=True, kw_only=True)
class OracleAttestation:
    """The signatures with which an oracle attests the outcome of an event."""

    event_id: str
    public_key: bytes
    signatures: tuple[bytes, ...]
    outcomes: tuple[str, ...]

    def assert_valid(self) -> None:
        """Refuse signatures and outcomes that are not pairs."""
        _assert_string(self.event_id, "event id")
        _assert_x_only(self.public_key, "oracle public key")
        assert_type(self.signatures, tuple, "signatures")
        assert_type(self.outcomes, tuple, "outcomes")
        if len(self.signatures) > _U16:
            raise BTClibValueError("too many signatures")
        for signature in self.signatures:
            _assert_signature(signature, "attestation signature")
        for outcome in self.outcomes:
            _assert_string(outcome, "outcome")
        if len(self.outcomes) != len(self.signatures):
            raise BTClibValueError("the outcomes and the signatures differ in number")

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the `oracle_attestation` TLV."""
        if check_validity:
            self.assert_valid()
        return _tlv(
            _ATTESTATION_TYPE,
            _string(self.event_id)
            + self.public_key
            + _int_bytes(len(self.signatures), 2, "count of signatures", signed=False)
            + b"".join(self.signatures)
            + b"".join(_string(o) for o in self.outcomes),
        )

    @classmethod
    def parse(
        cls, data: BinaryData, *, check_validity: bool = True
    ) -> OracleAttestation:
        """Return the attestation of its TLV.

        Octets are one attestation and bytes after it are refused. A
        stream is left on the byte after the attestation.
        """
        stream = bytesio_from_binarydata(data)
        _, body = _Reader(stream).tlv(_ATTESTATION_TYPE)
        assert_no_trailing(data, stream, "oracle attestation")
        event_id = body.string()
        public_key = body.take(32)
        count = body.uint(2)
        signatures = tuple(body.take(64) for _ in range(count))
        outcomes = tuple(body.string() for _ in range(count))
        body.end()
        attestation = cls(
            event_id=event_id,
            public_key=public_key,
            signatures=signatures,
            outcomes=outcomes,
        )
        if check_validity:
            attestation.assert_valid()
        return attestation


def sign_attestation(
    announcement: OracleAnnouncement,
    outcomes: tuple[str, ...],
    prv_key: Integer,
    nonces: tuple[Integer, ...],
) -> OracleAttestation:
    """Return the attestation of outcomes, signed with the committed nonces.

    `nonces` are the secret keys of the announcement's nonces, in their
    order.
    """
    assert_type(announcement, OracleAnnouncement, "announcement")
    announcement.assert_valid()
    assert_type(outcomes, tuple, "outcomes")
    for outcome in outcomes:
        _assert_string(outcome, "outcome")
    assert_type(nonces, tuple, "nonces")
    event = announcement.event
    if not _outcomes_fit(event.descriptor, outcomes):
        raise BTClibValueError("the outcomes are not the event's")
    q, x_q = ssa.gen_keys(scalar_from_prv_key(prv_key))
    if x_q.to_bytes(32, "big") != announcement.public_key:
        raise BTClibValueError("the key is not the announcement's")
    secrets = [scalar_from_prv_key(n) for n in nonces]
    committed = [mult(k)[0].to_bytes(32, "big") for k in secrets]
    if tuple(committed) != event.nonces:
        raise BTClibValueError("the nonces are not the announcement's")
    signatures = tuple(
        dlc_oracle.sign_(outcome_message(o), q, k).serialize()
        for o, k in zip(outcomes, secrets, strict=True)
    )
    return OracleAttestation(
        event_id=event.event_id,
        public_key=announcement.public_key,
        signatures=signatures,
        outcomes=outcomes,
    )


def verify_attestation(
    announcement: OracleAnnouncement, attestation: OracleAttestation
) -> bool:
    """Return whether attestation attests an outcome of the announced event.

    It must come from the announced oracle and event, sign with the
    committed nonces in their order, name outcomes the event allows, and
    carry a valid signature of each. The announcement is taken as given: the
    caller has had `verify_announcement` accept it and has pinned its key, as
    the module docstring says.
    """
    assert_type(announcement, OracleAnnouncement, "announcement")
    announcement.assert_valid()
    assert_type(attestation, OracleAttestation, "attestation")
    attestation.assert_valid()
    event = announcement.event
    if (
        attestation.event_id != event.event_id
        or attestation.public_key != announcement.public_key
        or not _outcomes_fit(event.descriptor, attestation.outcomes)
    ):
        return False
    return all(
        sig[:32] == nonce
        and ssa.verify_(outcome_message(outcome), attestation.public_key, sig)
        for sig, nonce, outcome in zip(
            attestation.signatures, event.nonces, attestation.outcomes, strict=True
        )
    )
