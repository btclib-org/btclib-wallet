# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The transactions of a DLC: funding, contract execution and refund.

https://github.com/discreetlogcontracts/dlcspecs/blob/master/Transactions.md

The funding transaction pays both parties' collateral, and the fee of
the transaction that will later spend it, to a 2-of-2 P2WSH. A contract
execution transaction (CET) per outcome, and the refund transaction,
each spend that output to the parties' payout scripts. Two parties who
build these from the same terms get the same bytes, which is what lets
each sign the other's.

**Inputs are sorted by serial id.** So are the outputs of the funding
transaction (the funding output and the two change outputs) and those of
a CET or of the refund (the two payouts). A payout under 1000 satoshis
is not produced.

**Fees** follow the specification's expected weights, a rate in
satoshis per virtual byte. The funding transaction's fee is taken from
each party's change, and so is the fee of the CET that will spend the
funding output, which is added to the funding output: a CET pays its
outcome's payouts in full and carries no fee of its own to subtract.

**The unsigned transactions carry the funding witness script** as the
only witness item of the input of a CET or of the refund, which is how
the specification's vectors write them; `btclib_wallet.dlc.signing`
completes the stack.

**The funding output's index** is where the serial ids put it. The
specification's text says 0, but it sorts the outputs by serial id, and
bitcoin-s follows the sorting. The dlcspecs vectors put the funding output
first.

**A change under the dust limit is refused.** The specification asks the
party to add funding until it is not, and bitcoin-s drops the output
instead, which gives the value to the miners. No vector has such a
change.

**A collateral under the dust limit is accepted.** Protocol.md has the
sender of an offer set `offer_collateral_satoshis` to at least 1000, and
lets the receiver reject an offer under it. `Dlc` holds terms that both
parties have agreed, and the receiver builds them too, so a rule that
binds the sender is not enforced; terms that cannot be built are refused
by the dust checks.

**The refund opens after the CETs, in the same unit.** Protocol.md
requires the CET lock time to be less than the refund's, and both to be
heights or both timestamps. A refund that opens no later lets the loser
take the collateral back before the oracle attests, and a height cannot
be compared with a timestamp.
"""

from __future__ import annotations

from dataclasses import dataclass

from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash160
from btclib.key import PubKeyData
from btclib.script.script_pub_key import (
    ScriptPubKey,
    is_p2pkh,
    is_p2sh,
    is_p2wpkh,
    is_p2wsh,
    is_segwit,
)
from btclib.script.witness import Witness
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from btclib.utils import assert_type, is_integer
from ecc.curves import point_from_pub_key

__all__ = [
    "CET_SEQUENCE",
    "DUST_LIMIT",
    "Dlc",
    "DlcParty",
    "DlcTransactions",
    "FundingInput",
    "build_cet",
    "build_funding_tx",
    "build_refund_tx",
    "build_transactions",
    "closing_fee",
    "funding_fee",
    "funding_script",
    "funding_script_pub_key",
]

# the value under which a payout is not made, and a change is refused
DUST_LIMIT = 1000

# the sequence of the input of a CET and of the refund: final, but for
# enabling their lock times
CET_SEQUENCE = 0xFFFFFFFE

_FINAL_SEQUENCE = 0xFFFFFFFF
_LOCKTIME_THRESHOLD = 500_000_000
_MAX_U32 = 0xFFFFFFFF
_MAX_U64 = 0xFFFFFFFFFFFFFFFF
_MAX_VALUE = 21_000_000 * 10**8


def _assert_int(value: object, what: str, *, low: int, high: int) -> None:
    if not is_integer(value):
        raise BTClibTypeError(f"invalid {what} type: {type(value).__name__}")
    if not low <= value <= high:  # type: ignore[operator]
        raise BTClibValueError(f"{what} out of range: {value}")


def _assert_bytes(value: object, what: str) -> None:
    assert_type(value, bytes, what)


def _assert_standard(spk: bytes, what: str) -> None:
    """Refuse a script that is not one of Protocol.md's standard forms.

    Those are P2PKH, P2SH, P2WPKH, P2WSH, and a witness program of version
    1 to 16 of 2 to 40 bytes, taproot included.
    """
    witness_program = is_segwit(spk) and spk[0] != 0
    if not (
        is_p2pkh(spk)
        or is_p2sh(spk)
        or is_p2wpkh(spk)
        or is_p2wsh(spk)
        or witness_program
    ):
        raise BTClibValueError(f"the {what} is not a standard script")


@dataclass(frozen=True, kw_only=True)
class FundingInput:
    """An output of `prev_tx` that a party spends into the funding transaction.

    It is native SegWit, or P2SH wrapping a SegWit v0 script whose
    `redeem_script` is then given. `max_witness_len` is the size of the
    serialized witness the spend will carry, its item count included, as
    the specification's example counts it.
    """

    serial_id: int
    prev_tx: Tx
    prev_vout: int
    max_witness_len: int
    redeem_script: bytes = b""
    sequence: int = _FINAL_SEQUENCE

    def __post_init__(self) -> None:
        """Refuse an input that cannot be spent as the specification asks."""
        _assert_int(self.serial_id, "serial id", low=0, high=_MAX_U64)
        assert_type(self.prev_tx, Tx, "prev_tx")
        _assert_int(self.prev_vout, "prev_vout", low=0, high=_MAX_U32)
        _assert_int(self.max_witness_len, "max_witness_len", low=0, high=_MAX_U32)
        _assert_bytes(self.redeem_script, "redeem script")
        _assert_int(self.sequence, "sequence", low=0, high=_MAX_U32)
        if self.prev_vout >= len(self.prev_tx.vout):
            raise BTClibValueError(f"no output {self.prev_vout} in the previous tx")
        spk = self.prev_tx.vout[self.prev_vout].script_pub_key.script
        if self.redeem_script:
            if not is_p2sh(spk) or hash160(self.redeem_script) != spk[2:22]:
                raise BTClibValueError("the redeem script is not the output's")
            if not (is_p2wpkh(self.redeem_script) or is_p2wsh(self.redeem_script)):
                raise BTClibValueError("the redeem script is not a SegWit v0 one")
        elif not is_segwit(spk):
            raise BTClibValueError("a funding input must be SegWit")

    @property
    def out_point(self) -> OutPoint:
        """Return the output this input spends."""
        return OutPoint(self.prev_tx.id, self.prev_vout)

    @property
    def value(self) -> int:
        """Return the value of the output this input spends."""
        return self.prev_tx.vout[self.prev_vout].value

    @property
    def script_sig_len(self) -> int:
        """Return the size of the script_sig, which is 0 when there is none."""
        return 1 + len(self.redeem_script) if self.redeem_script else 0

    @property
    def script_sig(self) -> bytes:
        """Return the script_sig, the redeem script pushed if there is one."""
        if not self.redeem_script:
            return b""
        return bytes([len(self.redeem_script)]) + self.redeem_script


@dataclass(frozen=True, kw_only=True)
class DlcParty:
    """What one party of a DLC puts in and takes out.

    `funding_pub_key` is the compressed key of the party's half of the
    funding output. The party pays `collateral` and the fees of its own
    part from `inputs`, and gets the rest back at `change_spk`.
    """

    funding_pub_key: bytes
    payout_spk: bytes
    payout_serial_id: int
    change_spk: bytes
    change_serial_id: int
    collateral: int
    inputs: tuple[FundingInput, ...]

    def __post_init__(self) -> None:
        """Refuse a party whose fields are of the wrong type, form or range."""
        _assert_bytes(self.funding_pub_key, "funding public key")
        if len(self.funding_pub_key) != 33:
            raise BTClibValueError("the funding public key is not compressed")
        point_from_pub_key(self.funding_pub_key)
        _assert_bytes(self.payout_spk, "payout script")
        _assert_bytes(self.change_spk, "change script")
        _assert_int(self.payout_serial_id, "payout serial id", low=0, high=_MAX_U64)
        _assert_int(self.change_serial_id, "change serial id", low=0, high=_MAX_U64)
        _assert_int(self.collateral, "collateral", low=0, high=_MAX_VALUE)
        assert_type(self.inputs, tuple, "inputs")
        for funding_input in self.inputs:
            assert_type(funding_input, FundingInput, "funding input")
        if not self.inputs:
            raise BTClibValueError("a party needs at least one funding input")


@dataclass(frozen=True, kw_only=True)
class Dlc:
    """The terms two parties agree on, from which every transaction follows.

    `offer_payouts[i]` is what the offerer gets in the CET of outcome i;
    the accepter gets the rest of the two collaterals.
    """

    offer: DlcParty
    accept: DlcParty
    fund_output_serial_id: int
    fee_rate: int
    offer_payouts: tuple[int, ...]
    cet_locktime: int
    refund_locktime: int

    def __post_init__(self) -> None:
        """Refuse terms that two parties cannot build the same bytes from."""
        assert_type(self.offer, DlcParty, "offer")
        assert_type(self.accept, DlcParty, "accept")
        _assert_int(self.fund_output_serial_id, "serial id", low=0, high=_MAX_U64)
        _assert_int(self.fee_rate, "fee rate", low=0, high=_MAX_U64)
        _assert_int(self.cet_locktime, "CET locktime", low=0, high=_MAX_U32)
        _assert_int(self.refund_locktime, "refund locktime", low=0, high=_MAX_U32)
        if (self.cet_locktime < _LOCKTIME_THRESHOLD) != (
            self.refund_locktime < _LOCKTIME_THRESHOLD
        ):
            raise BTClibValueError("the lock times are a height and a timestamp")
        if self.cet_locktime >= self.refund_locktime:
            raise BTClibValueError("the refund lock time is not after the CETs'")
        assert_type(self.offer_payouts, tuple, "offer payouts")
        total = self.offer.collateral + self.accept.collateral
        for payout in self.offer_payouts:
            _assert_int(payout, "payout", low=0, high=total)
        if self.offer.funding_pub_key == self.accept.funding_pub_key:
            raise BTClibValueError("both parties have the same funding key")
        serials = [self.offer.payout_serial_id, self.accept.payout_serial_id]
        if len(set(serials)) != len(serials):
            raise BTClibValueError("the payout serial ids are not distinct")
        serials = [
            self.fund_output_serial_id,
            self.offer.change_serial_id,
            self.accept.change_serial_id,
        ]
        if len(set(serials)) != len(serials):
            raise BTClibValueError("the funding output serial ids are not distinct")
        funding_spk = _funding_spk_of(self.offer, self.accept)
        # `build_funding_tx` finds the funding output by its script
        if funding_spk in (self.offer.change_spk, self.accept.change_spk):
            raise BTClibValueError("a change script is the funding script")
        self._assert_not_dust(total)
        _assert_standard(self.offer.payout_spk, "payout script")
        _assert_standard(self.offer.change_spk, "change script")
        _assert_standard(self.accept.payout_spk, "payout script")
        _assert_standard(self.accept.change_spk, "change script")
        ids = [i.serial_id for i in self.offer.inputs + self.accept.inputs]
        if len(set(ids)) != len(ids):
            raise BTClibValueError("the input serial ids are not distinct")
        outpoints = [i.out_point for i in self.offer.inputs + self.accept.inputs]
        if len(set(outpoints)) != len(outpoints):
            raise BTClibValueError("an output is spent twice")

    def _assert_not_dust(self, total: int) -> None:
        """Refuse terms whose funding output or whose transactions are dust."""
        # a party whose inputs leave less than the dust limit of change
        # cannot fund its share
        _change(self.offer, self.fee_rate)
        _change(self.accept, self.fee_rate)
        closing = closing_fee(self.offer, self.fee_rate) + closing_fee(
            self.accept, self.fee_rate
        )
        if total + closing < DUST_LIMIT:
            raise BTClibValueError("the funding output is under the dust limit")
        # one party under the dust limit is valid, its output is left
        # out; a transaction with no output at all cannot be built
        if max(self.offer.collateral, self.accept.collateral) < DUST_LIMIT:
            raise BTClibValueError("the refund would have no output: dust")
        for payout in self.offer_payouts:
            if max(payout, total - payout) < DUST_LIMIT:
                raise BTClibValueError("a CET would have no output: dust")


@dataclass(frozen=True, kw_only=True)
class DlcTransactions:
    """The unsigned transactions of a DLC, and where the funding output is."""

    funding_tx: Tx
    funding_vout: int
    cets: tuple[Tx, ...]
    refund_tx: Tx


def _vbytes(weight: int) -> int:
    return -(-weight // 4)


def funding_fee(party: DlcParty, fee_rate: int) -> int:
    """Return the fee of the party's share of the funding transaction.

    The share is the party's inputs, its change output and half of the
    shared fields: 107 weight units, the specification's.
    """
    assert_type(party, DlcParty, "party")
    _assert_int(fee_rate, "fee rate", low=0, high=_MAX_U64)
    weight = 107 + 36 + 4 * len(party.change_spk)
    for funding_input in party.inputs:
        weight += 164 + 4 * funding_input.script_sig_len + funding_input.max_witness_len
    return _vbytes(weight) * fee_rate


def closing_fee(party: DlcParty, fee_rate: int) -> int:
    """Return the fee of the party's share of a CET or of the refund.

    The share is half of the shared fields and the party's payout output:
    249 weight units, plus 4 per byte of the payout script, the
    specification's.
    """
    assert_type(party, DlcParty, "party")
    _assert_int(fee_rate, "fee rate", low=0, high=_MAX_U64)
    return _vbytes(249 + 4 * len(party.payout_spk)) * fee_rate


def funding_script(offer_key: bytes, accept_key: bytes) -> bytes:
    """Return the 2-of-2 witness script of the funding output.

    The keys are in lexicographic order, as BIP67 asks.
    """
    for key in (offer_key, accept_key):
        _assert_bytes(key, "funding public key")
        if len(key) != 33:
            raise BTClibValueError("the funding public key is not compressed")
        point_from_pub_key(key)
    return ScriptPubKey.p2ms(2, [PubKeyData(offer_key), PubKeyData(accept_key)]).script


def funding_script_pub_key(offer_key: bytes, accept_key: bytes) -> bytes:
    """Return the P2WSH script_pub_key of the funding output."""
    return ScriptPubKey.p2wsh(funding_script(offer_key, accept_key)).script


def _funding_spk_of(offer: DlcParty, accept: DlcParty) -> bytes:
    return funding_script_pub_key(offer.funding_pub_key, accept.funding_pub_key)


def _funding_spk(dlc: Dlc) -> bytes:
    return _funding_spk_of(dlc.offer, dlc.accept)


def _change(party: DlcParty, fee_rate: int) -> int:
    fees = funding_fee(party, fee_rate) + closing_fee(party, fee_rate)
    change = sum(i.value for i in party.inputs) - party.collateral - fees
    if change < DUST_LIMIT:
        raise BTClibValueError(
            f"the inputs leave {change} satoshis of change, under {DUST_LIMIT}"
        )
    return change


def _sorted_outputs(outputs: list[tuple[int, int, bytes]]) -> list[TxOut]:
    """Return the outputs of (serial id, value, script) in order, less dust."""
    return [
        TxOut(value, spk)
        for _, value, spk in sorted(outputs, key=lambda o: o[0])
        if value >= DUST_LIMIT
    ]


def build_funding_tx(dlc: Dlc) -> tuple[Tx, int]:
    """Return the unsigned funding transaction, and its funding output's index.

    A party whose change is under the dust limit is refused: the
    specification asks it to add funding.
    """
    assert_type(dlc, Dlc, "dlc")
    offer, accept = dlc.offer, dlc.accept
    inputs = sorted(offer.inputs + accept.inputs, key=lambda i: i.serial_id)
    vin = [TxIn(i.out_point, i.script_sig, i.sequence) for i in inputs]
    funding_spk = _funding_spk(dlc)
    fees = sum(closing_fee(p, dlc.fee_rate) for p in (offer, accept))
    outputs = [
        (
            dlc.fund_output_serial_id,
            offer.collateral + accept.collateral + fees,
            funding_spk,
        ),
        (offer.change_serial_id, _change(offer, dlc.fee_rate), offer.change_spk),
        (accept.change_serial_id, _change(accept, dlc.fee_rate), accept.change_spk),
    ]
    vout = _sorted_outputs(outputs)
    index = [o.script_pub_key.script for o in vout].index(funding_spk)
    return Tx(2, 0, vin, vout), index


def _spend_funding(
    dlc: Dlc,
    funding_tx: Tx,
    funding_vout: int,
    lock_time: int,
    offer_value: int,
    accept_value: int,
) -> Tx:
    """Return the unsigned transaction spending the funding output."""
    assert_type(funding_tx, Tx, "funding tx")
    _assert_int(funding_vout, "funding vout", low=0, high=len(funding_tx.vout) - 1)
    script = funding_script(dlc.offer.funding_pub_key, dlc.accept.funding_pub_key)
    if funding_tx.vout[funding_vout].script_pub_key.script != _funding_spk(dlc):
        raise BTClibValueError("the funding output is not this DLC's")
    vin = [
        TxIn(
            OutPoint(funding_tx.id, funding_vout),
            b"",
            CET_SEQUENCE,
            Witness([script]),
        )
    ]
    vout = _sorted_outputs(
        [
            (dlc.offer.payout_serial_id, offer_value, dlc.offer.payout_spk),
            (dlc.accept.payout_serial_id, accept_value, dlc.accept.payout_spk),
        ]
    )
    return Tx(2, lock_time, vin, vout)


def build_cet(dlc: Dlc, funding_tx: Tx, funding_vout: int, offer_payout: int) -> Tx:
    """Return the unsigned CET that pays the offerer `offer_payout`."""
    assert_type(dlc, Dlc, "dlc")
    total = dlc.offer.collateral + dlc.accept.collateral
    _assert_int(offer_payout, "payout", low=0, high=total)
    return _spend_funding(
        dlc,
        funding_tx,
        funding_vout,
        dlc.cet_locktime,
        offer_payout,
        total - offer_payout,
    )


def build_refund_tx(dlc: Dlc, funding_tx: Tx, funding_vout: int) -> Tx:
    """Return the unsigned refund: each party gets its collateral."""
    assert_type(dlc, Dlc, "dlc")
    return _spend_funding(
        dlc,
        funding_tx,
        funding_vout,
        dlc.refund_locktime,
        dlc.offer.collateral,
        dlc.accept.collateral,
    )


def build_transactions(dlc: Dlc) -> DlcTransactions:
    """Return the unsigned funding transaction, every CET and the refund."""
    funding_tx, vout = build_funding_tx(dlc)
    return DlcTransactions(
        funding_tx=funding_tx,
        funding_vout=vout,
        cets=tuple(build_cet(dlc, funding_tx, vout, p) for p in dlc.offer_payouts),
        refund_tx=build_refund_tx(dlc, funding_tx, vout),
    )
