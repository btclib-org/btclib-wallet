# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests of what `btclib_wallet.dlc` refuses, and what the refusal says."""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest
from btclib.exceptions import BTClibException, BTClibTypeError, BTClibValueError
from btclib.hashes import hash160
from btclib.script.witness import Witness
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from btclib_ecc.exceptions import BTClibEccException

from btclib_wallet import dlc
from tests.dlc.dlc_vectors_test import _TX, _dlc


def _terms() -> dlc.Dlc:
    return _dlc(_TX[0]["inputs"])


def test_the_refund_opens_after_the_cets_and_in_the_same_unit() -> None:
    """Refuse a refund that opens no later than the CETs, or in another unit."""
    terms = _terms()
    cet = terms.cet_locktime
    for refund in (0, cet, cet - 1):
        with pytest.raises(BTClibValueError, match="not after the CETs"):
            dataclasses.replace(terms, refund_locktime=refund)
    for cet_time, refund_time in ((100, 500_000_000), (500_000_000, 1)):
        with pytest.raises(BTClibValueError, match="height and a timestamp"):
            dataclasses.replace(
                terms, cet_locktime=cet_time, refund_locktime=refund_time
            )
    both_timestamps = dataclasses.replace(
        terms, cet_locktime=500_000_000, refund_locktime=500_000_001
    )
    assert both_timestamps.refund_locktime == 500_000_001


def test_dust_change_is_refused() -> None:
    """Refuse a party whose inputs leave under 1000 satoshis of change."""
    terms = _terms()
    party = dataclasses.replace(terms.offer, collateral=terms.offer.collateral + 10**8)
    with pytest.raises(BTClibValueError, match="of change, under 1000"):
        dlc.build_funding_tx(dataclasses.replace(terms, offer=party))


def test_a_payout_under_the_dust_limit_is_not_made() -> None:
    """Leave the offerer's output out of a CET that pays it 999 satoshis."""
    terms = _terms()
    built = dlc.build_transactions(terms)
    cet = dlc.build_cet(terms, built.funding_tx, built.funding_vout, 999)
    assert [o.script_pub_key.script for o in cet.vout] == [terms.accept.payout_spk]


@pytest.mark.parametrize(
    "change",
    [
        {"offer_payouts": (10**9,)},
        {"fee_rate": -1},
        {"cet_locktime": 2**32},
    ],
)
def test_terms_out_of_range(change: dict[str, Any]) -> None:
    """Refuse terms no two parties can build the same bytes from."""
    with pytest.raises(BTClibValueError):
        dataclasses.replace(_terms(), **change)


def test_a_wrong_type_is_a_type_error() -> None:
    """Refuse a bool or a string where a number is owed."""
    with pytest.raises(BTClibTypeError):
        dataclasses.replace(_terms(), fee_rate=True)
    with pytest.raises(BTClibTypeError):
        dlc.funding_fee("party", 1)  # type: ignore[arg-type]


def test_an_input_must_be_segwit() -> None:
    """Refuse an input spending a P2PKH output."""
    spk = b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"
    prev = Tx(2, 0, [TxIn(OutPoint(b"\1" * 32, 0))], [TxOut(10**6, spk)])
    with pytest.raises(BTClibValueError, match="must be SegWit"):
        dlc.FundingInput(serial_id=0, prev_tx=prev, prev_vout=0, max_witness_len=108)


def test_the_funding_output_must_be_this_dlcs() -> None:
    """Refuse a funding transaction that does not hold the 2-of-2."""
    terms = _terms()
    built = dlc.build_transactions(terms)
    with pytest.raises(BTClibValueError, match="not this DLC's"):
        dlc.build_refund_tx(terms, built.funding_tx, 1)


def test_completion_needs_the_two_funding_keys() -> None:
    """Refuse signatures that are not the funding keys'."""
    terms = _terms()
    built = dlc.build_transactions(terms)
    with pytest.raises(BTClibValueError, match="funding keys"):
        dlc.complete_spend(built.refund_tx, {b"\2" + bytes(32): b"x"})


def test_a_refusal_does_not_print_a_secret() -> None:
    """Keep a refused private key and a refused adaptor out of the message."""
    terms = _terms()
    built = dlc.build_transactions(terms)
    key = 0xDEADBEEF * 2**200
    refused = key + 2**256
    for call in (
        lambda: dlc.sign(terms, built.cets[0], 0),
        lambda: dlc.sign(terms, built.cets[0], refused),
        lambda: dlc.complete_cet(
            built.cets[0],
            local_pub_key=terms.offer.funding_pub_key,
            local_sig=b"",
            remote_pub_key=terms.accept.funding_pub_key,
            remote_adaptor_sig=b"\x07" * 162,
            decryption_key=key,
        ),
    ):
        with pytest.raises((BTClibException, BTClibEccException)) as excinfo:
            call()
        text = str(excinfo.value).lower()
        for secret in (key, refused):
            assert f"{secret:x}" not in text
            assert str(secret) not in text
        assert "07" * 20 not in text


def _input(spk: bytes, **change: Any) -> dlc.FundingInput:
    prev = Tx(2, 0, [TxIn(OutPoint(b"\1" * 32, 0))], [TxOut(10**6, spk)])
    fields: dict[str, Any] = {
        "serial_id": 0,
        "prev_tx": prev,
        "prev_vout": 0,
        "max_witness_len": 108,
    }
    return dlc.FundingInput(**(fields | change))


def test_a_funding_input_is_checked_against_its_output() -> None:
    """Refuse a missing output, a wrong redeem script, a non-SegWit one."""
    p2wpkh = b"\x00\x14" + bytes(20)
    with pytest.raises(BTClibValueError, match="no output 5"):
        _input(p2wpkh, prev_vout=5)
    with pytest.raises(BTClibValueError, match="not the output's"):
        _input(p2wpkh, redeem_script=b"\x00\x14" + bytes(20))
    p2sh = b"\xa9\x14" + hash160(b"\x51") + b"\x87"
    with pytest.raises(BTClibValueError, match="not the output's"):
        _input(p2sh, redeem_script=b"\x00\x14" + bytes(20))
    with pytest.raises(BTClibValueError, match="not a SegWit v0 one"):
        _input(p2sh, redeem_script=b"\x51")


def test_a_party_is_checked() -> None:
    """Refuse an uncompressed key and a party with no input."""
    party = _terms().offer
    with pytest.raises(BTClibValueError, match="not compressed"):
        dataclasses.replace(party, funding_pub_key=party.funding_pub_key[:-1])
    with pytest.raises(BTClibValueError, match="at least one"):
        dataclasses.replace(party, inputs=())
    with pytest.raises(BTClibValueError, match="not compressed"):
        dlc.funding_script(party.funding_pub_key[:-1], party.funding_pub_key)


def test_the_serial_ids_and_the_inputs_are_distinct() -> None:
    """Refuse the same serial id or the same output twice."""
    terms = _terms()
    offer, accept = terms.offer, terms.accept
    same_key = dataclasses.replace(accept, funding_pub_key=offer.funding_pub_key)
    with pytest.raises(BTClibValueError, match="same funding key"):
        dataclasses.replace(terms, accept=same_key)
    same_payout = dataclasses.replace(accept, payout_serial_id=offer.payout_serial_id)
    with pytest.raises(BTClibValueError, match="payout serial ids"):
        dataclasses.replace(terms, accept=same_payout)
    same_change = dataclasses.replace(accept, change_serial_id=offer.change_serial_id)
    with pytest.raises(BTClibValueError, match="funding output serial ids"):
        dataclasses.replace(terms, accept=same_change)
    with pytest.raises(BTClibValueError, match="funding output serial ids"):
        dataclasses.replace(terms, fund_output_serial_id=offer.change_serial_id)
    first = offer.inputs[0]
    same_id = dataclasses.replace(
        accept,
        inputs=(dataclasses.replace(accept.inputs[0], serial_id=first.serial_id),),
    )
    with pytest.raises(BTClibValueError, match="input serial ids"):
        dataclasses.replace(terms, accept=same_id)
    twice = dataclasses.replace(
        accept, inputs=(dataclasses.replace(first, serial_id=first.serial_id + 1000),)
    )
    with pytest.raises(BTClibValueError, match="spent twice"):
        dataclasses.replace(terms, accept=twice)


def test_the_signing_functions_check_their_transactions() -> None:
    """Refuse a transaction that is not a CET or the refund, wrong witnesses."""
    terms = _terms()
    built = dlc.build_transactions(terms)
    with pytest.raises(BTClibValueError, match="this DLC's terms"):
        dlc.sig_hash(terms, built.funding_tx)
    with pytest.raises(BTClibValueError, match="not those of the inputs"):
        dlc.complete_funding_tx(built.funding_tx, {})


def test_a_change_script_cannot_be_the_funding_script() -> None:
    """Refuse a change script equal to the funding script."""
    terms = _terms()
    spk = dlc.funding_script_pub_key(
        terms.offer.funding_pub_key, terms.accept.funding_pub_key
    )
    for side in ("offer", "accept"):
        party = dataclasses.replace(getattr(terms, side), change_spk=spk)
        with pytest.raises(BTClibValueError, match="funding script"):
            dataclasses.replace(terms, **{side: party})


def test_a_funding_output_under_dust_is_refused() -> None:
    """Refuse terms whose funding output would not be produced."""
    terms = _terms()
    with pytest.raises(BTClibValueError, match="funding output is under"):
        dataclasses.replace(
            terms,
            fee_rate=0,
            offer=dataclasses.replace(terms.offer, collateral=0),
            accept=dataclasses.replace(terms.accept, collateral=0),
            offer_payouts=(0,),
        )


def test_the_funding_output_is_where_the_serial_ids_put_it() -> None:
    """Spend the funding output at index 1 when its serial id sorts there."""
    terms = dataclasses.replace(_terms(), fund_output_serial_id=50)
    built = dlc.build_transactions(terms)
    assert built.funding_vout == 1
    spk = dlc.funding_script_pub_key(
        terms.offer.funding_pub_key, terms.accept.funding_pub_key
    )
    assert built.funding_tx.vout[1].script_pub_key.script == spk
    for tx in (*built.cets, built.refund_tx):
        assert tx.vin[0].prev_out == OutPoint(built.funding_tx.id, 1)


def _hand(
    tx: Tx,
    *,
    version: int | None = None,
    lock_time: int | None = None,
    vin: list[TxIn] | None = None,
    vout: list[TxOut] | None = None,
) -> Tx:
    """Return tx with fields replaced, as a counterparty would send it."""
    return Tx(
        tx.version if version is None else version,
        tx.lock_time if lock_time is None else lock_time,
        tx.vin if vin is None else vin,
        tx.vout if vout is None else vout,
    )


def _every_signer(terms: dlc.Dlc, tx: Tx) -> None:
    """Require every signing function to refuse tx; verify_adaptor answers False."""
    point = (1, 2)
    key = terms.offer.funding_pub_key
    for call in (
        lambda: dlc.sig_hash(terms, tx),
        lambda: dlc.sign(terms, tx, 1),
        lambda: dlc.adaptor_sign(terms, tx, 1, point),
    ):
        with pytest.raises(BTClibValueError, match="this DLC's terms"):
            call()
    # verify_adaptor signs nothing: a wrong value answers False
    assert dlc.verify_adaptor(terms, tx, b"\0" * 162, key, point) is False


def test_the_agreed_transactions_are_signed() -> None:
    """Sign the built CETs and the refund, and nothing else."""
    terms = _terms()
    built = dlc.build_transactions(terms)
    key = 0xDEADBEEF
    for tx in (*built.cets, built.refund_tx):
        sig = dlc.sign(terms, tx, key)
        assert sig[-1] == 1
    assert len({dlc.sig_hash(terms, t) for t in (*built.cets, built.refund_tx)}) == (
        len(built.cets) + 1
    )


def test_a_changed_output_is_not_signed() -> None:
    """Refuse a CET and a refund that pay somebody else, or something else."""
    terms = _terms()
    built = dlc.build_transactions(terms)
    for tx in (built.cets[0], built.refund_tx):
        thief = TxOut(tx.vout[0].value, b"\x00\x14" + bytes(20))
        _every_signer(terms, _hand(tx, vout=[thief, *tx.vout[1:]]))
        richer = TxOut(tx.vout[0].value + 1, tx.vout[0].script_pub_key)
        _every_signer(terms, _hand(tx, vout=[richer, *tx.vout[1:]]))
        _every_signer(terms, _hand(tx, vout=[*tx.vout, tx.vout[0]]))
        _every_signer(terms, _hand(tx, lock_time=tx.lock_time + 1))
        _every_signer(terms, _hand(tx, version=1))


def test_another_outpoint_is_not_signed() -> None:
    """Refuse a spend of any output but the funding output."""
    terms = _terms()
    built = dlc.build_transactions(terms)
    for tx in (built.cets[0], built.refund_tx):
        spent = tx.vin[0]
        for prev_out in (
            OutPoint(spent.prev_out.tx_id, spent.prev_out.vout + 1),
            OutPoint(b"\2" * 32, spent.prev_out.vout),
        ):
            vin = TxIn(prev_out, spent.script_sig, spent.sequence, spent.script_witness)
            _every_signer(terms, _hand(tx, vin=[vin]))


def test_another_script_is_not_signed() -> None:
    """Refuse a witness, a script_sig or a sequence other than the built one."""
    terms = _terms()
    built = dlc.build_transactions(terms)
    for tx in (built.cets[0], built.refund_tx):
        spent = tx.vin[0]
        script = spent.script_witness.stack[-1]
        for stack in (
            [script, script],
            [b"\x51"],
            [b"", script],
            [script[:-1] + b"\xad"],
            [],
        ):
            vin = TxIn(spent.prev_out, spent.script_sig, spent.sequence, Witness(stack))
            _every_signer(terms, _hand(tx, vin=[vin]))
        vin = TxIn(spent.prev_out, b"\x51", spent.sequence, spent.script_witness)
        _every_signer(terms, _hand(tx, vin=[vin]))
        vin = TxIn(spent.prev_out, b"", 0xFFFFFFFF, spent.script_witness)
        _every_signer(terms, _hand(tx, vin=[vin]))


def test_a_cet_of_an_unagreed_outcome_is_not_signed() -> None:
    """Refuse a CET built for a payout the terms do not list."""
    terms = _terms()
    built = dlc.build_transactions(terms)
    vout = built.funding_vout
    total = terms.offer.collateral + terms.accept.collateral
    for payout in (1000, 999, total - 999, total // 2):
        assert payout not in terms.offer_payouts
        cet = dlc.build_cet(terms, built.funding_tx, vout, payout)
        _every_signer(terms, cet)


def test_a_signed_transaction_is_not_signed_again() -> None:
    """Refuse a completed refund: only the unsigned one is agreed."""
    terms = _terms()
    built = dlc.build_transactions(terms)
    script = built.refund_tx.vin[0].script_witness.stack[-1]
    done = dlc.complete_spend(
        built.refund_tx,
        {
            terms.offer.funding_pub_key: b"x",
            terms.accept.funding_pub_key: b"y",
        },
    )
    assert done.vin[0].script_witness.stack[-1] == script
    _every_signer(terms, done)


def test_the_signing_functions_check_their_types() -> None:
    """Raise a type error on a transaction or terms of the wrong type."""
    terms = _terms()
    built = dlc.build_transactions(terms)
    with pytest.raises(BTClibTypeError):
        dlc.sign(terms, b"x", 1)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError):
        dlc.sign(built, built.refund_tx, 1)  # type: ignore[arg-type]


def test_the_signatures_are_a_mapping() -> None:
    """Refuse a list where a mapping of signatures is owed."""
    built = dlc.build_transactions(_terms())
    with pytest.raises(BTClibTypeError):
        dlc.complete_spend(built.refund_tx, [b"a", b"b"])  # type: ignore[arg-type]


def test_complete_funding_tx_checks_its_witnesses() -> None:
    """Refuse a list, and a mapping whose values are not witnesses."""
    built = dlc.build_transactions(_terms())
    with pytest.raises(BTClibTypeError):
        dlc.complete_funding_tx(built.funding_tx, [])  # type: ignore[arg-type]
    spent = built.funding_tx.vin[0].prev_out
    with pytest.raises(BTClibTypeError):
        dlc.complete_funding_tx(built.funding_tx, {spent: b"x"})  # type: ignore[dict-item]


@pytest.mark.parametrize("side", ["local_pub_key", "remote_pub_key"])
def test_complete_cet_checks_its_keys(side: str) -> None:
    """Refuse a key that is not bytes, before it is used as a dict key."""
    terms = _terms()
    built = dlc.build_transactions(terms)
    args: dict[str, Any] = {
        "local_pub_key": terms.offer.funding_pub_key,
        "local_sig": b"",
        "remote_pub_key": terms.accept.funding_pub_key,
        "remote_adaptor_sig": b"\x07" * 162,
        "decryption_key": 1,
        side: [1],
    }
    with pytest.raises(BTClibTypeError):
        dlc.complete_cet(built.cets[0], **args)


def test_complete_spend_checks_its_key_types() -> None:
    """Refuse keys and signatures that are not bytes, before comparing."""
    built = dlc.build_transactions(_terms())
    with pytest.raises(BTClibTypeError):
        dlc.complete_spend(built.refund_tx, {1: b"a", b"x": b"b"})  # type: ignore[dict-item]
    with pytest.raises(BTClibTypeError):
        dlc.complete_spend(built.refund_tx, {b"x": 1})  # type: ignore[dict-item]


def test_a_transaction_with_no_output_is_refused() -> None:
    """Refuse terms under which a CET or the refund would have no output."""
    terms = _terms()
    with pytest.raises(BTClibValueError, match="refund would have no output"):
        dataclasses.replace(
            terms,
            offer=dataclasses.replace(terms.offer, collateral=750),
            accept=dataclasses.replace(terms.accept, collateral=750),
            offer_payouts=(),
        )
    # one side under dust is valid: its output is left out
    ok = dataclasses.replace(
        terms, offer_payouts=(999, terms.offer.collateral + terms.accept.collateral)
    )
    built = dlc.build_transactions(ok)
    assert [len(c.vout) for c in built.cets] == [1, 1]
    with pytest.raises(BTClibValueError, match="CET would have no output"):
        dataclasses.replace(
            terms,
            offer=dataclasses.replace(terms.offer, collateral=1000),
            accept=dataclasses.replace(terms.accept, collateral=500),
            offer_payouts=(750,),
        )


def test_a_cet_needs_one_output_of_the_dust_limit() -> None:
    """Accept a CET whose larger payout is exactly 1000, refuse one of 999."""
    terms = _terms()
    offer = dataclasses.replace(terms.offer, collateral=1000)
    accept = dataclasses.replace(terms.accept, collateral=500)
    # 1000 to the offerer and 500 to the accepter, and the other way round
    for payout in (1000, 500):
        ok = dataclasses.replace(
            terms, offer=offer, accept=accept, offer_payouts=(payout,)
        )
        assert ok.offer_payouts == (payout,)
    accept = dataclasses.replace(terms.accept, collateral=998)
    with pytest.raises(BTClibValueError, match="CET would have no output"):
        dataclasses.replace(terms, offer=offer, accept=accept, offer_payouts=(999,))


_STANDARD = {
    "p2pkh": b"\x76\xa9\x14" + bytes(20) + b"\x88\xac",
    "p2sh": b"\xa9\x14" + bytes(20) + b"\x87",
    "p2wpkh": b"\x00\x14" + bytes(20),
    "p2wsh": b"\x00\x20" + bytes(32),
    "p2tr": b"\x51\x20" + bytes(32),
    "v16": b"\x60\x28" + bytes(40),
}


@pytest.mark.parametrize("field", ["payout_spk", "change_spk"])
@pytest.mark.parametrize("side", ["offer", "accept"])
@pytest.mark.parametrize(
    "spk",
    [b"", b"\x51", bytes(10_000), b"\x00\x19" + bytes(25)],
    ids=["empty", "op-true", "zeros", "v0-of-25-bytes"],
)
def test_a_non_standard_script_is_refused(field: str, side: str, spk: bytes) -> None:
    """Refuse an empty script, OP_TRUE, zeros and a v0 program of 25 bytes."""
    terms = _terms()
    party = dataclasses.replace(getattr(terms, side), **{field: spk})
    with pytest.raises(BTClibValueError, match="not a standard script"):
        dataclasses.replace(terms, **{side: party})


@pytest.mark.parametrize("spk", _STANDARD.values(), ids=_STANDARD)
def test_a_standard_script_is_accepted(spk: bytes) -> None:
    """Accept each standard form of Protocol.md as payout and as change."""
    terms = _terms()
    offer = dataclasses.replace(terms.offer, payout_spk=spk, change_spk=spk)
    dlc.build_transactions(dataclasses.replace(terms, offer=offer))


def _with_change(party: dlc.DlcParty, fee_rate: int, change: int) -> dlc.DlcParty:
    """Return the party with one input that leaves exactly `change` satoshis."""
    first = party.inputs[0]
    spk = first.prev_tx.vout[first.prev_vout].script_pub_key.script
    one = dataclasses.replace(
        first,
        prev_tx=Tx(2, 0, [TxIn(OutPoint(b"\1" * 32, 0))], [TxOut(1, spk)]),
        prev_vout=0,
    )
    alone = dataclasses.replace(party, inputs=(one,))
    fees = dlc.funding_fee(alone, fee_rate) + dlc.closing_fee(alone, fee_rate)
    paid = TxOut(party.collateral + fees + change, spk)
    funded = Tx(2, 0, [TxIn(OutPoint(b"\1" * 32, 0))], [paid])
    return dataclasses.replace(
        alone, inputs=(dataclasses.replace(one, prev_tx=funded),)
    )


def test_the_change_is_accepted_at_the_dust_limit_and_refused_under() -> None:
    """Keep a change of exactly 1000 satoshis, refuse one of 999."""
    terms = _terms()
    at_limit = dataclasses.replace(
        terms, offer=_with_change(terms.offer, terms.fee_rate, 1000)
    )
    funding_tx, _ = dlc.build_funding_tx(at_limit)
    spk = at_limit.offer.change_spk
    changes = [o for o in funding_tx.vout if o.script_pub_key.script == spk]
    assert [o.value for o in changes] == [1000]
    under = dataclasses.replace(
        terms, offer=_with_change(terms.offer, terms.fee_rate, 999)
    )
    with pytest.raises(BTClibValueError, match="of change, under 1000"):
        dlc.build_funding_tx(under)


def test_a_payout_of_the_dust_limit_is_made() -> None:
    """Keep the offerer's output of a CET that pays it exactly 1000 satoshis."""
    terms = _terms()
    built = dlc.build_transactions(terms)
    cet = dlc.build_cet(terms, built.funding_tx, built.funding_vout, 1000)
    assert sorted(o.value for o in cet.vout) == [1000, 2 * 10**8 - 1000]
    spks = {o.script_pub_key.script for o in cet.vout}
    assert spks == {terms.offer.payout_spk, terms.accept.payout_spk}


def test_the_bounds_of_the_amounts_and_the_rate() -> None:
    """Accept each upper bound and refuse the value after it."""
    terms = _terms()
    top = 21_000_000 * 10**8
    dataclasses.replace(terms.offer, collateral=top)
    with pytest.raises(BTClibValueError, match="collateral out of range"):
        dataclasses.replace(terms.offer, collateral=top + 1)
    dataclasses.replace(terms, fee_rate=2**64 - 1)
    for rate in (-1, 2**64):
        with pytest.raises(BTClibValueError, match="fee rate out of range"):
            dataclasses.replace(terms, fee_rate=rate)
    total = terms.offer.collateral + terms.accept.collateral
    dataclasses.replace(terms, offer_payouts=(total,))
    for payout in (-1, total + 1):
        with pytest.raises(BTClibValueError, match="payout out of range"):
            dataclasses.replace(terms, offer_payouts=(payout,))
    built = dlc.build_transactions(terms)
    for payout in (-1, total + 1):
        with pytest.raises(BTClibValueError, match="payout out of range"):
            dlc.build_cet(terms, built.funding_tx, built.funding_vout, payout)
    assert dlc.build_cet(terms, built.funding_tx, built.funding_vout, total).vout


def test_the_funding_vout_is_in_range() -> None:
    """Refuse an index past the outputs, or before them, as a value error."""
    terms = _terms()
    built = dlc.build_transactions(terms)
    for vout in (-1, len(built.funding_tx.vout)):
        with pytest.raises(BTClibValueError, match="funding vout out of range"):
            dlc.build_refund_tx(terms, built.funding_tx, vout)


def test_a_funding_input_pins_each_bound() -> None:
    """Accept each bound of an input's numbers and refuse the one beside it."""
    p2wpkh = b"\x00\x14" + bytes(20)
    top = 2**32 - 1
    assert _input(p2wpkh, max_witness_len=0).max_witness_len == 0
    assert _input(p2wpkh, sequence=top).sequence == top
    with pytest.raises(BTClibValueError, match="max_witness_len out of range"):
        _input(p2wpkh, max_witness_len=-1)
    with pytest.raises(BTClibValueError, match="sequence out of range"):
        _input(p2wpkh, sequence=top + 1)
    with pytest.raises(BTClibValueError, match="prev_vout out of range"):
        _input(p2wpkh, prev_vout=-1)


def test_a_party_takes_funding_inputs_only() -> None:
    """Refuse an input that is not a FundingInput."""
    party = _terms().offer
    with pytest.raises(BTClibTypeError):
        dataclasses.replace(party, inputs=(party.inputs[0], "x"))  # type: ignore[arg-type]


def test_the_signing_functions_count_inputs_and_witnesses() -> None:
    """Refuse a spend of two inputs, and witnesses beyond the inputs'."""
    terms = _terms()
    built = dlc.build_transactions(terms)
    refund = built.refund_tx
    other = TxIn(OutPoint(b"\2" * 32, 0), b"", 0, refund.vin[0].script_witness)
    two = Tx(2, 0, [refund.vin[0], other], refund.vout)
    with pytest.raises(BTClibValueError, match="this DLC's terms"):
        dlc.sig_hash(terms, two)
    with pytest.raises(BTClibValueError, match="spending the funding output"):
        dlc.complete_spend(two, {})
    witnesses = {i.prev_out: Witness([b"x"]) for i in built.funding_tx.vin}
    done = dlc.complete_funding_tx(built.funding_tx, witnesses)
    assert [i.script_witness.stack for i in done.vin] == [(b"x",)] * len(done.vin)
    extra = witnesses | {OutPoint(b"\2" * 32, 0): Witness([b"y"])}
    with pytest.raises(BTClibValueError, match="not those of the inputs"):
        dlc.complete_funding_tx(built.funding_tx, extra)
