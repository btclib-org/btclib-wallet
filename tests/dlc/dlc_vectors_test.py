# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests of `btclib_wallet.dlc` against the dlcspecs vectors.

`dlc_fee_test.json`, `dlc_tx_test.json` and `dlc_test.json` are
discreetlogcontracts/dlcspecs's `test/` files, pinned in
`tests/_data/README.md`, which says where they come from and what they
lack. Their order is the offerer's before the accepter's, and the funding
output before the change outputs, so the fixtures give the serial ids in
that order: that is what makes every case reproducible byte for byte.

`dlc_test.json` adds the signed transactions. bitcoin-s's generator
signs the CET adaptor signatures with the fixed randomness `"DLC_TEST"`
left-padded to 32 bytes. The adaptor signatures here use that randomness;
the vectors' own signatures are not reproduced, and
`tests/_data/README.md` says why. A funding input's signature is the wallet's,
so the helper here signs each kind the vectors hold.
"""

from __future__ import annotations

from typing import Any

import pytest
from btclib.hashes import hash160
from btclib.script.engine import verify_transaction
from btclib.script.script_pub_key import ScriptPubKey
from btclib.script.sig_hash import segwit_v0
from btclib.script.witness import Witness
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from btclib_ecc.curves import bytes_from_point, mult, secp256k1
from btclib_ecc.ecc import dlc_oracle, dsa

from btclib_wallet import dlc
from btclib_wallet.dlc import DlcParty, FundingInput
from tests import load, vector_id

_AUX = b"DLC_TEST".rjust(32, b"\0")

_FEE = load("dlc", "_data", "dlc_fee_test.json")
_TX = load("dlc", "_data", "dlc_tx_test.json")
_SIGNED = load("dlc", "_data", "dlc_test.json")


def _pub_key(prv_key_hex: str) -> bytes:
    return bytes_from_point(mult(int(prv_key_hex, 16)), secp256k1)


def _party(params: dict[str, Any], first_id: int) -> DlcParty:
    inputs = tuple(
        FundingInput(
            serial_id=first_id + k,
            prev_tx=Tx.parse(bytes.fromhex(f["tx"])),
            prev_vout=f["idx"],
            max_witness_len=f["maxWitnessLen"],
            redeem_script=bytes.fromhex(f.get("redeemScript") or ""),
        )
        for k, f in enumerate(params["fundingInputTxs"])
    )
    return DlcParty(
        funding_pub_key=_pub_key(params["fundingPrivKey"]),
        payout_spk=ScriptPubKey.from_address(params["payoutAddress"]).script,
        payout_serial_id=first_id,
        change_spk=ScriptPubKey.from_address(params["changeAddress"]).script,
        change_serial_id=first_id + 1,
        collateral=params["collateral"],
        inputs=inputs,
    )


def _dlc(inputs: dict[str, Any]) -> dlc.Dlc:
    params = inputs["params"]
    return dlc.Dlc(
        offer=_party(inputs["offerParams"], 10),
        accept=_party(inputs["acceptParams"], 100),
        fund_output_serial_id=0,
        fee_rate=params["feeRate"],
        offer_payouts=tuple(c["localPayout"] for c in params["contractInfo"]),
        cet_locktime=params["contractMaturityBound"],
        refund_locktime=params["contractTimeout"],
    )


# a fee vector gives the length of a redeem script and nothing of it, so
# the script is zeros of a length the vectors use, and the output it
# redeems is the P2SH one that `FundingInput` checks it against
_REDEEM = {0: b"", 22: b"\x00\x14" + bytes(20), 34: b"\x00\x20" + bytes(32)}


def _fee_input(serial_id: int, case: dict[str, Any]) -> FundingInput:
    redeem = _REDEEM[case["redeemScriptLen"]]
    spk = b"\xa9\x14" + hash160(redeem) + b"\x87" if redeem else b"\x00\x14" + bytes(20)
    prev_tx = Tx(2, 0, [TxIn(OutPoint(b"\1" * 32, 0))], [TxOut(10**6, spk)])
    return FundingInput(
        serial_id=serial_id,
        prev_tx=prev_tx,
        prev_vout=0,
        max_witness_len=case["maxWitnessLen"],
        redeem_script=redeem,
    )


def _fee_party(side: str, inputs: dict[str, Any]) -> DlcParty:
    """Return a party with the lengths a fee vector gives, and no more."""
    return DlcParty(
        funding_pub_key=_pub_key("01"),
        payout_spk=bytes(inputs[f"{side}PayoutSPKLen"]),
        payout_serial_id=0,
        change_spk=bytes(inputs[f"{side}ChangeSPKLen"]),
        change_serial_id=1,
        collateral=1,
        inputs=tuple(_fee_input(k, i) for k, i in enumerate(inputs[f"{side}Inputs"])),
    )


@pytest.mark.parametrize("case", _FEE, ids=[vector_id(i) for i in range(len(_FEE))])
def test_fee(case: dict[str, Any]) -> None:
    """Return each party's fees as each vector says."""
    inputs = case["inputs"]
    for side in ("offer", "accept"):
        party = _fee_party(side, inputs)
        assert dlc.funding_fee(party, inputs["feeRate"]) == case[f"{side}FundingFee"]
        assert dlc.closing_fee(party, inputs["feeRate"]) == case[f"{side}ClosingFee"]


def _hex(tx: Tx) -> str:
    return tx.serialize(include_witness=True).hex()


@pytest.mark.parametrize("case", _TX, ids=[vector_id(i) for i in range(len(_TX))])
def test_transactions(case: dict[str, Any]) -> None:
    """Build the funding, the CETs and the refund byte for byte."""
    built = dlc.build_transactions(_dlc(case["inputs"]))
    assert _hex(built.funding_tx) == case["txs"]["fundingTx"]
    assert [_hex(c) for c in built.cets] == case["txs"]["cets"]
    assert _hex(built.refund_tx) == case["txs"]["refundTx"]
    assert built.funding_vout == 0


def _sign_input(
    funding_tx: Tx, index: int, fi: dict[str, Any], prev_out: TxOut
) -> Witness:
    """Sign input `index` of the funding transaction as its vector says."""
    template = Witness.parse(bytes.fromhex(fi["scriptWitness"])).stack
    keys = [int(k, 16) for k in fi["inputKeys"]]
    if len(template) == 2 and len(template[1]) == 33:
        # P2WPKH: the template is a placeholder and the public key
        script_code = b"\x76\xa9\x14" + hash160(template[1]) + b"\x88\xac"
        digest = segwit_v0(script_code, funding_tx, index, 1, prev_out.value)
        sig = dsa.sign_(digest, keys[0]).serialize() + b"\x01"
        return Witness([sig, template[1]])
    # P2WSH multisig: signatures in the order of the script's keys
    script = template[-1]
    digest = segwit_v0(script, funding_tx, index, 1, prev_out.value)
    by_pub = {_pub_key(f"{k:064x}"): k for k in keys}
    sigs = [
        dsa.sign_(digest, by_pub[script[2 + 34 * n : 35 + 34 * n]]).serialize()
        + b"\x01"
        for n in range(len(keys))
    ]
    return Witness([b"", *sigs, script])


def _prev_outs(terms: dlc.Dlc) -> dict[OutPoint, TxOut]:
    return {
        i.out_point: i.prev_tx.vout[i.prev_vout]
        for p in (terms.offer, terms.accept)
        for i in p.inputs
    }


def _without_witnesses(tx: Tx) -> Tx:
    return Tx(
        tx.version,
        tx.lock_time,
        [TxIn(i.prev_out, i.script_sig, i.sequence) for i in tx.vin],
        tx.vout,
    )


def _shape(tx: Tx) -> list[int]:
    """Return the number of witness items of each input."""
    return [len(i.script_witness.stack) for i in tx.vin]


@pytest.mark.parametrize(
    "case", _SIGNED, ids=[vector_id(i) for i in range(len(_SIGNED))]
)
def test_signed_transactions(case: dict[str, Any]) -> None:
    """Sign what dlc_test.json signs, and hold both to the script engine.

    The vectors' signatures are not reproducible byte for byte:
    `tests/_data/README.md` says why. So each signed transaction here is
    the vector's up to its signatures' values, and both the vector's
    signatures and ours are verified by the script engine.
    """
    inputs = case["testInputs"]
    terms = _dlc(inputs)
    built = dlc.build_transactions(terms)
    params = inputs["params"]
    assert _hex(built.funding_tx) == case["unsignedTxs"]["fundingTx"]
    assert [_hex(c) for c in built.cets] == case["unsignedTxs"]["cets"]
    assert _hex(built.refund_tx) == case["unsignedTxs"]["refundTx"]
    funding_out = built.funding_tx.vout[built.funding_vout]

    # the funding transaction: the vector's, and ours, each input signed
    vector_funding = Tx.parse(bytes.fromhex(case["signedTxs"]["fundingTx"]))
    assert _without_witnesses(vector_funding) == built.funding_tx
    vectors = {
        OutPoint(Tx.parse(bytes.fromhex(f["tx"])).id, f["idx"]): f
        for side in ("offerParams", "acceptParams")
        for f in inputs[side]["fundingInputTxs"]
    }
    prevs = _prev_outs(terms)
    witnesses = {
        i.prev_out: _sign_input(
            built.funding_tx, n, vectors[i.prev_out], prevs[i.prev_out]
        )
        for n, i in enumerate(built.funding_tx.vin)
    }
    funding = dlc.complete_funding_tx(built.funding_tx, witnesses)
    spent = [prevs[i.prev_out] for i in funding.vin]
    verify_transaction(spent, funding)
    verify_transaction(spent, vector_funding)
    assert _shape(funding) == _shape(vector_funding)

    keys = {
        "offer": int(inputs["offerParams"]["fundingPrivKey"], 16),
        "accept": int(inputs["acceptParams"]["fundingPrivKey"], 16),
    }
    pubs = {
        "offer": terms.offer.funding_pub_key,
        "accept": terms.accept.funding_pub_key,
    }

    # the refund
    refund = dlc.complete_spend(
        built.refund_tx,
        {pubs[w]: dlc.sign(terms, built.refund_tx, keys[w]) for w in keys},
    )
    vector_refund = Tx.parse(bytes.fromhex(case["signedTxs"]["refundTx"]))
    verify_transaction([funding_out], refund)
    verify_transaction([funding_out], vector_refund)
    assert _shape(refund) == _shape(vector_refund)
    assert _without_witnesses(refund) == _without_witnesses(vector_refund)
    assert (
        refund.vin[0].script_witness.stack[-1]
        == (vector_refund.vin[0].script_witness.stack[-1])
    )

    # the CET of the real outcome, completed by each party in turn
    oracle = params["oracleInfo"]
    outcomes = [c["outcome"] for c in params["contractInfo"]]
    index = outcomes.index(params["realOutcome"])
    secret = int.from_bytes(bytes.fromhex(params["oracleSignature"])[32:], "big")
    cet = built.cets[index]
    point = dlc_oracle.sig_point_(
        bytes.fromhex(outcomes[index]),
        bytes.fromhex(oracle["publicKey"]),
        bytes.fromhex(oracle["nonce"]),
    )
    assert mult(secret) == point
    for (local, remote), vector_hex in zip(
        (("offer", "accept"), ("accept", "offer")),
        case["signedTxs"]["cets"],
        strict=True,
    ):
        adaptor = dlc.adaptor_sign(terms, cet, keys[remote], point, _AUX)
        assert dlc.verify_adaptor(terms, cet, adaptor, pubs[remote], point)
        assert not dlc.verify_adaptor(terms, cet, adaptor, pubs[local], point)
        signed = dlc.complete_cet(
            cet,
            local_pub_key=pubs[local],
            local_sig=dlc.sign(terms, cet, keys[local]),
            remote_pub_key=pubs[remote],
            remote_adaptor_sig=adaptor,
            decryption_key=secret,
        )
        vector_cet = Tx.parse(bytes.fromhex(vector_hex))
        verify_transaction([funding_out], signed)
        verify_transaction([funding_out], vector_cet)
        assert _without_witnesses(signed) == _without_witnesses(vector_cet)
        assert _shape(signed) == _shape(vector_cet)
