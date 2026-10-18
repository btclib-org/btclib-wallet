# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The Extractor's fee ceiling is priced on the finalized virtual size."""

from typing import Any

import pytest
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.fee import FeeRate, fee_from_vsize
from btclib.script import ScriptPubKey, Witness
from btclib.tx import OutPoint, Tx, TxIn, TxOut

from btclib_wallet.psbt import Psbt, extract_tx
from btclib_wallet.tx_builder import DEFAULT_MAX_FEE_RATE


def _finalized_psbt(value: int) -> Psbt:
    """Spend an OP_1 witness script, with no signature to obscure the fee."""
    tx = Tx(vin=[TxIn(OutPoint(b"\x01" * 32, 0))], vout=[TxOut(1, b"\x51")])
    psbt = Psbt.from_tx(tx)
    psbt.inputs[0].witness_utxo = TxOut(value, ScriptPubKey.p2wsh(b"\x51"))
    psbt.inputs[0].final_script_witness = Witness([b"\x51"])
    return psbt


@pytest.mark.parametrize("verify_scripts", [False, True])
def test_extract_tx_refuses_an_excessive_fee_by_default(verify_scripts: bool) -> None:
    """A PSBT built elsewhere has the ceiling even with script checks off."""
    psbt = _finalized_psbt(100_000_000)
    unchanged = psbt.serialize()
    with pytest.raises(BTClibValueError, match="^a fee of .* exceeds max_fee_rate"):
        extract_tx(psbt, verify_scripts=verify_scripts)
    assert psbt.serialize() == unchanged


@pytest.mark.parametrize("maximum", [None, FeeRate.from_sats_per_vbyte(2_000_000)])
def test_extract_tx_allows_an_explicitly_raised_or_disabled_ceiling(
    maximum: FeeRate | None,
) -> None:
    """The caller can pay the high fee, without changing the PSBT."""
    psbt = _finalized_psbt(100_000_000)
    unchanged = psbt.serialize()
    tx = extract_tx(psbt, max_fee_rate=maximum)
    assert tx.vin[0].script_witness == Witness([b"\x51"])
    assert tx.vout == psbt.tx.vout
    assert psbt.serialize() == unchanged


@pytest.mark.parametrize("rate", [0, 1, 1234, DEFAULT_MAX_FEE_RATE.sats_per_kvbyte])
def test_extract_tx_prices_the_ceiling_on_final_vsize(rate: int) -> None:
    """The exact rounded ceiling passes; one more satoshi is refused."""
    psbt = _finalized_psbt(1)
    maximum = FeeRate(sats_per_kvbyte=rate)
    tx = psbt.tx
    tx.vin[0].script_witness = Witness([b"\x51"])
    ceiling = fee_from_vsize(tx.vsize, maximum)
    psbt.inputs[0].witness_utxo = TxOut(ceiling + 1, ScriptPubKey.p2wsh(b"\x51"))
    assert extract_tx(psbt, max_fee_rate=maximum).vsize == tx.vsize
    psbt.inputs[0].witness_utxo = TxOut(ceiling + 2, ScriptPubKey.p2wsh(b"\x51"))
    with pytest.raises(BTClibValueError, match="exceeds max_fee_rate"):
        extract_tx(psbt, max_fee_rate=maximum)


def test_extract_tx_fee_check_needs_the_utxo_without_script_checks() -> None:
    """Turning both checks off keeps extraction without UTXO data available."""
    psbt = _finalized_psbt(1)
    psbt.inputs[0].witness_utxo = None
    with pytest.raises(
        BTClibValueError,
        match="^no utxo for input 0: the fee check needs every input's amount$",
    ):
        extract_tx(psbt, verify_scripts=False)
    assert extract_tx(psbt, verify_scripts=False, max_fee_rate=None) is not None


@pytest.mark.parametrize("maximum", [True, 1000, "1000", object()])
def test_extract_tx_validates_the_fee_rate(maximum: Any) -> None:
    """A fee rate is typed, even when both existing checks are disabled."""
    with pytest.raises(BTClibTypeError, match="max fee rate"):
        extract_tx(
            _finalized_psbt(1),
            max_fee_rate=maximum,
            check_validity=False,
            verify_scripts=False,
        )
