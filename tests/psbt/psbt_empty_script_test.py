# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An empty PSBT_OUT_SCRIPT value is a present field, not a missing one."""

from __future__ import annotations

import pytest
from btclib.exceptions import BTClibValueError
from btclib.tx import OutPoint, Tx, TxIn, TxOut

from btclib_wallet.psbt import Psbt, PsbtIn, PsbtOut
from btclib_wallet.psbt.psbt_view import PsbtView


def test_empty_output_script_map_is_preserved() -> None:
    """BIP370 permits a zero-byte script value after the 0x04 key."""
    raw = bytes.fromhex("010308010000000000000001040000")
    output = PsbtOut.parse(raw, psbt_version=2)
    assert output.script_pub_key == b""
    assert output.serialize(psbt_version=2) == raw


@pytest.mark.parametrize("script", [None, b"", b"\x51"])
def test_output_script_presence_round_trips(script: bytes | None) -> None:
    """The object, JSON and map retain absence separately from emptiness."""
    output = PsbtOut(amount=1, script_pub_key=script)
    assert PsbtOut.from_dict(output.to_dict()) == output
    assert PsbtOut.parse(output.serialize(psbt_version=2), psbt_version=2) == output
    assert (output.to_dict()["script_pub_key"] is None) == (script is None)


@pytest.mark.parametrize("script", [b"", "", {"hex": "", "asm": ""}])
def test_empty_output_script_json_spellings(script: object) -> None:
    """Existing byte, hex and script-dict representations still mean empty."""
    encoded = PsbtOut().to_dict()
    encoded["script_pub_key"] = script
    assert PsbtOut.from_dict(encoded).script_pub_key == b""


def test_v2_empty_script_is_readable_by_both_readers() -> None:
    """A required field is present even when the output pays to no script."""
    psbt = Psbt(
        2,
        [PsbtIn(previous_tx_id=b"\x11" * 32, output_index=0)],
        [PsbtOut(amount=1, script_pub_key=b"")],
        2,
        {},
    )
    raw = psbt.serialize()
    assert Psbt.parse(raw) == psbt
    assert Psbt.from_dict(psbt.to_dict()) == psbt
    view = PsbtView(raw)
    assert view.output(0) == psbt.outputs[0]
    assert view.tx == psbt.tx
    assert psbt.tx.vout[0].script_pub_key.script == b""

    psbt.outputs[0].script_pub_key = None
    with pytest.raises(BTClibValueError, match="missing PSBT_OUT_SCRIPT"):
        psbt.assert_valid()


def test_v0_empty_script_converts_without_losing_the_v2_field() -> None:
    """A valid empty transaction output survives both version conversions."""
    tx = Tx(2, 0, [TxIn(OutPoint(b"\x11" * 32, 0))], [TxOut(1, b"")])
    original = Psbt.from_tx(tx)
    converted = original.to_v2()
    assert converted.outputs[0].script_pub_key == b""
    assert Psbt.parse(converted.serialize()) == converted
    assert converted.to_v0().tx == tx
    assert Psbt.parse(converted.to_v0().serialize()) == original


def test_v0_constructor_keeps_an_omitted_script_empty() -> None:
    """A v0 transaction supplies an empty script when its caller omits one."""
    psbt = Psbt(
        2,
        [PsbtIn(previous_tx_id=b"\x11" * 32, output_index=0, sequence=0xFFFFFFFF)],
        [PsbtOut(amount=1)],
        0,
        {},
        fallback_lock_time=0,
    )
    assert psbt.outputs[0].script_pub_key == b""
    assert Psbt.parse(psbt.serialize()) == psbt
    assert Psbt.parse(psbt.to_v2().serialize()).tx == psbt.tx
    assert PsbtOut().script_pub_key is None
