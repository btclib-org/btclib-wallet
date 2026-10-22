# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Generated PSBTs retain their transaction and every metadata map."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from btclib_wallet.psbt import Psbt, PsbtIn, PsbtOut
from tests.strategies.psbt import psbts


@pytest.mark.parametrize("version", [0, 2])
@pytest.mark.parametrize("taproot", [False, True])
@pytest.mark.parametrize("musig2", [False, True])
@settings(max_examples=50, deadline=None)
@given(data=st.data())
def test_generated_psbt_round_trip(
    version: int, taproot: bool, musig2: bool, data: st.DataObject
) -> None:
    """Both wire formats retain BIP371, BIP373 and proprietary records."""
    psbt = data.draw(psbts(version, taproot=taproot, musig2=musig2))
    encoded = psbt.serialize()
    decoded = Psbt.parse(encoded)
    assert decoded == psbt
    assert decoded.serialize() == encoded
    assert Psbt.b64decode(psbt.b64encode()) == psbt
    assert Psbt.from_dict(psbt.to_dict()) == psbt
    assert decoded.tx == psbt.tx
    assert all(
        not item.script_sig and not item.script_witness.stack for item in psbt.tx.vin
    )
    maps: list[PsbtIn | PsbtOut] = [*decoded.inputs, *decoded.outputs]
    for item in maps:
        assert bool(item.taproot_internal_key) == taproot
        assert bool(item.musig2_participant_pub_keys) == musig2
