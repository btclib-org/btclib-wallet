# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Finalize a BIP379 multi_a leaf and spend it through the script engine."""

from copy import deepcopy

import pytest
from btclib.alias import ScriptList, TaprootScriptTree
from btclib.exceptions import BTClibValueError, ScriptError
from btclib.key import PrvKeyData
from btclib.script import ScriptPubKey, Witness, push_int, sig_hash, taproot
from btclib.script.engine import verify_transaction
from btclib.script.limits import MAX_STACK_SIZE
from btclib.script.taproot import input_script_sig
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from btclib_ecc.ecc import ssa

from btclib_wallet.psbt import Psbt, extract_tx, finalize, taproot_sig_hash
from btclib_wallet.psbt.psbt_in import ValidSigHashType


def _signed_psbt(
    threshold: int,
    count: int,
    signers: tuple[int, ...],
    hash_type: ValidSigHashType,
    repeat_keys: bool,
) -> tuple[Psbt, list[bytes], bytes, bytes]:
    """Put the signers' signatures in the map in the supplied order."""
    private_keys = [1 if repeat_keys else i + 1 for i in range(count)]
    keys = [PrvKeyData(key).pub.sec[1:] for key in private_keys]
    commands: ScriptList = [keys[0], "OP_CHECKSIG"]
    for key in keys[1:]:
        commands += [key, "OP_CHECKSIGADD"]
    commands += [push_int(threshold), "OP_NUMEQUAL"]
    tree: TaprootScriptTree = [(0xC0, commands)]
    internal_key = PrvKeyData(count + 1).pub
    script = taproot.serialize(commands)
    control_block = input_script_sig(internal_key, tree, 0)[1]
    leaf_hash = taproot.leaf_hash(0xC0, script)
    spent = TxOut(100_000, ScriptPubKey.p2tr(internal_key, tree))
    tx = Tx(vin=[TxIn(OutPoint(b"\x01" * 32, 0))], vout=[TxOut(99_000, b"\x51")])
    psbt = Psbt.from_tx(tx)
    psbt.inputs[0].witness_utxo = spent
    psbt.inputs[0].taproot_leaf_scripts[control_block] = (script, 0xC0)
    if hash_type != sig_hash.DEFAULT:
        psbt.inputs[0].sig_hash_type = hash_type
    message = taproot_sig_hash(psbt, 0, leaf_hash=leaf_hash)
    for index in signers:
        signature = ssa.sign_(message, private_keys[index]).serialize()
        if hash_type != sig_hash.DEFAULT:
            signature += bytes([hash_type])
        psbt.inputs[0].taproot_script_spend_signatures[keys[index] + leaf_hash] = (
            signature
        )
    return psbt, keys, script, control_block


@pytest.mark.parametrize(
    "threshold, count, signers",
    [
        (2, 2, (1, 0)),
        (2, 3, (2, 0)),
        (1, 3, (1,)),
        (2, 3, (2, 1, 0)),
        (1, 1, (0,)),
        (17, 17, tuple(reversed(range(17)))),
    ],
)
@pytest.mark.parametrize("hash_type", [sig_hash.DEFAULT, sig_hash.ALL])
def test_finalize_spends_multi_a_in_script_key_order(
    threshold: int, count: int, signers: tuple[int, ...], hash_type: ValidSigHashType
) -> None:
    """Map order is irrelevant; unused keys take empty witness elements."""
    psbt, keys, script, control_block = _signed_psbt(
        threshold, count, signers, hash_type, False
    )
    unchanged = deepcopy(psbt)
    finalized = finalize(psbt)
    assert psbt == unchanged
    witness = finalized.inputs[0].final_script_witness
    assert witness is not None
    selected = set(sorted(signers)[:threshold])
    leaf_hash = taproot.leaf_hash(0xC0, script)
    expected = [
        psbt.inputs[0].taproot_script_spend_signatures[key + leaf_hash]
        if index in selected
        else b""
        for index, key in enumerate(keys)
    ]
    assert witness.stack == (*reversed(expected), script, control_block)
    spent = psbt.inputs[0].witness_utxo
    assert spent is not None
    verify_transaction([spent], extract_tx(finalized))
    assert finalize(finalized) == finalized


def test_finalize_refuses_an_incomplete_multi_a_quorum() -> None:
    """A valid signature does not satisfy a leaf requiring another key."""
    psbt, _, _, _ = _signed_psbt(2, 2, (0,), 0, False)
    with pytest.raises(
        BTClibValueError, match="not enough taproot script path signatures"
    ):
        finalize(psbt)


def test_finalize_verifies_extra_multi_a_signatures() -> None:
    """Verify every supplied signature, even outside the chosen quorum."""
    psbt, keys, script, _ = _signed_psbt(1, 2, (0, 1), 0, False)
    psbt.inputs[0].taproot_script_spend_signatures[
        keys[1] + taproot.leaf_hash(0xC0, script)
    ] = b"\x01" * 64
    with pytest.raises(BTClibValueError, match="invalid taproot script path signature"):
        finalize(psbt)


def test_finalize_refuses_a_signature_for_a_key_outside_multi_a() -> None:
    """The same leaf hash does not make an unrelated key part of the script."""
    psbt, _, script, _ = _signed_psbt(1, 2, (0,), 0, False)
    leaf_hash = taproot.leaf_hash(0xC0, script)
    psbt.inputs[0].taproot_script_spend_signatures[
        PrvKeyData(4).pub.sec[1:] + leaf_hash
    ] = next(iter(psbt.inputs[0].taproot_script_spend_signatures.values()))
    with pytest.raises(BTClibValueError, match="not the key of leaf script"):
        finalize(psbt)


@pytest.mark.parametrize("number", [b"\x53", b"\x01\x81", b"\x01\x02"])
def test_finalize_does_not_guess_an_invalid_multi_a_threshold(number: bytes) -> None:
    """Refuse an out-of-range or nonminimal threshold."""
    psbt, keys, script, control_block = _signed_psbt(2, 2, (0,), 0, False)
    altered_script = script[:-2] + number + b"\x9c"
    psbt.inputs[0].taproot_leaf_scripts = {control_block: (altered_script, 0xC0)}
    signature = next(iter(psbt.inputs[0].taproot_script_spend_signatures.values()))
    psbt.inputs[0].taproot_script_spend_signatures = {
        keys[0] + taproot.leaf_hash(0xC0, altered_script): signature
    }
    with pytest.raises(BTClibValueError, match="not a single key and OP_CHECKSIG"):
        finalize(psbt)


@pytest.mark.parametrize("count", [MAX_STACK_SIZE - 1, MAX_STACK_SIZE])
def test_finalize_reserves_stack_space_for_the_first_multi_a_key(count: int) -> None:
    """BIP342's stack bound includes the first key the script pushes."""
    psbt, _, script, control_block = _signed_psbt(1, count, (0,), 0, True)
    spent = psbt.inputs[0].witness_utxo
    assert spent is not None
    if count < MAX_STACK_SIZE:
        verify_transaction([spent], extract_tx(finalize(psbt)))
        return

    signature = next(iter(psbt.inputs[0].taproot_script_spend_signatures.values()))
    tx = psbt.tx
    tx.vin[0].script_witness = Witness(
        [*([b""] * (count - 1)), signature, script, control_block]
    )
    with pytest.raises(ScriptError, match="more than 1000 stack elements"):
        verify_transaction([spent], tx)
    with pytest.raises(BTClibValueError, match="not a single key and OP_CHECKSIG"):
        finalize(psbt)
