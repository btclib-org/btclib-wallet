# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BIP174's Updater for the script a descriptor describes.

`update_psbt_input` and `update_psbt_output` write what
`Descriptor.expansion` returns into one input or one output of a psbt, for
signers to fill in at their own pace and `finalize` to assemble. The
output half is also what tells change from a payment, and it makes that
claim only where the descriptor derives the very script being paid:
`Descriptor.index_of` is the same question asked the other way round, and
neither answers from a key origin whose fingerprint happens to match.
"""

from __future__ import annotations

from copy import deepcopy

from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import assert_type, is_integer

from btclib_wallet.descriptors.descriptors import Descriptor, Expansion
from btclib_wallet.descriptors.key_expression import PrvKeys
from btclib_wallet.psbt.psbt import Psbt
from btclib_wallet.psbt.psbt_in import PsbtIn
from btclib_wallet.psbt.psbt_out import PsbtOut

__all__ = ["update_psbt_input", "update_psbt_output"]


def _assert_arguments(
    descriptor: Descriptor, psbt: Psbt, map_i: int, side: str
) -> None:
    """Refuse a descriptor, a psbt or a map index of another type."""
    assert_type(descriptor, Descriptor, "descriptor")
    assert_type(psbt, Psbt, "psbt")
    if not is_integer(map_i):
        err_msg = f"invalid {side} index type: {type(map_i).__name__}"
        raise BTClibTypeError(err_msg)


def _write(psbt_map: PsbtIn | PsbtOut, expansion: Expansion) -> None:
    """Write the fields an input and an output share.

    One function for both maps, because BIP174 gives the two the same
    fields wherever they mean the same thing: a redeem script, a witness
    script and a key origin say what they say whether the psbt is spending
    the script or paying to it. Only a ``tr()`` differs, an input carrying
    the leaf it spends and an output the whole tree, and that is where the
    two functions below part company.

    A mapping is added to and not replaced: BIP174 keys it by public key,
    so a psbt already carrying another signer's key keeps it, and this
    descriptor's entry wins for a key held by both. A script and an
    internal key are written where the descriptor has one, and left alone
    where it has none.
    """
    psbt_map.hd_key_paths = {**psbt_map.hd_key_paths, **expansion.hd_key_paths}
    if expansion.redeem_script:
        psbt_map.redeem_script = expansion.redeem_script
    if expansion.witness_script:
        psbt_map.witness_script = expansion.witness_script
    if expansion.taproot_internal_key:
        psbt_map.taproot_internal_key = expansion.taproot_internal_key
    psbt_map.taproot_hd_key_paths = {
        **psbt_map.taproot_hd_key_paths,
        **expansion.taproot_hd_key_paths,
    }
    psbt_map.musig2_participant_pub_keys = {
        **psbt_map.musig2_participant_pub_keys,
        **expansion.musig2_participant_pub_keys,
    }


def update_psbt_input(
    descriptor: Descriptor,
    psbt: Psbt,
    vin_i: int,
    index: int = 0,
    prv_keys: PrvKeys | None = None,
) -> Psbt:
    """Return the psbt with input `vin_i` told what the descriptor knows.

    BIP174's Updater, for the one input this descriptor describes: the
    redeem script of a ``sh()``, the witness script of a ``wsh()``, the
    internal key, merkle root and leaf scripts of a ``tr()``, and the
    origin of every key. `finalize` then assembles the same bytes
    `Descriptor.satisfy` does, from the signatures the signers filled in
    at their own pace: that pipeline is what a psbt is for, and what
    `satisfy` cannot answer, refusing a partial satisfaction rather than
    returning bytes that do not spend.

    A control block is the field an Updater is needed for rather than
    convenient -- it holds the merkle path from its leaf to the root,
    which is the whole tree seen from that leaf -- and the merkle root is
    what a verifier tweaks the internal key with.

    A copy, the psbt handed in being left alone, and the fields of the
    copy mutated in place: `finalize` is the same construction, and
    BIP174's roles read as steps that update a psbt rather than as
    functions that return a field at a time.

    What is not filled is what a descriptor does not know: the utxo, the
    sighash type, the signatures. Nor is the script checked against the
    output being spent -- an input may not carry it yet, and
    `Psbt.assert_signable` asks that question for every input at once,
    being the role after this one.
    """
    _assert_arguments(descriptor, psbt, vin_i, "input")
    expansion = descriptor.expansion(index, prv_keys)
    # an IndexError out of a public function is not an answer, and a
    # negative index would quietly update the input at the other end
    if not 0 <= vin_i < len(psbt.inputs):
        raise BTClibValueError(f"invalid input index: {vin_i}")
    psbt = deepcopy(psbt)
    psbt_in = psbt.inputs[vin_i]
    _write(psbt_in, expansion)
    if expansion.taproot_merkle_root is not None:
        psbt_in.taproot_merkle_root = expansion.taproot_merkle_root
    psbt_in.taproot_leaf_scripts = {
        **psbt_in.taproot_leaf_scripts,
        **expansion.taproot_leaf_scripts,
    }
    psbt.assert_valid()
    return psbt


def update_psbt_output(
    descriptor: Descriptor,
    psbt: Psbt,
    vout_i: int,
    index: int = 0,
    prv_keys: PrvKeys | None = None,
) -> Psbt:
    """Return the psbt with output `vout_i` told what the descriptor knows.

    The Updater's other half, and what makes an output recognizable as the
    wallet's own: the redeem script of a ``sh()``, the witness script of a
    ``wsh()``, the internal key and the whole script tree of a ``tr()``,
    and the origin of every key. A signing device reads them to tell
    change from a payment -- it can derive the script itself and see that
    the money comes back -- and a wallet reading a psbt somebody else
    built reads them for the same reason.

    Unlike the input half, the script *is* checked: the output being paid
    is in the psbt already, so this refuses unless the descriptor derives
    exactly that script at `index`. Marking an output as one's own is a
    claim about where money goes, and the only evidence for it is the
    whole script -- never a key origin whose four-byte fingerprint
    matches, which is what `Descriptor.index_of` is for and what it says.

    The output tree is BIP371's PSBT_OUT_TAP_TREE and not the leaf script
    an input carries: an output has no leaf being spent, so what it
    publishes is every leaf, each with its depth, which is what lets a
    reader rebuild the tree and check the output key for itself. No merkle
    root goes with it, the root being the fold of the tree.
    """
    _assert_arguments(descriptor, psbt, vout_i, "output")
    expansion = descriptor.expansion(index, prv_keys)
    # an IndexError out of a public function is not an answer, and a
    # negative index would quietly update the output at the other end
    if not 0 <= vout_i < len(psbt.outputs):
        raise BTClibValueError(f"invalid output index: {vout_i}")
    paid = psbt.tx.vout[vout_i].script_pub_key.script
    if all(
        script.script != paid for script in descriptor.script_pub_keys(index, prv_keys)
    ):
        err_msg = f"output {vout_i} pays to {paid.hex()}, which is not the"
        err_msg += f" script this descriptor describes at index {index}"
        raise BTClibValueError(err_msg)
    psbt = deepcopy(psbt)
    psbt_out = psbt.outputs[vout_i]
    _write(psbt_out, expansion)
    if expansion.taproot_tree is not None:
        psbt_out.taproot_tree = list(expansion.taproot_tree)
    psbt.assert_valid()
    return psbt
