# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib_wallet.psbt.psbt_updater` module.

BIP174's Updater over a descriptor: what `update_psbt_input` and
`update_psbt_output` write into a psbt, what they leave alone, and that
`finalize` then assembles the spend `Descriptor.satisfy` builds.
"""

from __future__ import annotations

from typing import Any

import pytest
from btclib.alias import Octets
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash160
from btclib.key import PrvKeyData
from btclib.script import taproot
from btclib.script.script import serialize
from btclib.script.script_pub_key import ScriptPubKey
from btclib.script.witness import Witness
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from ecc.ecc import dsa, ssa
from ecc.hashes import tagged_hash

from btclib_wallet.bip32 import BIP32KeyOrigin
from btclib_wallet.bip32.bip32 import prv_keyinfo_from_xprv
from btclib_wallet.descriptors import Descriptor, TrDescriptor, parse
from btclib_wallet.psbt.musig2 import nonce_gen, partial_sign, partial_sigs_agg
from btclib_wallet.psbt.psbt import (
    Psbt,
    _finalized_input,
    finalize,
    taproot_sig_hash,
)
from btclib_wallet.psbt.psbt_in import PsbtIn
from btclib_wallet.psbt.psbt_updater import update_psbt_input, update_psbt_output
from tests import vector_id

XPUB = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
XONLY = "a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
# a second xpub, for the case where an origin agrees and a script does not
XPUB_OTHER = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
# two xpubs of BIP390's, a MuSig2 group with a path of its own
MUSIG_XPUB_A = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
MUSIG_XPUB_B = "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"
XPRV_ROOT = (
    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvv"
    "NKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
)
# a second one, so that a MuSig2 group of two has two keys to hold
XPRV_SECOND = (
    "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWP"
    "rS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L"
)

# three keys and a signature made with each. Real DER signatures rather
# than placeholder bytes because the psbt finalizer that satisfaction is
# checked against parses every partial signature it is handed, so a
# placeholder would not reach the comparison
PRV_KEYS = (1, 2, 3)
SEC_KEYS = [PrvKeyData(prv_key).pub.sec.hex() for prv_key in PRV_KEYS]
SIGNATURES = {
    sec: (dsa.sign(bytes([i]) * 32, prv_key).serialize() + b"\x01").hex()
    for i, (sec, prv_key) in enumerate(zip(SEC_KEYS, PRV_KEYS, strict=True))
}
KEY_A, KEY_B, KEY_C = SEC_KEYS
# the x-only spelling of the same three, which is what a tr() holds
XONLY_A, XONLY_B, XONLY_C = (sec[2:] for sec in SEC_KEYS)

MULTI = f"multi(2,{KEY_A},{KEY_B},{KEY_C})"
SORTED_MULTI = f"sortedmulti(2,{KEY_A},{KEY_B},{KEY_C})"
# the threshold the two constructions used to disagree about: one
# signature is a full satisfaction and OP_CHECKMULTISIG pops the dummy
# all the same, which the psbt finalizer decided by counting (issue
# btclib-org/btclib#305)
MULTI_1 = f"multi(1,{KEY_A},{KEY_B},{KEY_C})"


def signatures_of(*keys: str) -> dict[Octets, Octets]:
    """Return the signature of each key, in the shape satisfy takes."""
    return {key: SIGNATURES[key] for key in keys}


# a descriptor, the keys that sign, and the descriptors of the redeem
# script and of the witness script a psbt would have to be told about --
# the two fields the finalizer dispatches on, and the ones an Updater
# built from a descriptor would fill in
FINALIZER_VECTORS = [
    pytest.param(f"pk({KEY_A})", [KEY_A], "", "", id="pk"),
    pytest.param(f"pkh({KEY_A})", [KEY_A], "", "", id="pkh"),
    pytest.param(f"wpkh({KEY_A})", [KEY_A], "", "", id="wpkh"),
    pytest.param(f"sh(wpkh({KEY_A}))", [KEY_A], f"wpkh({KEY_A})", "", id="sh-wpkh"),
    pytest.param(MULTI, [KEY_A, KEY_C], "", "", id="multi"),
    pytest.param(f"sh({MULTI})", [KEY_A, KEY_C], MULTI, "", id="sh-multi"),
    pytest.param(f"wsh({MULTI})", [KEY_A, KEY_C], "", MULTI, id="wsh-multi"),
    pytest.param(
        f"sh(wsh({MULTI}))",
        [KEY_A, KEY_C],
        f"wsh({MULTI})",
        MULTI,
        id="sh-wsh-multi",
    ),
    pytest.param(
        f"wsh({SORTED_MULTI})", [KEY_A, KEY_C], "", SORTED_MULTI, id="wsh-sortedmulti"
    ),
    pytest.param(MULTI_1, [KEY_A], "", "", id="multi-1"),
    pytest.param(f"sh({MULTI_1})", [KEY_A], MULTI_1, "", id="sh-multi-1"),
    pytest.param(f"wsh({MULTI_1})", [KEY_A], "", MULTI_1, id="wsh-multi-1"),
    pytest.param(
        f"sh(wsh({MULTI_1}))",
        [KEY_A],
        f"wsh({MULTI_1})",
        MULTI_1,
        id="sh-wsh-multi-1",
    ),
]

# what cannot update a psbt, and what says so. The three `satisfy`
# refuses as well, for reasons of their own: an Updater has nothing to
# choose between, and these have nothing to write
UNUPDATABLE = [
    (f"combo({KEY_A})", "combo\\(\\) is four scripts"),
    ("addr(1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH)", "addr\\(\\) cannot update a psbt"),
    ("raw(76a914000000000000000000000000000000000000000088ac)", "raw\\(\\) cannot"),
]


def test_a_musig_descriptor_builds_a_psbt_its_group_can_sign() -> None:
    """The whole point of naming an aggregate key: BIP373's rounds can run.

    What the Updater has to write for that is three things, and all three
    come from the descriptor: the internal key, which is the aggregate key
    derived at this index; the participants, under the *undervied*
    aggregate key, which is what BIP373 keys its field by; and the BIP328
    path from that key to this one, under the fingerprint of the synthetic
    xpub, which is how `psbt.musig2` recognizes the derivation.

    Then the two signers play BIP373's two rounds and the Finalizer adds
    their partial signatures up. `finalize` is the oracle: it verifies the
    aggregate signature against the output key it reads out of the script,
    so it accepts only if every tweak on the way agreed.
    """
    prv_keys: dict[str, str] = {}
    descriptor = parse(f"tr(musig({XPRV_ROOT},{XPRV_SECOND})/0/*)", prv_keys=prv_keys)
    key = descriptor.key_expressions[0]
    psbt = update_psbt_input(descriptor, psbt_spending(descriptor, 1), 0, 1)
    psbt.assert_signable()

    aggregate = key.aggregate(1)
    psbt_in = psbt.inputs[0]
    assert psbt_in.taproot_internal_key == key.sec(1)[1:]
    assert psbt_in.musig2_participant_pub_keys == {aggregate: key.participant_keys(1)}
    leaf_hashes, origin = psbt_in.taproot_hd_key_paths[key.sec(1)[1:]]
    assert leaf_hashes == []
    assert origin.master_fingerprint == hash160(aggregate)[:4]
    assert origin.description.endswith("/0/1")

    signers = [prv_keyinfo_from_xprv(xprv)[0] for xprv in (XPRV_ROOT, XPRV_SECOND)]
    sec_nonces = [nonce_gen(psbt, 0, signer, aggregate) for signer in signers]
    for signer, sec_nonce in zip(signers, sec_nonces, strict=True):
        partial_sign(psbt, 0, sec_nonce, signer, aggregate)
    signature = partial_sigs_agg(psbt, 0, aggregate)

    witness = finalize(psbt).inputs[0].final_script_witness
    assert witness == Witness([signature.serialize()])


def test_the_updater_writes_a_musig_group_that_derives_nothing() -> None:
    """An aggregate key that *is* the internal key has an empty path.

    Which is the first of BIP373's four ways for an aggregate key to reach
    what is spent. The participants are written too, and each participant's
    origin -- the entry a signer looks itself up in.
    """
    participant = f"[d34db33f/0h]{MUSIG_XPUB_A}"
    descriptor = parse(f"tr(musig({participant},{MUSIG_XPUB_B}))")
    key = descriptor.key_expressions[0]
    psbt_in = update_psbt_input(descriptor, psbt_spending(descriptor), 0).inputs[0]

    aggregate = key.aggregate()
    assert psbt_in.taproot_internal_key == aggregate[1:]
    assert psbt_in.musig2_participant_pub_keys == {aggregate: key.participant_keys()}
    leaf_hashes, origin = psbt_in.taproot_hd_key_paths[aggregate[1:]]
    assert leaf_hashes == []
    assert origin.description == hash160(aggregate)[:4].hex()
    leaf_hashes, origin = psbt_in.taproot_hd_key_paths[key.participants[0].sec()[1:]]
    assert leaf_hashes == []
    assert origin.description == "d34db33f/0h"


@pytest.mark.parametrize("descriptor, signing_keys, redeem, witness", FINALIZER_VECTORS)
def test_satisfy_matches_the_psbt_finalizer(
    descriptor: str, signing_keys: list[str], redeem: str, witness: str
) -> None:
    """The two ways btclib builds a spend agree, byte for byte.

    `finalize` assembles the same script_sig and witness from a
    psbt input carrying the same signatures, and it is the older and the
    independently tested of the two: BIP174 describes what it does, and
    what a descriptor adds is knowing the scripts and the key order
    without being told them. So the psbt is told them here -- the redeem
    script, the witness script and the output being spent -- and the two
    constructions are compared.
    """
    parsed = parse(descriptor)
    psbt_in = PsbtIn(
        witness_utxo=TxOut(1000, parsed.script_pub_key()),
        partial_sigs={
            bytes.fromhex(key): bytes.fromhex(SIGNATURES[key]) for key in signing_keys
        },
        redeem_script=parse(redeem).redeem_script() if redeem else b"",
        witness_script=parse(witness).redeem_script() if witness else b"",
    )
    assert parsed.satisfy(signatures_of(*signing_keys)) == _finalized_input(psbt_in)


def psbt_spending(descriptor: Descriptor, index: int = 0) -> Psbt:
    """Return a one-input psbt spending what the descriptor describes.

    The whole previous transaction as the utxo, rather than the spent
    output alone: a witness_utxo beside a legacy input is what
    `Psbt.assert_signable` refuses as "script type not in ('p2wpkh',
    'p2wsh')", and these vectors are of every kind.
    """
    script_pub_key = descriptor.script_pub_key(index)
    prev_tx = Tx(
        vin=[TxIn(OutPoint(b"\x02" * 32, 0))], vout=[TxOut(1000, script_pub_key)]
    )
    psbt = Psbt.from_tx(
        Tx(vin=[TxIn(OutPoint(prev_tx.id, 0))], vout=[TxOut(900, script_pub_key)])
    )
    psbt.inputs[0].non_witness_utxo = prev_tx
    return psbt


@pytest.mark.parametrize("descriptor, signing_keys, redeem, witness", FINALIZER_VECTORS)
def test_the_updater_fills_what_the_finalizer_dispatches_on(
    descriptor: str, signing_keys: list[str], redeem: str, witness: str
) -> None:
    """The vectors above, with the two scripts written by the descriptor.

    Which is the whole of issue btclib-org/btclib#306 for a legacy input: the
    test beside this one hands the psbt the redeem and witness scripts by
    parsing a second descriptor of each, and here nothing is handed to it. That
    the same signatures then finalize to the same spend says the fields are the
    ones the Finalizer needs, and `assert_signable` says each script is the one
    the output being spent commits to.
    """
    parsed = parse(descriptor)
    psbt = update_psbt_input(parsed, psbt_spending(parsed), 0)
    psbt.assert_signable()

    psbt_in = psbt.inputs[0]
    assert psbt_in.redeem_script == (parse(redeem).redeem_script() if redeem else b"")
    assert psbt_in.witness_script == (
        parse(witness).redeem_script() if witness else b""
    )
    psbt_in.partial_sigs = {
        bytes.fromhex(key): bytes.fromhex(SIGNATURES[key]) for key in signing_keys
    }
    assert parsed.satisfy(signatures_of(*signing_keys)) == _finalized_input(psbt_in)


def test_the_updater_carries_the_key_origin_of_the_derived_key() -> None:
    """The path down to the key itself, and not down to the xpub above it.

    What BIP174 carries is what a signer derives with, so the origin of
    a ranged descriptor's key is the origin written in it, the steps the
    descriptor derives, and the index -- three pieces the psbt sees as
    one path.
    """
    descriptor = parse(f"wpkh([d34db33f/84h/0h/0h]{XPUB}/0/*)")
    key = descriptor.key_expressions[0]
    for index in (0, 7):
        psbt = update_psbt_input(descriptor, psbt_spending(descriptor, index), 0, index)
        hd_key_paths = psbt.inputs[0].hd_key_paths
        assert list(hd_key_paths) == [key.sec(index)]
        assert (
            hd_key_paths[key.sec(index)].description == f"d34db33f/84h/0h/0h/0/{index}"
        )


def test_the_updater_adds_to_what_the_psbt_already_carries() -> None:
    """An Updater is a role a psbt passes through, and not the first one.

    Another signer's key origin is left where it is, and the entry for a
    key this descriptor names too is this one: what the descriptor knows
    is knowledge about its own keys.
    """
    descriptor = parse(f"wsh(multi(2,[d34db33f/0h]{XPUB}/0,{KEY_B},{KEY_C}))")
    key = descriptor.key_expressions[0].sec()
    psbt = psbt_spending(descriptor)
    psbt.inputs[0].hd_key_paths = {
        bytes.fromhex(KEY_A): BIP32KeyOrigin("ffffffff", "m/1"),
        key: BIP32KeyOrigin("ffffffff", "m/2"),
    }
    hd_key_paths = update_psbt_input(descriptor, psbt, 0).inputs[0].hd_key_paths
    assert hd_key_paths[bytes.fromhex(KEY_A)].description == "ffffffff/1"
    assert hd_key_paths[key].description == "d34db33f/0h/0"


def test_the_updater_leaves_the_psbt_it_was_given_alone() -> None:
    """A copy, as `finalize` returns one."""
    descriptor = parse(f"sh({MULTI})")
    psbt = psbt_spending(descriptor)
    assert update_psbt_input(descriptor, psbt, 0).inputs[0].redeem_script
    assert not psbt.inputs[0].redeem_script


def test_the_updater_refuses_an_index_that_names_no_input() -> None:
    """An IndexError out of a public method is not an answer.

    A negative one least of all: it is the input at the other end of the
    psbt, updated with the fields of an output it does not spend.
    """
    descriptor = parse(f"wpkh({KEY_A})")
    psbt = psbt_spending(descriptor)
    for vin_i in (-1, 1):
        with pytest.raises(BTClibValueError, match="invalid input index"):
            update_psbt_input(descriptor, psbt, vin_i)
    with pytest.raises(BTClibValueError, match="not a ranged descriptor"):
        update_psbt_input(descriptor, psbt, 0, 1)


def taproot_leaf_of(psbt_in: PsbtIn, x_only: str) -> tuple[bytes, bytes]:
    """Return the leaf script a key is the whole of, and its control block."""
    return next(
        (script, control_block)
        for control_block, (script, _) in psbt_in.taproot_leaf_scripts.items()
        if script[1:-1] == bytes.fromhex(x_only)
    )


def test_the_updater_fills_the_taproot_fields() -> None:
    """The internal key, the merkle root, and every leaf of the tree.

    A control block is the field an Updater is needed for rather than
    convenient: it holds the merkle path from its leaf to the root, which
    is the whole tree seen from that leaf, so a psbt handed one leaf
    cannot work out another. `check_output_pubkey` is the verifier's own
    side of BIP341 and says each of them is the path and the parity bit
    that leaf needs.
    """
    descriptor = parse(f"tr({XONLY_A},{{pk({XONLY_B}),pk({XONLY_C})}})")
    assert isinstance(descriptor, TrDescriptor)
    psbt_in = update_psbt_input(descriptor, psbt_spending(descriptor), 0).inputs[0]

    assert psbt_in.taproot_internal_key == bytes.fromhex(XONLY_A)
    assert psbt_in.taproot_merkle_root == descriptor.taproot_merkle_root()
    output_key = descriptor.script_pub_key().script[2:]
    for leaf_key in (XONLY_B, XONLY_C):
        script, control_block = taproot_leaf_of(psbt_in, leaf_key)
        assert script == serialize([bytes.fromhex(leaf_key), "OP_CHECKSIG"])
        assert taproot.check_output_pubkey(output_key, script, control_block)
    # 0xc0 is the leaf version of every BIP386 tree, and what the
    # control block's first byte carries beside the parity bit
    assert {version for _, version in psbt_in.taproot_leaf_scripts.values()} == {0xC0}


def test_a_taproot_key_path_descriptor_has_no_root_and_no_leaf() -> None:
    """Which is not the same as a tree that is empty.

    `tr(KEY)` tweaks its internal key with no tree at all, and BIP371
    says so by leaving PSBT_IN_TAP_MERKLE_ROOT out.
    """
    descriptor = parse(f"tr({XONLY_A})")
    assert isinstance(descriptor, TrDescriptor)
    assert descriptor.taproot_merkle_root() == b""
    assert descriptor.taproot_leaf_scripts() == {}

    psbt_in = update_psbt_input(descriptor, psbt_spending(descriptor), 0).inputs[0]
    assert psbt_in.taproot_internal_key == bytes.fromhex(XONLY_A)
    assert not psbt_in.taproot_merkle_root
    assert not psbt_in.taproot_leaf_scripts


def test_a_taproot_key_origin_names_the_leaves_it_is_in() -> None:
    """BIP371 keys the field by x-only key and carries the tapleaf hashes.

    None for the internal key, which no leaf commits to, and one per leaf
    for a key in the tree. `hd_key_paths` stays empty: the same key in
    its 33-byte spelling there would be a second entry for a signer that
    signs with neither.
    """
    internal = f"[d34db33f/86h]{XPUB}/0"
    left, right = f"[aabbccdd/1]{XPUB}/1", f"[11223344/2]{XPUB}/2"
    # the left key is in two leaves, at two depths, so its two control
    # blocks are two entries of `taproot_leaf_scripts` -- and one leaf
    # hash here, the two leaves being the same script
    descriptor = parse(f"tr({internal},{{pk({left}),{{pk({right}),pk({left})}}}})")
    psbt_in = update_psbt_input(descriptor, psbt_spending(descriptor), 0).inputs[0]

    assert not psbt_in.hd_key_paths
    # the left key twice among the key expressions, and once here
    keys = list(dict.fromkeys(key.sec()[1:] for key in descriptor.key_expressions))
    assert len(descriptor.key_expressions) == len(keys) + 1
    assert list(psbt_in.taproot_hd_key_paths) == keys
    assert len(psbt_in.taproot_leaf_scripts) == 3
    leaf_hashes, origin = psbt_in.taproot_hd_key_paths[keys[0]]
    assert leaf_hashes == []
    assert origin.description == "d34db33f/86h/0"
    for key, description in zip(
        keys[1:], ("aabbccdd/1/1", "11223344/2/2"), strict=True
    ):
        leaf_hashes, origin = psbt_in.taproot_hd_key_paths[key]
        script = taproot_leaf_of(psbt_in, key.hex())[0]
        assert leaf_hashes == [taproot.leaf_hash(0xC0, script)]
        assert origin.description == description


def test_the_updater_names_the_leaf_a_multi_a_key_is_in() -> None:
    """A leaf commits to as many keys as it names, and BIP371 to each.

    The tapleaf hash is of the whole script, so both keys of one
    `multi_a()` name one hash and the same one: what a signer reads there
    is which scripts it has to sign for, and this is a script both of them
    have to sign.
    """
    left, right = f"[aabbccdd/1]{XPUB}/1", f"[11223344/2]{XPUB}/2"
    descriptor = parse(f"tr({XONLY},multi_a(2,{left},{right}))")
    assert isinstance(descriptor, TrDescriptor)
    psbt_in = update_psbt_input(descriptor, psbt_spending(descriptor), 0).inputs[0]

    assert psbt_in.taproot_leaf_scripts == descriptor.taproot_leaf_scripts()
    ((script, version),) = psbt_in.taproot_leaf_scripts.values()
    assert version == 0xC0
    keys = [key.sec()[1:] for key in descriptor.key_expressions[1:]]
    for key, description in zip(keys, ("aabbccdd/1/1", "11223344/2/2"), strict=True):
        leaf_hashes, origin = psbt_in.taproot_hd_key_paths[key]
        assert leaf_hashes == [taproot.leaf_hash(0xC0, script)]
        assert origin.description == description


def test_a_taproot_script_path_is_finalizable_only_after_the_updater() -> None:
    """A psbt cannot invent a leaf script.

    The gap issue btclib-org/btclib#306 names.

    The Finalizer builds the witness of a script path spend out of the
    leaf script and the control block the input carries, and a
    descriptor writes them there only through the Updater. With them,
    the psbt finalizes to the very bytes `satisfy` builds from the same
    signature.
    """
    descriptor = parse(f"tr({XONLY_A},{{pk({XONLY_B}),pk({XONLY_C})}})")
    psbt = update_psbt_input(descriptor, psbt_spending(descriptor), 0)
    script, control_block = taproot_leaf_of(psbt.inputs[0], XONLY_B)

    # sign_ and not sign: what BIP341 signs is the hash BIP342 makes of
    # the transaction, and the Finalizer checks it with verify_
    leaf_hash = taproot.leaf_hash(0xC0, script)
    msg_hash = taproot_sig_hash(psbt, 0, leaf_hash=leaf_hash)
    signature = ssa.sign_(msg_hash, 2).serialize()
    key_data = bytes.fromhex(XONLY_B) + leaf_hash
    psbt.inputs[0].taproot_script_spend_signatures = {key_data: signature}

    witness = Witness([signature, script, control_block])
    assert finalize(psbt).inputs[0].final_script_witness == witness
    assert descriptor.satisfy({XONLY_B: signature}) == (b"", witness)

    # the same signature in a psbt the descriptor never updated: the
    # leaf it names is one that input says nothing about
    not_updated = psbt_spending(descriptor)
    not_updated.inputs[0].taproot_script_spend_signatures = {key_data: signature}
    with pytest.raises(BTClibValueError, match="no leaf script for tapleaf hash"):
        finalize(not_updated)


@pytest.mark.parametrize(
    "descriptor, message",
    [
        pytest.param(descriptor, message, id=vector_id(index, descriptor))
        for index, (descriptor, message) in enumerate(UNUPDATABLE)
    ],
)
def test_what_cannot_update_a_psbt(descriptor: str, message: str) -> None:
    """Refuse update_psbt_input on combo(), addr() and raw()."""
    parsed = parse(descriptor)
    # combo() is four scripts and script_pub_key refuses to pick one, so
    # the psbt is built around the p2pkh of the same key: what is being
    # tested is the refusal, and it comes before anything reads the utxo
    psbt = psbt_spending(parse(f"pkh({KEY_A})"))
    with pytest.raises(BTClibValueError, match=message):
        update_psbt_input(parsed, psbt, 0)


def psbt_paying(script_pub_key: ScriptPubKey) -> Psbt:
    """Return a psbt paying somebody else at output 0 and this at output 1.

    Which is the shape change detection is about: one output is the
    payment being made and the other comes back to the wallet, and nothing
    but the script says which is which.
    """
    elsewhere = parse(f"wpkh({KEY_B})").script_pub_key()
    tx = Tx(
        vin=[TxIn(OutPoint(b"\x03" * 32, 0))],
        vout=[TxOut(500, elsewhere), TxOut(400, script_pub_key)],
    )
    return Psbt.from_tx(tx)


@pytest.mark.parametrize("descriptor, signing_keys, redeem, witness", FINALIZER_VECTORS)
def test_the_output_updater_fills_the_scripts_and_the_origins(
    descriptor: str, signing_keys: list[str], redeem: str, witness: str
) -> None:
    """The same fields as the input half, on the map an output has.

    A redeem script, a witness script and a key origin say what they say
    whether the psbt is spending the script or paying to it, so the two
    updaters share the writer -- and these are the vectors the input half
    is checked with.
    """
    parsed = parse(descriptor)
    psbt = update_psbt_output(parsed, psbt_paying(parsed.script_pub_key()), 1)
    psbt_out = psbt.outputs[1]

    assert psbt_out.redeem_script == (parse(redeem).redeem_script() if redeem else b"")
    assert psbt_out.witness_script == (
        parse(witness).redeem_script() if witness else b""
    )
    assert list(psbt_out.hd_key_paths) == list(
        update_psbt_input(parsed, psbt_spending(parsed), 0).inputs[0].hd_key_paths
    )
    # and the output the psbt pays to somebody else is left alone
    assert psbt.outputs[0] == Psbt.from_tx(psbt.tx).outputs[0]


def test_the_output_updater_refuses_an_output_it_does_not_describe() -> None:
    """The claim is "this output is mine", and the evidence is the script.

    Never the key origin: four bytes of a hash160 collide, and a psbt is
    written by whoever sends it, so an output marked as change on a
    fingerprint is one a wallet may hand to somebody else believing it
    keeps it. The refusal names the script that was paid.
    """
    descriptor = parse(f"wpkh([d34db33f/84h/0h/0h]{XPUB}/1/*)")
    psbt = psbt_paying(descriptor.script_pub_key(3))

    assert update_psbt_output(descriptor, psbt, 1, 3).outputs[1].hd_key_paths
    # output 0 pays elsewhere, and index 4 is another script of this very
    # descriptor: both are the same refusal
    with pytest.raises(BTClibValueError, match="which is not the script"):
        update_psbt_output(descriptor, psbt, 0, 3)
    with pytest.raises(BTClibValueError, match="which is not the script"):
        update_psbt_output(descriptor, psbt, 1, 4)

    # the same origin, another key: everything a fingerprint check would
    # look at agrees, and the scripts do not
    other = parse(f"wpkh([d34db33f/84h/0h/0h]{XPUB_OTHER}/1/*)")
    with pytest.raises(BTClibValueError, match="which is not the script"):
        update_psbt_output(other, psbt, 1, 3)


def test_the_output_updater_refuses_an_index_that_names_no_output() -> None:
    """An IndexError out of a public method is not an answer."""
    descriptor = parse(f"wpkh({KEY_A})")
    psbt = psbt_paying(descriptor.script_pub_key())
    for vout_i in (-1, 2):
        with pytest.raises(BTClibValueError, match="invalid output index"):
            update_psbt_output(descriptor, psbt, vout_i)
    with pytest.raises(BTClibValueError, match="not a ranged descriptor"):
        update_psbt_output(descriptor, psbt, 1, 1)


@pytest.mark.parametrize(
    "descriptor, message",
    [
        pytest.param(descriptor, message, id=vector_id(index, descriptor))
        for index, (descriptor, message) in enumerate(UNUPDATABLE)
    ],
)
def test_what_cannot_update_an_output(descriptor: str, message: str) -> None:
    """combo(), addr() and raw() have nothing to write into an output either.

    The refusal comes from the same method the input half calls, which is
    the point of there being one: what a fragment knows does not depend on
    which side of the transaction is asking.
    """
    parsed = parse(descriptor)
    # the psbt pays to a script of this very descriptor, so the refusal is
    # the fragment's whichever of the two is asked first: combo() is the
    # one with four, and any of the four is the same index
    psbt = psbt_paying(parsed.script_pub_keys()[0])
    with pytest.raises(BTClibValueError, match=message):
        update_psbt_output(parsed, psbt, 1)


def taproot_merkle_root_of(tree: list[tuple[int, int, bytes]]) -> bytes:
    """Return the merkle root a PSBT_OUT_TAP_TREE field folds up to.

    What a reader does with the field, and the reason the field is the
    tree rather than the root: the leaves arrive depth-first, each with
    its depth, so two of the same depth in a row are siblings and fold
    into their parent. BIP341's TapBranch hash sorts the two, which is
    what makes the fold independent of the order they arrived in.
    """
    stack: list[tuple[int, bytes]] = []
    for depth, leaf_version, script in tree:
        stack.append((depth, taproot.leaf_hash(leaf_version, script)))
        while len(stack) > 1 and stack[-1][0] == stack[-2][0]:
            (depth_, right), (_, left) = stack.pop(), stack.pop()
            branch = min(left, right) + max(left, right)
            stack.append((depth_ - 1, tagged_hash(b"TapBranch", branch)))
    ((depth, root),) = stack
    assert depth == 0
    return root


def test_the_output_updater_publishes_the_whole_taproot_tree() -> None:
    """PSBT_OUT_TAP_TREE, where an input carries the one leaf it spends.

    An output has no leaf being spent, so what it publishes is every leaf
    with the depth it sits at -- and that is enough to rebuild the tree,
    which is what makes the field worth more than the merkle root an input
    carries. The check is the rebuild: fold the leaves back up, tweak the
    internal key with the root, and land on the output key the psbt pays.
    """
    descriptor = parse(
        f"tr({XONLY_A},{{pk({XONLY_B}),{{pk({XONLY_C}),multi_a(1,{XONLY_A})}}}})"
    )
    assert isinstance(descriptor, TrDescriptor)
    psbt_out = update_psbt_output(
        descriptor, psbt_paying(descriptor.script_pub_key()), 1
    ).outputs[1]

    assert psbt_out.taproot_internal_key == bytes.fromhex(XONLY_A)
    assert [depth for depth, _, _ in psbt_out.taproot_tree] == [1, 2, 2]
    assert {version for _, version, _ in psbt_out.taproot_tree} == {0xC0}
    assert [script for _, _, script in psbt_out.taproot_tree] == [
        serialize([bytes.fromhex(XONLY_B), "OP_CHECKSIG"]),
        serialize([bytes.fromhex(XONLY_C), "OP_CHECKSIG"]),
        serialize([bytes.fromhex(XONLY_A), "OP_CHECKSIG", "OP_1", "OP_NUMEQUAL"]),
    ]

    root = taproot_merkle_root_of(psbt_out.taproot_tree)
    assert root == descriptor.taproot_merkle_root()
    output_key = taproot.output_pubkey_from_merkle_root_var(
        psbt_out.taproot_internal_key, root
    )[0]
    assert output_key == descriptor.script_pub_key().script[2:]

    # what an output does not carry: the merkle root is the fold of the
    # tree and would be the same fact twice, and there is no leaf being
    # spent, so no control block either
    assert not hasattr(psbt_out, "taproot_merkle_root")
    assert not hasattr(psbt_out, "taproot_leaf_scripts")


def test_a_taproot_output_with_no_tree_publishes_none() -> None:
    """`tr(KEY)` commits to no script, and BIP371 leaves the field out."""
    descriptor = parse(f"tr({XONLY_A})")
    assert isinstance(descriptor, TrDescriptor)
    assert descriptor.taproot_tree() == []

    psbt_out = update_psbt_output(
        descriptor, psbt_paying(descriptor.script_pub_key()), 1
    ).outputs[1]
    assert psbt_out.taproot_internal_key == bytes.fromhex(XONLY_A)
    assert not psbt_out.taproot_tree


def test_the_output_updater_names_a_musig_group() -> None:
    """BIP373 asks for the participants on an output too, for change.

    A wallet reading a psbt it did not build finds out that an output
    comes back to a group it is in, which is the same question the input
    field answers on the way out.
    """
    descriptor = parse(f"tr(musig({MUSIG_XPUB_A},{MUSIG_XPUB_B})/0/*)")
    key = descriptor.key_expressions[0]
    psbt_out = update_psbt_output(
        descriptor, psbt_paying(descriptor.script_pub_key(2)), 1, 2
    ).outputs[1]

    aggregate = key.aggregate(2)
    assert psbt_out.musig2_participant_pub_keys == {aggregate: key.participant_keys(2)}
    assert psbt_out.taproot_internal_key == key.sec(2)[1:]
    leaf_hashes, origin = psbt_out.taproot_hd_key_paths[key.sec(2)[1:]]
    assert leaf_hashes == []
    assert origin.master_fingerprint == hash160(aggregate)[:4]


def test_a_rawtr_spend_is_finalized_from_the_untweaked_key() -> None:
    """The key path spend of a rawtr(), signed by the key as written.

    `finalize` verifies against the output key it reads out of the
    script, so the signature of the untweaked key finalizes the psbt to
    the same witness `satisfy` builds from it.
    """
    descriptor = parse(f"rawtr({XONLY_A})")
    psbt = update_psbt_input(descriptor, psbt_spending(descriptor), 0)
    psbt.assert_signable()
    # key 1 is XONLY_A itself, signing with no tweak at all
    signature = ssa.sign_(taproot_sig_hash(psbt, 0), 1).serialize()
    psbt.inputs[0].taproot_key_spend_signature = signature
    witness = finalize(psbt).inputs[0].final_script_witness
    assert witness == Witness([signature])
    assert descriptor.satisfy({XONLY_A: signature}) == (b"", witness)


def test_the_updater_writes_one_taproot_field_for_a_rawtr() -> None:
    """The derivation, and none of the other three.

    PSBT_IN_TAP_INTERNAL_KEY names the key a verifier tweaks and a
    ``rawtr()`` has none, so it has no merkle root and no leaf script
    either; what it does have is a key with an origin, keyed by the 32
    bytes the script holds. `hd_key_paths` stays empty for the reason it
    does under a ``tr()``: the same key in its 33-byte spelling would be a
    second entry for a signer that signs with neither.
    """
    descriptor = parse(f"rawtr([d34db33f/86h/0h/0h]{XPUB}/0/*)")
    key = descriptor.key_expressions[0]
    psbt_in = update_psbt_input(descriptor, psbt_spending(descriptor, 3), 0, 3).inputs[
        0
    ]

    assert not psbt_in.hd_key_paths
    assert not psbt_in.taproot_internal_key
    assert not psbt_in.taproot_merkle_root
    assert not psbt_in.taproot_leaf_scripts
    leaf_hashes, origin = psbt_in.taproot_hd_key_paths[key.sec(3)[1:]]
    assert leaf_hashes == []
    assert origin.description == "d34db33f/86h/0h/0h/0/3"


def test_the_updater_refuses_an_argument_of_another_type() -> None:
    """A descriptor's text is no descriptor, and a psbt's bytes no psbt.

    Each is refused as a `BTClibTypeError` before a field of it is read,
    and so is a map index that is no integer: a bool would otherwise be
    the input or the output at index 0 or 1.
    """
    descriptor = parse(f"wpkh({KEY_A})")
    cases = (
        (update_psbt_input, psbt_spending(descriptor), 0),
        (update_psbt_output, psbt_paying(descriptor.script_pub_key()), 1),
    )
    for function, psbt, map_i in cases:
        with pytest.raises(BTClibTypeError, match="invalid descriptor type: str"):
            function(str(descriptor), psbt, map_i)  # type: ignore[arg-type]
        with pytest.raises(BTClibTypeError, match="invalid psbt type: bytes"):
            function(descriptor, psbt.serialize(), map_i)  # type: ignore[arg-type]
        for wrong in (str(map_i), float(map_i), bool(map_i), None):
            with pytest.raises(BTClibTypeError, match="put index type: "):
                function(descriptor, psbt, wrong)  # type: ignore[arg-type]


@pytest.mark.parametrize("index", ["1", None, b"\x01", 1.0, True, False, object()])
def test_the_updater_refuses_a_derivation_index_that_is_no_integer(
    index: object,
) -> None:
    """The index a descriptor is expanded at is refused before it derives."""
    descriptor = parse(f"tr({XPUB}/*)")
    wrong: Any = index
    with pytest.raises(BTClibTypeError, match="^invalid derivation index type:"):
        update_psbt_input(descriptor, psbt_spending(descriptor), 0, wrong)
    paying = psbt_paying(descriptor.script_pub_key())
    with pytest.raises(BTClibTypeError, match="^invalid derivation index type:"):
        update_psbt_output(descriptor, paying, 1, wrong)
