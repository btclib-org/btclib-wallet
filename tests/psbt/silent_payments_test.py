# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib_wallet.psbt.silent_payments` module, BIP375's roles.

The vectors are BIP375's own `bip375_test_vectors.json`, already vendored
under `tests/psbt/_data/` for `bip375_test.py`, which holds the codec to
them; this module holds the two roles to the same file, and where that one
had to say that seventeen of the invalid psbts are accepted, here **all 22
are refused and all 20 valid ones pass**.

The `checks` field of a case names which of BIP375's four checks it is
about, so each invalid case is asserted against the check that should
refuse it rather than against "something raised": a psbt refused for the
wrong reason is a psbt this module got right by accident. A valid case
naming `checks` is isolating one of them instead -- the rest of the psbt
is not necessarily complete for the others -- so only the named check
runs.

**The k ordering is measured here, not assumed**, because BIP375's prose
and its own vectors disagree and the disagreement is load-bearing. The
prose says to sort the codes of one scan key lexicographically; the
vectors' scripts are the ones output-index order derives, and one case
published as *valid* has its two spend keys in descending order, so the
two readings differ on it. `test_the_k_ordering_is_the_output_index` pins
that, so a revision settling it the other way fails here rather than
passing quietly.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest
from btclib.alias import Octets
from btclib.exceptions import BTClibValueError, ScriptError
from btclib.hashes import hash160
from btclib.key import PubKeyData
from btclib.script import ScriptPubKey, Witness, serialize, taproot
from btclib.script.script_pub_key import is_p2wpkh
from btclib.script.taproot import output_pubkey_from_merkle_root
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from btclib_ecc.curves import bytes_from_point, mult, secp256k1
from btclib_ecc.ecc import dleq

from btclib_wallet import silent_payments as sp
from btclib_wallet.bip32 import (
    BIP32KeyData,
    BIP32KeyOrigin,
    derive,
    pub_keyinfo_from_xkey,
    rootxprv_from_seed,
)
from btclib_wallet.psbt import (
    Psbt,
    PsbtIn,
    PsbtOut,
    combine,
    extract_tx,
    finalize,
    sign,
)
from btclib_wallet.psbt import silent_payments as role
from btclib_wallet.psbt_signer import SoftwareSigner
from tests import load, vector_id

_VECTORS = load("psbt", "_data", "bip375_test_vectors.json", encoding="utf-8")

# which of BIP375's four checks each invalid case is about, read off the
# description's own prefix: the file groups them that way, and the
# categories are the ones its README lists
_CATEGORIES = ("psbt structure", "ecdh coverage", "input eligibility", "output scripts")


def _params(group: str) -> tuple[list[dict[str, Any]], list[str]]:
    vectors = _VECTORS[group]
    ids = [vector_id(i, v["description"]) for i, v in enumerate(vectors)]
    return vectors, ids


def _decoded(encoded: str) -> Psbt:
    """Return a vector's psbt, each input's script committing to its key.

    BIP375's vectors give a p2wpkh input a witness_utxo whose program is
    not the hash160 of the one key its PSBT_IN_BIP32_DERIVATION names but
    the key's sha256 cut to 20 bytes -- their `supplementary` data carries
    the same program, so no key in the file could spend those outputs --
    and a taproot input whose internal
    key is NUMS_H an output key that is NUMS_H untweaked. `input_pub_key`
    answers only a key the spent script commits to, and a NUMS_H claim
    only with a proof against the output key, so each such script is
    rewritten from the psbt's own claim. Nothing a silent payment is
    derived from changes: the shares, the proofs, the outpoints and the
    keys are the file's.
    """
    psbt = Psbt.b64decode(encoded)
    for psbt_in in psbt.inputs:
        utxo = psbt_in.witness_utxo
        if utxo is None:
            continue
        keys = [k for k in psbt_in.hd_key_paths if len(k) == 33]
        if is_p2wpkh(utxo.script_pub_key.script) and len(keys) == 1:
            script = ScriptPubKey.p2wpkh(PubKeyData(keys[0]))
        elif psbt_in.taproot_internal_key == sp.NUMS_H:
            output_key, _ = output_pubkey_from_merkle_root(
                sp.NUMS_H, psbt_in.taproot_merkle_root
            )
            script = ScriptPubKey(serialize(["OP_1", output_key]))
        else:
            continue
        psbt_in.witness_utxo = TxOut(utxo.value, script)
    return psbt


_VALID, _VALID_IDS = _params("valid")
_INVALID, _INVALID_IDS = _params("invalid")


def _category(description: str) -> str:
    """Return which of the four checks a case is about."""
    for category in _CATEGORIES:
        if description.startswith(category):
            return category
    msg = f"vector in no category: {description}"
    raise AssertionError(msg)


# the same field `checks` names, for a vector that restricts itself to one
# of BIP375's four checks rather than asking for the whole protocol; the
# vocabulary is upstream's own test runner's, `CHECK_FUNCTIONS` in
# `bip-0375/test_runner.py`
_ONLY_CHECK = {
    "ecdh_coverage": role.assert_shares_as_valid,
    "input_eligibility": role.assert_eligibility_as_valid,
    "output_scripts": role.assert_output_scripts_as_valid,
}


@pytest.mark.parametrize("vector", _VALID, ids=_VALID_IDS)
def test_every_valid_psbt_passes_every_check(vector: dict[str, Any]) -> None:
    """The whole file's valid half, both roles applied.

    Including the "in progress" ones, which is the half that says the
    checks know what a psbt under construction looks like: an output whose
    script is not derived yet is not an output whose script is wrong.

    A vector naming its own `checks` is isolating one of them, so only that
    one runs: the rest of the psbt is not necessarily complete for the
    others.
    """
    psbt = _decoded(vector["psbt"])
    checks = vector.get("checks")
    if checks is not None:
        for name in checks:
            _ONLY_CHECK[name](psbt)
        return
    role.assert_as_valid(psbt)
    # and each check on its own, so that a pass is not one check masking
    # another's opinion
    role.assert_shares_as_valid(psbt)
    role.assert_eligibility_as_valid(psbt)
    role.assert_output_scripts_as_valid(psbt)


@pytest.mark.parametrize("vector", _INVALID, ids=_INVALID_IDS)
def test_every_invalid_psbt_is_refused(vector: dict[str, Any]) -> None:
    """All 22, where the codec alone refused five.

    The other seventeen are what this module adds, and each is refused by
    the check its own category names -- `Psbt.parse` and `assert_valid`
    for the structural ones, and one of the three role checks otherwise.
    """
    category = _category(vector["description"])
    if category == "psbt structure":
        # the codec's own, five of the six: parse refuses four for a
        # length and one for a missing script, and the sixth is the
        # modifiable flags, which is a Signer's obligation
        with pytest.raises(BTClibValueError):
            role.assert_as_valid(_decoded(vector["psbt"]))
        return

    psbt = _decoded(vector["psbt"])
    checks = {
        "ecdh coverage": (
            role.assert_shares_as_valid,
            role.assert_output_scripts_as_valid,
        ),
        "input eligibility": (role.assert_eligibility_as_valid,),
        "output scripts": (role.assert_output_scripts_as_valid,),
    }[category]
    # its own category's check refuses it, and not merely the whole
    with pytest.raises(BTClibValueError):
        # `no branch`: the first check of the category refuses, which is
        # what the enclosing `raises` asserts, so the loop is never
        # exhausted -- the several entries are the checks that must all
        # be reached across the categories, not several to be run here
        for check in checks:  # pragma: no branch -- the first check refuses
            check(psbt)
    with pytest.raises(BTClibValueError):
        role.assert_as_valid(psbt)


def _vector(group: str, prefix: str) -> dict[str, Any]:
    """Return the one case whose description starts with the prefix."""
    return next(v for v in _VECTORS[group] if v["description"].startswith(prefix))


def test_the_k_ordering_is_the_output_index() -> None:
    """BIP375's prose and BIP375's vectors disagree; the vectors win.

    "If there are multiple silent payment codes with the same scan key,
    sort the codes lexicographically in ascending order to determine the
    ordering of the k value" -- and the case below is published as valid,
    shares one scan key across two outputs, and has its spend keys in
    *descending* order. So the lexicographic rule would give output 1 the
    k of 0, and the scripts the file carries are the ones output index
    order derives.

    Asserted rather than described, in both directions: index order
    reproduces both scripts, and the byte order and the address order --
    the two readings of "the codes" -- reproduce neither. Upstream's own
    validator walks index order too, so the prose is the outlier.
    """
    vector = _vector("valid", "can finalize: two sp outputs - output 0 uses label=3")
    psbt = _decoded(vector["psbt"])
    outputs = [(i, o) for i, o in enumerate(psbt.outputs) if o.sp_v0_info]
    assert len(outputs) == 2
    scan_key = outputs[0][1].sp_v0_info[: sp._PK_SIZE]
    # one scan key, and the spend keys the other way round
    assert all(o.sp_v0_info[: sp._PK_SIZE] == scan_key for _, o in outputs)
    assert outputs[0][1].sp_v0_info > outputs[1][1].sp_v0_info

    found = role._share_and_sum(psbt, scan_key)
    assert found is not None
    share, A_sum = found
    secret = role.shared_secret_from_share(psbt, share, A_sum)

    def script(psbt_out: Any, k: int) -> bytes:
        B_m = psbt_out.sp_v0_info[sp._PK_SIZE :]
        return serialize(["OP_1", sp.output_key(secret, B_m, k)])

    # index order: k is the position among the silent payment outputs
    for k, (_, psbt_out) in enumerate(outputs):
        assert psbt_out.script_pub_key == script(psbt_out, k)
    # the lexicographic order would swap them, and neither script matches
    for k, (_, psbt_out) in enumerate(reversed(outputs)):
        assert psbt_out.script_pub_key != script(psbt_out, k)

    # and what the module derives is what the file carries
    assert role.output_scripts(psbt) == {i: o.script_pub_key for i, o in outputs}


def test_the_two_ordering_vectors_are_refused_whatever_the_order() -> None:
    """The invalid cases named after ordering are not about ordering.

    Both have all three candidate orderings agree -- their spend keys are
    already ascending, or identical -- so what makes them invalid is that
    their scripts match no k assignment at all. Worth pinning: a reader of
    the descriptions would expect them to be the vectors that decide the
    ordering question, and they are not; the valid case above is.
    """
    for prefix in (
        "output scripts: two sp outputs (same scan / different spend keys)",
        "output scripts: k values assigned to wrong output indices",
    ):
        psbt = _decoded(_vector("invalid", prefix)["psbt"])
        outputs = [(i, o) for i, o in enumerate(psbt.outputs) if o.sp_v0_info]
        by_index = [i for i, _ in outputs]
        by_bytes = [
            i for i, _ in sorted(outputs, key=lambda p: (p[1].sp_v0_info, p[0]))
        ]
        assert by_index == by_bytes
        with pytest.raises(BTClibValueError, match="not the silent payment script"):
            role.assert_output_scripts_as_valid(psbt)


def test_an_input_pub_key_comes_from_the_derivation_or_the_script() -> None:
    """Where BIP375 says to look, and what a psbt not saying costs.

    A taproot input's key is in the script_pub_key, so it is readable
    whatever else the psbt carries. Every other eligible kind keeps it in
    PSBT_IN_BIP32_DERIVATION, which BIP375 asks an Updater to add for
    exactly this -- an unsigned input has no witness and no scriptSig to
    read one out of, which is why `btclib_wallet.silent_payments`'s reader
    cannot serve here.
    """
    psbt = _decoded(_vector("valid", "can finalize: one P2PKH input")["psbt"])
    psbt_in = psbt.inputs[0]
    pub_key = role.input_pub_key(psbt_in)
    assert pub_key is not None
    assert bytes_from_point(pub_key) in psbt_in.hd_key_paths

    # the field gone, the key is gone with it, and the input is still
    # counted: the recipient sums it, so a share proved against the others
    # alone proves nothing, and the sum is refused rather than taken short
    stripped = deepcopy(psbt)
    stripped.inputs[0].hd_key_paths = {}
    assert role.input_pub_key(stripped.inputs[0]) is None
    with pytest.raises(BTClibValueError, match="carries no public key"):
        role.eligible_pub_keys(stripped)
    with pytest.raises(BTClibValueError, match="no public key"):
        role.assert_shares_as_valid(stripped)

    # and a key the spent script does not commit to is no key of the input
    other = deepcopy(psbt)
    origin = next(iter(psbt_in.hd_key_paths.values()))
    other.inputs[0].hd_key_paths = {bytes_from_point(mult(2)): origin}
    assert role.input_pub_key(other.inputs[0]) is None

    # a taproot input needs no field: the output key is the script's
    taproot = _decoded(_vector("valid", "in progress: two P2TR inputs")["psbt"])
    for taproot_in in taproot.inputs:
        assert role.input_pub_key(taproot_in) is not None


def test_an_ineligible_input_is_passed_over_rather_than_refused() -> None:
    """A share on an input BIP352 does not count proves nothing.

    And is not an error: one of BIP375's valid vectors carries exactly
    that, a p2sh multisig input beside the eligible ones. It contributes
    to no sum and is held to no proof -- which is a different thing from
    an input that *is* counted and carries no public key, the case above,
    and one of the invalid vectors.
    """
    psbt = _decoded(
        _vector("valid", "can finalize: two inputs using per-input ECDH")["psbt"]
    )
    eligible = role.eligible_pub_keys(psbt)
    assert len(eligible) < len(psbt.inputs)
    ineligible = next(i for i in range(len(psbt.inputs)) if i not in eligible)
    assert role.input_pub_key(psbt.inputs[ineligible]) is None
    role.assert_as_valid(psbt)


def test_a_share_needs_its_proof_and_a_proof_its_share() -> None:
    """Each half of the pair is useless alone, so neither stands alone."""
    psbt = _decoded(
        _vector("valid", "can finalize: two inputs single-signer using global")["psbt"]
    )
    scan_key = next(iter(psbt.sp_ecdh_shares))

    no_proof = deepcopy(psbt)
    no_proof.sp_dleq_proofs = {}
    with pytest.raises(
        BTClibValueError, match="global ECDH share with no proof beside it"
    ):
        role.assert_shares_as_valid(no_proof)

    no_share = deepcopy(psbt)
    no_share.sp_ecdh_shares = {}
    with pytest.raises(
        BTClibValueError, match="global DLEQ proof with no share to prove"
    ):
        role.assert_shares_as_valid(no_share)

    # and the same for the per-input pair
    per_input = _decoded(
        _vector("valid", "can finalize: two inputs single-signer using per")["psbt"]
    )
    damaged = deepcopy(per_input)
    damaged.inputs[0].sp_dleq_proofs = {}
    with pytest.raises(
        BTClibValueError, match="input 0 ECDH share with no proof beside it"
    ):
        role.assert_shares_as_valid(damaged)
    damaged = deepcopy(per_input)
    damaged.inputs[0].sp_ecdh_shares = {}
    with pytest.raises(
        BTClibValueError, match="input 0 DLEQ proof with no share to prove"
    ):
        role.assert_shares_as_valid(damaged)

    # a proof of the right shape that proves the wrong thing is refused by
    # the verification and not by a length, which is the point of carrying
    # one at all
    forged = deepcopy(psbt)
    forged.sp_ecdh_shares[scan_key] = bytes_from_point(mult(2))
    with pytest.raises(BTClibValueError, match="invalid global DLEQ proof"):
        role.assert_shares_as_valid(forged)


def test_the_share_is_not_the_shared_secret() -> None:
    """`a*B_scan` carries no input hash; BIP352's secret does.

    The step the two BIPs give no shared name, and the one an
    implementation gets wrong silently: skip the input hash and every
    output script comes out different, with nothing else to say so.
    """
    psbt = _decoded(
        _vector("valid", "can finalize: two inputs single-signer using global")["psbt"]
    )
    scan_key, share = next(iter(psbt.sp_ecdh_shares.items()))
    A_sum = sp.pub_key_sum(list(role.eligible_pub_keys(psbt).values()))
    secret = role.shared_secret_from_share(psbt, share, A_sum)

    outpoints = [psbt_in.prev_out for psbt_in in psbt.inputs]
    h = sp.input_hash(outpoints, A_sum)
    assert secret == mult(h, sp.pub_key_sum([share]))
    # the share alone is a different point, and would derive different
    # scripts with nothing to report
    assert secret != sp.pub_key_sum([share])
    assert bytes_from_point(secret) != share
    # and the share is what a DLEQ proof is about, the secret is not
    assert dleq.verify_proof(A_sum, scan_key, share, psbt.sp_dleq_proofs[scan_key])


def test_a_signer_writes_the_shares_it_can_prove() -> None:
    """The Signer's side, held to the Extractor's.

    A psbt stripped of its shares is written again from the private keys
    the vector publishes, and what says the two agree is not a byte
    comparison but the checks themselves: the proofs verify, the scripts
    derive to what the file already carried, and `assert_as_valid` passes
    over the result.
    """
    vector = _vector("valid", "can finalize: two inputs single-signer using per")
    psbt = _decoded(vector["psbt"])
    prv_keys = {
        i["input_index"]: i["private_key"]
        for i in vector["supplementary"]["inputs"]
        if i["private_key"]
    }
    expected = {i: o.script_pub_key for i, o in enumerate(psbt.outputs) if o.sp_v0_info}

    stripped = deepcopy(psbt)
    for psbt_in in stripped.inputs:
        psbt_in.sp_ecdh_shares = {}
        psbt_in.sp_dleq_proofs = {}
    for i in role.eligible_pub_keys(stripped):
        role.set_input_share(stripped, i, prv_keys[i], aux=bytes(32))
    role.assert_shares_as_valid(stripped)
    assert role.output_scripts(stripped) == expected
    role.assert_as_valid(stripped)

    # the same psbt with one global share instead, which is what a signer
    # holding every key may write: a different psbt, the same outputs
    global_psbt = deepcopy(stripped)
    for psbt_in in global_psbt.inputs:
        psbt_in.sp_ecdh_shares = {}
        psbt_in.sp_dleq_proofs = {}
    eligible = list(role.eligible_pub_keys(global_psbt))
    role.set_global_share(global_psbt, [prv_keys[i] for i in eligible], aux=bytes(32))
    role.assert_shares_as_valid(global_psbt)
    assert role.output_scripts(global_psbt) == expected
    role.assert_as_valid(global_psbt)


def test_a_signer_is_held_to_the_key_of_the_input_it_writes_for() -> None:
    """A share proved against the wrong key is refused before it is written.

    Which is worth doing at the writing end: every reader of the psbt
    would reject it, and the signer would have published a proof of its
    own error.
    """
    vector = _vector("valid", "can finalize: two inputs single-signer using per")
    psbt = _decoded(vector["psbt"])
    prv_keys = {
        i["input_index"]: i["private_key"]
        for i in vector["supplementary"]["inputs"]
        if i["private_key"]
    }
    eligible = list(role.eligible_pub_keys(psbt))
    other = prv_keys[eligible[1]]
    with pytest.raises(BTClibValueError, match="not the one of its public key"):
        role.set_input_share(psbt, eligible[0], other)

    # and the ineligible-input refusal, which needs a psbt that has one:
    # the P2SH multisig case, where a share would contribute to no sum
    excluded = _decoded(
        _vector("valid", "can finalize: two inputs using per-input ECDH")["psbt"]
    )
    excluded_eligible = role.eligible_pub_keys(excluded)
    ineligible = next(
        i for i in range(len(excluded.inputs)) if i not in excluded_eligible
    )
    with pytest.raises(BTClibValueError, match="no share BIP352 would count"):
        role.set_input_share(excluded, ineligible, next(iter(prv_keys.values())))

    with pytest.raises(BTClibValueError, match="private keys for"):
        role.set_global_share(psbt, [next(iter(prv_keys.values()))])
    with pytest.raises(BTClibValueError, match="do not sum to"):
        role.set_global_share(psbt, [other] * len(eligible))


def test_a_signer_derives_the_scripts_and_freezes_the_psbt() -> None:
    """BIP375: the scripts written, and nothing left modifiable.

    The scripts are a function of the input set and of where the codes
    sit, so a psbt that publishes one and still invites inputs invites its
    own scripts to become wrong. The flags are cleared in the same step
    that writes them, and `assert_as_valid` refuses the state where they
    are not.
    """
    vector = _vector("valid", "in progress: one P2TR input / one sp output")
    psbt = _decoded(vector["psbt"])
    psbt_out = next(o for o in psbt.outputs if o.sp_v0_info)
    assert not psbt_out.script_pub_key

    # no share yet: nothing to derive from, and it says so rather than
    # writing half a transaction
    with pytest.raises(BTClibValueError, match="no ECDH share for scan key"):
        role.set_output_scripts(psbt)

    signed = _decoded(
        _vector("valid", "can finalize: two inputs single-signer using global")["psbt"]
    )
    expected = {
        i: o.script_pub_key for i, o in enumerate(signed.outputs) if o.sp_v0_info
    }
    stripped = deepcopy(signed)
    for i in expected:
        stripped.outputs[i].script_pub_key = b""
    stripped.tx_modifiable = 0xFF

    role.set_output_scripts(stripped)
    assert {
        i: o.script_pub_key for i, o in enumerate(stripped.outputs) if o.sp_v0_info
    } == expected
    assert stripped.tx_modifiable is not None
    assert not stripped.tx_modifiable & 0b11
    # the five bits BIP370 leaves undefined are untouched: dropping a flag
    # somebody set is the change with consequences
    assert stripped.tx_modifiable == 0xFF & ~0b11
    role.assert_as_valid(stripped)


def test_a_psbt_with_no_silent_payment_output_passes() -> None:
    """There is nothing to derive, so there is nothing to refuse.

    The BIP371 taproot psbts of `bip371_test_vectors.json` are what say
    so: none of them carries a BIP375 field, and every role check has to
    be a no-op over them rather than an opinion.
    """
    checked = 0
    for case in load("psbt", "_data", "bip371_test_vectors.json")["valid psbts"]:
        psbt = Psbt.b64decode(case["encoded psbt"])
        assert not any(o.sp_v0_info for o in psbt.outputs), case["description"]
        role.assert_shares_as_valid(psbt)
        role.assert_eligibility_as_valid(psbt)
        role.assert_output_scripts_as_valid(psbt)
        assert role.output_scripts(psbt) == {}
        # and the whole check, which for a version 0 psbt is also what
        # reaches the modifiable rule with no field to read: BIP370's flags
        # do not exist there, and no silent payment script depends on them
        role.assert_as_valid(psbt)
        assert psbt.tx_modifiable is None
        checked += 1
    assert checked


def test_the_categories_cover_every_invalid_vector() -> None:
    """The dispatch above is only as good as the prefixes it knows.

    A description in none of the four would otherwise pick a check by
    accident, so it raises -- and this is what says the raise is reachable
    rather than decoration, which is the failure mode of every guard
    written in the negative.
    """
    for vector in _VECTORS["invalid"]:
        assert _category(vector["description"]) in _CATEGORIES
    with pytest.raises(AssertionError, match="vector in no category"):
        _category("something upstream has not grouped yet")


def test_a_witness_version_is_read_off_the_shape() -> None:
    """What `assert_eligibility_as_valid` asks of every input's script.

    None where the script is no witness program at all, which is most
    scripts: a p2pkh, and a p2pk whose push length happens to fit the
    shape a program has. The versions above 1 are the ones refused, and
    v0 and v1 are the ones every silent payment is made of.
    """
    p2wpkh = bytes.fromhex("0014" + "11" * 20)
    p2tr = bytes.fromhex("5120" + "11" * 32)
    v2 = bytes.fromhex("5220" + "11" * 32)
    v16 = bytes.fromhex("6020" + "11" * 32)
    # the shape of a program -- one opcode, then a push of the rest -- with
    # an opcode that is no witness version: OP_NOP, which is what says the
    # shape alone does not make a program
    shaped = bytes.fromhex("6102" + "1111")
    p2pkh = bytes.fromhex("76a914" + "11" * 20 + "88ac")
    assert role._witness_version(p2wpkh) == 0
    assert role._witness_version(p2tr) == 1
    assert role._witness_version(v2) == 2
    assert role._witness_version(v16) == 16
    assert role._witness_version(shaped) is None
    # the shape does not fit
    assert role._witness_version(p2pkh) is None
    assert role._witness_version(b"") is None


def test_a_global_share_with_no_input_to_prove_it_against() -> None:
    """A share is a claim about the inputs, so it needs one.

    Not a psbt any signer writes -- it would have had a key to write the
    share with -- but a psbt a reader can be handed, and "no eligible
    input" is then a different failure from "the proof does not verify":
    there is nothing to verify it against.
    """
    psbt = _decoded(
        _vector("valid", "can finalize: two inputs single-signer using global")["psbt"]
    )
    # every input made ineligible, a p2wsh BIP352 does not count, the
    # global share left in place
    for psbt_in in psbt.inputs:
        assert psbt_in.witness_utxo is not None
        p2wsh = ScriptPubKey(bytes.fromhex("0020") + bytes(32))
        psbt_in.witness_utxo = TxOut(psbt_in.witness_utxo.value, p2wsh)
        psbt_in.sp_ecdh_shares = {}
        psbt_in.sp_dleq_proofs = {}
    assert role.eligible_pub_keys(psbt) == {}
    with pytest.raises(BTClibValueError, match="no eligible input to prove it against"):
        role.assert_shares_as_valid(psbt)
    # and nothing to derive from, the share standing for no input at all
    assert role.output_scripts(psbt) == {}


def test_the_modifiable_flags_are_asked_about_only_once_a_script_is_there() -> None:
    """Before that the psbt is under construction and may still change.

    Which is what makes the check about the derivation rather than about
    tidiness: the flags matter from the moment a script depends on the
    input set, and not one step earlier.
    """
    psbt = _decoded(
        _vector("valid", "in progress: one P2TR input / one sp output")["psbt"]
    )
    assert not any(o.sp_v0_info and o.script_pub_key for o in psbt.outputs)
    psbt.tx_modifiable = 0b11
    role.assert_as_valid(psbt)


def test_deriving_nothing_leaves_the_psbt_alone() -> None:
    """A psbt with no silent payment output has no script to derive.

    `set_output_scripts` is then a no-op rather than an error, and in
    particular does not clear the modifiable flags: there is no derived
    script for them to protect, and a Constructor still has work to do.
    """
    case = load("psbt", "_data", "bip371_test_vectors.json")["valid psbts"][0]
    psbt = Psbt.b64decode(case["encoded psbt"])
    before = psbt.serialize()
    role.set_output_scripts(psbt)
    assert psbt.serialize() == before


def test_private_keys_summing_to_zero_write_no_global_share() -> None:
    """The sum is the scalar the share is computed with, and zero is none.

    BIP352 fails on it for the sending side; here it is the same fact one
    step earlier, and refusing it is what stops a share of the point at
    infinity being written and proved.
    """
    vector = _vector("valid", "can finalize: two inputs single-signer using per")
    psbt = _decoded(vector["psbt"])
    eligible = list(role.eligible_pub_keys(psbt))
    assert len(eligible) == 2
    a = 0x0F694E068028A717F8AF6B9411F9A133DD3565258714CC226594B34DB90C1F2C
    with pytest.raises(BTClibValueError, match="sum to zero"):
        role.set_global_share(psbt, [a, secp256k1.n - a])


# one p2wpkh input whose key `_SIGNER` holds, paying one silent payment
# address: the smallest psbt each role below can be run over end to end
_ROOT = rootxprv_from_seed(bytes(range(32)))
_PATH = "m/84h/0h/0h/0/0"
_SIGNER = SoftwareSigner(_ROOT)
_XPRV = derive(_ROOT, _PATH)
_PRV_KEY = BIP32KeyData.b58decode(_XPRV).key[1:]
_SEC = pub_keyinfo_from_xkey(_XPRV)[0]
# scan key 2G, spend key 3G
_SP_INFO = bytes_from_point(mult(2)) + bytes_from_point(mult(3))
# a taproot script no share derives
_OTHER_SCRIPT = bytes.fromhex("5120" + "11" * 32)


_SPENT = TxOut(100_000, ScriptPubKey.p2wpkh(PubKeyData(_SEC)))
# the transaction holding it, which is what vouches for its amount
_PREV_TX = Tx(2, 0, [TxIn(OutPoint(b"\x06" * 32, 0))], [_SPENT])


def _sp_psbt(*, script: bytes = b"") -> Psbt:
    """Return the psbt above, its output script as given."""
    psbt_in = PsbtIn(
        non_witness_utxo=_PREV_TX,
        witness_utxo=_SPENT,
        previous_tx_id=_PREV_TX.id,
        output_index=0,
        hd_key_paths={_SEC: BIP32KeyOrigin(_SIGNER.master_fingerprint, _PATH)},
    )
    psbt_out = PsbtOut(amount=90_000, script_pub_key=script, sp_v0_info=_SP_INFO)
    return Psbt(2, [psbt_in], [psbt_out], 2, {}, tx_modifiable=0b11)


def _derived() -> Psbt:
    """Return the psbt above with its share written and its script derived."""
    psbt = _sp_psbt()
    role.set_input_share(psbt, 0, _PRV_KEY, aux=bytes(32))
    role.set_output_scripts(psbt)
    return psbt


def test_sign_waits_for_the_silent_payment_script() -> None:
    """BIP375: "the Signer must not yet add a signature" without a script.

    Refused rather than left unsigned, so that a caller is told which step
    is missing instead of reading an empty list as "no key of mine here".
    Once the share is written and the script derived, the same key signs.
    """
    psbt = _sp_psbt()
    with pytest.raises(BTClibValueError, match="Signer must not yet sign"):
        sign(psbt, _SIGNER)
    _, signed_vins = sign(_derived(), _SIGNER)
    assert signed_vins == [0]


def test_sign_refuses_a_sighash_other_than_all() -> None:
    """BIP375: "the signer must fail if the sighash type is not SIGHASH_ALL".

    A script is set, so the refusal is the sighash's and not the missing
    script's: the rule holds whatever else the psbt is ready for.
    """
    psbt = _derived()
    psbt.inputs[0].sig_hash_type = 2
    with pytest.raises(BTClibValueError, match="requires SIGHASH_ALL"):
        sign(psbt, _SIGNER)


def test_sign_refuses_a_script_or_a_share_that_does_not_verify() -> None:
    """BIP375's "should verify": the proofs, and the scripts they derive.

    A signature commits the funds to whatever script the output carries,
    and a wrong one is consensus-valid, so this is the last point at which
    a wrong script costs nothing.
    """
    # the flags cleared, as whoever wrote the script had to
    no_share = _sp_psbt(script=_OTHER_SCRIPT)
    no_share.tx_modifiable = 0
    with pytest.raises(BTClibValueError, match="no ECDH share for scan key"):
        sign(no_share, _SIGNER)
    no_share.tx_modifiable = 0b11
    with pytest.raises(BTClibValueError, match="still invites changes"):
        sign(no_share, _SIGNER)

    wrong_script = _derived()
    wrong_script.outputs[0].script_pub_key = _OTHER_SCRIPT
    with pytest.raises(BTClibValueError, match="not the silent payment script"):
        sign(wrong_script, _SIGNER)

    forged = _derived()
    scan_key = _SP_INFO[:33]
    forged.inputs[0].sp_ecdh_shares[scan_key] = bytes_from_point(mult(2))
    with pytest.raises(BTClibValueError, match="invalid DLEQ proof"):
        sign(forged, _SIGNER)


def test_extract_tx_checks_the_silent_payment_outputs() -> None:
    """BIP375's Extractor: every script present, and each one derived.

    The finalized psbt is altered after the Finalizer, which is the psbt
    an Extractor can be handed: a script dropped would pay the empty
    script, and a script swapped would pay somebody no share derives.
    `check_validity=False` skips the check with the rest; the signature no
    longer covers the altered output, so `verify_scripts=False` goes with it.
    """
    finalized = finalize(sign(_derived(), _SIGNER)[0])
    expected = finalized.outputs[0].script_pub_key
    assert extract_tx(finalized).vout[0].script_pub_key.script == expected

    dropped = deepcopy(finalized)
    dropped.outputs[0].script_pub_key = b""
    with pytest.raises(BTClibValueError, match="the extracted transaction would pay"):
        extract_tx(dropped)
    extracted = extract_tx(dropped, check_validity=False, verify_scripts=False)
    assert extracted.vout[0].script_pub_key.script == b""
    with pytest.raises(ScriptError):
        extract_tx(dropped, check_validity=False)

    swapped = deepcopy(finalized)
    swapped.outputs[0].script_pub_key = _OTHER_SCRIPT
    with pytest.raises(BTClibValueError, match="not the silent payment script"):
        extract_tx(swapped)


def test_a_finalized_input_is_read_from_its_final_scripts() -> None:
    """The key an Extractor sums survives the Finalizer and the wire.

    `PsbtIn.serialize` drops PSBT_IN_BIP32_DERIVATION from a finalized
    input, so a finalized psbt that is serialized and parsed again carries
    the input's key only in its witness. Read from there, the shares still
    prove and the script still derives.

    A final witness is not trusted for it, consensus not having checked it
    yet: one whose key the script does not commit to leaves the input
    counted, with the derivation's key where there is one and with none
    where there is not -- refused then, rather than dropped from the sum.
    """
    finalized = finalize(sign(_derived(), _SIGNER)[0])
    parsed = Psbt.parse(finalized.serialize())
    assert parsed.inputs[0].hd_key_paths == {}
    pub_key = role.input_pub_key(parsed.inputs[0])
    assert pub_key is not None
    assert bytes_from_point(pub_key) == _SEC
    role.assert_as_valid(parsed)
    assert extract_tx(parsed) == extract_tx(finalized)

    garbled = deepcopy(parsed)
    garbled.inputs[0].final_script_witness = Witness([b"\x01"])
    assert role.input_pub_key(garbled.inputs[0]) is None
    with pytest.raises(BTClibValueError, match="carries no public key"):
        role.eligible_pub_keys(garbled)
    with pytest.raises(BTClibValueError, match="no public key"):
        role.assert_as_valid(garbled)
    in_memory = deepcopy(finalized)
    in_memory.inputs[0].final_script_witness = Witness([b"\x01"])
    assert role.eligible_pub_keys(in_memory) == role.eligible_pub_keys(finalized)
    role.assert_as_valid(in_memory)

    # an uncompressed key the script commits to is one BIP352 skips
    uncompressed = bytes_from_point(mult(2), compressed=False)
    skipped = deepcopy(parsed)
    # a program no standard wallet writes, which is why it is spelled out
    p2wpkh = ScriptPubKey(bytes.fromhex("0014") + hash160(uncompressed))
    # the witness utxo alone, so that its script is the one read
    skipped.inputs[0].non_witness_utxo = None
    skipped.inputs[0].witness_utxo = TxOut(100_000, p2wpkh)
    skipped.inputs[0].final_script_witness = Witness([b"\x30", uncompressed])
    assert role.input_pub_key(skipped.inputs[0]) is None
    assert role.eligible_pub_keys(skipped) == {}


def test_combine_merges_a_silent_payment_script() -> None:
    """BIP375 identifies the output by its address, not by its script.

    So one copy may carry the derived script while another does not yet,
    and the script is taken whichever copy comes first. Two different
    scripts are refused: one of them is wrong and neither psbt says which.
    """
    derived = _derived()
    script = derived.outputs[0].script_pub_key
    without = _derived()
    without.outputs[0].script_pub_key = b""
    for psbts in ([without, derived], [derived, without], [derived, derived]):
        assert combine(psbts).outputs[0].script_pub_key == script

    other = _derived()
    other.outputs[0].script_pub_key = _OTHER_SCRIPT
    with pytest.raises(BTClibValueError, match="mismatched silent payment output"):
        combine([derived, other])


def test_the_signer_and_the_extractor_hold_the_vectors_to_their_roles() -> None:
    """What `sign` and `extract_tx` ask, over BIP375's own psbts.

    A valid psbt with every silent payment script derived passes both; one
    still in progress is early for both, and says so. Every invalid psbt
    that parses is refused by both, the modifiable flags included, which
    `assert_as_valid` refuses and the Signer does too. A valid case naming
    its own `checks` is incomplete for the others, and is left out.
    """
    for vector in _VALID:
        if vector.get("checks") is not None:
            continue
        psbt = _decoded(vector["psbt"])
        if all(o.script_pub_key for o in psbt.outputs if o.sp_v0_info):
            role._assert_signable(psbt)
            role._assert_extractable(psbt)
            continue
        with pytest.raises(BTClibValueError, match="Signer must not yet sign"):
            role._assert_signable(psbt)
        with pytest.raises(BTClibValueError, match="extracted transaction would"):
            role._assert_extractable(psbt)

    refused = 0
    for vector in _INVALID:
        try:
            psbt = _decoded(vector["psbt"])
        except BTClibValueError:
            continue
        with pytest.raises(BTClibValueError):
            role._assert_signable(psbt)
        with pytest.raises(BTClibValueError):
            role._assert_extractable(psbt)
        refused += 1
    assert refused


_PATH_1 = "m/84h/0h/0h/0/1"
_XPRV_1 = derive(_ROOT, _PATH_1)
_PRV_KEY_1 = BIP32KeyData.b58decode(_XPRV_1).key[1:]
_SEC_1 = pub_keyinfo_from_xkey(_XPRV_1)[0]
_P2WSH = ScriptPubKey(bytes.fromhex("0020") + bytes(32))


def _two_inputs(*, derivation_1: bool) -> Psbt:
    """Return `_sp_psbt` with a second p2wpkh input, its derivation optional."""
    psbt = _sp_psbt()
    hd_key_paths: dict[Octets, BIP32KeyOrigin] = {}
    if derivation_1:
        hd_key_paths[_SEC_1] = BIP32KeyOrigin(_SIGNER.master_fingerprint, _PATH_1)
    psbt.inputs.append(
        PsbtIn(
            witness_utxo=TxOut(100_000, ScriptPubKey.p2wpkh(PubKeyData(_SEC_1))),
            previous_tx_id=b"\x07" * 32,
            output_index=0,
            hd_key_paths=hd_key_paths,
        )
    )
    psbt.outputs[0].amount = 190_000
    return psbt


def test_an_input_is_counted_by_its_script_not_by_its_key() -> None:
    """A counted input whose key the psbt lacks is refused, not left out.

    The recipient sums the key of every input its script type counts, so a
    script derived from the others is one nobody scans for. Before the
    script: `set_output_scripts` refuses to derive it. After, where a
    psbt arrives carrying one derived that way: `assert_as_valid` and
    `sign` refuse it, as BIP375's reference validator does.
    """
    psbt = _two_inputs(derivation_1=False)
    role.set_input_share(psbt, 0, _PRV_KEY, aux=bytes(32))
    assert role.input_pub_key(psbt.inputs[1]) is None
    with pytest.raises(BTClibValueError, match="input 1: BIP352 counts it"):
        role.set_output_scripts(psbt)
    with pytest.raises(BTClibValueError, match="input 1: BIP352 counts it"):
        role.set_input_share(psbt, 1, _PRV_KEY_1)
    # a psbt still in progress is not refused for it
    role.assert_as_valid(psbt)

    # the script input 0 alone derives: input 1 made a p2wsh for the
    # derivation, the outpoints unchanged, then put back
    short = deepcopy(psbt)
    spent = short.inputs[1].witness_utxo
    short.inputs[1].witness_utxo = TxOut(100_000, _P2WSH)
    role.set_output_scripts(short)
    short.inputs[1].witness_utxo = spent
    with pytest.raises(BTClibValueError, match="input 1: BIP352 counts it"):
        role.assert_as_valid(short)
    # input 1 carries no non_witness_utxo, and that is not the refusal
    # asked about here
    with pytest.raises(BTClibValueError, match="input 1: BIP352 counts it"):
        sign(short, _SIGNER, require_non_witness_utxo=False)


def test_the_scripts_wait_for_every_counted_share() -> None:
    """BIP375: "If all eligible inputs have an ECDH share", and not before.

    A script summed from the shares that have arrived is one the Signer's
    own checks refuse, so it is not written; once the second share is
    there, it is.
    """
    psbt = _two_inputs(derivation_1=True)
    role.set_input_share(psbt, 0, _PRV_KEY, aux=bytes(32))
    with pytest.raises(BTClibValueError, match="input 1: no ECDH share for scan"):
        role.set_output_scripts(psbt)
    assert not psbt.outputs[0].script_pub_key
    role.set_input_share(psbt, 1, _PRV_KEY_1, aux=bytes(32))
    role.set_output_scripts(psbt)
    role.assert_as_valid(psbt)

    # a final witness does not take a counted input out of the sum: the
    # derivation is what the script commits to, whatever the witness says
    garbled = _two_inputs(derivation_1=True)
    role.set_input_share(garbled, 0, _PRV_KEY, aux=bytes(32))
    garbled.inputs[1].final_script_witness = Witness([b"\x01"])
    assert sorted(role.eligible_pub_keys(garbled)) == [0, 1]
    with pytest.raises(BTClibValueError, match="input 1: no ECDH share for scan"):
        role.set_output_scripts(garbled)


def _p2sh_input(wrapped: bytes, **fields: Any) -> PsbtIn:
    """Return an input spending the p2sh of a redeem script."""
    script = ScriptPubKey(bytes.fromhex("a914") + hash160(wrapped) + b"\x87")
    return PsbtIn(
        witness_utxo=TxOut(100_000, script),
        previous_tx_id=b"\x08" * 32,
        output_index=0,
        **fields,
    )


def test_a_p2sh_input_is_read_from_the_redeem_script_it_commits_to() -> None:
    """The redeem script counts only where it hashes to the script_pub_key.

    A p2sh-p2wpkh is counted, its key the one the wrapped program commits
    to, and read from PSBT_IN_REDEEM_SCRIPT or from the final scriptSig's
    push. A p2sh of anything else is not counted. A redeem script the
    psbt does not carry, or one that does not hash to the script, leaves
    the input counted and keyless: whether BIP352 counts it is the psbt's
    to show, and taking it for not counted is what would let it out of
    the sum.
    """
    wrapped = ScriptPubKey.p2wpkh(PubKeyData(_SEC)).script
    origin = BIP32KeyOrigin(_SIGNER.master_fingerprint, _PATH)
    unsigned = _p2sh_input(wrapped, redeem_script=wrapped, hd_key_paths={_SEC: origin})
    key = role.input_pub_key(unsigned)
    assert key is not None
    assert bytes_from_point(key) == _SEC

    finalized = _p2sh_input(
        wrapped,
        final_script_sig=bytes([len(wrapped)]) + wrapped,
        final_script_witness=Witness([b"\x30", _SEC]),
    )
    key = role.input_pub_key(finalized)
    assert key is not None
    assert bytes_from_point(key) == _SEC

    # a scriptSig that is not push-only carries no redeem script BIP16 reads
    not_push_only = _sp_psbt()
    not_push_only.inputs = [
        _p2sh_input(
            wrapped,
            final_script_sig=bytes([len(wrapped)]) + wrapped + b"\x76",
            final_script_witness=Witness([b"\x30", _SEC]),
        )
    ]
    with pytest.raises(BTClibValueError, match="input 0: BIP352 counts it"):
        role.eligible_pub_keys(not_push_only)

    psbt = _sp_psbt()
    psbt.inputs = [_p2sh_input(wrapped, hd_key_paths={_SEC: origin})]
    assert role.input_pub_key(psbt.inputs[0]) is None
    with pytest.raises(BTClibValueError, match="input 0: BIP352 counts it"):
        role.eligible_pub_keys(psbt)
    psbt.inputs[0].redeem_script = ScriptPubKey.p2wpkh(PubKeyData(_SEC_1)).script
    with pytest.raises(BTClibValueError, match="input 0: BIP352 counts it"):
        role.eligible_pub_keys(psbt)

    multisig = serialize(["OP_1", _SEC, "OP_1", "OP_CHECKMULTISIG"])
    psbt.inputs = [_p2sh_input(multisig, redeem_script=multisig)]
    assert role.eligible_pub_keys(psbt) == {}


def test_a_p2pkh_input_is_read_from_its_scriptsig() -> None:
    """BIP352's own reading of a p2pkh spend, held to the script's hash.

    The compressed key is found wherever the scriptSig carries it, and an
    uncompressed one the script commits to is an input BIP352 skips.
    """
    script = ScriptPubKey.p2pkh(PubKeyData(_SEC))
    psbt_in = PsbtIn(
        witness_utxo=TxOut(100_000, script),
        previous_tx_id=b"\x09" * 32,
        output_index=0,
        final_script_sig=b"\x01\x30\x21" + _SEC,
    )
    key = role.input_pub_key(psbt_in)
    assert key is not None
    assert bytes_from_point(key) == _SEC

    uncompressed = bytes_from_point(mult(2), compressed=False)
    p2pkh = ScriptPubKey(
        bytes.fromhex("76a914") + hash160(uncompressed) + bytes.fromhex("88ac")
    )
    psbt = _sp_psbt()
    psbt.inputs[0] = PsbtIn(
        witness_utxo=TxOut(100_000, p2pkh),
        previous_tx_id=b"\x09" * 32,
        output_index=0,
        final_script_sig=b"\x01\x30\x41" + uncompressed,
    )
    assert role.eligible_pub_keys(psbt) == {}


def test_a_nums_internal_key_counts_only_proven() -> None:
    """BIP352 skips a taproot input with no key path, if that is shown.

    Proven three ways: the merkle root tweaking NUMS_H into the output
    key, a leaf script's control block, or the final witness's. Claimed
    without a proof, the input is counted with its output key: a claim
    alone is what a co-signer would write to take its input out of the
    sum.
    """
    leaf = serialize([_SEC[1:], "OP_CHECKSIG"])
    merkle_root = taproot.leaf_hash(0xC0, leaf)
    output_key, parity = output_pubkey_from_merkle_root(sp.NUMS_H, merkle_root)
    control = bytes([0xC0 | parity]) + sp.NUMS_H
    spent = TxOut(100_000, ScriptPubKey(serialize(["OP_1", output_key])))

    def taproot_in(**fields: Any) -> PsbtIn:
        return PsbtIn(
            witness_utxo=spent, previous_tx_id=b"\x0a" * 32, output_index=0, **fields
        )

    proven = (
        taproot_in(taproot_internal_key=sp.NUMS_H, taproot_merkle_root=merkle_root),
        taproot_in(taproot_leaf_scripts={control: (leaf, 0xC0)}),
        taproot_in(final_script_witness=Witness([b"\x30" * 64, leaf, control])),
        # the annex, which the witness carries above the control block
        taproot_in(
            final_script_witness=Witness([b"\x30" * 64, leaf, control, b"\x50"])
        ),
    )
    for psbt_in in proven:
        psbt = _sp_psbt()
        psbt.inputs[0] = psbt_in
        assert role.eligible_pub_keys(psbt) == {}

    claimed = (
        taproot_in(taproot_internal_key=sp.NUMS_H),
        # a control block of another internal key says nothing of NUMS_H
        taproot_in(taproot_leaf_scripts={bytes([0xC0]) + _SEC[1:]: (leaf, 0xC0)}),
        taproot_in(taproot_leaf_scripts={control: (leaf + b"\x51", 0xC0)}),
        # a control block of no length BIP341 allows proves nothing either
        taproot_in(
            final_script_witness=Witness([b"\x30" * 64, leaf, control + b"\x00"])
        ),
    )
    for psbt_in in claimed:
        key = role.input_pub_key(psbt_in)
        assert key is not None
        assert bytes_from_point(key)[1:] == output_key


def test_what_no_key_can_be_read_from() -> None:
    """Bytes a script commits to that are no point, and no input to count.

    A p2wpkh program hashing 33 bytes that are not a public key, and a
    taproot output key that is not an x coordinate: counted, since the
    type counts them, and keyless, since no key is there. A psbt of no
    counted input at all has no share to derive a script from.
    """
    not_a_key = b"\x02" + b"\xff" * 32
    psbt = _sp_psbt()
    # the witness utxo alone, so that each script below is the one read
    psbt.inputs[0].non_witness_utxo = None
    psbt.inputs[0].witness_utxo = TxOut(
        100_000, ScriptPubKey(bytes.fromhex("0014") + hash160(not_a_key))
    )
    psbt.inputs[0].hd_key_paths = {
        not_a_key: BIP32KeyOrigin(_SIGNER.master_fingerprint, _PATH)
    }
    with pytest.raises(BTClibValueError, match="input 0: BIP352 counts it"):
        role.eligible_pub_keys(psbt)

    psbt.inputs[0].hd_key_paths = {}
    psbt.inputs[0].witness_utxo = TxOut(
        100_000, ScriptPubKey(bytes.fromhex("5120") + b"\xff" * 32)
    )
    with pytest.raises(BTClibValueError, match="input 0: BIP352 counts it"):
        role.eligible_pub_keys(psbt)

    psbt.inputs[0].witness_utxo = TxOut(100_000, _P2WSH)
    assert role.eligible_pub_keys(psbt) == {}
    with pytest.raises(BTClibValueError, match="no ECDH share to derive"):
        role.set_output_scripts(psbt)


def test_a_finalized_p2sh_multisig_input_is_read_from_its_last_push() -> None:
    """BIP16 puts the redeem script in the scriptSig's last push.

    `PsbtIn.serialize` drops PSBT_IN_REDEEM_SCRIPT once an input is
    finalized, so a p2sh multisig input that crossed the wire shows what it
    wraps only there -- behind a dummy and the signatures. Read from the
    last push, it wraps no p2wpkh and is not counted, and the psbt it is in
    validates and extracts as it did before the round trip.
    """
    vector = _vector("valid", "can finalize: two inputs using per-input ECDH")
    psbt = _decoded(vector["psbt"])
    eligible = role.eligible_pub_keys(psbt)
    [multisig_i] = [i for i in range(len(psbt.inputs)) if i not in eligible]
    [single_i] = list(eligible)
    redeem_script = psbt.inputs[multisig_i].redeem_script
    assert not is_p2wpkh(redeem_script)

    signature = b"\x30" * 71
    psbt.inputs[multisig_i].final_script_sig = serialize(
        ["OP_0", signature, redeem_script]
    )
    [key] = list(psbt.inputs[single_i].hd_key_paths)
    psbt.inputs[single_i].final_script_witness = Witness([signature, key])
    role.assert_as_valid(psbt)

    parsed = Psbt.parse(psbt.serialize())
    assert not parsed.inputs[multisig_i].redeem_script
    assert role.eligible_pub_keys(parsed) == eligible
    role.assert_as_valid(parsed)
    # the signatures are placeholders, so the scripts are not run
    assert extract_tx(parsed, verify_scripts=False) == extract_tx(
        psbt, verify_scripts=False
    )


def test_the_last_push_of_a_scriptsig() -> None:
    """Push-only or nothing: BIP16 reads no redeem script out of any other.

    Each push opcode, the three PUSHDATA widths among them, and the two
    ways a script is not one to read: an opcode that is no push, and a
    push running past the end.
    """
    data = b"\x11" * 80
    assert role._last_push(b"") is None
    assert role._last_push(b"\x00") == b""
    assert role._last_push(b"\x02\x11\x11") == b"\x11\x11"
    assert role._last_push(b"\x4c\x50" + data) == data
    assert role._last_push(b"\x4d\x50\x00" + data) == data
    assert role._last_push(b"\x4e\x50\x00\x00\x00" + data) == data
    assert role._last_push(b"\x02\x11\x11\x4f") == b"\x81"
    assert role._last_push(b"\x60") == b"\x10"
    assert role._last_push(b"\x02\x11\x11\x76") is None
    assert role._last_push(b"\x4c\x50" + data[:-1]) is None
