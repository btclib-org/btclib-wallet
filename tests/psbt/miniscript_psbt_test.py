# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the psbt roles over a BIP379 miniscript.

`miniscript_solver`, which `finalize` takes for a witness script or a
taproot leaf script that is a miniscript, `miniscript_sizer` and
`satisfaction_sizer`, which `estimated_input_sizes` takes for a witness
script that is one or a taproot input whose leaves are, and the Updater
over a miniscript descriptor.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from copy import deepcopy

import pytest
from bip32_descriptors.bip32.key_origin import BIP32KeyOrigin
from bip32_descriptors.descriptors import TrDescriptor, WshDescriptor
from bip32_descriptors.descriptors import parse as parse_descriptor
from bip32_descriptors.descriptors.miniscript import (
    P2WSH,
    TAPSCRIPT,
    Miniscript,
    SpendContext,
    from_script,
    parse,
)
from btclib.alias import Octets
from btclib.exceptions import BTClibValueError, ScriptError, ScriptErrorCode
from btclib.hashes import hash160, sha256
from btclib.key import PrvKeyData, PubKeyData
from btclib.script import Witness, sig_hash
from btclib.script.engine import verify_transaction
from btclib.script.limits import MAX_SCRIPT_SIZE
from btclib.script.script import op_code_spans, serialize
from btclib.script.script_pub_key import ScriptPubKey
from btclib.script.taproot import (
    leaf_hash,
    output_prvkey_from_merkle_root,
    output_pubkey_from_merkle_root_var,
)
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx
from btclib.tx.tx_in import TxIn
from btclib.tx.tx_out import TxOut
from ecc import dsa, ssa
from ecc.hashes import tagged_hash

from btclib_wallet.psbt import psbt as psbt_module
from btclib_wallet.psbt.psbt import (
    Psbt,
    _lacks_only_keys,
    finalize,
    miniscript_solver,
    taproot_sig_hash,
)
from btclib_wallet.psbt.psbt_in import PsbtIn
from btclib_wallet.psbt.psbt_size import (
    estimated_input_sizes,
    miniscript_sizer,
    satisfaction_sizer,
)
from btclib_wallet.psbt.psbt_updater import update_psbt_input, update_psbt_output
from tests import vector_id
from tests.secret_free import assert_secret_free

# Core's own test keys: the public keys of the private keys 1 to 255, which
# is what its `TestData` generates
KEYS = [PrvKeyData(i).pub.sec.hex() for i in range(1, 256)]


# the six keys of the two custody expressions
CUSTODY_KEYS = [
    "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65",
    "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556",
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
    "022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01",
]


KEY = CUSTODY_KEYS[0]


AUTHORIZATION_GATE = (
    f"andor(multi(2,{CUSTODY_KEYS[0]},{CUSTODY_KEYS[1]})"
    f",multi(2,{CUSTODY_KEYS[4]},{CUSTODY_KEYS[5]})"
    f",and_v(v:multi(2,{CUSTODY_KEYS[2]},{CUSTODY_KEYS[3]}),older(144)))"
)


def test_a_ranged_miniscript_descriptor_fills_a_psbt() -> None:
    """Update a psbt from a miniscript descriptor, as any other fills one."""
    xpub = (
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoC"
        "u1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
    )
    descriptor = f"wsh(and_v(v:pk([deadbeef/0h]{xpub}/*),older(36)))"
    parsed = parse_descriptor(descriptor)
    assert isinstance(parsed, WshDescriptor)
    assert parsed.is_ranged
    tx = Tx(
        vin=[TxIn(OutPoint(b"\x03" * 32, 0))],
        vout=[TxOut(400, parsed.script_pub_key(1))],
    )
    psbt_out = update_psbt_output(parsed, Psbt.from_tx(tx), 0, 1).outputs[0]
    assert psbt_out.witness_script == parsed.inner.redeem_script(1)
    assert psbt_out.hd_key_paths


# Core's `TestData`: the private keys 1 to 255, each its index in 32 bytes
PRV_KEYS = [31 * b"\x00" + bytes([i]) for i in range(1, 256)]


SIGNING_KEYS = dict(zip(KEYS, PRV_KEYS, strict=True))


# the shapes a psbt is finalized in below: a timelocked single key, a
# 2-of-2 whose recovery branch is timelocked, a hash lock, and the
# authorization gate of issue btclib-org/btclib#187, which is the one with three
# branches
SOLVER_EXPRESSIONS = [
    f"and_v(v:pk({KEYS[0]}),older(36))",
    f"or_d(pk({KEYS[0]}),and_v(v:pkh({KEYS[1]}),older(1008)))",
    f"and_v(v:pk({KEYS[0]}),sha256({sha256(PRV_KEYS[3]).hex()}))",
    AUTHORIZATION_GATE,
]


def signed_psbt(
    node: Miniscript, keys: list[str], locktime: int, sequence: int
) -> tuple[Psbt, list[TxOut]]:
    """Return a psbt spending a p2wsh miniscript, signed by `keys`.

    What an Updater would write is set by hand: the witness script and the
    preimages, which the solver reads from the input.
    """
    script = node.script()
    prevout = TxOut(50_000, ScriptPubKey.p2wsh(script))
    tx = Tx(
        version=2,
        lock_time=locktime,
        vin=[TxIn(OutPoint(b"\x05" * 32, 0), sequence=sequence)],
        vout=[TxOut(49_000, ScriptPubKey.p2wpkh(PubKeyData(KEYS[0])))],
    )
    psbt = Psbt.from_tx(tx)
    psbt.inputs[0].witness_utxo = prevout
    psbt.inputs[0].witness_script = script
    psbt.inputs[0].sha256_preimages = {sha256(k): k for k in PRV_KEYS[:8]}
    msg_hash = sig_hash.segwit_v0(script, tx, 0, 1, prevout.value)
    psbt.inputs[0].partial_sigs = {
        bytes.fromhex(key): dsa.sign_(msg_hash, SIGNING_KEYS[key]).serialize() + b"\x01"
        for key in keys
    }
    return psbt, [prevout]


@pytest.mark.parametrize(
    "expression",
    [
        pytest.param(expression, id=vector_id(index, expression))
        for index, expression in enumerate(SOLVER_EXPRESSIONS)
    ],
)
def test_the_solver_finalizes_a_miniscript_input(expression: str) -> None:
    """Finalize a p2wsh miniscript input, and run what it built.

    `finalize` reads no miniscript itself, so the solver is what spends
    one, and this is the whole flow through it: the witness script and the
    preimages in the input, the signatures over the sig hash of the
    transaction being built, and `verify_transaction` on what comes out.
    """
    node = parse(expression)
    signers = [key.sec().hex() for key in node.key_expressions]
    psbt, prevouts = signed_psbt(node, signers, 499999999, 0x0000FFFF)
    final = finalize(psbt, solver=miniscript_solver)
    psbt_in = final.inputs[0]
    assert psbt_in.final_script_sig == b""
    assert psbt_in.final_script_witness.stack[-1] == node.script()
    # the finalized fields are what the extractor puts in the transaction,
    # and the engine is what says the spend is one the network takes
    spending = final.tx
    spending.vin[0].script_witness = psbt_in.final_script_witness
    verify_transaction(prevouts, spending)


def test_the_solver_answers_for_what_is_its_business_and_no_more() -> None:
    """Return None where the input is not a miniscript, and refuse where it is.

    Three answers, and the middle one is the point of a solver returning
    None rather than raising: an input it does not recognize is one the
    generic finalizer still answers for, exactly as it did before.
    """
    node = parse(f"and_v(v:pk({KEYS[0]}),older(36))")
    # a sequence of 35 does not open a branch that wants 36
    psbt, _ = signed_psbt(node, [KEYS[0]], 499999999, 35)
    with pytest.raises(BTClibValueError, match="no satisfaction"):
        finalize(psbt, solver=miniscript_solver)
    # an input with no witness script at all
    psbt, _ = signed_psbt(node, [KEYS[0]], 499999999, 0x0000FFFF)
    psbt.inputs[0].witness_script = b""
    assert miniscript_solver(psbt, 0) is None
    # and one whose witness script is no miniscript
    psbt, _ = signed_psbt(node, [KEYS[0]], 499999999, 0x0000FFFF)
    psbt.inputs[0].witness_script = serialize(["OP_DROP", "OP_1"])
    assert miniscript_solver(psbt, 0) is None


def test_the_solver_names_an_input_that_exists() -> None:
    """A negative index solved the input at the other end, and said nothing.

    `psbt.inputs[vin_i]` is a list index, so -1 was the last input: the
    solver read another input's witness script and preimages and
    answered a witness for it, which the caller then attaches to the
    input it did ask about. Its siblings `update_psbt_input` and
    `update_psbt_output` carry this guard already, with the comment
    saying why.
    """
    node = parse(f"and_v(v:pk({KEYS[0]}),older(36))")
    psbt, _ = signed_psbt(node, [KEYS[0]], 499999999, 36)
    assert miniscript_solver(psbt, 0) is not None

    for out_of_range in (-1, 1, 99):
        with pytest.raises(BTClibValueError, match="invalid input index: "):
            miniscript_solver(psbt, out_of_range)


def test_the_solver_reads_a_key_the_input_knows_by_its_hash() -> None:
    """Recognize a pkh() fragment, whose script holds no key.

    The keys an input carries are what makes that readable: the ones that
    signed, and the ones a key origin names. Without either the witness
    script cannot be read, and the solver refuses it, though the branch
    these signatures open needs nothing of that key: so does Bitcoin
    Core's ``finalizepsbt``.
    """
    node = parse(f"or_d(pk({KEYS[0]}),and_v(v:pkh({KEYS[1]}),older(1008)))")
    psbt, _ = signed_psbt(node, [KEYS[1]], 499999999, 1008)
    assert miniscript_solver(psbt, 0) is not None
    # the origin of a key is enough, the psbt knowing the key from it
    psbt, _ = signed_psbt(node, [KEYS[0]], 499999999, 0x0000FFFF)
    with pytest.raises(BTClibValueError, match=UNKNOWN_KEY):
        miniscript_solver(psbt, 0)
    psbt.inputs[0].hd_key_paths = {
        bytes.fromhex(KEYS[1]): BIP32KeyOrigin("deadbeef", [0])
    }
    assert miniscript_solver(psbt, 0) is not None


UNKNOWN_KEY = "input 0: no public key for a hash160 the witness script holds"


def test_no_witness_is_guessed_for_a_key_hash_the_input_does_not_name() -> None:
    """Refuse a miniscript whose pk_h() key the input names nowhere.

    Answered None, `finalize` would build its guess for a script of no
    standard kind: the two signatures and the script, without the empty
    element OP_CHECKMULTISIG pops, which the engine refuses. The key's origin
    makes the script readable, and the witness is then the one that
    verifies.
    """
    node = parse(
        f"or_d(multi(2,{KEYS[0]},{KEYS[1]}),and_v(v:pkh({KEYS[2]}),older(144)))"
    )
    psbt, prevouts = signed_psbt(node, KEYS[:2], 499999999, 0xFFFFFFFD)
    with pytest.raises(BTClibValueError, match=UNKNOWN_KEY):
        finalize(psbt, solver=miniscript_solver)
    psbt.inputs[0].hd_key_paths = {
        bytes.fromhex(KEYS[2]): BIP32KeyOrigin("deadbeef", [0])
    }
    final = finalize(psbt, solver=miniscript_solver)
    spending = final.tx
    spending.vin[0].script_witness = final.inputs[0].final_script_witness
    verify_transaction(prevouts, spending)


def test_an_uncompressed_key_beside_a_missing_one_is_left_to_finalize() -> None:
    """Answer None for an uncompressed pk_h() key beside a key not named.

    The input names the uncompressed key, by its origin and its signature,
    and not the key of the second pk_h(). bip32-descriptors refuses an
    uncompressed key inside P2WSH, so the script is no miniscript to the
    solver, whatever key a stand-in fills: `finalize` answers as it does
    without a solver.
    """
    uncompressed = PrvKeyData(1, compressed=False).pub.sec
    script = parse(f"and_v(v:pkh({KEYS[0]}),pkh({KEYS[2]}))").script()
    script = script.replace(hash160(bytes.fromhex(KEYS[0])), hash160(uncompressed))
    psbt, _ = signed_psbt(parse(f"pk({KEYS[0]})"), [], 0, 0)
    psbt_in = psbt.inputs[0]
    psbt_in.witness_utxo = TxOut(50_000, ScriptPubKey.p2wsh(script))
    psbt_in.witness_script = script
    psbt_in.hd_key_paths = {uncompressed: BIP32KeyOrigin("deadbeef", [0])}
    msg_hash = sig_hash.segwit_v0(script, psbt.tx, 0, 1, 50_000)
    psbt_in.partial_sigs = {uncompressed: dsa.sign_(msg_hash, 1).serialize() + b"\x01"}
    assert miniscript_solver(psbt, 0) is None
    solved = finalize(psbt, solver=miniscript_solver).inputs[0]
    assert solved.final_script_witness == finalize(psbt).inputs[0].final_script_witness
    assert solved.final_script_witness.stack[-1] == script


@pytest.mark.parametrize(
    "shape, refused",
    [
        pytest.param("or_d(pkh(U),pk(A))", True, id="or_d-pkh-first"),
        pytest.param("or_i(pk(A),and_v(v:pkh(U),older(144)))", True, id="or_i"),
        pytest.param(
            "or_d(multi(1,A),and_v(v:pkh(U),older(144)))", True, id="or_d-multi"
        ),
        pytest.param("or_d(pk(A),and_v(v:pkh(U),older(144)))", False, id="or_d-pk"),
    ],
)
def test_a_named_uncompressed_key_leaves_the_input_to_finalize(
    shape: str, refused: bool
) -> None:
    """Answer None where every key is named and a pkh() one is uncompressed.

    U is the uncompressed key of private key 1, named by its origin, and A
    the compressed key that signed, on a branch without U. bip32-descriptors
    refuses an uncompressed key inside P2WSH, so the witness script is no
    miniscript to the solver or to either sizer. `finalize` then builds
    what it builds without a solver, A's signature and the script, which
    the engine refuses for three of these scripts and accepts for the
    fourth. ISS btclib-org/btclib-wallet#962 is what restores the solver.
    """
    uncompressed = PrvKeyData(1, compressed=False).pub.sec
    text = shape.replace("U", KEYS[0]).replace("A", KEYS[1])
    script = parse(text).script()
    script = script.replace(hash160(bytes.fromhex(KEYS[0])), hash160(uncompressed))
    psbt, _ = signed_psbt(parse(f"pk({KEYS[0]})"), [], 0, 0)
    psbt_in = psbt.inputs[0]
    prevout = TxOut(50_000, ScriptPubKey.p2wsh(script))
    psbt_in.witness_utxo = prevout
    psbt_in.witness_script = script
    psbt_in.hd_key_paths = {uncompressed: BIP32KeyOrigin("deadbeef", [0])}
    msg_hash = sig_hash.segwit_v0(script, psbt.tx, 0, 1, prevout.value)
    sig = dsa.sign_(msg_hash, SIGNING_KEYS[KEYS[1]]).serialize() + b"\x01"
    psbt_in.partial_sigs = {bytes.fromhex(KEYS[1]): sig}
    tx_in = psbt.tx.vin[0]
    assert miniscript_solver(psbt, 0) is None
    assert miniscript_sizer(psbt_in, tx_in) is None
    assert satisfaction_sizer([KEYS[1]])(psbt_in, tx_in) is None
    final = finalize(psbt, solver=miniscript_solver)
    witness = final.inputs[0].final_script_witness
    assert witness == finalize(psbt).inputs[0].final_script_witness
    assert list(witness.stack) == [sig, script]
    spending = final.tx
    spending.vin[0].script_witness = witness
    if refused:
        with pytest.raises(ScriptError):
            verify_transaction([prevout], spending)
    else:
        verify_transaction([prevout], spending)


def test_a_key_hash_in_a_script_that_is_no_miniscript_is_not_the_refusal() -> None:
    """Answer None for a script that is no miniscript, whatever key it lacks.

    The pk_h() at its end is read with a stand-in key, and what is left
    before it is no expression: the input is not this solver's business.
    The second script's CHECKMULTISIG counts -100 keys, which the walk
    past the missing key reaches.
    """
    pkh = parse(f"pkh({KEYS[2]})").script()
    psbt, _ = signed_psbt(parse(f"pk({KEYS[0]})"), [KEYS[0]], 499999999, 0)
    for prefix in (serialize(["OP_DROP"]), bytes.fromhex("5101e4ae")):
        psbt.inputs[0].witness_script = prefix + pkh
        assert miniscript_solver(psbt, 0) is None


def _older_chain(count: int) -> Miniscript:
    """Return ``pk()`` inside `count` nested ``and_v(v:older(1), ...)``."""
    return parse("and_v(v:older(1)," * count + f"pk({KEYS[0]})" + ")" * count)


def test_a_witness_script_past_the_op_limit_is_refused() -> None:
    """Refuse a satisfied witness script that counts more than 201 op codes.

    Each ``v:older(1)`` counts two op codes and the ``pk()`` one: a
    hundred and one of them make 203, and the script engine refuses the
    run at the 202nd, its refusal being the answer. A hundred make 201,
    and the input is spent.
    """
    node = _older_chain(101)
    assert node.max_ops == 203
    psbt, _ = signed_psbt(node, [KEYS[0]], 0, 1)
    with pytest.raises(ScriptError, match="^more than 201 op codes") as e:
        finalize(psbt, solver=miniscript_solver)
    # the engine's own refusal, raised from a fresh run and chained by it
    assert e.value.code is ScriptErrorCode.OP_COUNT
    assert_secret_free(e.value, [PRV_KEYS[0]])

    node = _older_chain(100)
    assert node.max_ops == 201
    psbt, prevouts = signed_psbt(node, [KEYS[0]], 0, 1)
    final = finalize(psbt, solver=miniscript_solver)
    spending = final.tx
    spending.vin[0].script_witness = final.inputs[0].final_script_witness
    verify_transaction(prevouts, spending)


def test_a_witness_past_the_standard_element_count_is_spent() -> None:
    """Spend a p2wsh witness of a hundred and one signatures.

    Policy relays a p2wsh witness of at most a hundred elements beside its
    script, and consensus allows more. The script engine runs the
    consensus rules, and takes this one: so does Bitcoin Core's
    ``finalizepsbt``, which finalizes this input.
    """
    expression = f"pk({KEYS[100]})"
    for key in reversed(KEYS[:100]):
        expression = f"and_v(v:pk({key}),{expression})"
    node = parse(expression)
    psbt, prevouts = signed_psbt(node, KEYS[:101], 0, 0)
    final = finalize(psbt, solver=miniscript_solver)
    witness = final.inputs[0].final_script_witness
    assert len(witness.stack) == 102
    spending = final.tx
    spending.vin[0].script_witness = witness
    verify_transaction(prevouts, spending)


def test_a_wrapped_p2wsh_input_is_run_with_its_redeem_script() -> None:
    """Spend a p2sh-wrapped p2wsh miniscript, its script_sig run too.

    The script_sig pushes the redeem script, which the p2sh output asks
    for before the witness is run: without it, the engine refuses.
    """
    node = parse(f"and_v(v:pk({KEYS[0]}),older(36))")
    psbt, _ = signed_psbt(node, [KEYS[0]], 0, 36)
    redeem_script = ScriptPubKey.p2wsh(node.script()).script
    prevout = TxOut(50_000, ScriptPubKey.p2sh(redeem_script))
    psbt.inputs[0].witness_utxo = prevout
    psbt.inputs[0].redeem_script = redeem_script
    final = finalize(psbt, solver=miniscript_solver)
    spending = final.tx
    spending.vin[0].script_sig = final.inputs[0].final_script_sig
    spending.vin[0].script_witness = final.inputs[0].final_script_witness
    verify_transaction([prevout], spending)


def test_a_high_s_signature_is_spent() -> None:
    """Spend a p2wsh input whose signature carries a high s.

    The low-s rule is policy, not consensus, and the script engine runs
    the consensus rules alone: it takes this witness. Bitcoin Core's
    ``finalizepsbt`` runs its standard flags, LOW_S among them, and leaves
    the input unfinalized. This pins the answer issue
    btclib-org/btclib-wallet#1042 records: the solver answers for
    consensus.
    """
    node = parse(f"and_v(v:pk({KEYS[0]}),older(36))")
    psbt, prevouts = signed_psbt(node, [KEYS[0]], 0, 36)
    msg_hash = sig_hash.segwit_v0(node.script(), psbt.tx, 0, 1, prevouts[0].value)
    low = dsa.sign_(msg_hash, PRV_KEYS[0])
    high = dsa.Sig(low.r, low.ec.n - low.s)
    assert high.s > high.ec.n // 2
    psbt.inputs[0].partial_sigs = {bytes.fromhex(KEYS[0]): high.serialize() + b"\x01"}
    final = finalize(psbt, solver=miniscript_solver)
    witness = final.inputs[0].final_script_witness
    assert witness.stack[0] == high.serialize() + b"\x01"
    spending = final.tx
    spending.vin[0].script_witness = witness
    verify_transaction(prevouts, spending)


def test_a_p2wsh_input_with_no_utxo_is_refused() -> None:
    """Refuse a satisfied p2wsh input that names no output it spends.

    The script engine runs the witness against that output, so without it
    the witness is one nothing has run.
    """
    node = parse(f"and_v(v:pk({KEYS[0]}),older(36))")
    psbt, _ = signed_psbt(node, [KEYS[0]], 0, 36)
    assert miniscript_solver(psbt, 0) is not None
    psbt.inputs[0].witness_utxo = None
    with pytest.raises(BTClibValueError, match="^no utxo for input 0: "):
        miniscript_solver(psbt, 0)


def test_a_signature_that_does_not_verify_is_refused_as_one() -> None:
    """Refuse a partial signature over another amount before the engine runs.

    The signature commits to 50,000 satoshi, and the input spends 45,000:
    the refusal names the signature, as `finalize` names it, rather than
    the engine's false top stack element.
    """
    node = parse(f"and_v(v:pk({KEYS[0]}),older(36))")
    psbt, prevouts = signed_psbt(node, [KEYS[0]], 0, 36)
    psbt.inputs[0].witness_utxo = TxOut(45_000, prevouts[0].script_pub_key)
    message = "^input 0: partial signature 0: invalid$"
    with pytest.raises(BTClibValueError, match=message):
        finalize(psbt, solver=miniscript_solver)


def test_a_signature_is_verified_before_the_script_is_satisfied() -> None:
    """Refuse a signature over another amount, whose quorum it leaves short.

    The 2-of-2 carries one signature, and that one commits to 50,000
    satoshi where the input spends 45,000. The satisfier would answer
    that the signatures do not satisfy the script, and the refusal names
    the signature instead, as `finalize` names it.
    """
    node = parse(f"multi(2,{KEYS[0]},{KEYS[1]})")
    psbt, prevouts = signed_psbt(node, [KEYS[0]], 0, 0)
    psbt.inputs[0].witness_utxo = TxOut(45_000, prevouts[0].script_pub_key)
    message = "^input 0: partial signature 0: invalid$"
    with pytest.raises(BTClibValueError, match=message):
        miniscript_solver(psbt, 0)


def test_a_signature_of_another_sighash_type_is_refused() -> None:
    """Refuse a SIGHASH_NONE signature on an input that asks for SIGHASH_ALL.

    The signature verifies, over the hash its own type commits to, and
    the engine takes the witness: the type the input asks for is what
    refuses it, as `finalize` refuses it.
    """
    node = parse(f"and_v(v:pk({KEYS[0]}),older(36))")
    psbt, prevouts = signed_psbt(node, [], 0, 36)
    script = node.script()
    msg_hash = sig_hash.segwit_v0(script, psbt.tx, 0, 2, prevouts[0].value)
    signature = dsa.sign_(msg_hash, PRV_KEYS[0]).serialize() + b"\x02"
    psbt.inputs[0].partial_sigs = {bytes.fromhex(KEYS[0]): signature}
    with pytest.raises(BTClibValueError, match="^mismatched sig_hash type: "):
        miniscript_solver(psbt, 0)
    psbt.inputs[0].sig_hash_type = 2
    assert miniscript_solver(psbt, 0) is not None


def test_a_witness_script_the_utxo_does_not_commit_to_is_refused() -> None:
    """Refuse a witness script other than the one the spent output names.

    The signature is good for the script the input carries, and the
    script engine runs the witness against the output the utxo holds,
    whose witness program is the hash of another script.
    """
    node = parse(f"and_v(v:pk({KEYS[0]}),older(36))")
    psbt, prevouts = signed_psbt(node, [KEYS[0]], 0, 36)
    other = parse(f"and_v(v:pk({KEYS[0]}),older(37))").script()
    psbt.inputs[0].witness_utxo = TxOut(prevouts[0].value, ScriptPubKey.p2wsh(other))
    with pytest.raises(BTClibValueError, match="^invalid witness script sha256"):
        finalize(psbt, solver=miniscript_solver)


def test_the_engine_reads_the_utxo_of_the_p2wsh_input_alone() -> None:
    """Spend the second input of a psbt whose first input carries no utxo.

    A segwit v0 spend commits to the amount of its own input alone, and
    the script engine reads no other: the witness is the one built where
    the first input carries its utxo too. The engine runs the second
    input, against the output that input spends.
    """
    node = parse(f"and_v(v:pk({KEYS[0]}),older(36))")
    script = node.script()
    prevout = TxOut(50_000, ScriptPubKey.p2wsh(script))
    tx = Tx(
        version=2,
        lock_time=0,
        vin=[TxIn(OutPoint(bytes([i + 1]) * 32, i), sequence=36) for i in range(2)],
        vout=[TxOut(49_000, ScriptPubKey.p2wpkh(PubKeyData(KEYS[0])))],
    )
    psbt = Psbt.from_tx(tx)
    psbt.inputs[1].witness_utxo = prevout
    psbt.inputs[1].witness_script = script
    msg_hash = sig_hash.segwit_v0(script, tx, 1, 1, prevout.value)
    signature = dsa.sign_(msg_hash, PRV_KEYS[0]).serialize() + b"\x01"
    psbt.inputs[1].partial_sigs = {bytes.fromhex(KEYS[0]): signature}
    answered = miniscript_solver(psbt, 1)
    assert answered is not None
    other = TxOut(1_000, ScriptPubKey.p2wpkh(PubKeyData(KEYS[1])))
    psbt.inputs[0].witness_utxo = other
    assert miniscript_solver(psbt, 1) == answered


def _known(*keys: str) -> dict[Octets, Octets]:
    """Return the keys an input names, each filed under its hash160."""
    return {hash160(bytes.fromhex(key)): bytes.fromhex(key) for key in keys}


_PKH = parse(f"pkh({KEYS[2]})").script()
_OR_D = parse(
    f"or_d(multi(2,{KEYS[0]},{KEYS[1]}),and_v(v:pkh({KEYS[2]}),older(144)))"
).script()
# a hash160() digest is a 20-byte push the input names no key for too
_HASH_LOCK = parse(
    f"and_v(v:hash160({hash160(PRV_KEYS[3]).hex()}),pkh({KEYS[2]}))"
).script()


@pytest.mark.parametrize(
    "script, key_hashes, lacks_only_keys",
    [
        pytest.param(_OR_D, _known(KEYS[0], KEYS[1]), True, id="lacks-one"),
        pytest.param(_OR_D, _known(), True, id="lacks-all"),
        pytest.param(_HASH_LOCK, _known(), True, id="beside-a-hash-lock"),
        pytest.param(
            _HASH_LOCK + serialize(["OP_DROP"]), _known(), False, id="no-miniscript"
        ),
        pytest.param(serialize(["OP_DROP"]) + _PKH, _known(), False, id="drop-first"),
        pytest.param(
            bytes.fromhex("5101e4ae") + _PKH, _known(), False, id="multi-count"
        ),
        pytest.param(
            _PKH.replace(b"\x88", b"\x87\x69"), _known(), False, id="split-verify"
        ),
        pytest.param(_OR_D[:-3], _known(), False, id="truncated"),
        pytest.param(_OR_D[:40], _known(), False, id="push-past-end"),
        # a key filed under a hash that is not its own is the decoder's
        # refusal, not a missing key
        pytest.param(
            _PKH, {hash160(bytes.fromhex(KEYS[2])): KEYS[0]}, False, id="wrong-key"
        ),
        # KEYS[0] is G, whose hash160 the first stand-in would be filed under
        pytest.param(
            parse(f"pkh({KEYS[0]})").script(),
            {hash160(bytes.fromhex(KEYS[0])): KEYS[1]},
            False,
            id="wrong-key-under-the-stand-in-hash",
        ),
        pytest.param(_OR_D, _known(KEYS[0]), True, id="lacks-one-beside-g"),
        # Octets admits hex strings, which from_script reads as their bytes
        pytest.param(
            _PKH,
            {hash160(bytes.fromhex(KEYS[2])).hex(): KEYS[0]},
            False,
            id="hex-wrong-key",
        ),
        pytest.param(
            _OR_D,
            {hash160(bytes.fromhex(key)).hex(): key for key in KEYS[:2]},
            True,
            id="hex-lacks-one",
        ),
        pytest.param(_PKH, {"zz": KEYS[2]}, False, id="no-hex"),
    ],
)
def test_the_solver_tells_a_missing_key(
    script: bytes, key_hashes: dict[Octets, Octets], lacks_only_keys: bool
) -> None:
    """Tell a script that lacks only keys from one that is wrong otherwise.

    Asked where `from_script` refuses the script, which is where the solver
    asks it: whether the refusal is only for a pk_h() whose key the input
    does not name.
    """
    with pytest.raises(BTClibValueError):
        from_script(script, P2WSH, key_hashes)
    assert _lacks_only_keys(script, P2WSH, key_hashes) is lacks_only_keys


def test_a_script_past_consensus_size_is_answered_before_it_is_walked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A witness script past `MAX_SCRIPT_SIZE` is no miniscript, at no walk.

    A parsed psbt can carry a witness script of any length, and
    `from_script` refuses one past its own, smaller bound.
    """
    script = _PKH * (MAX_SCRIPT_SIZE // len(_PKH) + 1)
    with pytest.raises(BTClibValueError, match="script too large"):
        from_script(script, P2WSH, {})

    walked: list[bytes] = []

    def walk(script: bytes) -> Iterator[tuple[int, int, int]]:
        walked.append(script)
        return op_code_spans(script)

    monkeypatch.setattr(psbt_module, "op_code_spans", walk)
    assert not _lacks_only_keys(script, P2WSH, {})
    assert not walked
    # and a script within the bound is walked
    assert _lacks_only_keys(_PKH, P2WSH, {})
    assert walked == [_PKH]


# a tr() whose script tree holds a miniscript leaf beside a key one: the
# recovery branch of a taproot custody, which is the shape BIP379 allows
# inside tr() and btclib-org/btclib#503 could only read as a wsh()
TR_MINISCRIPT = f"tr({KEYS[0]},{{pk({KEYS[1]}),and_v(v:pk({KEYS[2]}),older(36))}})"


def test_a_tr_miniscript_leaf_is_signed_over_the_psbt_sig_hash() -> None:
    """Sign the miniscript leaf of a tr() over `taproot_sig_hash`.

    The hash a psbt gives a script path signer is the one the engine checks:
    the satisfaction of the leaf, signed over it, is a spend
    `verify_transaction` accepts.
    """
    parsed = parse_descriptor(TR_MINISCRIPT)
    prevout = TxOut(50_000, parsed.script_pub_key())
    tx = Tx(
        version=2,
        vin=[TxIn(OutPoint(b"\x07" * 32, 0), sequence=36)],
        vout=[TxOut(49_000, ScriptPubKey.p2wpkh(PubKeyData(KEYS[0])))],
    )
    psbt = Psbt.from_tx(tx)
    psbt.inputs[0].witness_utxo = prevout
    leaf_script = parse(f"and_v(v:pk({KEYS[2]}),older(36))", TAPSCRIPT).script()
    msg_hash = taproot_sig_hash(psbt, 0, leaf_hash=leaf_hash(0xC0, leaf_script))
    signature = ssa.sign_(msg_hash, SIGNING_KEYS[KEYS[2]]).serialize()
    script_sig, witness = parsed.satisfy(
        {KEYS[2]: signature}, spend=SpendContext(sequence=36)
    )
    assert script_sig == b""
    # the satisfaction, the leaf script, the control block
    assert witness.stack[0] == signature
    assert witness.stack[1] == leaf_script
    tx.vin[0].script_witness = witness
    verify_transaction([prevout], tx)
    # and without the sequence the branch is shut, so no leaf is satisfied
    with pytest.raises(BTClibValueError, match="no signature for the tr"):
        parsed.satisfy({KEYS[2]: signature})


def psbt_input(node: Miniscript) -> tuple[PsbtIn, TxIn]:
    """Return an unsigned p2wsh input of the expression, and its TxIn.

    With the key origins an Updater writes, which is what a `pkh()`
    fragment needs to be readable at all: its script holds the hash of its
    key, so an input carrying neither a signature nor an origin for that
    key is one whose witness script cannot be read.
    """
    script = node.script()
    psbt_in = PsbtIn(
        witness_utxo=TxOut(50_000, ScriptPubKey.p2wsh(script)),
        witness_script=script,
        # one origin per key, and a path of its own for each: a psbt refuses
        # two keys claiming the same one
        hd_key_paths={
            key.sec(): BIP32KeyOrigin("deadbeef", [position])
            for position, key in enumerate(node.key_expressions)
        },
    )
    return psbt_in, TxIn(OutPoint(b"\x09" * 32, 0), sequence=36)


@pytest.mark.parametrize(
    "expression",
    [
        pytest.param(expression, id=vector_id(index, expression))
        for index, expression in enumerate(SOLVER_EXPRESSIONS)
    ],
)
def test_the_sizer_answers_before_there_is_a_signature(expression: str) -> None:
    """Size a miniscript input, and pay the fee the spend will need.

    The witness of a p2wsh spend is the satisfaction and then the witness
    script, so that is the list; what makes it an estimate rather than a
    measurement is that no signature exists yet, and what makes it enough
    is that the size of one does not depend on the key.
    """
    node = parse(expression)
    psbt_in, tx_in = psbt_input(node)
    script_sig, witness = estimated_input_sizes(psbt_in, tx_in, sizer=miniscript_sizer)
    assert script_sig == 0
    assert witness == [*(node.max_witness_stack or ()), len(node.script())]
    # the fee is paid on this, so it is the bound and not the cheapest
    assert sum(size + 1 for size in witness[:-1]) == node.max_witness_size
    # and without the sizer there is no estimate to be had
    with pytest.raises(BTClibValueError, match="no estimate for a script"):
        estimated_input_sizes(psbt_in, tx_in)


def test_the_sizer_answers_for_what_is_its_business_and_no_more() -> None:
    """Return None where the input is not a miniscript, as the solver does."""
    node = parse(f"and_v(v:pk({KEY}),older(36))")
    psbt_in, tx_in = psbt_input(node)
    native = miniscript_sizer(psbt_in, tx_in)
    assert native is not None
    # wrapped in p2sh, the witness is the same, whatever the outer type
    redeem_script = ScriptPubKey.p2wsh(node.script()).script
    wrapped = deepcopy(psbt_in)
    wrapped.witness_utxo = TxOut(50_000, ScriptPubKey.p2sh(redeem_script))
    wrapped.redeem_script = redeem_script
    assert miniscript_sizer(wrapped, tx_in) == native
    psbt_in.witness_script = b""
    assert miniscript_sizer(psbt_in, tx_in) is None
    psbt_in.witness_script = serialize(["OP_DROP", "OP_1"])
    assert miniscript_sizer(psbt_in, tx_in) is None
    # a script nothing satisfies has no spend to size, which is the answer
    # "not mine" too: the refusal is the caller's to make
    unspendable = parse("or_b(0,a:0)")
    psbt_in.witness_script = unspendable.script()
    assert miniscript_sizer(psbt_in, tx_in) is None


# a primary quorum larger than its timelocked recovery quorum, which is
# issue btclib-org/btclib#547's own shape: which branch a spend takes is decided
# before anything is estimated, and `max_witness_stack` cannot use that
_PRIMARY = f"multi(3,{KEYS[0]},{KEYS[1]},{KEYS[2]},{KEYS[3]},{KEYS[4]})"
_RECOVERY = f"and_v(v:older(36),multi(2,{KEYS[5]},{KEYS[6]}))"


def test_the_satisfaction_sizer_answers_for_the_branch_these_keys_build() -> None:
    """Size the branch a caller knows it will build, not the largest one.

    `max_witness_stack` reports the larger of the two branches -- the
    primary quorum here -- and a recovery spend pays for it too, though it
    never opens that branch. `satisfaction_sizer` given the keys that will
    actually sign reports what that spend builds instead, the same psbt
    input and the same `TxIn` both times: only the signers change.
    """
    node = parse(f"or_i({_RECOVERY},{_PRIMARY})")
    psbt_in, tx_in = psbt_input(node)
    assert node.max_witness_stack == (0, 72, 72, 72, 0)

    primary = estimated_input_sizes(psbt_in, tx_in, sizer=satisfaction_sizer(KEYS[:3]))
    assert primary == (0, [0, 72, 72, 72, 0, len(node.script())])
    # the primary quorum is the larger branch, so this is what
    # `miniscript_sizer` would have answered too: no savings to find
    assert primary == estimated_input_sizes(psbt_in, tx_in, sizer=miniscript_sizer)

    recovery = estimated_input_sizes(
        psbt_in, tx_in, sizer=satisfaction_sizer(KEYS[5:7])
    )
    assert recovery == (0, [0, 72, 72, 1, len(node.script())])
    # the bytes issue btclib-org/btclib#547 measures: paid on every recovery
    # spend by a sizer that does not know which branch it is, and not on this
    # one
    assert sum(recovery[1][:-1]) < sum(primary[1][:-1])


def test_the_satisfaction_sizer_answers_for_what_is_its_business_and_no_more() -> None:
    """Refuse for the two reasons `miniscript_sizer` does, and a third.

    No witness script and no miniscript are the two they share; building
    no satisfaction at all from the given keys is this sizer's own.
    """
    node = parse(f"and_v(v:pk({KEY}),older(36))")
    psbt_in, tx_in = psbt_input(node)
    assert satisfaction_sizer([KEY])(psbt_in, tx_in) is not None
    psbt_in.witness_script = b""
    assert satisfaction_sizer([KEY])(psbt_in, tx_in) is None
    psbt_in.witness_script = serialize(["OP_DROP", "OP_1"])
    assert satisfaction_sizer([KEY])(psbt_in, tx_in) is None
    # a key that will not sign this quorum builds no satisfaction either
    psbt_in.witness_script = node.script()
    assert satisfaction_sizer([KEYS[0]])(psbt_in, tx_in) is None


# the x-only keys of Core's test keys: X[i] is the key of the private key
# i + 1, which is what a tapscript holds
X = [key[2:] for key in KEYS]
# BIP341's NUMS point H, x-only: the internal key nobody signs for, which
# is what a tr() whose every path is a leaf holds
NUMS = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
# a sequence that opens no older() and is no final one
NO_LOCK = 0xFFFFFFFD

# an internal key that spends by the key path, and a timelocked leaf
SIMPLE_INHERITANCE = f"tr({X[0]},and_v(v:pk({X[1]}),older(52560)))"


def tr_psbt(
    text: str, sequence: int, lock_time: int
) -> tuple[Psbt, TxOut, TrDescriptor]:
    """Return the unsigned psbt of a tr() descriptor, filled by the Updater."""
    descriptor = parse_descriptor(text)
    assert isinstance(descriptor, TrDescriptor)
    prevout = TxOut(50_000, descriptor.script_pub_key(0))
    tx = Tx(
        version=2,
        lock_time=lock_time,
        vin=[TxIn(OutPoint(b"\x0b" * 32, 0), sequence=sequence)],
        vout=[TxOut(49_000, ScriptPubKey.p2wpkh(PubKeyData(KEYS[0])))],
    )
    psbt = Psbt.from_tx(tx)
    psbt.inputs[0].witness_utxo = prevout
    return update_psbt_input(descriptor, psbt, 0, 0), prevout, descriptor


def sign_leaf(psbt: Psbt, script: bytes, signers: list[int]) -> None:
    """Add the script path signatures of `signers` for one leaf script."""
    hash_ = leaf_hash(0xC0, script)
    msg_hash = taproot_sig_hash(psbt, 0, leaf_hash=hash_)
    for signer in signers:
        signature = ssa.sign_(msg_hash, signer + 1).serialize()
        key_data = bytes.fromhex(X[signer]) + hash_
        psbt.inputs[0].taproot_script_spend_signatures[key_data] = signature


def tr_signed(
    text: str, leaf: int | None, signers: list[int], sequence: int
) -> tuple[Psbt, TxOut, TrDescriptor]:
    """Return the psbt spending a tr() descriptor, signed along one path.

    `leaf` is the leaf's position in `taproot_tree`, None for the key
    path, which its one signer signs with the tweaked internal key.
    """
    psbt, prevout, descriptor = tr_psbt(text, sequence, 0)
    if leaf is not None:
        sign_leaf(psbt, descriptor.taproot_tree(0)[leaf][2], signers)
    for signer in signers if leaf is None else []:
        merkle_root = descriptor.taproot_merkle_root(0)
        tweaked = output_prvkey_from_merkle_root(signer + 1, merkle_root)
        signature = ssa.sign_(taproot_sig_hash(psbt, 0), tweaked).serialize()
        psbt.inputs[0].taproot_key_spend_signature = signature
    return psbt, prevout, descriptor


def spent(final: Psbt, prevout: TxOut) -> tuple[bytes, ...]:
    """Return the witness `finalize` built, once the script engine ran it."""
    spending = final.tx
    spending.vin[0].script_witness = final.inputs[0].final_script_witness
    verify_transaction([prevout], spending)
    return final.inputs[0].final_script_witness.stack


NO_SATISFACTION = "no satisfaction with the signatures, preimages and lock times given"


def test_a_key_path_signature_leaves_the_input_to_finalize() -> None:
    """Answer None beside a key path signature, whatever leaf is signed too.

    `finalize` prefers the key path, as Bitcoin Core's finalizer does, and
    builds it: one signature, where the leaf would have spent two
    elements and a control block.
    """
    text = SIMPLE_INHERITANCE
    psbt, prevout, descriptor = tr_signed(text, None, [0], 52560)
    sign_leaf(psbt, descriptor.taproot_tree(0)[0][2], [1])
    assert miniscript_solver(psbt, 0) is None
    assert [len(item) for item in spent(finalize(psbt), prevout)] == [64]
    # and without it the leaf is the solver's
    psbt.inputs[0].taproot_key_spend_signature = b""
    script_sig, witness = miniscript_solver(psbt, 0) or (b"-", Witness())
    assert script_sig == b""
    assert witness.stack[-2] == descriptor.taproot_tree(0)[0][2]


def _signed_twice(text: str, leaves: list[int], signers: list[int]) -> Psbt:
    """Return the psbt of `text` with `signers` signing each of `leaves`."""
    psbt, _, descriptor = tr_psbt(text, 144, 0)
    for leaf in leaves:
        sign_leaf(psbt, descriptor.taproot_tree(0)[leaf][2], signers)
    return psbt


def test_the_smallest_witness_is_spent_where_two_leaves_are_satisfied() -> None:
    """Spend the leaf whose witness is smaller, though it is the second.

    The same two keys satisfy both leaves of a quorum with a timelocked
    recovery quorum behind it, and the recovery leaf comes first both in
    the tree and in the order of leaf scripts. The witness of each, spent
    alone, is the measurement: the primary leaf's is the smaller one.
    """
    text = (
        f"tr({NUMS},{{and_v(v:multi_a(2,{X[0]},{X[1]},{X[2]}),older(144)),"
        f"multi_a(2,{X[0]},{X[1]})}})"
    )
    tree = tr_psbt(text, 144, 0)[2].taproot_tree(0)
    recovery, primary = (script for _, _, script in tree)
    assert recovery < primary
    alone = [
        miniscript_solver(_signed_twice(text, [leaf], [0, 1]), 0) for leaf in (0, 1)
    ]
    sizes = [len(spend[1].serialize()) for spend in alone if spend is not None]
    assert sizes[1] < sizes[0]

    psbt = _signed_twice(text, [0, 1], [0, 1])
    chosen = miniscript_solver(psbt, 0)
    assert chosen is not None
    assert alone[1] is not None
    # the signatures are fresh ones: BIP340 signing draws its aux randomness
    assert chosen[1].stack[-2:] == alone[1][1].stack[-2:]
    assert len(chosen[1].serialize()) == sizes[1]
    # `Descriptor.satisfy` spends the first leaf the signatures satisfy
    descriptor = tr_psbt(text, 144, 0)[2]
    script_sigs = psbt.inputs[0].taproot_script_spend_signatures
    signatures: dict[Octets, Octets] = {
        key_data[:32]: signature for key_data, signature in script_sigs.items()
    }
    _, first = descriptor.satisfy(signatures, spend=SpendContext(sequence=144))
    assert first.stack[-2] == recovery


def test_the_control_block_is_part_of_the_size() -> None:
    """Spend the shallower of two leaves whose scripts are the same size.

    The deeper leaf's script is the smaller one, which wins only where the
    witnesses are equal: its control block is one node longer.
    """
    small, big = sorted([X[5], X[6]])
    text = (
        f"tr({NUMS},{{and_v(v:pk({big}),older(144)),"
        f"{{and_v(v:pk({small}),older(144)),pk({X[7]})}}}})"
    )
    signers = [X.index(big), X.index(small)]
    psbt, prevout, descriptor = tr_psbt(text, 144, 0)
    for leaf, signer in zip((0, 1), signers, strict=True):
        sign_leaf(psbt, descriptor.taproot_tree(0)[leaf][2], [signer])
    stack = spent(finalize(psbt, solver=miniscript_solver), prevout)
    assert stack[-2] == descriptor.taproot_tree(0)[0][2]
    assert len(stack[-1]) == 33 + 32


def test_equal_witnesses_spend_the_smaller_leaf_script() -> None:
    """Spend the smaller leaf script where the witnesses are the same size.

    Bitcoin Core's choice: the first smallest witness over leaves ordered
    by script. The smaller script is the second leaf of the tree, and its
    control block is the larger one: these two keys order the leaves one
    way by script and the other by control block.
    """
    small, big = sorted([X[6], X[7]])
    text = (
        f"tr({NUMS},{{and_v(v:pk({big}),older(144)),and_v(v:pk({small}),older(144))}})"
    )
    psbt, prevout, descriptor = tr_psbt(text, 144, 0)
    for leaf, key in enumerate((big, small)):
        sign_leaf(psbt, descriptor.taproot_tree(0)[leaf][2], [X.index(key)])
    stack = spent(finalize(psbt, solver=miniscript_solver), prevout)
    assert stack[-2] == descriptor.taproot_tree(0)[1][2]
    assert stack[-1] == max(psbt.inputs[0].taproot_leaf_scripts)


def test_one_leaf_under_two_control_blocks_spends_the_smaller_one() -> None:
    """Spend the smaller control block of a leaf the tree holds twice.

    Both are as long, and the order of `taproot_leaf_scripts` does not
    change which one is spent.
    """
    leaf = f"and_v(v:pk({X[0]}),older(144))"
    text = f"tr({NUMS},{{{{{leaf},pk({X[1]})}},{{{leaf},pk({X[2]})}}}})"
    psbt, prevout, descriptor = tr_psbt(text, 144, 0)
    script = descriptor.taproot_tree(0)[0][2]
    records = psbt.inputs[0].taproot_leaf_scripts
    control_blocks = [
        control_block
        for control_block, (leaf_script, _) in records.items()
        if leaf_script == script
    ]
    assert len(control_blocks) == 2
    sign_leaf(psbt, script, [0])
    for records in (
        psbt.inputs[0].taproot_leaf_scripts,
        dict(reversed(psbt.inputs[0].taproot_leaf_scripts.items())),
    ):
        psbt.inputs[0].taproot_leaf_scripts = records
        stack = spent(finalize(psbt, solver=miniscript_solver), prevout)
        assert stack[-1] == min(control_blocks)


@pytest.mark.parametrize(
    "fragment,lock_time",
    [
        pytest.param(f"sha256({sha256(PRV_KEYS[3]).hex()})", 0, id="sha256"),
        pytest.param("after(500)", 500, id="after"),
    ],
)
def test_a_leaf_reads_the_preimages_and_the_lock_time_of_the_psbt(
    fragment: str, lock_time: int
) -> None:
    """Satisfy a hash lock with the input's preimage, an after() at its height.

    The spend context the p2wsh branch builds, read the same way. With the
    preimage of another hash, or one block early, there is no
    satisfaction, and the refusal prints neither preimage.
    """
    text = f"tr({NUMS},and_v(v:pk({X[0]}),{fragment}))"
    for preimage, height, satisfied in (
        (PRV_KEYS[3], lock_time, True),
        (PRV_KEYS[4], lock_time - 1, False),
    ):
        psbt, prevout, descriptor = tr_psbt(text, NO_LOCK, max(height, 0))
        psbt.inputs[0].sha256_preimages = {sha256(preimage): preimage}
        sign_leaf(psbt, descriptor.taproot_tree(0)[0][2], [0])
        if satisfied:
            spent(finalize(psbt, solver=miniscript_solver), prevout)
            continue
        refused = f"^{re.escape(NO_SATISFACTION)}$"
        with pytest.raises(BTClibValueError, match=refused) as e:
            miniscript_solver(psbt, 0)
        assert e.value.__cause__ is None
        assert e.value.__context__ is None
        assert_secret_free(e.value, [PRV_KEYS[3], PRV_KEYS[4]])


def test_the_solver_leaves_a_taproot_input_it_cannot_read_to_finalize() -> None:
    """Answer None where no leaf a signature names is a miniscript.

    No script path signature, a signature of a leaf the input holds no
    script for, a leaf script that is no miniscript, and a leaf of a version
    that is not BIP342's: `finalize` then answers as it does without a
    solver.
    """
    text = f"tr({NUMS},and_v(v:pk({X[0]}),older(144)))"
    psbt, _, descriptor = tr_psbt(text, 144, 0)
    assert miniscript_solver(psbt, 0) is None
    with pytest.raises(BTClibValueError, match="^input 0: missing taproot signature$"):
        finalize(psbt, solver=miniscript_solver)

    script = descriptor.taproot_tree(0)[0][2]
    (control_block,) = psbt.inputs[0].taproot_leaf_scripts
    other = parse(f"and_v(v:pk({X[0]}),older(145))", TAPSCRIPT).script()
    sign_leaf(psbt, other, [0])
    assert miniscript_solver(psbt, 0) is None

    psbt.inputs[0].taproot_script_spend_signatures = {}
    no_miniscript = serialize(["OP_DROP", "OP_1"])
    psbt.inputs[0].taproot_leaf_scripts = {control_block: (no_miniscript, 0xC0)}
    sign_leaf(psbt, no_miniscript, [0])
    assert miniscript_solver(psbt, 0) is None

    psbt.inputs[0].taproot_script_spend_signatures = {}
    psbt.inputs[0].taproot_leaf_scripts = {control_block: (script, 0xC2)}
    hash_ = leaf_hash(0xC2, script)
    msg_hash = taproot_sig_hash(psbt, 0, leaf_hash=hash_)
    key_data = bytes.fromhex(X[0]) + hash_
    signature = ssa.sign_(msg_hash, 1).serialize()
    psbt.inputs[0].taproot_script_spend_signatures = {key_data: signature}
    assert miniscript_solver(psbt, 0) is None


def test_every_script_path_signature_is_verified() -> None:
    """Refuse a signature that does not verify, of the leaf spent or not.

    `finalize` checks no signature of a spend a solver answers, so the
    solver does, as `finalize` does for its own: by the sig_hash type the
    input accepts, and against the hash that type commits to.
    """
    text = (
        f"tr({NUMS},{{and_v(v:pk({X[0]}),older(144)),"
        f"and_v(v:multi_a(2,{X[1]},{X[2]},{X[3]}),older(144))}})"
    )
    psbt = _signed_twice(text, [0], [0])
    sign_leaf(psbt, tr_psbt(text, 144, 0)[2].taproot_tree(0)[1][2], [1])
    assert miniscript_solver(psbt, 0) is not None
    signatures = psbt.inputs[0].taproot_script_spend_signatures
    for position, key_data in enumerate(signatures):
        signature = signatures[key_data]
        signatures[key_data] = signature[:-1] + bytes([signature[-1] ^ 1])
        message = f"^input 0: taproot script path signature {position}: invalid$"
        with pytest.raises(BTClibValueError, match=message):
            miniscript_solver(psbt, 0)
        signatures[key_data] = signature + b"\x02"
        with pytest.raises(BTClibValueError, match="invalid sig_hash type"):
            miniscript_solver(psbt, 0)
        signatures[key_data] = signature


UNKNOWN_LEAF_KEY = "^input 0: no public key for a hash160 a leaf script holds$"


def test_a_leaf_reads_a_key_the_input_knows_by_its_hash() -> None:
    """Read a pkh() leaf with the x-only keys that signed and those named.

    A key that signed reads it. A key no signature and no taproot origin
    names leaves the leaf unread, which is the refusal unless another
    leaf is satisfied; its origin, which the Updater writes, is enough.
    """
    unknown = bytes.fromhex(X[1])
    text = f"tr({NUMS},and_v(v:pkh({X[1]}),older(144)))"
    psbt, prevout, descriptor = tr_psbt(text, 144, 0)
    del psbt.inputs[0].taproot_hd_key_paths[unknown]
    sign_leaf(psbt, descriptor.taproot_tree(0)[0][2], [1])
    spent(finalize(psbt, solver=miniscript_solver), prevout)

    text = (
        f"tr({NUMS},{{or_d(pk({X[0]}),and_v(v:pkh({X[1]}),older(144))),"
        f"and_v(v:pk({X[0]}),older(145))}})"
    )
    psbt, prevout, descriptor = tr_psbt(text, 144, 0)
    origin = psbt.inputs[0].taproot_hd_key_paths.pop(unknown)
    or_d, timelocked = (script for _, _, script in descriptor.taproot_tree(0))
    sign_leaf(psbt, or_d, [0])
    sign_leaf(psbt, timelocked, [0])
    # the timelocked leaf is read and not satisfied, and the other unread
    with pytest.raises(BTClibValueError, match=UNKNOWN_LEAF_KEY) as e:
        finalize(psbt, solver=miniscript_solver)
    assert e.value.__cause__ is None
    assert e.value.__context__ is None
    assert_secret_free(e.value, [PRV_KEYS[0], PRV_KEYS[1]])
    psbt.inputs[0].taproot_hd_key_paths[unknown] = origin
    assert spent(finalize(psbt, solver=miniscript_solver), prevout)[-2] == or_d

    # a leaf satisfied beside the unread one is spent
    psbt, prevout, descriptor = tr_psbt(text, 145, 0)
    del psbt.inputs[0].taproot_hd_key_paths[unknown]
    sign_leaf(psbt, or_d, [0])
    sign_leaf(psbt, timelocked, [0])
    assert spent(finalize(psbt, solver=miniscript_solver), prevout)[-2] == timelocked
    # and the unread leaf alone is the refusal
    psbt.inputs[0].taproot_script_spend_signatures = {}
    sign_leaf(psbt, or_d, [0])
    with pytest.raises(BTClibValueError, match=UNKNOWN_LEAF_KEY):
        miniscript_solver(psbt, 0)


def _x_known(*keys: str) -> dict[Octets, Octets]:
    """Return the x-only keys an input names, each filed under its hash160."""
    return {hash160(bytes.fromhex(key)): bytes.fromhex(key) for key in keys}


_X_PKH = parse(f"pkh({X[2]})", TAPSCRIPT).script()
_X_OR_D = parse(
    f"or_d(multi_a(2,{X[0]},{X[1]}),and_v(v:pkh({X[2]}),older(144)))", TAPSCRIPT
).script()
# a pkh() beside a multi_a() of more keys than a P2WSH script can hold
_MANY = ",".join(PrvKeyData(i).pub.sec[1:].hex() for i in range(300, 600))
_X_LONG = parse(f"and_v(v:pkh({X[2]}),multi_a(1,{_MANY}))", TAPSCRIPT).script()


@pytest.mark.parametrize(
    "script, key_hashes, lacks_only_keys",
    [
        pytest.param(_X_OR_D, _x_known(X[0], X[1]), True, id="lacks-one"),
        pytest.param(_X_OR_D, _x_known(), True, id="lacks-all"),
        pytest.param(
            serialize(["OP_DROP"]) + _X_PKH, _x_known(), False, id="drop-first"
        ),
        pytest.param(_X_OR_D[:-3], _x_known(), False, id="truncated"),
        # a SEC key is no tapscript key, whichever hash it is filed under
        pytest.param(
            _X_PKH, {hash160(bytes.fromhex(X[2])): KEYS[2]}, False, id="sec-key"
        ),
        # X[0] is the x of G, whose hash160 the first stand-in would be
        # filed under
        pytest.param(
            parse(f"pkh({X[0]})", TAPSCRIPT).script(),
            {hash160(bytes.fromhex(X[0])): X[1]},
            False,
            id="wrong-key-under-the-stand-in-hash",
        ),
        pytest.param(_X_OR_D, _x_known(X[0]), True, id="lacks-one-beside-g"),
        # a script past the P2WSH bound is walked under tapscript, and is
        # a miniscript but for a key there
        pytest.param(_X_LONG, _x_known(), True, id="long"),
        pytest.param(
            _X_PKH * (MAX_SCRIPT_SIZE // len(_X_PKH) + 1),
            _x_known(),
            False,
            id="long-no-miniscript",
        ),
    ],
)
def test_the_solver_tells_a_missing_tapscript_key(
    script: bytes, key_hashes: dict[Octets, Octets], lacks_only_keys: bool
) -> None:
    """Tell a tapscript that lacks only x-only keys from one wrong otherwise."""
    with pytest.raises(BTClibValueError):
        from_script(script, TAPSCRIPT, key_hashes)
    assert _lacks_only_keys(script, TAPSCRIPT, key_hashes) is lacks_only_keys


def test_a_taproot_input_is_spent_by_its_leaves_whatever_witness_script() -> None:
    """Spend a taproot input by a leaf, beside a witness script it carries.

    The output being spent decides, as `_is_taproot` says: a witness
    script on a taproot input is no p2wsh, even one that is a miniscript.
    """
    text = SIMPLE_INHERITANCE
    psbt, _, descriptor = tr_signed(text, 0, [1], 52560)
    psbt.inputs[0].witness_script = parse(f"pk({KEYS[0]})").script()
    script_sig, witness = miniscript_solver(psbt, 0) or (b"-", Witness())
    assert script_sig == b""
    assert witness.stack[-2] == descriptor.taproot_tree(0)[0][2]


def test_a_control_block_that_proves_no_leaf_is_refused() -> None:
    """Refuse a leaf record whose control block does not reach the output key.

    The same leaf under a 33-byte control block, which leaves out the
    sibling hash: the smallest witness, and one the script engine refuses.
    The input's taproot fields are held to the output as `sign` holds them.
    """
    text = f"tr({NUMS},{{and_v(v:pk({X[0]}),older(144)),pk({X[1]})}})"
    psbt, prevout, descriptor = tr_psbt(text, 144, 0)
    script = descriptor.taproot_tree(0)[0][2]
    records = psbt.inputs[0].taproot_leaf_scripts
    (proof,) = (cb for cb, (leaf_script, _) in records.items() if leaf_script == script)
    sign_leaf(psbt, script, [0])
    records[proof[:33]] = (script, 0xC0)
    message = "^a control block does not prove its leaf script against the output key$"
    with pytest.raises(BTClibValueError, match=message) as e:
        finalize(psbt, solver=miniscript_solver)
    assert e.value.__cause__ is None
    assert e.value.__context__ is None
    del records[proof[:33]]
    assert spent(finalize(psbt, solver=miniscript_solver), prevout)[-1] == proof


def test_signatures_under_two_key_leaves_spend_the_cheaper_one() -> None:
    """Spend the shallower of two signed pk() leaves, which `finalize` refuses.

    `finalize` alone does not choose between two leaves; the solver
    spends the smaller witness, the leaf one level up.
    """
    text = f"tr({NUMS},{{pk({X[0]}),{{pk({X[1]}),pk({X[2]})}}}})"
    psbt, prevout, descriptor = tr_psbt(text, NO_LOCK, 0)
    tree = descriptor.taproot_tree(0)
    sign_leaf(psbt, tree[0][2], [0])
    sign_leaf(psbt, tree[1][2], [1])
    with pytest.raises(BTClibValueError, match="the psbt does not say which leaf"):
        finalize(psbt)
    stack = spent(finalize(psbt, solver=miniscript_solver), prevout)
    assert stack[-2] == tree[0][2]
    assert len(stack[-1]) == 33 + 32


def test_a_key_leaf_beside_a_record_that_proves_nothing_is_refused() -> None:
    """Refuse a signed pk() leaf where another record's proof is false.

    `finalize` alone builds the signed leaf and reads no other record;
    the solver holds every record to the output key, as `sign` does.
    """
    text = f"tr({NUMS},{{pk({X[0]}),pk({X[1]})}})"
    psbt, prevout, descriptor = tr_psbt(text, NO_LOCK, 0)
    signed, other = (script for _, _, script in descriptor.taproot_tree(0))
    records = psbt.inputs[0].taproot_leaf_scripts
    (proof,) = (cb for cb, (script, _) in records.items() if script == other)
    del records[proof]
    records[proof[:33]] = (other, 0xC0)
    sign_leaf(psbt, signed, [0])
    assert spent(finalize(psbt), prevout)[-2] == signed
    message = "^a control block does not prove its leaf script against the output key$"
    with pytest.raises(BTClibValueError, match=message):
        finalize(psbt, solver=miniscript_solver)


def _x_only(prv_key: int) -> str:
    """Return the x-only key of a private key, as hex."""
    return PrvKeyData(prv_key).pub.sec[1:].hex()


def _two_quorums(first: int, second: int) -> str:
    """Return two 1-of-n ``multi_a()`` quorums of the keys of 1, 2, 3 and on."""
    keys = [_x_only(prv_key) for prv_key in range(1, first + second + 1)]
    return (
        f"and_v(v:multi_a(1,{','.join(keys[:first])}),"
        f"multi_a(1,{','.join(keys[first:])}))"
    )


def _hand_tr(scripts: list[bytes]) -> tuple[Psbt, TxOut]:
    """Return the unsigned psbt of a NUMS output with one or two leaves.

    Built by hand and not from a tr() descriptor, which refuses a leaf
    that is not sane: these are not.
    """
    hashes = [leaf_hash(0xC0, script) for script in scripts]
    root = hashes[0]
    if len(hashes) == 2:
        root = tagged_hash(b"TapBranch", b"".join(sorted(hashes)))
    nums = bytes.fromhex(NUMS)
    output_key, parity = output_pubkey_from_merkle_root_var(nums, root)
    prevout = TxOut(50_000, ScriptPubKey(b"\x51\x20" + output_key))
    tx = Tx(
        version=2,
        lock_time=0,
        vin=[TxIn(OutPoint(b"\x0b" * 32, 0), sequence=NO_LOCK)],
        vout=[TxOut(49_000, ScriptPubKey.p2wpkh(PubKeyData(KEYS[0])))],
    )
    psbt = Psbt.from_tx(tx)
    psbt_in = psbt.inputs[0]
    psbt_in.witness_utxo = prevout
    psbt_in.taproot_internal_key = nums
    psbt_in.taproot_merkle_root = root
    for i, script in enumerate(scripts):
        path = hashes[1 - i] if len(hashes) == 2 else b""
        control_block = bytes([0xC0 + parity]) + nums + path
        psbt_in.taproot_leaf_scripts[control_block] = (script, 0xC0)
    return psbt, prevout


def _sign_with(psbt: Psbt, script: bytes, prv_keys: list[int]) -> None:
    """Add the script path signatures of `prv_keys` for one leaf script."""
    hash_ = leaf_hash(0xC0, script)
    msg_hash = taproot_sig_hash(psbt, 0, leaf_hash=hash_)
    for prv_key in prv_keys:
        key_data = bytes.fromhex(_x_only(prv_key)) + hash_
        signature = ssa.sign_(msg_hash, prv_key).serialize()
        psbt.inputs[0].taproot_script_spend_signatures[key_data] = signature


def test_a_leaf_past_the_stack_limit_is_refused() -> None:
    """Refuse a satisfied leaf whose stack passes a thousand elements.

    Two 1-of-500 quorums are satisfied by a thousand elements, and the
    first key the script pushes on them is the thousand and first, which
    BIP342 refuses: the script engine's refusal is the answer. With one
    key fewer the stack peaks at a thousand, and the leaf is spent.
    """
    node = parse(_two_quorums(500, 500), TAPSCRIPT)
    assert node.max_exec_stack_items == 1001
    script = node.script()
    psbt, _ = _hand_tr([script])
    _sign_with(psbt, script, [1, 501])
    message = "^more than 1000 stack elements: 1001 "
    with pytest.raises(BTClibValueError, match=message) as e:
        finalize(psbt, solver=miniscript_solver)
    # the engine's own refusal, raised from a fresh run and chained by it
    assert_secret_free(e.value, [PRV_KEYS[0], (501).to_bytes(32, "big")])

    node = parse(_two_quorums(499, 500), TAPSCRIPT)
    assert node.max_exec_stack_items == 1000
    script = node.script()
    psbt, prevout = _hand_tr([script])
    _sign_with(psbt, script, [1, 500])
    stack = spent(finalize(psbt, solver=miniscript_solver), prevout)
    assert stack[-2] == script


def test_a_leaf_past_the_stack_limit_is_passed_over() -> None:
    """Spend the larger of two satisfied leaves, the smaller being refused.

    The leaf of two 1-of-500 quorums has the smaller witness, and one the
    script engine refuses. The other leaf is an ``or_d()`` whose ``pk()``
    branch spends with one signature beside two 1-of-600 quorums: its
    miniscript is not within its resource limits, and its witness is one
    the engine takes.
    """
    past = parse(_two_quorums(500, 500), TAPSCRIPT)
    guarded = parse(f"or_d(pk({_x_only(1201)}),{_two_quorums(600, 600)})", TAPSCRIPT)
    assert not guarded.is_within_resource_limits
    psbt, prevout = _hand_tr([past.script(), guarded.script()])
    _sign_with(psbt, past.script(), [1, 501])
    _sign_with(psbt, guarded.script(), [1201])
    stack = spent(finalize(psbt, solver=miniscript_solver), prevout)
    assert stack[-2] == guarded.script()
    # the witness passed over, built as the solver builds it
    past_hash = leaf_hash(0xC0, past.script())
    script_sigs = psbt.inputs[0].taproot_script_spend_signatures
    signatures: dict[Octets, Octets] = {
        key_data[:32]: signature
        for key_data, signature in script_sigs.items()
        if key_data[32:] == past_hash
    }
    records = psbt.inputs[0].taproot_leaf_scripts
    (proof,) = (cb for cb, (script, _) in records.items() if script == past.script())
    passed_over = Witness([*past.satisfy(signatures), past.script(), proof])
    assert len(passed_over.serialize()) < len(Witness(list(stack)).serialize())


def test_a_smaller_leaf_within_its_limits_is_sized_beside_one_past_them() -> None:
    """Size the smaller leaf where it is within its limits, as it is spent.

    The other leaf, two 1-of-500 quorums, is past its limits and satisfied
    too: it is not what the solver spends, nor what is paid for.
    """
    small = parse(f"pk({_x_only(1)})", TAPSCRIPT)
    past = parse(_two_quorums(500, 500), TAPSCRIPT)
    assert small.is_within_resource_limits
    assert not past.is_within_resource_limits
    psbt, prevout = _hand_tr([small.script(), past.script()])
    psbt_in, tx_in = psbt.inputs[0], psbt.tx.vin[0]
    sized = satisfaction_sizer([_x_only(1), _x_only(501)])(psbt_in, tx_in)
    _sign_with(psbt, small.script(), [1])
    _sign_with(psbt, past.script(), [1, 501])
    stack = spent(finalize(psbt, solver=miniscript_solver), prevout)
    assert stack[-2] == small.script()
    assert sized == _sizes(stack)


def test_a_leaf_past_its_limits_is_sized_at_the_largest_satisfied() -> None:
    """Size the leaf the solver spends, not the smaller one it passes over.

    `satisfaction_sizer` cannot run the script engine without the
    signatures, so where a satisfied leaf is past its resource limits it
    answers the largest satisfied leaf, which is the one spent here.
    """
    past = parse(_two_quorums(500, 500), TAPSCRIPT)
    guarded = parse(f"or_d(pk({_x_only(1201)}),{_two_quorums(600, 600)})", TAPSCRIPT)
    psbt, prevout = _hand_tr([past.script(), guarded.script()])
    psbt_in, tx_in = psbt.inputs[0], psbt.tx.vin[0]
    keys = [_x_only(1), _x_only(501), _x_only(1201)]
    sized = satisfaction_sizer(keys)(psbt_in, tx_in)
    _sign_with(psbt, past.script(), [1, 501])
    _sign_with(psbt, guarded.script(), [1201])
    stack = spent(finalize(psbt, solver=miniscript_solver), prevout)
    assert sized == _sizes(stack)


def test_the_engine_runs_the_input_being_finalized() -> None:
    """Spend a leaf on each of two inputs, the engine running each one.

    Each input spends the timelocked leaf of an output of its own, and its
    witness is run on that input of the transaction, not on another.
    """
    descriptor = parse_descriptor(SIMPLE_INHERITANCE)
    assert isinstance(descriptor, TrDescriptor)
    prevouts = [TxOut(50_000 + i, descriptor.script_pub_key(0)) for i in range(2)]
    tx = Tx(
        version=2,
        lock_time=0,
        vin=[TxIn(OutPoint(bytes([i + 1]) * 32, i), sequence=52560) for i in range(2)],
        vout=[TxOut(99_000, ScriptPubKey.p2wpkh(PubKeyData(KEYS[0])))],
    )
    psbt = Psbt.from_tx(tx)
    for i, prevout in enumerate(prevouts):
        psbt.inputs[i].witness_utxo = prevout
        psbt = update_psbt_input(descriptor, psbt, i, 0)
    for i in range(2):
        script = descriptor.taproot_tree(0)[0][2]
        hash_ = leaf_hash(0xC0, script)
        msg_hash = taproot_sig_hash(psbt, i, leaf_hash=hash_)
        signature = ssa.sign_(msg_hash, 2).serialize()
        key_data = bytes.fromhex(X[1]) + hash_
        psbt.inputs[i].taproot_script_spend_signatures[key_data] = signature
    final = finalize(psbt, solver=miniscript_solver)
    spending = final.tx
    for tx_in, psbt_in in zip(spending.vin, final.inputs, strict=True):
        tx_in.script_witness = psbt_in.final_script_witness
    verify_transaction(prevouts, spending)


# -- the sizers over a taproot input ---------------------------------------


def _sizes(stack: tuple[bytes, ...]) -> list[int]:
    """Return the size of each element of a witness."""
    return [len(item) for item in stack]


def _witness_bytes(sizes: list[int]) -> int:
    """Return the bytes a witness of elements of these sizes takes."""
    return len(Witness([bytes(size) for size in sizes]).serialize())


def test_the_sizer_answers_the_largest_taproot_spend() -> None:
    """Size a tr() input at its largest path, never below the one spent.

    The key path is one signature; the leaf is a signature, its script and
    its control block. A signer may take either, so the leaf, the larger,
    is the answer, at 65 bytes a signature, which a non-default sig_hash
    type costs. Each witness `finalize` builds is no larger.
    """
    text = SIMPLE_INHERITANCE
    psbt, prevout, descriptor = tr_psbt(text, 52560, 0)
    psbt_in, tx_in = psbt.inputs[0], psbt.tx.vin[0]
    script = descriptor.taproot_tree(0)[0][2]
    ((control_block, _),) = psbt_in.taproot_leaf_scripts.items()
    largest = [65, len(script), len(control_block)]
    assert miniscript_sizer(psbt_in, tx_in) == largest
    assert estimated_input_sizes(psbt_in, tx_in, sizer=miniscript_sizer) == (
        0,
        largest,
    )
    for leaf in (None, 0):
        signed, _, _ = tr_signed(text, leaf, [0] if leaf is None else [1], 52560)
        built = _sizes(spent(finalize(signed, solver=miniscript_solver), prevout))
        assert _witness_bytes(built) <= _witness_bytes(largest)


def test_the_sizer_answers_the_largest_of_two_leaves() -> None:
    """The quorum leaf is larger than the single key one, whichever order."""
    text = f"tr({NUMS},{{pk({X[0]}),multi_a(2,{X[1]},{X[2]},{X[3]})}})"
    psbt, _, descriptor = tr_psbt(text, NO_LOCK, 0)
    psbt_in, tx_in = psbt.inputs[0], psbt.tx.vin[0]
    quorum = descriptor.taproot_tree(0)[1][2]
    (control_block,) = (
        cb for cb, (s, _) in psbt_in.taproot_leaf_scripts.items() if s == quorum
    )
    # two signatures and the empty push of the third key, in witness order
    stack = from_script(quorum, TAPSCRIPT).max_witness_stack or ()
    assert sorted(stack) == [0, 65, 65]
    expected = [*stack, len(quorum), len(control_block)]
    assert miniscript_sizer(psbt_in, tx_in) == expected


def test_a_taproot_leaf_the_sizer_cannot_read_has_no_estimate() -> None:
    """A leaf that is no miniscript, or no tapscript, or nothing satisfies.

    `miniscript_sizer` answers None for each, so `estimated_input_sizes`
    refuses the input as it does with no sizer; `satisfaction_sizer`
    answers None too, the internal key aside.
    """
    psbt, _, _ = tr_psbt(f"tr({NUMS},pk({X[0]}))", NO_LOCK, 0)
    psbt_in, tx_in = psbt.inputs[0], psbt.tx.vin[0]
    ((control_block, (script, version)),) = psbt_in.taproot_leaf_scripts.items()
    unspendable = parse("or_b(0,a:0)").script()
    for record in (
        (serialize(["OP_DROP", "OP_1"]), version),
        (script, 0xC2),
        (script, 0xBE),
        (unspendable, version),
    ):
        psbt_in.taproot_leaf_scripts = {control_block: record}
        assert miniscript_sizer(psbt_in, tx_in) is None
        with pytest.raises(BTClibValueError, match="no estimate for a taproot"):
            estimated_input_sizes(psbt_in, tx_in, sizer=miniscript_sizer)
    psbt_in.taproot_leaf_scripts = {control_block: (serialize(["OP_DROP"]), version)}
    assert satisfaction_sizer([X[0]])(psbt_in, tx_in) is None


def test_the_sizers_read_no_taproot_spend_of_an_input_with_no_utxo() -> None:
    """With no utxo the input spends nothing they can see, so no witness."""
    psbt, _, _ = tr_psbt(SIMPLE_INHERITANCE, 52560, 0)
    psbt_in, tx_in = psbt.inputs[0], psbt.tx.vin[0]
    psbt_in.witness_utxo = None
    assert miniscript_sizer(psbt_in, tx_in) is None
    assert satisfaction_sizer([X[0]])(psbt_in, tx_in) is None


@pytest.mark.parametrize("spelling", ["x-only", "SEC", "uncompressed SEC"])
def test_the_satisfaction_sizer_answers_the_path_these_keys_spend(
    spelling: str,
) -> None:
    """The key path where they hold the internal key, else their leaf.

    Each answer is the witness `finalize` builds from the signatures of
    those keys, element by element. A key is read x-only, or in SEC bytes
    compressed or not.
    """
    keys = {
        "x-only": X,
        "SEC": KEYS,
        "uncompressed SEC": [
            PrvKeyData(i, "mainnet", False).pub.sec.hex() for i in range(1, 7)
        ],
    }[spelling]
    text = SIMPLE_INHERITANCE
    psbt, prevout, _ = tr_psbt(text, 52560, 0)
    psbt_in, tx_in = psbt.inputs[0], psbt.tx.vin[0]
    for leaf, signer in ((None, 0), (0, 1)):
        signed, _, _ = tr_signed(text, leaf, [signer], 52560)
        built = _sizes(spent(finalize(signed, solver=miniscript_solver), prevout))
        assert satisfaction_sizer([keys[signer]])(psbt_in, tx_in) == built
    # a key of neither path spends nothing
    assert satisfaction_sizer([keys[5]])(psbt_in, tx_in) is None
    # nor does the leaf's key while its timelock is shut
    tx_in.sequence = NO_LOCK
    assert satisfaction_sizer([keys[1]])(psbt_in, tx_in) is None


def test_the_satisfaction_sizer_answers_the_smaller_leaf_it_satisfies() -> None:
    """Two leaves a key satisfies: the one with the smaller witness.

    A key path signature carries the sig_hash byte where the input asks
    for a type other than the default one.
    """
    text = f"tr({NUMS},{{multi_a(1,{X[0]},{X[1]},{X[2]}),pk({X[0]})}})"
    psbt, _, descriptor = tr_psbt(text, NO_LOCK, 0)
    psbt_in, tx_in = psbt.inputs[0], psbt.tx.vin[0]
    single = descriptor.taproot_tree(0)[1][2]
    (control_block,) = (
        cb for cb, (s, _) in psbt_in.taproot_leaf_scripts.items() if s == single
    )
    expected = [64, len(single), len(control_block)]
    assert satisfaction_sizer([X[0]])(psbt_in, tx_in) == expected
    psbt_in.sig_hash_type = 1
    assert satisfaction_sizer([X[0]])(psbt_in, tx_in) == [65, *expected[1:]]
    internal = bytes.fromhex(X[4])
    psbt_in.taproot_internal_key = internal
    assert satisfaction_sizer([internal])(psbt_in, tx_in) == [65]


def test_a_leaf_the_keys_do_not_satisfy_leaves_the_others_to_size() -> None:
    """X[1] satisfies the quorum leaf alone, whichever leaf is read first."""
    text = f"tr({NUMS},{{pk({X[0]}),multi_a(1,{X[0]},{X[1]},{X[2]})}})"
    psbt, _, descriptor = tr_psbt(text, NO_LOCK, 0)
    psbt_in, tx_in = psbt.inputs[0], psbt.tx.vin[0]
    quorum = descriptor.taproot_tree(0)[1][2]
    records = psbt_in.taproot_leaf_scripts
    (control_block,) = (cb for cb, (s, _) in records.items() if s == quorum)
    for order in (records, dict(reversed(records.items()))):
        psbt_in.taproot_leaf_scripts = order
        sizes = satisfaction_sizer([X[1]])(psbt_in, tx_in)
        assert sizes is not None
        assert sizes[-2:] == [len(quorum), len(control_block)]
