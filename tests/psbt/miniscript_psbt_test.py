# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the psbt roles over a BIP379 miniscript.

`miniscript_solver`, which `finalize` takes for a witness script that is a
miniscript, `miniscript_sizer` and `satisfaction_sizer`, which
`estimated_input_sizes` takes for the same inputs, and the Updater over a
miniscript descriptor.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

import pytest
from btclib.alias import Octets
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160, sha256
from btclib.key import PrvKeyData, PubKeyData
from btclib.script import sig_hash
from btclib.script.engine import verify_transaction
from btclib.script.script import serialize
from btclib.script.script_pub_key import ScriptPubKey
from btclib.script.taproot import leaf_hash
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx
from btclib.tx.tx_in import TxIn
from btclib.tx.tx_out import TxOut
from ecc import dsa, ssa
from ecc.curves import bytes_from_point, point_from_pub_key

from btclib_wallet.bip32.key_origin import BIP32KeyOrigin
from btclib_wallet.descriptors import WshDescriptor
from btclib_wallet.descriptors import parse as parse_descriptor
from btclib_wallet.descriptors.miniscript import (
    P2WSH,
    TAPSCRIPT,
    Miniscript,
    SpendContext,
    from_script,
    parse,
)
from btclib_wallet.psbt.psbt import Psbt, finalize, miniscript_solver, taproot_sig_hash
from btclib_wallet.psbt.psbt_in import PsbtIn
from btclib_wallet.psbt.psbt_size import (
    SIG_SIZE,
    estimated_input_sizes,
    miniscript_sizer,
    satisfaction_sizer,
)
from btclib_wallet.psbt.psbt_updater import update_psbt_output
from tests import vector_id

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
    node: Miniscript | bytes, keys: list[str], locktime: int, sequence: int
) -> tuple[Psbt, list[TxOut]]:
    """Return a psbt spending a p2wsh miniscript, or a script, signed by `keys`.

    What an Updater would write is set by hand: the witness script and the
    preimages, which the solver reads from the input.
    """
    script = node if isinstance(node, bytes) else node.script()
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


UNKNOWN_KEY = "input 0: no public key for a hash160 the script holds"


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


def exactly(message: str) -> str:
    """Return the pattern `pytest.raises` matches against this message alone."""
    return f"^{re.escape(message)}$"


def named_in_another_form(
    expression: str, field: str, key: bytes
) -> tuple[Psbt, list[TxOut]]:
    """Return a psbt of the expression, its pk_h() of `KEYS[1]` hashing `key`.

    `key` is the point of `KEYS[1]` in a form no P2WSH holds, and the input
    names it in `field`: in hd_key_paths, or in partial_sigs with its
    signature. `KEYS[0]` signs.
    """
    script = parse(expression).script()
    script = script.replace(hash160(bytes.fromhex(KEYS[1])), hash160(key))
    psbt, prevouts = signed_psbt(script, [KEYS[0]], 499999999, 0x0000FFFF)
    psbt_in = psbt.inputs[0]
    if field == "hd_key_paths":
        psbt_in.hd_key_paths = {key: BIP32KeyOrigin("deadbeef", [0])}
    else:
        msg_hash = sig_hash.segwit_v0(script, psbt.tx, 0, 1, prevouts[0].value)
        signature = dsa.sign_(msg_hash, PRV_KEYS[1]).serialize() + b"\x01"
        psbt_in.partial_sigs[key] = signature
    return psbt, prevouts


UNCOMPRESSED = bytes_from_point(point_from_pub_key(KEYS[1]), compressed=False)
# the same point in the hybrid encoding, whose prefix gives the parity of y
HYBRID = bytes([6 + UNCOMPRESSED[64] % 2]) + UNCOMPRESSED[1:]
# a hybrid key is no key of partial_sigs, which `Psbt.assert_valid` refuses
OTHER_FORMS = [
    pytest.param("hd_key_paths", UNCOMPRESSED, "uncompressed", id="paths-uncompressed"),
    pytest.param("partial_sigs", UNCOMPRESSED, "uncompressed", id="sigs-uncompressed"),
    pytest.param("hd_key_paths", HYBRID, "65 bytes", id="paths-hybrid"),
]


@pytest.mark.parametrize("field, key, fault", OTHER_FORMS)
def test_a_key_the_input_names_in_another_form_is_read_as_core_signs(
    field: str, key: bytes, fault: str
) -> None:
    """Finalize a spend that runs no pk_h() of a key the input names so.

    Bitcoin Core's signer reads whatever key a signing provider answers
    for a hash, as the solver does, and finalizes this pk() branch, whose
    witness pushes nothing of the pk_h() key. `from_script` refuses the
    same script read with the same key, as Core's descriptor inference
    does.
    """
    expression = f"or_d(pk({KEYS[0]}),and_v(v:pkh({KEYS[1]}),older(1008)))"
    psbt, prevouts = named_in_another_form(expression, field, key)
    final = finalize(psbt, solver=miniscript_solver)
    witness = final.inputs[0].final_script_witness
    assert key not in witness.stack
    spending = final.tx
    spending.vin[0].script_witness = witness
    verify_transaction(prevouts, spending)
    message = f"not a P2WSH public key for a hash160 the script holds: {fault}"
    with pytest.raises(BTClibValueError, match=exactly(message)):
        from_script(witness.stack[-1], P2WSH, {hash160(key): key})


@pytest.mark.parametrize("field, key, fault", OTHER_FORMS)
def test_a_witness_pushing_a_key_named_in_another_form_is_refused(
    field: str, key: bytes, fault: str
) -> None:
    """Refuse a spend that runs the pk_h() of a key the input names so.

    Bitcoin Core verifies the witness it built under the standard flags,
    whose WITNESS_PUBKEYTYPE refuses that key to a P2WSH CHECKSIG, and
    leaves the input unfinalized; the solver refuses it by name. The
    pk_h() is dissatisfied here, which pushes its key too.
    """
    expression = f"or_d(pkh({KEYS[1]}),pk({KEYS[0]}))"
    psbt, _ = named_in_another_form(expression, field, key)
    message = f"input 0: not a P2WSH public key for a hash160 the script holds: {fault}"
    with pytest.raises(BTClibValueError, match=exactly(message)):
        finalize(psbt, solver=miniscript_solver)


@pytest.mark.parametrize("field, key, fault", OTHER_FORMS)
def test_the_sizers_read_a_key_named_in_another_form_as_the_solver(
    field: str, key: bytes, fault: str
) -> None:
    """Size the spend the solver builds, and none of the one it refuses.

    `miniscript_sizer` sizes every branch, the pk_h() one that pushes the
    key included; `satisfaction_sizer` sizes the branch the signers open,
    and answers None where that pushes the key.
    """
    spent, _ = named_in_another_form(
        f"or_d(pk({KEYS[0]}),and_v(v:pkh({KEYS[1]}),older(1008)))", field, key
    )
    psbt_in, tx_in = spent.inputs[0], spent.tx.vin[0]
    stack = (
        finalize(spent, solver=miniscript_solver).inputs[0].final_script_witness.stack
    )
    # the pk() branch: a signature of the allowance a sizer assumes, then
    # the script
    script = stack[-1]
    assert len(stack) == 2
    assert satisfaction_sizer([KEYS[0]])(psbt_in, tx_in) == [SIG_SIZE, len(script)]
    # the largest is the pk_h() branch: its signature and key, the empty
    # push dissatisfying the pk(), then the script
    largest = [SIG_SIZE, len(key), 0, len(script)]
    assert miniscript_sizer(psbt_in, tx_in) == largest
    refused, _ = named_in_another_form(
        f"or_d(pkh({KEYS[1]}),pk({KEYS[0]}))", field, key
    )
    assert satisfaction_sizer([KEYS[0]])(refused.inputs[0], refused.tx.vin[0]) is None


def near_tie(wrappers: int, lengths: tuple[int, int, int], signed: bool) -> Psbt:
    """Return a psbt of A and B, or U behind `wrappers` or_i(...,0).

    The script is ``or_i(and_v(v:pk(A),pk(B)),pkh(U))``, the ``pkh()``
    under the wrappers and its key U the uncompressed point of `KEYS[1]`.
    The signatures of A, B and U have `lengths`, U's left out where
    `signed` is False, U then being named by its origin: the satisfier
    reads their lengths alone, which is what chooses between the two
    branches, so filler bytes stand in for them.
    """
    right = f"pkh({KEYS[1]})"
    for _ in range(wrappers):
        right = f"or_i({right},0)"
    expression = f"or_i(and_v(v:pk({KEYS[0]}),pk({KEYS[2]})),{right})"
    script = parse(expression).script()
    script = script.replace(hash160(bytes.fromhex(KEYS[1])), hash160(UNCOMPRESSED))
    psbt, _ = signed_psbt(script, [], 499999999, 0x0000FFFF)
    psbt_in = psbt.inputs[0]
    signers = [bytes.fromhex(KEYS[0]), bytes.fromhex(KEYS[2]), UNCOMPRESSED]
    psbt_in.partial_sigs = {
        key: b"\x30" * (length - 1) + b"\x01"
        for key, length in zip(signers, lengths, strict=True)
        if signed or key != UNCOMPRESSED
    }
    if not signed:
        psbt_in.hd_key_paths = {UNCOMPRESSED: BIP32KeyOrigin("deadbeef", [0])}
    return psbt


def assert_bounds(sizes: list[int] | None, stack: Sequence[bytes]) -> None:
    """Assert an estimate of the same elements, none smaller than built."""
    assert sizes is not None
    assert len(sizes) == len(stack)
    assert all(len(element) <= size for element, size in zip(stack, sizes, strict=True))


def test_the_sizer_sizes_the_spend_the_solver_builds_on_a_near_tie() -> None:
    """Size the A and B branch the solver takes where the fillers choose U's.

    The signatures of A, B and U are 71, 70 and 71 bytes long: with them
    the solver, as Bitcoin Core, takes the A and B branch, while the
    `SIG_SIZE` fillers make U's the smaller. The sizer then sizes the
    spend built without U's signature, which is the solver's.
    """
    keys: list[Octets] = [KEYS[0], KEYS[2], UNCOMPRESSED]
    psbt = near_tie(3, (71, 70, 71), signed=True)
    solved = miniscript_solver(psbt, 0)
    assert solved is not None
    stack = solved[1].stack
    assert UNCOMPRESSED not in stack
    sizes = satisfaction_sizer(keys)(psbt.inputs[0], psbt.tx.vin[0])
    assert sizes == [SIG_SIZE, SIG_SIZE, 1, len(stack[-1])]
    assert_bounds(sizes, stack)


def test_the_sizer_sizes_the_spend_without_the_key_the_solver_refuses() -> None:
    """Size the A and B branch where the real lengths make U's the smaller.

    The signatures of A, B and U are 71, 72 and 70 bytes long: the solver,
    as Bitcoin Core, takes U's branch and refuses it, while the fillers
    choose the A and B branch. That is the spend the solver builds once
    U's signature is withheld, and the one the sizer sizes.
    """
    keys: list[Octets] = [KEYS[0], KEYS[2], UNCOMPRESSED]
    psbt = near_tie(4, (71, 72, 70), signed=True)
    message = (
        "input 0: not a P2WSH public key for a hash160 the script holds: uncompressed"
    )
    with pytest.raises(BTClibValueError, match=exactly(message)):
        miniscript_solver(psbt, 0)
    sizes = satisfaction_sizer(keys)(psbt.inputs[0], psbt.tx.vin[0])
    withheld = miniscript_solver(near_tie(4, (71, 72, 70), signed=False), 0)
    assert withheld is not None
    assert_bounds(sizes, withheld[1].stack)


def test_a_witness_satisfying_a_key_named_uncompressed_is_refused() -> None:
    """Refuse a spend whose signature is the one of the uncompressed key."""
    expression = f"and_v(v:pk({KEYS[0]}),pkh({KEYS[1]}))"
    psbt, _ = named_in_another_form(expression, "partial_sigs", UNCOMPRESSED)
    message = (
        "input 0: not a P2WSH public key for a hash160 the script holds: uncompressed"
    )
    with pytest.raises(BTClibValueError, match=exactly(message)):
        finalize(psbt, solver=miniscript_solver)


def test_a_key_of_no_sec_form_set_after_the_psbt_is_built_is_refused() -> None:
    """Refuse a pk_h() key of 65 bytes and no SEC prefix the input names.

    `miniscript_solver` reads the psbt it is handed without validating it,
    which `finalize` does first: a key assigned to hd_key_paths after the
    input was built reaches it. The solver reads an uncompressed or a
    hybrid key as Core's signer does, and no other 65 bytes, which Core's
    psbt parser refuses as a key.
    """
    expression = f"or_d(pk({KEYS[0]}),and_v(v:pkh({KEYS[1]}),older(1008)))"
    no_key = b"\x05" + UNCOMPRESSED[1:]
    psbt, _ = named_in_another_form(expression, "hd_key_paths", no_key)
    message = "input 0: not a P2WSH public key for a hash160 the script holds: 65 bytes"
    with pytest.raises(BTClibValueError, match=exactly(message)):
        miniscript_solver(psbt, 0)
    with pytest.raises(
        BTClibValueError, match=exactly("invalid public key: not a point")
    ):
        finalize(psbt, solver=miniscript_solver)


# 5**3 + 7 is no square modulo p, so no point of the curve has 5 as its x
OFF_CURVE = b"\x02" + (5).to_bytes(32, "big")


def test_a_key_of_the_p2wsh_form_that_is_no_point_is_spent_around() -> None:
    """Finalize a branch that needs nothing of a pushed key that is no point.

    Bitcoin Core's decoder reads the key, as `from_script` does, and its
    ``finalizepsbt`` completes both spends signed by A; whether decoding
    should refuse such a key is ISS btclib-org/btclib-wallet#977.
    """
    key = bytes.fromhex(KEYS[0])
    for script in (
        serialize(["OP_1", key, OFF_CURVE, "OP_2", "OP_CHECKMULTISIG"]),
        serialize(
            [
                key,
                "OP_CHECKSIG",
                "OP_IFDUP",
                "OP_NOTIF",
                OFF_CURVE,
                "OP_CHECKSIG",
                "OP_ENDIF",
            ]
        ),
    ):
        psbt, prevouts = signed_psbt(script, [KEYS[0]], 0, 0xFFFFFFFF)
        # the solver's spend, and not a guess `finalize` builds after a None
        assert miniscript_solver(psbt, 0) is not None
        final = finalize(psbt, solver=miniscript_solver)
        spending = final.tx
        spending.vin[0].script_witness = final.inputs[0].final_script_witness
        verify_transaction(prevouts, spending)


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
    assert miniscript_sizer(psbt_in, tx_in) is not None
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
