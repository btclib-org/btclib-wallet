# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the psbt roles over a BIP379 miniscript.

`miniscript_solver`, which `finalize` takes for a witness script or a
taproot leaf script that is a miniscript, `miniscript_sizer` and
`satisfaction_sizer`, which `estimated_input_sizes` takes for a witness
script that is one, and the Updater over a miniscript descriptor.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

import pytest
from btclib.alias import Octets
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160, sha256
from btclib.key import PrvKeyData, PubKeyData
from btclib.script import Witness, sig_hash
from btclib.script.engine import verify_transaction
from btclib.script.limits import MAX_SCRIPT_SIZE
from btclib.script.script import op_code_spans, serialize
from btclib.script.script_pub_key import ScriptPubKey
from btclib.script.taproot import leaf_hash, output_prvkey_from_merkle_root
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx
from btclib.tx.tx_in import TxIn
from btclib.tx.tx_out import TxOut
from ecc import dsa, ssa

from btclib_wallet.bip32.key_origin import BIP32KeyOrigin
from btclib_wallet.descriptors import TrDescriptor, WshDescriptor
from btclib_wallet.descriptors import parse as parse_descriptor
from btclib_wallet.descriptors.miniscript import (
    P2WSH,
    TAPSCRIPT,
    Miniscript,
    SpendContext,
    from_script,
    parse,
)
from btclib_wallet.descriptors.miniscript import (
    _lacks_only_keys as decoder_lacks_only_keys,
)
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
    "script, key_hashes",
    [
        pytest.param(_OR_D, _known(KEYS[0], KEYS[1]), id="lacks-one"),
        pytest.param(_OR_D, _known(), id="lacks-all"),
        pytest.param(_HASH_LOCK, _known(), id="beside-a-hash-lock"),
        pytest.param(_HASH_LOCK + serialize(["OP_DROP"]), _known(), id="no-miniscript"),
        pytest.param(serialize(["OP_DROP"]) + _PKH, _known(), id="drop-first"),
        pytest.param(bytes.fromhex("5101e4ae") + _PKH, _known(), id="multi-count"),
        pytest.param(_PKH.replace(b"\x88", b"\x87\x69"), _known(), id="split-verify"),
        pytest.param(_OR_D[:-3], _known(), id="truncated"),
        pytest.param(_OR_D[:40], _known(), id="push-past-end"),
        # a key filed under a hash that is not its own is the decoder's
        # refusal, not a missing key
        pytest.param(_PKH, {hash160(bytes.fromhex(KEYS[2])): KEYS[0]}, id="wrong-key"),
        # KEYS[0] is G, whose hash160 the first stand-in would be filed under
        pytest.param(
            parse(f"pkh({KEYS[0]})").script(),
            {hash160(bytes.fromhex(KEYS[0])): KEYS[1]},
            id="wrong-key-under-the-stand-in-hash",
        ),
        pytest.param(_OR_D, _known(KEYS[0]), id="lacks-one-beside-g"),
        # Octets admits hex strings, which from_script reads as their bytes
        pytest.param(
            _PKH, {hash160(bytes.fromhex(KEYS[2])).hex(): KEYS[0]}, id="hex-wrong-key"
        ),
        pytest.param(
            _OR_D,
            {hash160(bytes.fromhex(key)).hex(): key for key in KEYS[:2]},
            id="hex-lacks-one",
        ),
        pytest.param(_PKH, {"zz": KEYS[2]}, id="no-hex"),
    ],
)
def test_the_solver_tells_a_missing_key_as_the_decoder_does(
    script: bytes, key_hashes: dict[Octets, Octets]
) -> None:
    """`psbt` tells a missing key as `descriptors.miniscript` tells it.

    Asked where `from_script` refuses the script, which is where the solver
    asks it: whether the refusal is only for a pk_h() whose key the input
    does not name.
    """
    with pytest.raises(BTClibValueError):
        from_script(script, P2WSH, key_hashes)
    assert _lacks_only_keys(script, P2WSH, key_hashes) == decoder_lacks_only_keys(
        script, P2WSH, key_hashes
    )


def test_a_script_past_consensus_size_is_answered_before_it_is_walked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A witness script past `MAX_SCRIPT_SIZE` is no miniscript, at no walk.

    A parsed psbt can carry a witness script of any length, and both
    decoders refuse one past their own, smaller bound.
    """
    script = _PKH * (MAX_SCRIPT_SIZE // len(_PKH) + 1)
    with pytest.raises(BTClibValueError, match="script too large"):
        from_script(script, P2WSH, {})
    assert not decoder_lacks_only_keys(script, P2WSH, {})

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
    "script, key_hashes",
    [
        pytest.param(_X_OR_D, _x_known(X[0], X[1]), id="lacks-one"),
        pytest.param(_X_OR_D, _x_known(), id="lacks-all"),
        pytest.param(serialize(["OP_DROP"]) + _X_PKH, _x_known(), id="drop-first"),
        pytest.param(_X_OR_D[:-3], _x_known(), id="truncated"),
        # a SEC key is no tapscript key, whichever hash it is filed under
        pytest.param(_X_PKH, {hash160(bytes.fromhex(X[2])): KEYS[2]}, id="sec-key"),
        # X[0] is the x of G, whose hash160 the first stand-in would be
        # filed under
        pytest.param(
            parse(f"pkh({X[0]})", TAPSCRIPT).script(),
            {hash160(bytes.fromhex(X[0])): X[1]},
            id="wrong-key-under-the-stand-in-hash",
        ),
        pytest.param(_X_OR_D, _x_known(X[0]), id="lacks-one-beside-g"),
        # a script past the P2WSH bound is walked under tapscript, and is
        # a miniscript but for a key there
        pytest.param(_X_LONG, _x_known(), id="long"),
        pytest.param(
            _X_PKH * (MAX_SCRIPT_SIZE // len(_X_PKH) + 1),
            _x_known(),
            id="long-no-miniscript",
        ),
    ],
)
def test_the_solver_tells_a_missing_tapscript_key_as_the_decoder_does(
    script: bytes, key_hashes: dict[Octets, Octets]
) -> None:
    """`psbt` tells a missing x-only key as `descriptors.miniscript` does."""
    with pytest.raises(BTClibValueError):
        from_script(script, TAPSCRIPT, key_hashes)
    assert _lacks_only_keys(script, TAPSCRIPT, key_hashes) == decoder_lacks_only_keys(
        script, TAPSCRIPT, key_hashes
    )


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
