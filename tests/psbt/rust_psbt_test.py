# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Replay rust-psbt's PSBT vectors: a second implementation's reading.

rust-psbt, the `psbt-v2` crate of rust-bitcoin, publishes its cases as
JSON under `tests/data/`, each naming a task and what the task must
produce. Its runner, `tests/vectors/mod.rs`, is what says what a task
asks, and each test below asks btclib-wallet the same question.
`tests/_data/README.md` pins the files.

A psbt to parse sits in `supplementary.psbts` in most cases, and in
`expected` in the cases of `bip371.json` and in the valid ones of
`bip174.json`. Both are read here.
"""

from collections.abc import Iterator
from typing import Any

import pytest
from btclib.b58 import prv_key_data_from_wif
from btclib.network import NETWORKS
from btclib.script import ScriptPubKey
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from ecc.ecc import dsa
from typing_extensions import override

from btclib_wallet.bip32 import (
    BIP32KeyOrigin,
    derive,
    fingerprint,
    prv_keyinfo_from_xprv,
    rootxprv_from_seed,
)
from btclib_wallet.psbt import Psbt, combine, extract_tx, finalize, sign
from btclib_wallet.psbt_signer import SoftwareSigner
from tests import load, vector_id
from tests.exception_family_test import VALUE_ERRORS

FILES = ("bip174.json", "bip370.json", "bip371.json", "bip375.json", "fuzz.json")

# the tasks of rust-psbt's runner, every one of which has a role here: a
# task a refresh adds fails test_every_task_is_replayed until it has one
TASKS = frozenset(
    {
        "deserialize",
        "fail_deserialize",
        "create",
        "update",
        "trusted_sign",
        "strict_sign",
        "fail_sign",
        "fail_strict_sign",
        "combine",
        "finalize",
        "extract",
        "determine_lock_time",
        "fail_determine_lock_time",
    }
)

# BIP375's own invalid psbts. rust-psbt's file asks a parser to refuse
# BIP375's invalid psbts; btclib-wallet's codec refuses those with a field of
# the wrong shape, and `btclib_wallet.psbt.silent_payments` the rest,
# which `silent_payments_test.py` holds each of them to
_BIP375_INVALID = {
    vector["psbt"]
    for vector in load("psbt", "_data", "bip375_test_vectors.json", encoding="utf-8")[
        "invalid"
    ]
}


def _all_cases() -> Iterator[tuple[str, int, dict[str, Any]]]:
    for fname in FILES:
        for index, case in enumerate(
            load("psbt", "_data", "rust-psbt", fname)["cases"], 1
        ):
            yield fname, index, case


def cases(task: str) -> list[Any]:
    """Return the cases of one task, from every file, named by file and case."""
    return [
        pytest.param(
            case,
            id=vector_id(index, fname, case["description"]),
        )
        for fname, index, case in _all_cases()
        if case["supplementary"]["task"] == task
    ]


def _encodings(case: dict[str, Any]) -> list[dict[str, str]]:
    """Every psbt a (fail_)deserialize case gives, wherever it gives it."""
    found = list(case["supplementary"].get("psbts") or [])
    if case.get("expected"):
        found.append(case["expected"])
    return found


def _inputs(case: dict[str, Any]) -> list[Psbt]:
    return [
        Psbt.parse(bytes.fromhex(encoding["hex"]))
        for encoding in case["supplementary"]["psbts"]
    ]


def _input(case: dict[str, Any]) -> Psbt:
    (psbt,) = _inputs(case)
    return psbt


def _expected(case: dict[str, Any]) -> Psbt:
    return Psbt.parse(bytes.fromhex(case["expected"]["hex"]))


def test_every_task_is_replayed() -> None:
    """A task this module has no test for is a case nothing runs."""
    tasks = {case["supplementary"]["task"] for _, _, case in _all_cases()}
    assert tasks == TASKS


@pytest.mark.parametrize("case", cases("deserialize"))
def test_deserialize(case: dict[str, Any]) -> None:
    """Each valid psbt is read, the same from hex as from base64."""
    encodings = _encodings(case)
    assert encodings
    for encoding in encodings:
        psbt = Psbt.b64decode(encoding["base64"])
        if encoding["hex"]:
            assert Psbt.parse(bytes.fromhex(encoding["hex"])) == psbt
        assert Psbt.parse(psbt.serialize()) == psbt


def _refused(encoding: dict[str, str]) -> bool:
    """Whether the codec refuses a psbt, the same from hex as from base64.

    The hex is empty in the cases of `bip375.json`, and not read there.
    """
    try:
        Psbt.b64decode(encoding["base64"])
    except VALUE_ERRORS:
        if encoding["hex"]:
            with pytest.raises(VALUE_ERRORS):
                Psbt.parse(bytes.fromhex(encoding["hex"]))
        return True
    return False


@pytest.mark.parametrize("case", cases("fail_deserialize"))
def test_fail_deserialize(case: dict[str, Any]) -> None:
    """Each invalid psbt is refused, by the codec or by a silent payment role.

    rust-psbt's file asks a parser to refuse what BIP375's roles refuse.
    Here the codec refuses a field of the wrong shape, and what only a
    role can judge is left to that role: such a psbt has to be one of
    BIP375's own invalid ones, whose refusal `silent_payments_test.py`
    asserts.
    """
    encodings = _encodings(case)
    assert encodings
    for encoding in encodings:
        assert _refused(encoding) or encoding["base64"] in _BIP375_INVALID


@pytest.mark.parametrize("case", cases("create"))
def test_create(case: dict[str, Any]) -> None:
    """The Creator: version 2, lock time 0, every sequence final."""
    supplementary = case["supplementary"]
    tx_ins = []
    for outpoint in supplementary["inputs"]:
        tx_id, vout = outpoint.split(":")
        tx_ins.append(TxIn(OutPoint(tx_id, int(vout)), b"", 0xFFFFFFFF))
    tx_outs = [
        TxOut(output["value"], ScriptPubKey(output["script_pubkey"]))
        for output in supplementary["outputs"]
    ]
    psbt = Psbt.from_tx(Tx(2, 0, tx_ins, tx_outs))
    assert psbt.serialize().hex() == case["expected"]["hex"]


def _master(supplementary: dict[str, Any]) -> str:
    """Return the case's xprv, checked against the seed it is derived from."""
    xprv: str = supplementary["xpriv"]
    if supplementary.get("seed"):
        seed = prv_key_data_from_wif(supplementary["seed"]).q.to_bytes(32, "big")
        assert rootxprv_from_seed(seed, NETWORKS["testnet"].bip32_prv) == xprv
    return xprv


def _origins(derivations: list[dict[str, str]], master_fingerprint: bytes) -> Any:
    return {
        bytes.fromhex(d["key"]): BIP32KeyOrigin(master_fingerprint, d["path"])
        for d in derivations
    }


@pytest.mark.parametrize("case", cases("update"))
def test_update(case: dict[str, Any]) -> None:
    """The Updater: utxos, scripts and key origins, or a sig_hash type.

    An input update names its input by the transaction it spends from,
    and installs the output it spends as the witness utxo or the whole
    transaction as the non-witness utxo, as rust-psbt's runner does.
    """
    supplementary = case["supplementary"]
    psbt = _input(case)
    master_fingerprint = fingerprint(_master(supplementary))
    for update in supplementary.get("input_updates", []):
        prev_tx = Tx.parse(bytes.fromhex(update["previous_tx"]))
        psbt_in = next(p for p in psbt.inputs if p.previous_tx_id == prev_tx.id)
        assert psbt_in.output_index is not None
        if update.get("witness"):
            psbt_in.witness_utxo = prev_tx.vout[psbt_in.output_index]
        else:
            psbt_in.non_witness_utxo = prev_tx
        # an absent script is the empty one, which is what an input with
        # none carries
        psbt_in.redeem_script = bytes.fromhex(update.get("redeem_script", ""))
        psbt_in.witness_script = bytes.fromhex(update.get("witness_script", ""))
        psbt_in.hd_key_paths |= _origins(
            update.get("bip32_derivation", []), master_fingerprint
        )
    for psbt_out, update in zip(
        psbt.outputs, supplementary.get("output_updates", []), strict=False
    ):
        psbt_out.hd_key_paths |= _origins(
            update.get("bip32_derivation", []), master_fingerprint
        )
    if supplementary.get("sighash"):
        assert supplementary["sighash"] == "SIGHASH_ALL"
        for psbt_in in psbt.inputs:
            psbt_in.sig_hash_type = 1
    psbt.assert_valid()
    assert psbt == _expected(case)


class _KeyManager(SoftwareSigner):
    """The case's xprv, signing with the keys the case lists and no other.

    Each key is checked against the xprv and the path given beside it,
    and ECDSA signs with RFC6979 nonces and no low-R grinding, as
    BIP174's own signers did.
    """

    def __init__(self, supplementary: dict[str, Any]) -> None:
        xprv = _master(supplementary)
        super().__init__(xprv)
        self.prv_keys: dict[bytes, int] = {}
        for item in supplementary["private_keys"]:
            prv_key = prv_key_data_from_wif(item["key"])
            assert prv_keyinfo_from_xprv(derive(xprv, item["path"]))[0] == prv_key.q
            self.prv_keys[prv_key.pub.sec] = prv_key.q

    @override
    def sign_ecdsa(
        self, pub_key: bytes, origin: BIP32KeyOrigin | None, msg_hash: bytes
    ) -> bytes | None:
        """Return the signature of a key the case lists, or None."""
        del origin
        prv_key = self.prv_keys.get(pub_key)
        if prv_key is None:
            return None
        return dsa.sign_(msg_hash, prv_key, grind=False).serialize()


@pytest.mark.parametrize("case", cases("trusted_sign"))
def test_trusted_sign(case: dict[str, Any]) -> None:
    """The Signer, taking each input's witness utxo on trust."""
    signed, _ = sign(
        _input(case),
        _KeyManager(case["supplementary"]),
        require_non_witness_utxo=False,
    )
    assert signed == _expected(case)


@pytest.mark.parametrize("case", cases("strict_sign"))
def test_strict_sign(case: dict[str, Any]) -> None:
    """The Signer, asking every input for the transaction it spends from."""
    signed, _ = sign(_input(case), _KeyManager(case["supplementary"]))
    assert signed == _expected(case)


@pytest.mark.parametrize("case", cases("fail_sign"))
def test_fail_sign(case: dict[str, Any]) -> None:
    """BIP174's signer checks: refused before any key is asked."""
    psbt = _input(case)
    assert psbt == Psbt.b64decode(case["supplementary"]["psbts"][0]["base64"])
    with pytest.raises(VALUE_ERRORS):
        psbt.assert_signable(require_non_witness_utxo=False)


@pytest.mark.parametrize("case", cases("fail_strict_sign"))
def test_fail_strict_sign(case: dict[str, Any]) -> None:
    """Refused for the missing non-witness utxo, and for nothing else."""
    psbt = _input(case)
    psbt.assert_signable(require_non_witness_utxo=False)
    with pytest.raises(VALUE_ERRORS, match="no non_witness_utxo"):
        psbt.assert_signable()


@pytest.mark.parametrize("case", cases("combine"))
def test_combine(case: dict[str, Any]) -> None:
    """The Combiner, in either order."""
    psbts = _inputs(case)
    assert combine(psbts) == _expected(case)
    assert combine(psbts[::-1]) == _expected(case)


@pytest.mark.parametrize("case", cases("finalize"))
def test_finalize(case: dict[str, Any]) -> None:
    """The Input Finalizer, compared on the wire, which drops what it spent."""
    finalized = finalize(_input(case))
    assert Psbt.parse(finalized.serialize()) == _expected(case)


@pytest.mark.parametrize("case", cases("extract"))
def test_extract(case: dict[str, Any]) -> None:
    """The Transaction Extractor, byte for byte."""
    tx = extract_tx(_input(case))
    assert tx.serialize(include_witness=True).hex() == case["supplementary"]["tx"]


@pytest.mark.parametrize("case", cases("determine_lock_time"))
def test_determine_lock_time(case: dict[str, Any]) -> None:
    """BIP370's lock time algorithm, over every psbt the case gives."""
    for encoding in case["supplementary"]["psbts"]:
        psbt = Psbt.parse(bytes.fromhex(encoding["hex"]))
        assert psbt == Psbt.b64decode(encoding["base64"])
        assert psbt.lock_time == case["supplementary"]["expected_lock_time"]


@pytest.mark.parametrize("case", cases("fail_determine_lock_time"))
def test_fail_determine_lock_time(case: dict[str, Any]) -> None:
    """No lock time satisfies every input: the psbt is refused for it."""
    for encoding in case["supplementary"]["psbts"]:
        with pytest.raises(VALUE_ERRORS, match="no lock time satisfies every input"):
            Psbt.parse(bytes.fromhex(encoding["hex"]))
        psbt = Psbt.b64decode(encoding["base64"], check_validity=False)
        with pytest.raises(VALUE_ERRORS, match="no lock time satisfies every input"):
            psbt.assert_valid()
