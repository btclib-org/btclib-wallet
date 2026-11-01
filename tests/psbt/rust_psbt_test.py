# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Replay rust-psbt's PSBT vectors: a second implementation's reading.

rust-psbt, the `psbt-v2` crate of rust-bitcoin, publishes its cases as
JSON under `tests/data/`, each naming a task and what the task must
produce. Its runner, `tests/vectors/mod.rs`, is what says what a task
asks, and each test below asks btclib-wallet the same question.
`tests/_data/README.md` pins the files.
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


def _all_cases() -> Iterator[tuple[str, int, str, str, dict[str, Any]]]:
    """Yield each case's file, index, description, task and task data.

    A case's `task` object has one key, the task's name, holding what the
    task reads and what it must produce: the psbts in `psbts`, or in
    `psbt` for a role taking one, and the psbt the task produces in
    `expected`. A psbt is read from its base64, the only encoding the
    files give.
    """
    for fname in FILES:
        for index, case in enumerate(
            load("psbt", "_data", "rust-psbt", fname)["cases"], 1
        ):
            ((task, data),) = case["task"].items()
            yield fname, index, case["description"], task, data


def cases(task: str) -> list[Any]:
    """Return the data of one task, from every file, named by file and case."""
    return [
        pytest.param(data, id=vector_id(index, fname, description))
        for fname, index, description, name, data in _all_cases()
        if name == task
    ]


def _psbt(encoding: dict[str, str]) -> Psbt:
    return Psbt.b64decode(encoding["base64"])


def _inputs(case: dict[str, Any]) -> list[Psbt]:
    return [_psbt(encoding) for encoding in case["psbts"]]


def _input(case: dict[str, Any]) -> Psbt:
    return _psbt(case["psbt"])


def _expected(case: dict[str, Any]) -> Psbt:
    return _psbt(case["expected"])


def test_every_task_is_replayed() -> None:
    """A task this module has no test for is a case nothing runs."""
    tasks = {task for _, _, _, task, _ in _all_cases()}
    assert tasks == TASKS


@pytest.mark.parametrize("case", cases("deserialize"))
def test_deserialize(case: dict[str, Any]) -> None:
    """Each valid psbt is read, and read back from what it serializes to."""
    psbts = _inputs(case)
    assert psbts
    for psbt in psbts:
        assert Psbt.parse(psbt.serialize()) == psbt


def _refused(encoding: dict[str, str]) -> bool:
    """Whether the codec refuses a psbt."""
    try:
        _psbt(encoding)
    except VALUE_ERRORS:
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
    assert case["psbts"]
    for encoding in case["psbts"]:
        assert _refused(encoding) or encoding["base64"] in _BIP375_INVALID


@pytest.mark.parametrize("case", cases("create"))
def test_create(case: dict[str, Any]) -> None:
    """The Creator: version 2, lock time 0, every sequence final."""
    tx_ins = []
    for outpoint in case["inputs"]:
        tx_id, vout = outpoint.split(":")
        tx_ins.append(TxIn(OutPoint(tx_id, int(vout)), b"", 0xFFFFFFFF))
    tx_outs = [
        TxOut(output["value"], ScriptPubKey(output["script_pubkey"]))
        for output in case["outputs"]
    ]
    psbt = Psbt.from_tx(Tx(2, 0, tx_ins, tx_outs))
    assert psbt.b64encode() == case["expected"]["base64"]


def _master(case: dict[str, Any]) -> str:
    """Return the case's xprv, checked against the seed it is derived from."""
    xprv: str = case["xpriv"]
    if case.get("seed"):
        seed = prv_key_data_from_wif(case["seed"]).q.to_bytes(32, "big")
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
    psbt = _input(case)
    master_fingerprint = fingerprint(_master(case))
    for update in case.get("input_updates", []):
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
        psbt.outputs, case.get("output_updates", []), strict=False
    ):
        psbt_out.hd_key_paths |= _origins(
            update.get("bip32_derivation", []), master_fingerprint
        )
    if case.get("sighash"):
        assert case["sighash"] == "SIGHASH_ALL"
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

    def __init__(self, case: dict[str, Any]) -> None:
        xprv = _master(case)
        super().__init__(xprv)
        self.prv_keys: dict[bytes, int] = {}
        for item in case["private_keys"]:
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
        _KeyManager(case),
        require_non_witness_utxo=False,
    )
    assert signed == _expected(case)


@pytest.mark.parametrize("case", cases("strict_sign"))
def test_strict_sign(case: dict[str, Any]) -> None:
    """The Signer, asking every input for the transaction it spends from."""
    signed, _ = sign(_input(case), _KeyManager(case))
    assert signed == _expected(case)


@pytest.mark.parametrize("case", cases("fail_sign"))
def test_fail_sign(case: dict[str, Any]) -> None:
    """BIP174's signer checks: refused before any key is asked."""
    with pytest.raises(VALUE_ERRORS):
        _input(case).assert_signable(require_non_witness_utxo=False)


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
    assert tx.serialize(include_witness=True).hex() == case["tx"]


@pytest.mark.parametrize("case", cases("determine_lock_time"))
def test_determine_lock_time(case: dict[str, Any]) -> None:
    """BIP370's lock time algorithm, over every psbt the case gives."""
    for psbt in _inputs(case):
        assert psbt.lock_time == case["expected_lock_time"]


@pytest.mark.parametrize("case", cases("fail_determine_lock_time"))
def test_fail_determine_lock_time(case: dict[str, Any]) -> None:
    """No lock time satisfies every input: the psbt is refused for it."""
    for encoding in case["psbts"]:
        with pytest.raises(VALUE_ERRORS, match="no lock time satisfies every input"):
            _psbt(encoding)
        psbt = Psbt.b64decode(encoding["base64"], check_validity=False)
        with pytest.raises(VALUE_ERRORS, match="no lock time satisfies every input"):
            psbt.assert_valid()
