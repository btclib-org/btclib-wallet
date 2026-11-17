# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Bitcoin Core's psbts of the policies `recovery_descriptors` writes.

`tests/psbt/_data/core/recovery_psbts.json` holds them, as
`tests/integration/record_recovery_psbts_test.py` records them: for each
policy, under ``wsh()`` and ``tr()``, the descriptors Core imported, and
for each path the psbt Core funded, signed and finalized, and the
transaction it extracted. `tests/_data/README.md` pins the recording.

Each is read here by this package's own roles. The descriptors are the
ones the policy gives. Each psbt is written back with Core's pairs, and
the final one with Core's bytes. Our signers sign Core's psbt with the
same keys Core signed with, and `finalize` builds Core's spend from
Core's signatures, which the script engine accepts with ours too. A
ledger restored from the policy's BIP139 account watches Core's coin.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from bip32_descriptors.bip32.bip32 import (
    derive,
    fingerprint,
    rootxprv_from_seed,
    xpub_from_xprv,
)
from bip32_descriptors.descriptors import Descriptor, add_checksum
from btclib.network import NETWORKS
from btclib.script.engine import verify_transaction

from btclib_wallet import bip139
from btclib_wallet.ledger import Ledger
from btclib_wallet.psbt import Psbt
from btclib_wallet.psbt.psbt import (
    assert_signatures_only,
    extract_tx,
    finalize,
    miniscript_solver,
    prevouts,
)
from btclib_wallet.psbt_signer import SoftwareSigner
from btclib_wallet.recovery_paths import recovery_descriptors
from tests import load
from tests.ledger.conftest import FakeChain
from tests.psbt import psbt_maps

# the path of each signer's account, from its master key
ACCOUNT = "m/48h/1h/0h/2h"


def root(signer: int) -> str:
    """Return a signer's master key: its seed is the byte ``signer + 1``.

    Sixteen times, on regtest, and published nowhere: these are keys a
    test may sign with.
    """
    seed = bytes([signer + 1]) * 16
    return rootxprv_from_seed(seed, NETWORKS["regtest"].bip32_prv)


def account_key(signer: int) -> str:
    """Return a signer's account key, with its origin, as a policy names it."""
    master = root(signer)
    xpub = xpub_from_xprv(derive(master, ACCOUNT))
    return f"[{fingerprint(master).hex()}{ACCOUNT[1:]}]{xpub}"


def policy_descriptors(case: dict[str, Any]) -> tuple[Descriptor, Descriptor]:
    """Return the receive and change descriptors of a recorded policy.

    The policy names its signers by number, and `account_key` gives the
    key of each.
    """
    primary = [
        (threshold, [account_key(s) for s in signers])
        for threshold, signers in case["primary"]
    ]
    recovery = [
        (threshold, [account_key(s) for s in signers], blocks)
        for threshold, signers, blocks in case["recovery"]
    ]
    return recovery_descriptors(
        primary, recovery, "regtest", script_type=case["script_type"]
    )


def assert_core_lists_the_policy_descriptors(case: dict[str, Any]) -> None:
    """Core lists the descriptors the policy gives, checksums included."""
    receive, change = policy_descriptors(case)
    listed = sorted(entry["desc"] for entry in case["listdescriptors"])
    assert listed == sorted([add_checksum(str(receive)), add_checksum(str(change))])


def assert_each_psbt_reads_back(case: dict[str, Any], path: int) -> None:
    """Each psbt is written back with Core's pairs, the final one byte for byte.

    And the funded psbt spends the coin of the policy's receive
    descriptor, at the sequence the path asks.
    """
    recorded = case["paths"][path]
    for name in ("unsigned", "signed", "final"):
        psbt = Psbt.b64decode(recorded[name])
        assert psbt_maps(psbt.b64encode()) == psbt_maps(recorded[name])
    assert Psbt.b64decode(recorded["final"]).b64encode() == recorded["final"]
    unsigned = Psbt.b64decode(recorded["unsigned"])
    receive, _ = policy_descriptors(case)
    (spent,) = prevouts(unsigned)
    # the bytes: a psbt names no network, so it reads as mainnet's
    assert spent.script_pub_key.script == receive.script_pub_key(case["index"]).script
    assert unsigned.tx.vin[0].sequence == recorded["sequence"]


def our_signatures(case: dict[str, Any], path: int) -> Psbt:
    """Return Core's funded psbt, signed by our signers of the path."""
    psbt = Psbt.b64decode(case["paths"][path]["unsigned"])
    for signer in case["paths"][path]["signers"]:
        # the input's previous transaction is there only under wsh(): a
        # taproot signature commits to every amount spent instead
        psbt = SoftwareSigner(root(signer)).sign_psbt(
            psbt, require_non_witness_utxo=False
        )
    return psbt


def assert_we_sign_what_core_signed(case: dict[str, Any], path: int) -> None:
    """Our signers sign with the keys Core did, and ECDSA's bytes are Core's.

    Both make the deterministic, low-R ECDSA signature. A Schnorr
    signature of either takes auxiliary random bytes, so there the keys
    and leaves are compared, and each signature of either is verified.
    """
    unsigned = Psbt.b64decode(case["paths"][path]["unsigned"])
    signed = Psbt.b64decode(case["paths"][path]["signed"])
    assert_signatures_only(unsigned, our_signatures(case, path))
    assert_signatures_only(unsigned, signed)
    ours = our_signatures(case, path).inputs[0]
    cores = signed.inputs[0]
    assert ours.partial_sigs == cores.partial_sigs
    assert set(ours.taproot_script_spend_signatures) == set(
        cores.taproot_script_spend_signatures
    )
    assert bool(ours.taproot_key_spend_signature) == bool(
        cores.taproot_key_spend_signature
    )


def assert_we_finalize_cores_spend(case: dict[str, Any], path: int) -> None:
    """Core's signatures finalize to Core's final psbt and transaction."""
    recorded = case["paths"][path]
    final = finalize(Psbt.b64decode(recorded["signed"]), solver=miniscript_solver)
    assert final.b64encode() == recorded["final"]
    assert extract_tx(final).serialize(include_witness=True).hex() == recorded["tx"]


def assert_our_signatures_spend(case: dict[str, Any], path: int) -> None:
    """Our signatures finalize to a spend the script engine accepts."""
    final = finalize(our_signatures(case, path), solver=miniscript_solver)
    tx = final.tx
    tx.vin[0].script_witness = final.inputs[0].final_script_witness
    verify_transaction(prevouts(final), tx)


def check_case(case: dict[str, Any]) -> None:
    """Run the checks of this module on a case, as the recorder records one."""
    assert_core_lists_the_policy_descriptors(case)
    for path in range(len(case["paths"])):
        assert_each_psbt_reads_back(case, path)
        assert_we_sign_what_core_signed(case, path)
        assert_we_finalize_cores_spend(case, path)
        assert_our_signatures_spend(case, path)


_RECORDING = load("psbt", "_data", "core", "recovery_psbts.json")
_CASES = _RECORDING["cases"]

# the policies the recorder records, named here and not read from it
_POLICIES = (
    "simple inheritance",
    "multisig security",
    "two primaries",
    "decaying twice",
    "equal locks",
    "three heirs",
)


def _case_id(case: dict[str, Any]) -> str:
    """Name a case by its script type and its policy."""
    return f"{case['script_type']}-{case['policy'].replace(' ', '-')}"


_CASE_PARAMS = [pytest.param(case, id=_case_id(case)) for case in _CASES]


_PATH_PARAMS = [
    pytest.param(case, path, id=f"{_case_id(case)}-path-{path}")
    for case in _CASES
    for path in range(len(case["paths"]))
]


def test_the_recording_covers_both_script_types_and_every_path() -> None:
    """Each policy is there under wsh() and tr(), every path of it once."""
    assert sorted((c["script_type"], c["policy"]) for c in _CASES) == sorted(
        (script_type, policy)
        for script_type in ("p2wsh", "p2tr")
        for policy in _POLICIES
    )
    for case in _CASES:
        assert len(case["paths"]) == 1 + len(case["recovery"])


@pytest.mark.parametrize("case", _CASE_PARAMS)
def test_core_lists_the_descriptors_of_the_policy(case: dict[str, Any]) -> None:
    """The descriptors Core imported are the ones the policy gives."""
    assert_core_lists_the_policy_descriptors(case)


@pytest.mark.parametrize("case,path", _PATH_PARAMS)
def test_each_psbt_reads_back_as_core_wrote_it(case: dict[str, Any], path: int) -> None:
    """Parse each psbt, and write it back: its pairs, and its final bytes."""
    assert_each_psbt_reads_back(case, path)


@pytest.mark.parametrize("case,path", _PATH_PARAMS)
def test_our_signers_sign_what_core_signed(case: dict[str, Any], path: int) -> None:
    """Sign Core's funded psbt with the path's signers, as Core signed it."""
    assert_we_sign_what_core_signed(case, path)


@pytest.mark.parametrize("case,path", _PATH_PARAMS)
def test_core_signatures_finalize_to_cores_spend(
    case: dict[str, Any], path: int
) -> None:
    """Finalize Core's signed psbt into Core's final psbt and transaction."""
    assert_we_finalize_cores_spend(case, path)


@pytest.mark.parametrize("case,path", _PATH_PARAMS)
def test_our_signatures_finalize_to_a_valid_spend(
    case: dict[str, Any], path: int
) -> None:
    """Finalize our signed psbt, and run the spend through the script engine."""
    assert_our_signatures_spend(case, path)


@pytest.mark.parametrize("case", _CASE_PARAMS)
def test_the_recorder_checks_pass_on_the_recording(case: dict[str, Any]) -> None:
    """`check_case`, which the recorder runs on what it records, passes here.

    So a recording it accepts is one this module's tests pass on.
    """
    check_case(case)


def _account(case: dict[str, Any]) -> dict[str, str]:
    """Return the BIP139 account of a case's descriptors, as Core lists them."""
    assert_core_lists_the_policy_descriptors(case)
    receive, change = (add_checksum(str(d)) for d in policy_descriptors(case))
    return {"descriptor": receive, "change_descriptor": change}


@pytest.mark.parametrize("case", _CASE_PARAMS)
def test_cores_descriptors_are_a_bip139_account(case: dict[str, Any]) -> None:
    """Core's two descriptors are a BIP139 account, which reads back as written.

    The receive descriptor and its change, each with the checksum Core
    lists it with: what a restore of the policy reads.
    """
    account = _account(case)
    text = bip139.serialize([account], "regtest")
    assert bip139.parse(text) == {"network": "regtest", "accounts": [account]}


@pytest.mark.parametrize("case", _CASE_PARAMS)
def test_each_policy_restores(case: dict[str, Any], tmp_path: Path) -> None:
    """Restore a ledger from the policy's BIP139 account, and find Core's coin.

    The restored ledger watches the address Core funded, at its index on
    the receive branch.
    """
    text = bip139.serialize([_account(case)], "regtest")
    restored, _ = Ledger.restore_policy(
        text, tmp_path / "restored.sqlite", "regtest", FakeChain()
    )
    with restored:
        (spent,) = prevouts(Psbt.b64decode(case["paths"][0]["unsigned"]))
        assert restored.position_of(spent.script_pub_key) == (0, 0, case["index"])
