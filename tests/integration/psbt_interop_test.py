# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Generated PSBTs read by btclib-wallet, bitcoin-s and Bitcoin Core.

This informational comparison needs BTCLIB_PSBT_INTEROP=1 and a complete
command in BTCLIB_BITCOIN_S, as well as the regtest fixture's switches.
The command reads base64 PSBT lines and writes the JSON lines emitted by
`.github/interop/PsbtRoundTrip.scala`. One process handles the entire batch.
BTCLIB_PSBT_REPORT names the JSON artifact, including capability refusals.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from decimal import Decimal
from pathlib import Path
from typing import Any

import hypothesis
import pytest
from bitcoin_core_rpc import BitcoinCoreRpcClient, FetchError, RpcError
from hypothesis import given, seed, settings

from btclib_wallet.psbt import Psbt
from tests.strategies.psbt import psbts

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("BTCLIB_PSBT_INTEROP") != "1"
        or not os.environ.get("BTCLIB_BITCOIN_S"),
        reason="set BTCLIB_PSBT_INTEROP=1 and BTCLIB_BITCOIN_S to run the batch",
    ),
]

_EXAMPLES = 12
_TIMEOUT = 600


def _decimal_string(value: object) -> str:
    """Preserve Core's exact amounts in the report without float rounding."""
    if not isinstance(value, Decimal):
        raise TypeError("unexpected report value")
    return str(value)


def _configuration(version: int, taproot: bool, musig2: bool) -> list[dict[str, Any]]:
    """Draw one configuration with its recorded seed and settings."""
    cases: list[dict[str, Any]] = []
    batch_seed = 333000 + version * 100 + taproot * 10 + musig2

    @seed(batch_seed)
    @settings(
        max_examples=_EXAMPLES,
        database=None,
        derandomize=True,
        deadline=None,
    )
    @given(psbts(version, taproot=taproot, musig2=musig2))
    def collect(psbt: Psbt) -> None:
        cases.append(
            {
                "version": version,
                "taproot": taproot,
                "musig2": musig2,
                "seed": batch_seed,
                "base64": psbt.b64encode(),
                "unsigned_tx": psbt.tx.serialize(False).hex(),
            }
        )

    collect()
    return cases


def _batch() -> list[dict[str, Any]]:
    """Return reproducible examples from every version/metadata combination."""
    cases: list[dict[str, Any]] = []
    for version in (0, 2):
        for taproot in (False, True):
            for musig2 in (False, True):
                cases.extend(_configuration(version, taproot, musig2))
    for index, case in enumerate(cases):
        case["index"] = index
    return cases


# decodepsbt's name for each field btclib-wallet holds, from
# src/rpc/rawtransaction.cpp of Bitcoin Core. An unknown record is one
# Core did not recognize, so a field filed under a wrong key type shows
# there as well as missing from its own name.
_CORE_GLOBAL = {
    "hd_key_paths": "global_xpubs",
    "unknown": "proprietary",
}
_CORE_INPUT = {
    "non_witness_utxo": "non_witness_utxo",
    "witness_utxo": "witness_utxo",
    "partial_sigs": "partial_signatures",
    "sig_hash_type": "sighash",
    "redeem_script": "redeem_script",
    "witness_script": "witness_script",
    "hd_key_paths": "bip32_derivs",
    "final_script_sig": "final_scriptSig",
    "final_script_witness": "final_scriptwitness",
    "ripemd160_preimages": "ripemd160_preimages",
    "sha256_preimages": "sha256_preimages",
    "hash160_preimages": "hash160_preimages",
    "hash256_preimages": "hash256_preimages",
    "taproot_key_spend_signature": "taproot_key_path_sig",
    "taproot_script_spend_signatures": "taproot_script_path_sigs",
    "taproot_leaf_scripts": "taproot_scripts",
    "taproot_hd_key_paths": "taproot_bip32_derivs",
    "taproot_internal_key": "taproot_internal_key",
    "taproot_merkle_root": "taproot_merkle_root",
    "unknown": "proprietary",
    "musig2_participant_pub_keys": "musig2_participant_pubkeys",
    "musig2_pub_nonces": "musig2_pubnonces",
    "musig2_partial_sigs": "musig2_partial_sigs",
}
_CORE_OUTPUT = {
    "redeem_script": "redeem_script",
    "witness_script": "witness_script",
    "hd_key_paths": "bip32_derivs",
    "taproot_internal_key": "taproot_internal_key",
    "taproot_tree": "taproot_tree",
    "taproot_hd_key_paths": "taproot_bip32_derivs",
    "unknown": "proprietary",
    "musig2_participant_pub_keys": "musig2_participant_pubkeys",
}
# The fields of a v0 PSBT that the unsigned transaction carries, which
# the txid comparison already covers.
_IN_TRANSACTION = {
    "previous_tx_id",
    "output_index",
    "sequence",
    "required_time_lock_time",
    "required_height_lock_time",
}
_OUT_TRANSACTION = {"amount", "script_pub_key"}
_GLOBAL_TRANSACTION = {
    "tx_version",
    "version",
    "inputs",
    "outputs",
    "fallback_lock_time",
}


def _map_gaps(
    label: str,
    held: object,
    core: dict[str, Any],
    names: dict[str, str],
    transaction: set[str],
) -> list[str]:
    """Name each held field whose key Core's answer lacks.

    Only the key is checked, not the value or an entry count: Core always
    emits the global `global_xpubs` and `proprietary`, even empty. A record
    Core files as unknown is named too.
    """
    gaps = []
    for name, value in vars(held).items():
        if not value or name in transaction:
            continue
        # Core reads a null Taproot merkle root as absent and omits it
        if name == "taproot_merkle_root" and not any(value):
            continue
        core_name = names.get(name)
        if core_name is None:
            gaps.append(f"{label}.{name}: no Core name is mapped")
        elif core_name not in core:
            gaps.append(f"{label}.{name}: Core omits {core_name}")
    if core.get("unknown"):
        gaps.append(f"{label}: Core files {sorted(core['unknown'])} as unknown")
    return gaps


def _core_gaps(original: Psbt, response: dict[str, Any]) -> list[str]:
    """Return each held field whose key Core's answer lacks, empty if none.

    It also names a differing number of inputs or outputs. Values and entry
    counts inside a map are not compared.
    """
    gaps = _map_gaps("global", original, response, _CORE_GLOBAL, _GLOBAL_TRANSACTION)
    for kind, held, decoded, names, transaction in (
        (
            "inputs",
            original.inputs,
            response.get("inputs", []),
            _CORE_INPUT,
            _IN_TRANSACTION,
        ),
        (
            "outputs",
            original.outputs,
            response.get("outputs", []),
            _CORE_OUTPUT,
            _OUT_TRANSACTION,
        ),
    ):
        if len(held) != len(decoded):
            gaps.append(f"{kind}: Core decodes {len(decoded)}, expected {len(held)}")
            continue
        for index, (item, core) in enumerate(zip(held, decoded, strict=True)):
            gaps += _map_gaps(f"{kind}[{index}]", item, core, names, transaction)
    return gaps


def _core_result(node: BitcoinCoreRpcClient, case: dict[str, Any]) -> dict[str, Any]:
    """Keep the full response and distinguish Core's explicit v2 refusal."""
    try:
        response = node.call("decodepsbt", [case["base64"]])
    except FetchError as error:
        capability = (
            case["version"] == 2
            and isinstance(error, RpcError)
            and error.code == -22
            and "Unsupported version number" in str(error)
        )
        return {
            "status": "capability" if capability else "disagreement",
            "error_type": type(error).__name__,
            "error": str(error),
        }
    original = Psbt.b64decode(case["base64"])
    matches = response.get("tx", {}).get("txid") == original.tx.id.hex()
    gaps = _core_gaps(original, response)
    return {
        "status": "accepted" if matches and not gaps else "disagreement",
        "response": response,
        "unsigned_tx_matches": matches,
        "core_gaps": gaps,
    }


def _bitcoin_s_result(case: dict[str, Any], response: dict[str, Any]) -> dict[str, Any]:
    """Check all fields after bitcoin-s serialization, not just its txid."""
    if response.get("ok") is not True:
        capability = (
            response.get("ok") is False
            and case["version"] == 2
            and response.get("error_type") == "java.lang.IllegalArgumentException"
            and response.get("error")
            == "requirement failed: Unknown version number given: UInt32Impl(2)"
        )
        return {
            "status": "capability" if capability else "disagreement",
            "response": response,
        }
    try:
        encoded = response["base64"]
        if not isinstance(encoded, str):
            return {"status": "disagreement", "response": response}
        returned = Psbt.b64decode(encoded)
        original = Psbt.b64decode(case["base64"])
        matches = returned == original
        tx_matches = returned.tx.serialize(False).hex() == case["unsigned_tx"]
    except (ValueError, TypeError, KeyError) as error:
        return {
            "status": "disagreement",
            "response": response,
            "error_type": type(error).__name__,
            "error": str(error),
        }
    return {
        "status": "accepted" if matches and tx_matches else "disagreement",
        "response": response,
        "psbt_matches": matches,
        "unsigned_tx_matches": tx_matches,
    }


def _output_text(output: bytes | str | None) -> str:
    """Read even the partial byte output retained by a timed-out process."""
    if isinstance(output, bytes):
        return output.decode("utf-8", errors="replace")
    return output or ""


def _bitcoin_s_batch(cases: list[dict[str, Any]], command: list[str]) -> dict[str, Any]:
    """Run one external process and associate every response by input index."""
    if not command:
        return {"error": "BTCLIB_BITCOIN_S contains no command"}
    try:
        process = subprocess.run(  # noqa: S603
            command,
            input="".join(case["base64"] + "\n" for case in cases),
            capture_output=True,
            encoding="utf-8",
            timeout=_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        return {
            "error_type": type(error).__name__,
            "error": str(error),
            "stdout": _output_text(error.stdout),
            "stderr": _output_text(error.stderr),
        }
    except OSError as error:
        return {"error_type": type(error).__name__, "error": str(error)}
    execution: dict[str, Any] = {
        "returncode": process.returncode,
        "stdout": process.stdout,
        "stderr": process.stderr,
    }
    lines = process.stdout.splitlines()
    if process.returncode or len(lines) != len(cases):
        execution["error"] = "bitcoin-s did not return one result per input"
        return execution
    for case, line in zip(cases, lines, strict=True):
        try:
            response = json.loads(line)
        except json.JSONDecodeError as error:
            case["bitcoin_s"] = {"status": "disagreement", "error": str(error)}
            continue
        if (
            not isinstance(response, dict)
            or type(response.get("index")) is not int
            or response["index"] != case["index"]
        ):
            case["bitcoin_s"] = {
                "status": "disagreement",
                "error": "bitcoin-s response has no matching input index",
                "response": response,
            }
            continue
        case["bitcoin_s"] = _bitcoin_s_result(case, response)
    return execution


def test_generated_psbts_against_bitcoin_s_and_core(
    node: BitcoinCoreRpcClient, tmp_path: Path
) -> None:
    """Report every generated case, failing only on unexpected disagreements."""
    cases = _batch()
    command: list[str] = []
    execution: dict[str, Any] = {"error": "comparison did not complete"}
    report_path = Path(os.environ.get("BTCLIB_PSBT_REPORT", tmp_path / "interop.json"))
    try:
        for case in cases:
            case["core"] = _core_result(node, case)
        command = shlex.split(os.environ["BTCLIB_BITCOIN_S"])
        execution = _bitcoin_s_batch(cases, command)
    finally:
        report = {
            "hypothesis_version": hypothesis.__version__,
            "examples_per_configuration": _EXAMPLES,
            "database": None,
            "derandomize": True,
            "bitcoin_s_command": command,
            "bitcoin_s_execution": execution,
            "cases": cases,
        }
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            json.dumps(report, indent=2, default=_decimal_string) + "\n",
            encoding="utf-8",
        )
    assert "error" not in execution, report_path
    assert len(cases) == 8 * _EXAMPLES, report_path
    disagreements = [
        case["index"]
        for case in cases
        if any(case[tool]["status"] == "disagreement" for tool in ("core", "bitcoin_s"))
    ]
    assert not disagreements, f"cases {disagreements}: {report_path}"
