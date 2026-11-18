# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Bitcoin Core funds, signs and finalizes a spend of each recovery path.

The recording `tests/psbt/core_recovery_psbts_test.py` reads. For each
policy of `POLICIES`, under ``wsh()`` and ``tr()``, Core imports into a
watch-only wallet the two descriptors `recovery_descriptors` writes,
lists them with ``listdescriptors``, and funds one address. For each path
it then funds the psbt that spends that coin, at the sequence the path's
timelock asks, signs it with ``descriptorprocesspsbt`` and the private
keys of the path's signers, finalizes it with ``finalizepsbt`` and
extracts the transaction, which ``testmempoolaccept`` accepts.

The node is the test's own, started with ``-mocktime``. Its funding
transactions and the Schnorr signatures differ from run to run, and so
do the psbts. Each run checks this package against what it
records, as the offline module checks the file. Where
``BTCLIB_RECORD_RECOVERY_PSBTS`` names a file, a recording that passes is
written there, and `tests/_data/README.md` has the command; otherwise
its descriptors are compared with the file's.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from bitcoin_core_rpc import BitcoinCoreRpcClient

from btclib_wallet.bip32.bip32 import derive
from btclib_wallet.descriptors import add_checksum
from tests import load
from tests.integration.conftest import _start_node, _stop, start_on_free_ports
from tests.psbt import core_recovery_psbts_test as offline

pytestmark = pytest.mark.integration

# the switch that writes the recording, and the file it names
RECORD_ENV = "BTCLIB_RECORD_RECOVERY_PSBTS"

# the node's clock, fixed: 2023-11-14
_MOCKTIME = 1_700_000_000

# the address index of each descriptor that Core funds
_INDEX = 5

# the sequence of an input with no relative lock, which Core writes too
_NO_LOCK = 0xFFFFFFFD

# (primary, recovery, the signers of each path): a quorum is a threshold
# and its signers, by the number `offline.account_key` reads; a recovery
# path is one more, its blocks. Each shape the module docstring of
# `recovery_paths` lists, under either script type
POLICIES: dict[str, Any] = {
    "simple inheritance": ([(1, [0])], [(1, [1], 144)], [[0], [1]]),
    "multisig security": ([(2, [0, 1])], [(2, [0, 1, 2], 288)], [[0, 1], [1, 2]]),
    "two primaries": ([(1, [0]), (2, [1, 2])], [(1, [3], 144)], [[0, 1, 2], [3]]),
    "decaying twice": (
        [(3, [0, 1, 2])],
        [(2, [0, 1, 2], 144), (1, [0, 1, 2], 288)],
        [[0, 1, 2], [0, 2], [1]],
    ),
    "equal locks": (
        [(1, [0])],
        [(2, [1, 2, 3], 144), (1, [4], 144)],
        [[0], [1, 3], [4]],
    ),
    "three heirs": (
        [(2, [0, 1])],
        [(1, [2], 144), (1, [3], 216), (1, [4], 288)],
        [[0, 1], [2], [3], [4]],
    ),
}

_SCRIPT_TYPES = ("p2wsh", "p2tr")

# the blocks mined after the funding: more than any path waits
_BLOCKS = 300
# seconds a call may take: mining those blocks in one call outlasts the
# client's default on a loaded machine. It stays below the suite's
# `timeout`, which bounds the whole test, so that a call that stalls can
# fail with the client's error
_RPC_TIMEOUT = 180.0


@pytest.fixture
def recorder(bitcoind_path: str, tmp_path: Path) -> Iterator[BitcoinCoreRpcClient]:
    """Yield a client of a node of this test's own, its clock fixed."""
    process, client, _ = start_on_free_ports(
        lambda: _start_node(
            [bitcoind_path], tmp_path, None, (f"-mocktime={_MOCKTIME}",)
        )
    )
    try:
        yield BitcoinCoreRpcClient(
            client.url, cookie_path=client.cookie_path, timeout=_RPC_TIMEOUT
        )
    finally:
        _stop(process)


def _private(text: str, signers: list[int]) -> str:
    """Return a descriptor with the account keys of `signers` private."""
    text = text.partition("#")[0]
    for signer in signers:
        public = offline.account_key(signer).split("]")[1]
        text = text.replace(public, derive(offline.root(signer), offline.ACCOUNT))
    return add_checksum(text)


def _miner(node: BitcoinCoreRpcClient) -> tuple[BitcoinCoreRpcClient, str]:
    """Return a wallet of a fixed key, and its first address, mined to.

    A key of its own, so that the coinbases are the same on every run.
    """
    node.call("createwallet", ["miner", False, True])
    miner = node.for_wallet("miner")
    key = derive(offline.root(99), "m/84h/1h/0h")
    imports = [
        {
            "desc": add_checksum(f"wpkh({key}/{chain}/*)"),
            "active": True,
            "internal": bool(chain),
            "timestamp": "now",
        }
        for chain in (0, 1)
    ]
    assert all(
        result["success"] for result in miner.call("importdescriptors", [imports])
    )
    address = str(miner.call("getnewaddress"))
    miner.call("generatetoaddress", [101, address])
    return miner, address


def _record_path(
    node: BitcoinCoreRpcClient,
    watcher: BitcoinCoreRpcClient,
    utxo: dict[str, Any],
    texts: tuple[str, str],
    signers: list[int],
    sequence: int,
    pay_to: str,
) -> dict[str, Any]:
    """Return the psbts and the transaction of one path's spend."""
    inputs = [{"txid": utxo["txid"], "vout": utxo["vout"], "sequence": sequence}]
    options = {"add_inputs": False, "subtractFeeFromOutputs": [0], "fee_rate": 10}
    # the whole coin, the fee taken from it: the watch-only wallet has no
    # change address to give
    outputs = [{pay_to: str(utxo["amount"])}]
    funded = watcher.call("walletcreatefundedpsbt", [inputs, outputs, 0, options, True])
    descriptors = [_private(text, signers) for text in texts]
    signed = node.call(
        "descriptorprocesspsbt", [funded["psbt"], descriptors, "DEFAULT", True, False]
    )
    final = node.call("finalizepsbt", [signed["psbt"], False])
    extracted = node.call("finalizepsbt", [signed["psbt"]])
    assert final["complete"]
    assert extracted["complete"]
    (accepted,) = node.call("testmempoolaccept", [[extracted["hex"]]])
    assert accepted["allowed"], accepted
    return {
        "signers": signers,
        "sequence": sequence,
        "unsigned": funded["psbt"],
        "signed": signed["psbt"],
        "final": final["psbt"],
        "tx": extracted["hex"],
    }


def _record(node: BitcoinCoreRpcClient) -> dict[str, Any]:
    """Return the recording: each policy, under each script type."""
    miner, address = _miner(node)
    cases: list[dict[str, Any]] = []
    for script_type in _SCRIPT_TYPES:
        for name, (primary, recovery, paths) in POLICIES.items():
            case = {
                "policy": name,
                "script_type": script_type,
                "primary": primary,
                "recovery": recovery,
                "index": _INDEX,
                "paths": paths,
            }
            receive, change = offline.policy_descriptors(case)
            wallet = f"{script_type} {name}"
            node.call("createwallet", [wallet, True, True])
            watcher = node.for_wallet(wallet)
            texts = (add_checksum(str(receive)), add_checksum(str(change)))
            imports = [
                {"desc": text, "range": [0, 9], "timestamp": "now", "internal": bool(i)}
                for i, text in enumerate(texts)
            ]
            results = watcher.call("importdescriptors", [imports])
            assert all(result["success"] for result in results), results
            (funded,) = node.call("deriveaddresses", [texts[0], [_INDEX, _INDEX]])
            assert funded == receive.address(_INDEX)
            # listed before the funding: the watcher learns of the payment
            # from the node's validation queue, at a time of its own after
            # sendtoaddress returns, and the payment moves the receive
            # descriptor's `next` and `range`
            case["listdescriptors"] = watcher.call("listdescriptors")["descriptors"]
            miner.call("sendtoaddress", [funded, "2"])
            case["texts"] = texts
            cases.append(case)
    miner.call("generatetoaddress", [_BLOCKS, address])
    for case in cases:
        watcher = node.for_wallet(f"{case['script_type']} {case['policy']}")
        (utxo,) = watcher.call("listunspent")
        blocks = [None] + [b for *_, b in case["recovery"]]
        case["paths"] = [
            _record_path(
                node,
                watcher,
                utxo,
                case["texts"],
                signers,
                _NO_LOCK if lock is None else lock,
                address,
            )
            for signers, lock in zip(case["paths"], blocks, strict=True)
        ]
        del case["texts"]
    version = node.call("getnetworkinfo")["subversion"]
    return {"bitcoind": version, "mocktime": _MOCKTIME, "cases": cases}


def test_core_spends_each_recovery_path(recorder: BitcoinCoreRpcClient) -> None:
    """Record Core's spends, and read them as the recorded file is read.

    Then write the recording where asked, which replaces the file it
    would be compared with. Otherwise the descriptors Core lists are the
    recorded ones: they are the part of a recording that does not change
    from run to run.
    """
    recording = _record(recorder)
    for case in recording["cases"]:
        offline.check_case(case)
    if path := os.environ.get(RECORD_ENV):
        text = json.dumps(recording, indent=4) + "\n"
        Path(path).write_text(text, encoding="ascii")
        return
    recorded = load("psbt", "_data", "core", "recovery_psbts.json")
    assert [case["listdescriptors"] for case in recording["cases"]] == [
        case["listdescriptors"] for case in recorded["cases"]
    ]
