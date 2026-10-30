# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Bitcoin Core infers what `tests/descriptors/infer_test.py` records.

That module holds `infer_descriptor` to the answers it records; this one
holds the node to them. `scantxoutset` answers for a shape, once its
scripts are paid, and `decodescript` for a script.

Skipped unless `BTCLIB_INTEGRATION=1` and a `bitcoind` is available; the
conftest beside this says which switch was off.
"""

from __future__ import annotations

import time

import pytest
from bitcoin_core_rpc import BitcoinCoreRpcClient
from btclib.tx import Tx, TxOut

from tests.descriptors.infer_test import RANGED, SCRIPTS, SHAPES, _descriptors, _text

pytestmark = pytest.mark.integration


def test_core_infers_each_shape_as_recorded(node: BitcoinCoreRpcClient) -> None:
    """`scantxoutset` once each script is paid, over index 0."""
    name = f"infer-{time.monotonic_ns():x}"
    node.call("createwallet", [name])
    miner = node.for_wallet(name)
    address = miner.call("getnewaddress")
    miner.call("generatetoaddress", [101, address])
    scripts = {
        script.script: script
        for template, _ in SHAPES.values()
        for descriptor in _descriptors(template)
        for script in descriptor.script_pub_keys(0)
    }
    for index in range(2):
        for script in _descriptors(RANGED[0])[0].script_pub_keys(index):
            scripts[script.script] = script
    tx = Tx(
        vin=[],
        vout=[TxOut(100_000, script) for script in scripts.values()],
        check_validity=False,
    )
    unsigned = tx.serialize(include_witness=False, check_validity=False).hex()
    funded = miner.call("fundrawtransaction", [unsigned])
    signed = miner.call("signrawtransactionwithwallet", [funded["hex"]])
    # in a block of its own rather than through the mempool, whose policy
    # refuses some of these outputs
    node.call("generateblock", [address, [signed["hex"]]])

    for template, expected in SHAPES.values():
        scan = {"desc": _text(template), "range": [0, 0]}
        found = node.call("scantxoutset", ["start", [scan]])
        assert sorted(unspent["desc"] for unspent in found["unspents"]) == sorted(
            expected
        ), template
    scan = {"desc": _text(RANGED[0]), "range": [0, 1]}
    found = node.call("scantxoutset", ["start", [scan]])
    assert sorted(unspent["desc"] for unspent in found["unspents"]) == sorted(RANGED[1])


def test_core_decodes_each_script_as_recorded(node: BitcoinCoreRpcClient) -> None:
    """`decodescript`, which infers with an empty provider."""
    for script, expected in SCRIPTS.values():
        assert node.call("decodescript", [script])["desc"] == expected, script
