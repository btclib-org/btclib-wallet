# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Bitcoin Core derives what `OWN_VECTORS` say the raw functions describe.

Core reads none of ``rawnode()``, ``rawleaf()``, ``rawpkh()`` or a nested
``raw()``, so each vector that has one is held to the descriptor Core does
read that describes the same script: the ``pkh()`` of the key behind a
``rawpkh()``, the ``pk()`` leaf behind a ``rawleaf()`` or a ``rawnode()``.
`tests/descriptors/raw_descriptors_test.py` says how each script was
derived and holds this package to them; this module holds the node to them.

Skipped unless `BTCLIB_INTEGRATION=1` and a `bitcoind` is available; the
conftest beside this says which switch was off.
"""

from __future__ import annotations

import pytest
from bitcoin_core_rpc import BitcoinCoreRpcClient, FetchError
from btclib.script.script_pub_key import ScriptPubKey

from btclib_wallet.descriptors import parse
from tests import vector_id
from tests.descriptors.raw_descriptors_test import OWN_VECTORS

pytestmark = pytest.mark.integration


@pytest.mark.parametrize(
    "descriptor, script, core",
    [
        pytest.param(descriptor, script, core, id=vector_id(index, descriptor))
        for index, (descriptor, script, core) in enumerate(OWN_VECTORS)
        if core is not None
    ],
)
def test_core_derives_the_script_of_the_equivalent_descriptor(
    node: BitcoinCoreRpcClient, descriptor: str, script: str, core: str
) -> None:
    """The address of Core's equivalent is the address of the script."""
    checksummed = node.call("getdescriptorinfo", [core])["descriptor"]
    (derived,) = node.call("deriveaddresses", [checksummed])
    assert derived == ScriptPubKey(bytes.fromhex(script), "regtest").address
    assert parse(descriptor, "regtest").address() == derived


@pytest.mark.parametrize(
    "descriptor",
    [
        pytest.param(descriptor, id=vector_id(index, descriptor))
        for index, (descriptor, _, _) in enumerate(OWN_VECTORS)
    ],
)
def test_core_reads_none_of_the_descriptors(
    node: BitcoinCoreRpcClient, descriptor: str
) -> None:
    """Core refuses each vector: the functions are this package's."""
    with pytest.raises(FetchError, match="rpc error code -5"):
        node.call("getdescriptorinfo", [descriptor])
