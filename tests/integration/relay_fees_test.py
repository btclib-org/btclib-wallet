# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""`get_relay_fees` of both Core fetchers, against a node of this module's own.

The node is started with `-rest` and with a `-minrelaytxfee` and an
`-incrementalrelayfee` that are not Core's defaults, so an answer read
from the wrong member, or a default, does not pass. Each fetcher's call
also holds the reply under `_MAX_MEMPOOL_INFO_REPLY`, which it is read
with.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from bitcoin_core_rpc import BitcoinCoreRestClient, BitcoinCoreRpcClient
from btclib.fee import FeeRate

from btclib_wallet.fetch.bitcoin_core import BitcoinCoreFetcher
from btclib_wallet.fetch.bitcoin_core_rest import BitcoinCoreRestFetcher
from btclib_wallet.fetch.relay_fees import RelayFees
from tests.integration.conftest import _start_node, _stop, start_on_free_ports

# the rates the node is started with, in BTC/kvB, and what they are in
# satoshi/kvB
MIN_RELAY = "0.00001234"
INCREMENTAL = "0.00000567"
EXPECTED = RelayFees(
    min_relay=FeeRate(sats_per_kvbyte=1234),
    # an empty mempool evicted nothing, so its minimum is the relay one
    mempool_min=FeeRate(sats_per_kvbyte=1234),
    incremental=FeeRate(sats_per_kvbyte=567),
)


@pytest.fixture(scope="module")
def floors_node(
    bitcoind_path: str, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[tuple[BitcoinCoreRpcClient, int]]:
    """Yield a client of a node with `-rest` and these rates, and its port."""
    datadir = tmp_path_factory.mktemp("relay-fees-node")
    extra = (
        "-rest=1",
        f"-minrelaytxfee={MIN_RELAY}",
        f"-incrementalrelayfee={INCREMENTAL}",
    )
    process, client, port = start_on_free_ports(
        lambda: _start_node([bitcoind_path], datadir, None, extra)
    )
    try:
        yield client, port
    finally:
        _stop(process)


def test_the_node_runs_at_the_rates_it_was_given(
    floors_node: tuple[BitcoinCoreRpcClient, int],
) -> None:
    """What the fetchers are compared with is what the node reports."""
    client, _ = floors_node
    info = client.call("getmempoolinfo")
    assert str(info["minrelaytxfee"]) == MIN_RELAY
    assert str(info["incrementalrelayfee"]) == INCREMENTAL


def test_the_rpc_fetcher_answers_the_nodes_rates(
    floors_node: tuple[BitcoinCoreRpcClient, int],
) -> None:
    """`getmempoolinfo`, read through the fetcher."""
    client, _ = floors_node
    fetcher = BitcoinCoreFetcher(client, "regtest")
    assert fetcher.get_relay_fees() == EXPECTED


def test_the_rest_fetcher_answers_the_nodes_rates(
    floors_node: tuple[BitcoinCoreRpcClient, int],
) -> None:
    """`/mempool/info.json`, read through the fetcher."""
    _, port = floors_node
    rest = BitcoinCoreRestClient(f"http://127.0.0.1:{port}")
    fetcher = BitcoinCoreRestFetcher(rest, "regtest")
    assert fetcher.get_relay_fees() == EXPECTED
