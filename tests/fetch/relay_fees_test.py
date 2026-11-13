# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for btclib_wallet.fetch.relay_fees, and the Core fetchers' answers.

`BitcoinCoreFetcher.get_relay_fees` and
`BitcoinCoreRestFetcher.get_relay_fees` read the same reply, so each case
runs over both. `tests/integration/relay_fees_test.py` asks a real node.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable

import pytest
from btclib.exceptions import BTClibValueError
from btclib.fee import FeeRate

from btclib_wallet.exceptions import FetchError
from btclib_wallet.fetch.bitcoin_core import BitcoinCoreFetcher
from btclib_wallet.fetch.bitcoin_core_rest import BitcoinCoreRestFetcher
from btclib_wallet.fetch.relay_fees import RelayFeeReader, RelayFees
from tests import raises_from
from tests.fetch import bitcoin_core_rest_test as rest
from tests.fetch import bitcoin_core_test as rpc
from tests.fetch import chain_mismatch
from tests.fetch.compact_filters_test import build as compact_filter_fetcher
from tests.fetch.electrum_test import fetcher as electrum_fetcher
from tests.fetch.esplora_test import fetcher as esplora_fetcher

# the members of `getmempoolinfo` this reads, at the rates the integration
# test starts its node with, the rest of the reply omitted
MEMPOOL_INFO = {
    "mempoolminfee": 0.00001234,
    "minrelaytxfee": 0.00001234,
    "incrementalrelayfee": 0.00000567,
}


def rpc_fetcher(info: object) -> BitcoinCoreFetcher:
    """Return a fetcher whose node answers `getmempoolinfo` with `info`."""
    body = json.dumps({"result": info, "error": None, "id": "x"}).encode()
    return rpc.fetcher((200, body))


def rest_fetcher(info: object) -> BitcoinCoreRestFetcher:
    """Return a fetcher whose node answers `/mempool/info.json` with `info`."""
    return rest.fetcher((200, json.dumps(info).encode()))


BUILDS = pytest.mark.parametrize(
    "build", [rpc_fetcher, rest_fetcher], ids=["rpc", "rest"]
)
BOTH = pytest.mark.parametrize(
    "build, source",
    [(rpc_fetcher, "getmempoolinfo"), (rest_fetcher, "mempool info")],
    ids=["rpc", "rest"],
)

_Build = Callable[[object], BitcoinCoreFetcher | BitcoinCoreRestFetcher]


def test_relay_fees_carries_the_three_rates() -> None:
    """Three rates, each in its own field, nothing derived."""
    fees = RelayFees(
        FeeRate(sats_per_kvbyte=1),
        FeeRate(sats_per_kvbyte=2),
        FeeRate(sats_per_kvbyte=3),
    )
    assert fees.min_relay == FeeRate(sats_per_kvbyte=1)
    assert fees.mempool_min == FeeRate(sats_per_kvbyte=2)
    assert fees.incremental == FeeRate(sats_per_kvbyte=3)


@BUILDS
def test_get_relay_fees_reads_the_three_members(build: _Build) -> None:
    """Each rate is BTC/kvB, read from the member Core names it by."""
    assert build(MEMPOOL_INFO).get_relay_fees() == RelayFees(
        min_relay=FeeRate(sats_per_kvbyte=1234),
        mempool_min=FeeRate(sats_per_kvbyte=1234),
        incremental=FeeRate(sats_per_kvbyte=567),
    )


def test_get_relay_fees_asks_getmempoolinfo() -> None:
    """One call, `getmempoolinfo`, with no parameters."""
    fetcher = rpc_fetcher(MEMPOOL_INFO)
    fetcher.get_relay_fees()
    assert rpc.asked(fetcher.client) == ["getmempoolinfo"]
    assert rpc.sent(fetcher.client)["params"] == []


def test_get_relay_fees_asks_mempool_info_over_rest() -> None:
    """One request, `/mempool/info.json`."""
    fetcher = rest_fetcher(MEMPOOL_INFO)
    fetcher.get_relay_fees()
    assert rest.urls(fetcher.client) == [f"{rest.URL}/rest/mempool/info.json"]


@BUILDS
def test_a_rate_finer_than_a_satoshi_is_rounded_up(build: _Build) -> None:
    """1.5 satoshi/kvB is answered as 2, as `FeeEstimator` rounds a quote."""
    info = dict.fromkeys(MEMPOOL_INFO, 0.000000015)
    fees = build(info).get_relay_fees()
    assert fees == RelayFees(
        FeeRate(sats_per_kvbyte=2),
        FeeRate(sats_per_kvbyte=2),
        FeeRate(sats_per_kvbyte=2),
    )


@BOTH
@pytest.mark.parametrize("missing", sorted(MEMPOOL_INFO))
def test_a_missing_rate_is_refused(build: _Build, source: str, missing: str) -> None:
    """All three are answered, or none is."""
    info = {name: rate for name, rate in MEMPOOL_INFO.items() if name != missing}
    with raises_from(
        FetchError,
        match=f"^{source}: a malformed answer$",
        cause=f"no {missing!r} member",
    ):
        build(info).get_relay_fees()


@BOTH
@pytest.mark.parametrize("rate", ["fast", -0.00001, None])
def test_a_member_that_is_no_rate_is_refused(
    build: _Build, source: str, rate: object
) -> None:
    """A member that is no rate is the node's failure, named by its source."""
    info = {**MEMPOOL_INFO, "incrementalrelayfee": rate}
    with pytest.raises(FetchError, match=f"^{re.escape(source)}: "):
        build(info).get_relay_fees()


@BOTH
def test_a_reply_that_is_no_object_is_refused(build: _Build, source: str) -> None:
    """An array or a scalar is refused, not indexed."""
    with pytest.raises(FetchError, match=f"^{re.escape(source)}: "):
        build([MEMPOOL_INFO]).get_relay_fees()


def test_the_reply_is_bounded_by_what_it_is() -> None:
    """A reply past 1024 octets is refused before it is parsed."""
    with pytest.raises(
        FetchError, match="no usable answer from the server: FetchError"
    ):
        rest.fetcher((200, b"x" * 1025)).get_relay_fees()
    oversized = b'{"result":' + b"9" * 1100 + b',"error":null,"id":"x"}'
    with pytest.raises(
        FetchError, match="no usable answer from the server: FetchError"
    ):
        rpc.fetcher((200, oversized)).get_relay_fees()


def test_get_relay_fees_verifies_the_network_first() -> None:
    """The same guard every other question goes through first."""
    endpoint = rpc.client(rpc.blockchaininfo(chain="test"))
    with pytest.raises(BTClibValueError, match=chain_mismatch("test", "main")):
        BitcoinCoreFetcher(endpoint).get_relay_fees()
    assert rpc.asked(endpoint) == ["getblockchaininfo"]

    endpoint_rest = rest.client((200, rest.chaininfo(chain="test")))
    with pytest.raises(BTClibValueError, match="reports chain 'test'"):
        BitcoinCoreRestFetcher(endpoint_rest).get_relay_fees()
    assert rest.urls(endpoint_rest) == [f"{rest.URL}/rest/chaininfo.json"]


def test_which_fetchers_are_relay_fee_readers() -> None:
    """A mypy fact and not a runtime one, as `Broadcaster`'s tests have it.

    `RelayFeeReader` is not `runtime_checkable`. The assignments of the
    two Core fetchers type-check; each of the others carries a
    `# type: ignore[assignment]` that `warn_unused_ignores` fails the day
    that class gains a `get_relay_fees`.
    """
    readers: list[RelayFeeReader] = [rpc_fetcher(None), rest_fetcher(None)]
    assert len(readers) == 2
    _electrum: RelayFeeReader = electrum_fetcher()  # type: ignore[assignment]
    _esplora: RelayFeeReader = esplora_fetcher()  # type: ignore[assignment]
    _filters: RelayFeeReader = compact_filter_fetcher()[0]  # type: ignore[assignment]
