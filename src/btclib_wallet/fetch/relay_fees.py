# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The interface a chain backend answers to report its relay fee floors.

Kept apart from `Fetcher`, as `Broadcaster`, `FeeEstimator`,
`BalanceReader` and `HistoryReader` are, because not every backend can
answer it. `BitcoinCoreFetcher` and `BitcoinCoreRestFetcher` satisfy it.
A backend that cannot answer all three rates does not, and its docstring
says why.

Not `runtime_checkable`, for the reason `Broadcaster` is not: the
contract below is not what `isinstance(x, RelayFeeReader)` would verify.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from btclib.fee import FeeRate

__all__ = ["RelayFeeReader", "RelayFees"]


@dataclass(frozen=True)
class RelayFees:
    """The fee rates a node's mempool holds a transaction to.

    `min_relay` is the lowest rate the node accepts at all, Core's
    `minrelaytxfee`. `mempool_min` is the lowest rate its mempool accepts
    now, Core's `mempoolminfee`: never below `min_relay`, and above it
    after a full mempool evicted transactions. `incremental` is Core's
    `incrementalrelayfee`, the least rise in rate that a replacement pays
    over its own size, and that `mempool_min` rises by past what the
    mempool evicted (`policy.h`'s `DEFAULT_INCREMENTAL_RELAY_FEE`).
    """

    min_relay: FeeRate
    mempool_min: FeeRate
    incremental: FeeRate


class RelayFeeReader(Protocol):
    """A backend able to report the relay fee floors of its node.

    One method and one contract, binding on every implementation of it:

    - all three rates are answered, or the call raises;
    - a rate a backend expresses more finely than `FeeRate` can hold
      exactly is rounded up, never down, as `FeeEstimator`'s second
      contract bullet rounds a quote: a floor rounded down is one a
      transaction paying it can still miss.
    """

    def get_relay_fees(self) -> RelayFees:
        """Return the relay fee floors of the node."""
        ...
