# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A fetcher's refusal describes the int or tx id it refuses, or names it.

Section 7 of the btclib-org standard, *A refusal carries no secret*: an
argument in the wrong place may be a key. Each test passes the key of
`tests/refused_value_test.py` where a height, a bound, a target, a vout
or a tx id belongs, and checks the refusal with `assert_secret_free`.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from btclib.exceptions import BTClibValueError
from btclib.tx import OutPoint, Tx
from typing_extensions import override

from btclib_wallet.exceptions import FetchError
from btclib_wallet.fetch.fee_estimator import valid_confirmation_target
from tests.fetch import TX_ID, StubFetcher, recorded_body
from tests.fetch.compact_filters_test import build
from tests.fetch.electrum_test import fetcher as electrum_fetcher
from tests.fetch.esplora_history_test import _explorer, _fetcher
from tests.fetch.esplora_test import fee_estimates
from tests.fetch.esplora_test import fetcher as esplora_fetcher
from tests.fetch.history_test import OURS
from tests.fetch.peer_chain_test import WALLET
from tests.refused_value_test import KEY, SCALAR, SPELLINGS
from tests.secret_free import assert_secret_free

RAW = recorded_body("esplora_tx_hex.txt").decode().strip()


class _Unordered(int):
    """An int no comparison orders, so that it passes every bound."""

    @override
    def __lt__(self, _other: object) -> bool:
        return False

    @override
    def __gt__(self, _other: object) -> bool:
        return False

    @override
    def __le__(self, _other: object) -> bool:
        return False


@pytest.mark.parametrize(
    "call, err_msg",
    [
        (
            lambda: build()[0].get_tx(KEY),
            "^a compact filter client cannot serve a transaction by its id,",
        ),
        (
            lambda: build()[0].get_block_header(SCALAR),
            "^no block at the height asked: the tip is 14$",
        ),
        (
            lambda: build()[0].scan_blocks([WALLET], max_blocks=-SCALAR),
            "^invalid max_blocks: a negative int of 256 bits < 1$",
        ),
        (
            lambda: build()[0].scan_blocks([WALLET], SCALAR, 1),
            "^stop height below start height$",
        ),
        (
            lambda: build()[0].scan_blocks([WALLET], 0, SCALAR),
            "^the peer's chain ends at 14, below the stop height$",
        ),
        (
            lambda: valid_confirmation_target(-SCALAR),
            "^invalid confirmation target: a negative int of 256 bits < 1$",
        ),
        (
            lambda: esplora_fetcher().estimate_fee(SCALAR),
            "^confirmation target an int of 256 bits above the highest quoted, 1008$",
        ),
        (
            lambda: esplora_fetcher((200, fee_estimates(**{"1": 10}))).estimate_fee(
                _Unordered(SCALAR)
            ),
            "^fee-estimates: no target quoted at or above the one asked$",
        ),
        (
            lambda: electrum_fetcher(-1).estimate_fee(SCALAR),
            "^blockchain.estimatefee: no estimate for this target$",
        ),
        (
            lambda: _fetcher(_explorer()).get_history([OURS], max_pages=-SCALAR),
            "^invalid max_pages: a negative int of 256 bits < 1$",
        ),
        (
            lambda: StubFetcher(Tx.parse(RAW)).get_tx_out(
                OutPoint(TX_ID, SCALAR, check_validity=False)
            ),
            "^out of range vout: an int of 256 bits for a transaction with 2 outputs$",
        ),
    ],
    ids=[
        "compact filters tx id",
        "compact filters height",
        "compact filters max_blocks",
        "compact filters start height",
        "compact filters stop height",
        "confirmation target",
        "esplora target",
        "esplora target past every bound",
        "electrum target",
        "esplora max_pages",
        "vout",
    ],
)
def test_a_fetcher_describes_a_refused_int_or_tx_id(
    call: Callable[[], object], err_msg: str
) -> None:
    """By its sign and bit length, or by the parameter it was (issue #828)."""
    with pytest.raises((BTClibValueError, FetchError), match=err_msg) as e:
        call()
    assert_secret_free(e.value, SPELLINGS)
