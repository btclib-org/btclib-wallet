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

from btclib_wallet.exceptions import FetchError, HttpError
from btclib_wallet.fetch.fee_estimator import valid_confirmation_target
from tests.fetch import TX_ID, StubFetcher, recorded_body
from tests.fetch.bitcoin_core_rest_test import fetcher as rest_fetcher
from tests.fetch.compact_filters_test import build
from tests.fetch.electrum_test import fetcher as electrum_fetcher
from tests.fetch.esplora_history_test import _explorer, _fetcher
from tests.fetch.esplora_test import fee_estimates
from tests.fetch.esplora_test import fetcher as esplora_fetcher
from tests.fetch.history_test import OURS
from tests.fetch.peer_chain_test import WALLET
from tests.refused_value_test import HEX, KEY, SCALAR, SPELLINGS
from tests.secret_free import assert_secret_free

RAW = recorded_body("esplora_tx_hex.txt").decode().strip()


class _PastBounds(int):
    """An int whose < and > answer False.

    It passes both bounds of `EsploraFetcher.estimate_fee`, and as a
    negative value the `max_pages < 1` of `EsploraFetcher.get_history`.
    """

    @override
    def __lt__(self, _other: object) -> bool:
        return False

    @override
    def __gt__(self, _other: object) -> bool:
        return False


class _PastOne(int):
    """An int that is less than any int above 1.

    It passes `max_blocks < 1`, and `n > max_blocks` reflects to the same
    `__lt__`, so two matching blocks pass the bound.
    """

    @override
    def __lt__(self, other: object) -> bool:
        return isinstance(other, int) and other > 1


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
                _PastBounds(SCALAR)
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


@pytest.mark.parametrize(
    "call, err_msg",
    [
        (
            lambda: build()[0].scan_blocks([WALLET], max_blocks=_PastOne(SCALAR)),
            "^the filters match more blocks than max_blocks, an int of 256 bits$",
        ),
        (
            lambda: _fetcher(_explorer()).get_history(
                [OURS], max_pages=_PastBounds(-SCALAR)
            ),
            "^script history: more pages than max_pages, a negative int of 256 bits$",
        ),
    ],
    ids=["compact filters max_blocks", "esplora max_pages"],
)
def test_a_bound_reached_is_described(call: Callable[[], object], err_msg: str) -> None:
    """An int subclass passing the bound's check reaches it (issue #837)."""
    with pytest.raises(FetchError, match=err_msg) as e:
        call()
    assert_secret_free(e.value, SPELLINGS)


# a body that quotes the request, as a proxy's error page can
_QUOTING = (404, f"not found: {HEX} {SCALAR}".encode())


@pytest.mark.parametrize(
    "call, err_msg",
    [
        (
            lambda: esplora_fetcher(_QUOTING).get_tx(KEY),
            "^HTTP 404 from /tx/<txid>/hex$",
        ),
        (
            lambda: esplora_fetcher(_QUOTING).get_block_header(SCALAR),
            "^HTTP 404 from /block-height/<height>$",
        ),
        (
            lambda: rest_fetcher(_QUOTING).get_tx(KEY),
            "^GET /tx/<txid>.bin: HTTP 404$",
        ),
        (
            lambda: rest_fetcher(_QUOTING).get_block_header(SCALAR),
            "^GET /blockhashbyheight/<height>.bin: HTTP 404$",
        ),
    ],
    ids=["esplora tx", "esplora height", "rest tx", "rest height"],
)
def test_an_http_refusal_names_the_endpoint_and_not_the_value(
    call: Callable[[], object], err_msg: str
) -> None:
    """A height or tx id in the path is the caller's (issue #843)."""
    with pytest.raises(HttpError, match=err_msg) as e:
        call()
    assert e.value.status == 404
    assert_secret_free(e.value, SPELLINGS)
