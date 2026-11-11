# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A script hash's history over Electrum's transport-free codec."""

from __future__ import annotations

import json

import pytest
from btclib.exceptions import BTClibTypeError, BTClibValueError

from btclib_wallet import electrum
from btclib_wallet.exceptions import RpcError
from tests.electrum_balance_test import SCRIPT_HASH

A, B, C = "aa" * 32, "bb" * 32, "cc" * 32


def _line(result: object) -> bytes:
    """Write one scripted reply to request 7."""
    return json.dumps({"id": 7, "result": result}).encode() + b"\n"


def _entry(tx_id: object, height: object) -> dict[str, object]:
    """Return one history entry, as a server writes it."""
    return {"tx_hash": tx_id, "height": height}


def test_history_request_asks_for_the_script_hash_as_given() -> None:
    """No byte reversal: the caller's spelling goes on the wire."""
    line = electrum.scripthash_get_history_request(7, SCRIPT_HASH)
    assert json.loads(line) == {
        "id": 7,
        "method": "blockchain.scripthash.get_history",
        "params": [SCRIPT_HASH],
    }


@pytest.mark.parametrize("script_hash", ["ab" * 31, " " + SCRIPT_HASH])
def test_history_request_refuses_a_malformed_hash(script_hash: str) -> None:
    """The check `scripthash_get_balance_request` makes."""
    with pytest.raises(BTClibValueError, match="invalid scripthash"):
        electrum.scripthash_get_history_request(7, script_hash)
    with pytest.raises(BTClibTypeError, match="scripthash type"):
        electrum.scripthash_get_history_request(7, None)  # type: ignore[arg-type]


def test_history_response_keeps_the_servers_order() -> None:
    """Confirmed by height, then the two mempool heights, a fee unread."""
    result = [_entry(A, 5), _entry(B, 5), {**_entry(C, -1), "fee": 200}]
    items = electrum.scripthash_get_history_response(_line(result), 7)
    assert items == (
        electrum.HistoryItem(A, 5),
        electrum.HistoryItem(B, 5),
        electrum.HistoryItem(C, -1),
    )
    assert electrum.scripthash_get_history_response(_line([]), 7) == ()


@pytest.mark.parametrize(
    "result, error, match",
    [
        ({}, BTClibTypeError, "not a list"),
        ([[A, 5]], BTClibTypeError, "an entry is not an object"),
        ([_entry(A, "5")], BTClibTypeError, "invalid height type: str"),
        ([_entry(A, True)], BTClibTypeError, "invalid height type: bool"),
        ([_entry(None, 5)], BTClibTypeError, "invalid tx_id type: NoneType"),
        ([_entry("aa", 5)], BTClibValueError, "invalid tx_id: a str of length 2"),
        ([_entry(A, -2)], BTClibValueError, "invalid height -2"),
        ([_entry(A, 6), _entry(B, 5)], BTClibValueError, "out of order"),
        ([_entry(A, 0), _entry(B, 5)], BTClibValueError, "out of order"),
        ([_entry(A, 5), _entry(A, 0)], BTClibValueError, "listed twice"),
        ([_entry(A, 5), _entry(A.upper(), 5)], BTClibValueError, "listed twice"),
    ],
)
def test_history_response_refuses_what_a_history_is_not(
    result: object, error: type[Exception], match: str
) -> None:
    """Each check Electrum's client makes of the answer."""
    with pytest.raises(error, match=match):
        electrum.scripthash_get_history_response(_line(result), 7)


def test_history_response_raises_the_servers_error() -> None:
    """A server refusing a script with too much history says so."""
    line = json.dumps({"id": 7, "error": {"code": 1, "message": "too many"}})
    with pytest.raises(RpcError, match="too many"):
        electrum.scripthash_get_history_response(line.encode(), 7)


def test_history_response_spells_each_txid_in_lower_case() -> None:
    """One transaction is one key, however the server spelled its id."""
    items = electrum.scripthash_get_history_response(_line([_entry(A.upper(), 5)]), 7)
    assert items == (electrum.HistoryItem(A, 5),)
