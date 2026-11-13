# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `BitcoinCoreRestFetcher.get_history`, against a node in memory.

`FakeRest` answers the paths `get_history` asks from a chain and a mempool
held in memory, as `-rest` answers them. The blocks are rendered as
`tests/fetch/history_test.py`'s `FakeNode` renders them for `getblock`,
which `-rest` renders the same way; that module tests the checks the two
backends share.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any
from urllib.request import Request

import pytest
from bitcoin_core_rpc import BitcoinCoreRestClient
from btclib.exceptions import BTClibValueError
from btclib.tx import OutPoint

from btclib_wallet.exceptions import FetchError, HttpError
from btclib_wallet.fetch import bitcoin_core, bitcoin_core_rest
from btclib_wallet.fetch.bitcoin_core_rest import BitcoinCoreRestFetcher
from btclib_wallet.fetch.history import BlockRef
from tests.fetch import chain_mismatch
from tests.fetch.bitcoin_core_rest_test import URL
from tests.fetch.history_test import (
    COINBASE,
    OTHER,
    OURS,
    PAYMENT,
    SPEND,
    UNRELATED,
    FakeNode,
    _tx,
)
from tests.refused_value_test import HEX, SPELLINGS
from tests.secret_free import assert_secret_free


class FakeRest:
    """An HttpTransport answering `-rest` paths from a `FakeNode`'s chain.

    `utxos` maps each output of the chain to its script; `gone` is the
    status `/tx` answers for a txid instead; `edit` may rewrite any json
    reply before it is sent, keyed on the path's first part.
    """

    def __init__(self, node: FakeNode) -> None:
        self.node = node
        self.utxos: dict[OutPoint, bytes] = {}
        self.gone: dict[str, int] = {}
        self.paths: list[str] = []
        self.edit: Callable[[str, Any], Any] = lambda _kind, reply: reply

    def _json(self, path: str) -> Any:
        if path == "/chaininfo.json":
            return {"bestblockhash": self.node.hashes[-1]}
        if path.startswith("/block/"):
            return self.node._block(path[len("/block/") : -len(".json")])
        if path == "/mempool/contents.json?verbose=false":
            return [tx.id.hex() for tx in self.node.mempool]
        assert path.startswith("/getutxos/")
        asked = [
            OutPoint(tx_id, int(vout))
            for tx_id, vout in re.findall(r"([0-9a-f]{64})-(\d+)", path)
        ]
        hits = [out for out in asked if out in self.utxos]
        return {
            "chainHeight": len(self.node.hashes) - 1,
            "chaintipHash": self.node.hashes[-1],
            "bitmap": "".join("1" if out in self.utxos else "0" for out in asked),
            "utxos": [{"scriptPubKey": {"hex": self.utxos[out].hex()}} for out in hits],
        }

    def __call__(self, request: Request, timeout: float) -> tuple[int, bytes]:
        """Answer one `-rest` request, as a node does."""
        path = request.full_url.removeprefix(f"{URL}/rest")
        self.paths.append(path)
        if path.startswith("/tx/"):
            tx_id = path[len("/tx/") : -len(".bin")]
            if tx_id in self.gone:
                return self.gone[tx_id], b"not found"
            tx = next(tx for tx in self.node.mempool if tx.id.hex() == tx_id)
            return 200, tx.serialize(include_witness=True)
        kind = path.split("/")[1].split(".")[0]
        return 200, json.dumps(self.edit(kind, self._json(path))).encode()


def _fetcher(rest: FakeRest) -> BitcoinCoreRestFetcher:
    """Return a fetcher over `rest`, asking it no chain question."""
    client = BitcoinCoreRestClient(URL, transport=rest)
    return BitcoinCoreRestFetcher(client, "regtest", verify_network=False)


def _chain() -> FakeNode:
    """Return a chain of four blocks: a payment, nothing, a spend."""
    return FakeNode(
        [
            [(COINBASE, [None])],
            [(PAYMENT, [OTHER]), (UNRELATED, [OTHER])],
            [(_tx([None], [OTHER, OTHER]), [None])],
            [(SPEND, [OURS])],
        ]
    )


def test_get_history_lists_payments_and_spends_in_chain_order() -> None:
    """From genesis: each transaction touching the script, with its block."""
    rest = FakeRest(_chain())
    history = _fetcher(rest).get_history([OURS])
    hashes = rest.node.hashes
    assert [(entry.tx.id, entry.block) for entry in history.txs] == [
        (PAYMENT.id, BlockRef(1, bytes.fromhex(hashes[1]))),
        (SPEND.id, BlockRef(3, bytes.fromhex(hashes[3]))),
    ]
    assert history.start == BlockRef(0, bytes.fromhex(hashes[0]))
    assert history.tip == BlockRef(3, bytes.fromhex(hashes[3]))
    # an empty mempool asks nothing of the utxo set
    assert not [path for path in rest.paths if path.startswith("/getutxos/")]


def test_get_history_reads_from_the_start_height_up() -> None:
    """A block below `start_height` is not read, nor one above the tip."""
    rest = FakeRest(_chain())
    history = _fetcher(rest).get_history([OURS], 2)
    assert [entry.tx.id for entry in history.txs] == [SPEND.id]
    assert history.start.height == 2
    assert [path for path in rest.paths if path.startswith("/block/")] == [
        f"/block/{rest.node.hashes[3]}.json",
        f"/block/{rest.node.hashes[2]}.json",
    ]
    history = _fetcher(rest).get_history([OURS], 9)
    assert history.start == history.tip


def test_get_history_lists_the_mempool_last_and_unconfirmed() -> None:
    """A mempool payment, and the mempool's spends of a utxo and of it."""
    funding = _tx([OutPoint(COINBASE.id, 0)], [OURS])
    child = _tx([OutPoint(funding.id, 0)], [OTHER])
    old = OutPoint(bytes(range(32)), 3)
    spend_of_old = _tx([old], [OTHER])
    unrelated = _tx([OutPoint(bytes(32), 1)], [OTHER])
    node = FakeNode([[(COINBASE, [None])]], [unrelated, child, spend_of_old, funding])
    rest = FakeRest(node)
    rest.utxos = {old: OURS, OutPoint(bytes(32), 1): OTHER}
    history = _fetcher(rest).get_history([OURS])
    assert [(entry.tx.id, entry.block) for entry in history.txs] == [
        (child.id, None),
        (spend_of_old.id, None),
        (funding.id, None),
    ]
    # the input that spends a mempool output is not asked of the chain
    (asked,) = [path for path in rest.paths if path.startswith("/getutxos/")]
    assert funding.id.hex() not in asked


def test_getutxos_is_asked_fifteen_outputs_at_a_time() -> None:
    """Core refuses a request naming more than `MAX_GETUTXOS_OUTPOINTS`."""
    outs = [OutPoint(bytes([i]) * 32, i) for i in range(16)]
    spends = [_tx([out], [OTHER]) for out in outs]
    rest = FakeRest(FakeNode([[(COINBASE, [None])]], spends))
    rest.utxos = dict.fromkeys(outs, OTHER)
    rest.utxos[outs[-1]] = OURS
    history = _fetcher(rest).get_history([OURS])
    assert [entry.tx.id for entry in history.txs] == [spends[-1].id]
    asked = [path for path in rest.paths if path.startswith("/getutxos/")]
    assert [path.count("-") for path in asked] == [15, 1]
    assert bitcoin_core_rest._MAX_GETUTXOS_OUTPOINTS == 15


def test_get_history_skips_a_transaction_that_left_the_mempool() -> None:
    """Listed by `/mempool/contents`, gone by `/tx`: skipped."""
    funding = _tx([OutPoint(COINBASE.id, 0)], [OURS])
    rest = FakeRest(FakeNode([[(COINBASE, [None])]], [funding]))
    rest.gone = {funding.id.hex(): 404}
    assert _fetcher(rest).get_history([OURS]).txs == ()


def test_get_history_lists_a_mempool_txid_listed_twice_once() -> None:
    """A txid `/mempool/contents` repeats is asked for and listed once."""
    funding = _tx([OutPoint(COINBASE.id, 0)], [OURS])
    rest = FakeRest(FakeNode([[(COINBASE, [None])]], [funding]))
    rest.edit = lambda kind, reply: reply * 2 if kind == "mempool" else reply
    history = _fetcher(rest).get_history([OURS])
    assert [(entry.tx.id, entry.block) for entry in history.txs] == [(funding.id, None)]
    assert [path for path in rest.paths if path.startswith("/tx/")] == [
        f"/tx/{funding.id.hex()}.bin"
    ]


def test_get_history_raises_any_other_http_error() -> None:
    """Only the node not having the transaction is a skip."""
    rest = FakeRest(FakeNode([[(COINBASE, [None])]], [PAYMENT]))
    rest.gone = {PAYMENT.id.hex(): 503}
    with pytest.raises(HttpError) as raised:
        _fetcher(rest).get_history([OURS])
    assert raised.value.status == 503


def test_get_history_refuses_an_answer_whose_tip_moved() -> None:
    """A block arriving while the history is read voids the answer."""
    rest = FakeRest(_chain())
    moved = iter([rest.node.hashes[-1], rest.node.hashes[-2]])

    def move(kind: str, reply: Any) -> Any:
        return {"bestblockhash": next(moved)} if kind == "chaininfo" else reply

    rest.edit = move
    with pytest.raises(FetchError, match="the tip moved"):
        _fetcher(rest).get_history([OURS])


def _set(reply: dict[str, Any], key: str, value: Any) -> dict[str, Any]:
    """Return `reply` with `key` set to `value`."""
    reply[key] = value
    return reply


@pytest.mark.parametrize(
    "kind, change, match",
    [
        ("block", lambda r: _set(r, "height", 9), "the answer is at height 9"),
        ("chaininfo", lambda _r: {}, "no 'bestblockhash' member"),
        ("mempool", lambda _r: {}, "not an array: dict"),
        ("getutxos", lambda r: _set(r, "chaintipHash", "00" * 32), "read at 00"),
        (
            "getutxos",
            lambda r: _set(r, "bitmap", "10"),
            "invalid bitmap: a str of length 2",
        ),
        ("getutxos", lambda r: _set(r, "bitmap", None), "invalid bitmap: a NoneType"),
        (
            "getutxos",
            lambda r: _set(r, "bitmap", HEX),
            "invalid bitmap: a str of length 64",
        ),
        ("getutxos", lambda r: _set(r, "utxos", []), "not an output for each hit"),
        ("getutxos", lambda r: _set(r, "utxos", {}), "not an output for each hit"),
        ("getutxos", lambda _r: [], "no 'chaintipHash' member"),
    ],
)
def test_get_history_refuses_a_malformed_answer(
    kind: str, change: Callable[[Any], Any], match: str
) -> None:
    """Every answer the node gives is checked; a wrong one is a FetchError."""
    rest = FakeRest(_chain())
    old = OutPoint(bytes(range(32)), 3)
    rest.node.mempool = [_tx([old], [OTHER])]
    rest.utxos = {old: OURS}
    rest.edit = lambda k, reply: change(reply) if k == kind else reply
    with pytest.raises(FetchError, match=": a malformed answer") as e:
        _fetcher(rest).get_history([OURS], 3)
    assert_secret_free(e.value, SPELLINGS)


def test_get_history_verifies_the_network_first() -> None:
    """A node on another chain is refused before any block is read."""
    rest = FakeRest(_chain())
    rest.edit = lambda kind, reply: {"chain": "test"} if kind == "chaininfo" else reply
    client = BitcoinCoreRestClient(URL, transport=rest)
    with pytest.raises(BTClibValueError, match=chain_mismatch("test", "main")):
        BitcoinCoreRestFetcher(client).get_history([OURS])
    assert rest.paths == ["/chaininfo.json"]


def test_each_path_of_get_history_carries_its_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Which bound each request of `get_history` carries, by path."""
    rest = FakeRest(_chain())
    old = OutPoint(bytes(range(32)), 3)
    rest.node.mempool = [_tx([old], [OTHER])]
    fetcher = _fetcher(rest)
    bounds: dict[str, int | None] = {}
    get_json, get_bin = fetcher.client.get_json, fetcher.client.get_bin

    def json_bound(path: str, **kwargs: Any) -> Any:
        bounds[path.split("/")[1].split(".", maxsplit=1)[0]] = kwargs.get(
            "max_body_size"
        )
        return get_json(path, **kwargs)

    def bin_bound(path: str, **kwargs: Any) -> bytes:
        bounds["tx"] = kwargs.get("max_body_size")
        return get_bin(path, **kwargs)

    monkeypatch.setattr(fetcher.client, "get_json", json_bound)
    monkeypatch.setattr(fetcher.client, "get_bin", bin_bound)
    fetcher.get_history([OURS], 3)
    assert bounds == {
        "chaininfo": bitcoin_core_rest._MAX_CHAININFO_BODY,
        "block": bitcoin_core._MAX_LARGE_REPLY,
        "mempool": bitcoin_core._MAX_MEMPOOL_REPLY,
        "tx": None,
        "getutxos": bitcoin_core._MAX_LARGE_REPLY,
    }
