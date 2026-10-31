# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for btclib_wallet.fetch.history, and `BitcoinCoreFetcher.get_history`.

`FakeNode` answers the calls `get_history` makes from a chain and a
mempool held in memory, the way a node answers them at verbosity 3, so
each test states the chain it reads. `tests/integration/history_test.py`
asks a real node the same questions.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any
from urllib.request import Request

import pytest
from bitcoin_core_rpc import BitcoinCoreRpcClient, RPCErrorCode
from btclib.exceptions import BTClibTypeError, BTClibValueError, FetchError, RpcError
from btclib.script import ScriptPubKey
from btclib.tx import OutPoint, Tx, TxIn, TxOut

from btclib_wallet.fetch import bitcoin_core
from btclib_wallet.fetch.bitcoin_core import BitcoinCoreFetcher
from btclib_wallet.fetch.history import BlockRef, history_scripts
from btclib_wallet.fetch.transport import DEFAULT_MAX_BODY_SIZE
from tests.fetch import chain_mismatch
from tests.fetch.bitcoin_core_test import (
    RPC_PASSWORD,
    RPC_USER,
    URL,
    blockchaininfo,
)
from tests.fetch.bitcoin_core_test import client as rpc_client
from tests.fetch.bitcoin_core_test import recording as rpc_recording

OURS = bytes.fromhex("0014" + "11" * 20)
OTHER = bytes.fromhex("0014" + "22" * 20)


def _tx(prev_outs: list[OutPoint | None], scripts: list[bytes]) -> Tx:
    """Return a transaction spending `prev_outs` and paying to `scripts`.

    `None` among `prev_outs` is a coinbase input.
    """
    vin = [
        TxIn(OutPoint(), b"\x01\x01", 0xFFFFFFFF)
        if prev_out is None
        else TxIn(prev_out, b"", 0xFFFFFFFF)
        for prev_out in prev_outs
    ]
    vout = [TxOut(1_000, script) for script in scripts]
    return Tx(2, 0, vin, vout)


class _RefusedError(Exception):
    """An rpc error the fake node answers, by its code."""

    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code


class FakeNode:
    """An HttpTransport answering `get_history`'s calls from a chain in memory.

    `blocks` is the chain, from height `base` up, each block a list of
    `(tx, prevout scripts)` pairs, one prevout script per input and
    `None` for a coinbase one. `mempool` is the mempool's transactions,
    and `refused` the rpc error code `getrawtransaction` answers for a
    txid instead. `edit` may rewrite any result before it is sent.
    """

    def __init__(
        self,
        blocks: list[list[tuple[Tx, list[bytes | None]]]],
        mempool: list[Tx] | None = None,
        base: int = 0,
    ) -> None:
        self.blocks = blocks
        self.mempool = mempool or []
        self.base = base
        self.hashes = [f"{base + i + 1:064x}" for i in range(len(blocks))]
        self.utxos: list[OutPoint] = []
        self.refused: dict[str, int] = {}
        self.methods: list[str] = []
        self.edit: Callable[[str, Any, Any], Any] = lambda _m, _p, result: result

    def _block(self, block_hash: str) -> dict[str, Any]:
        index = self.hashes.index(block_hash)
        block: dict[str, Any] = {
            "hash": block_hash,
            "height": self.base + index,
            "tx": [_verbose(tx, prevouts) for tx, prevouts in self.blocks[index]],
        }
        if self.base + index > 0:
            block["previousblockhash"] = (
                self.hashes[index - 1] if index else f"{0:064x}"
            )
        return block

    def _result(self, method: str, params: list[Any]) -> Any:
        if method == "getbestblockhash":
            return self.hashes[-1]
        if method == "getblock":
            return self._block(params[0])
        if method == "getrawmempool":
            return [tx.id.hex() for tx in self.mempool]
        if method == "getrawtransaction":
            if params[0] in self.refused:
                raise _RefusedError(self.refused[params[0]])
            tx = next(tx for tx in self.mempool if tx.id.hex() == params[0])
            return tx.serialize(include_witness=True).hex()
        assert method == "scantxoutset"
        return {
            "success": True,
            "bestblock": self.hashes[-1],
            "unspents": [
                {"txid": utxo.tx_id.hex(), "vout": utxo.vout} for utxo in self.utxos
            ],
        }

    def __call__(self, request: Request, timeout: float) -> tuple[int, bytes]:
        """Answer one json-rpc request, as a node does."""
        data = request.data
        assert isinstance(data, bytes)
        asked = json.loads(data)
        method, params = asked["method"], asked["params"] or []
        self.methods.append(method)
        reply: dict[str, Any] = {"jsonrpc": "2.0", "id": asked["id"]}
        try:
            reply["result"] = self.edit(method, params, self._result(method, params))
        except _RefusedError as e:
            reply["error"] = {"code": e.code, "message": f"refused with {e.code}"}
        return 200, json.dumps(reply).encode()


def _verbose(tx: Tx, prevouts: list[bytes | None]) -> dict[str, Any]:
    """Return a transaction as `getblock` renders it at verbosity 3."""
    vin: list[dict[str, Any]] = [
        {"coinbase": "0101"}
        if script is None
        else {"prevout": {"scriptPubKey": {"hex": script.hex()}}}
        for script in prevouts
    ]
    vout = [
        {"scriptPubKey": {"hex": out.script_pub_key.script.hex()}} for out in tx.vout
    ]
    return {
        "txid": tx.id.hex(),
        "hex": tx.serialize(include_witness=True).hex(),
        "vin": vin,
        "vout": vout,
    }


def _fetcher(node: FakeNode) -> BitcoinCoreFetcher:
    """Return a fetcher over `node`, asking it no chain question."""
    client = BitcoinCoreRpcClient(
        URL, user=RPC_USER, password=RPC_PASSWORD, transport=node
    )
    return BitcoinCoreFetcher(client, "regtest", verify_network=False)


COINBASE = _tx([None], [OTHER])
PAYMENT = _tx([OutPoint(COINBASE.id, 0)], [OURS, OTHER])
SPEND = _tx([OutPoint(PAYMENT.id, 0)], [OTHER])
UNRELATED = _tx([OutPoint(COINBASE.id, 0)], [OTHER])


def _chain() -> FakeNode:
    """Return a chain of three blocks: a payment, nothing, a spend."""
    return FakeNode(
        [
            [(COINBASE, [None])],
            [(PAYMENT, [OTHER]), (UNRELATED, [OTHER])],
            [(_tx([None], [OTHER, OTHER]), [None])],
            [(SPEND, [OURS])],
        ]
    )


def test_history_scripts_takes_scripts_and_their_octets() -> None:
    """A `ScriptPubKey`, bytes and hex all name the same script, once."""
    scripts: list[bytes | str | ScriptPubKey] = [
        ScriptPubKey(OURS),
        OURS,
        OURS.hex(),
        OTHER,
    ]
    assert history_scripts(scripts) == {OURS, OTHER}


@pytest.mark.parametrize("scripts", [OURS, OURS.hex(), ScriptPubKey(OURS), 1])
def test_history_scripts_refuses_a_lone_script(scripts: object) -> None:
    """A single script is not an iterable of them, though octets iterate."""
    with pytest.raises(BTClibTypeError, match="not an iterable of scripts"):
        history_scripts(scripts)  # type: ignore[arg-type]


def test_history_scripts_refuses_an_empty_script() -> None:
    """No filter holds an empty script, and `scantxoutset` refuses one."""
    with pytest.raises(BTClibValueError, match="an empty script to look for"):
        history_scripts([OURS, b""])


def test_history_scripts_refuses_no_script() -> None:
    """An empty iterable asks nothing."""
    with pytest.raises(BTClibValueError, match="no scripts to look for"):
        history_scripts([])


def test_get_history_lists_payments_and_spends_in_chain_order() -> None:
    """From genesis: each transaction touching the script, with its block."""
    node = _chain()
    history = _fetcher(node).get_history([OURS])
    assert [(entry.tx.id, entry.block) for entry in history.txs] == [
        (PAYMENT.id, BlockRef(1, bytes.fromhex(node.hashes[1]))),
        (SPEND.id, BlockRef(3, bytes.fromhex(node.hashes[3]))),
    ]
    assert history.start == BlockRef(0, bytes.fromhex(node.hashes[0]))
    assert history.tip == BlockRef(3, bytes.fromhex(node.hashes[3]))
    # an empty mempool needs no scan of the utxo set
    assert "scantxoutset" not in node.methods


def test_get_history_reads_from_the_start_height_up() -> None:
    """A block below `start_height` is not read."""
    node = _chain()
    history = _fetcher(node).get_history([OURS], 2)
    assert [entry.tx.id for entry in history.txs] == [SPEND.id]
    assert history.start.height == 2
    assert node.methods.count("getblock") == 2


def test_get_history_from_the_tip_reads_one_block() -> None:
    """`start` is `tip` where the call starts at the tip."""
    node = FakeNode([[(COINBASE, [None])], [(PAYMENT, [OTHER])]], base=7)
    history = _fetcher(node).get_history([OURS], 8)
    assert history.start == history.tip == BlockRef(8, bytes.fromhex(node.hashes[1]))
    assert [entry.tx.id for entry in history.txs] == [PAYMENT.id]


def test_get_history_starts_from_the_tip_of_a_shorter_chain() -> None:
    """A chain ending below `start_height` is read from its tip.

    The caller's own tip was at height 4; a `start` at height 3 says a
    reorganization replaced it with a shorter chain.
    """
    node = _chain()
    node.mempool = [_tx([OutPoint(SPEND.id, 0)], [OURS])]
    history = _fetcher(node).get_history([OURS], 4)
    assert history.start == history.tip == BlockRef(3, bytes.fromhex(node.hashes[3]))
    assert [(entry.tx.id, entry.block) for entry in history.txs] == [
        (SPEND.id, history.tip),
        (node.mempool[0].id, None),
    ]


def test_get_history_checks_its_arguments_before_any_request() -> None:
    """A negative height and a lone script are refused without a call."""
    node = _chain()
    with pytest.raises(BTClibValueError, match="invalid height"):
        _fetcher(node).get_history([OURS], -1)
    with pytest.raises(BTClibTypeError, match="not an iterable of scripts"):
        _fetcher(node).get_history(OURS)  # type: ignore[arg-type]
    assert node.methods == []


def test_get_history_verifies_the_network_first() -> None:
    """A node on another chain is refused before any block is read."""
    endpoint = rpc_client(blockchaininfo(chain="test"))
    with pytest.raises(BTClibValueError, match=chain_mismatch("test", "main")):
        BitcoinCoreFetcher(endpoint).get_history([OURS])
    assert len(rpc_recording(endpoint).requests) == 1


def test_get_history_lists_the_mempool_last_and_unconfirmed() -> None:
    """A mempool payment, and the mempool's spends of a utxo and of it."""
    funding = _tx([OutPoint(COINBASE.id, 0)], [OURS])
    child = _tx([OutPoint(funding.id, 0)], [OTHER])
    old = OutPoint(bytes(range(32)), 3)
    spend_of_old = _tx([old], [OTHER])
    unrelated = _tx([OutPoint(bytes(32), 1)], [OTHER])
    node = FakeNode([[(COINBASE, [None])]], [unrelated, child, spend_of_old, funding])
    node.utxos = [old]
    history = _fetcher(node).get_history([OURS])
    assert [(entry.tx.id, entry.block) for entry in history.txs] == [
        (child.id, None),
        (spend_of_old.id, None),
        (funding.id, None),
    ]


def test_get_history_skips_a_transaction_that_left_the_mempool() -> None:
    """Listed by `getrawmempool`, gone by `getrawtransaction`: skipped."""
    funding = _tx([OutPoint(COINBASE.id, 0)], [OURS])
    node = FakeNode([[(COINBASE, [None])]], [funding])
    node.refused = {funding.id.hex(): int(RPCErrorCode.INVALID_ADDRESS_OR_KEY)}
    assert _fetcher(node).get_history([OURS]).txs == ()


def test_get_history_raises_any_other_rpc_error() -> None:
    """Only the node not having the transaction is a skip."""
    node = FakeNode([[(COINBASE, [None])]], [PAYMENT])
    node.refused = {PAYMENT.id.hex(): int(RPCErrorCode.IN_WARMUP)}
    with pytest.raises(RpcError, match="refused with -28") as raised:
        _fetcher(node).get_history([OURS])
    assert raised.value.code == RPCErrorCode.IN_WARMUP


def test_get_history_refuses_an_answer_whose_tip_moved() -> None:
    """A block arriving while the history is read voids the answer."""
    node = _chain()
    moved = iter([node.hashes[-1], node.hashes[-2]])

    def move(method: str, _params: Any, result: Any) -> Any:
        return next(moved) if method == "getbestblockhash" else result

    node.edit = move
    with pytest.raises(FetchError, match="the tip moved"):
        _fetcher(node).get_history([OURS])


def _edited(node: FakeNode, method: str, change: Callable[[Any], Any]) -> FakeNode:
    """Return `node`, with `change` applied to its replies to `method`."""
    node.edit = lambda m, _p, result: change(result) if m == method else result
    return node


def _set(result: dict[str, Any], key: str, value: Any) -> dict[str, Any]:
    """Return `result` with `key` set to `value`."""
    result[key] = value
    return result


def _without_prevout(result: dict[str, Any]) -> dict[str, Any]:
    """Return a block whose spending inputs name no previous output."""
    for entry in result["tx"]:
        for tx_in in entry["vin"]:
            tx_in.pop("prevout", None)
    return result


@pytest.mark.parametrize(
    "method, change, match",
    [
        ("getblock", lambda r: _set(r, "hash", "00" * 32), "the answer is block"),
        ("getblock", lambda r: _set(r, "height", 9), "the answer is at height 9"),
        ("getblock", lambda r: _set(r, "height", "2"), "the answer is at height 2"),
        ("getblock", lambda _r: [], "no 'hash' member"),
        ("getblock", _without_prevout, "no 'prevout' member"),
        ("getbestblockhash", lambda _r: "xx", "getbestblockhash"),
        ("getrawmempool", lambda _r: {}, "not an array: dict"),
        ("getrawmempool", lambda _r: ["00"], "getrawmempool"),
        ("scantxoutset", lambda r: _set(r, "success", False), "did not complete"),
        ("scantxoutset", lambda r: _set(r, "bestblock", "00" * 32), "read at 00"),
    ],
)
def test_get_history_refuses_a_malformed_answer(
    method: str, change: Callable[[Any], Any], match: str
) -> None:
    """Every answer the node gives is checked; a wrong one is a FetchError."""
    node = _chain()
    node.mempool = [_tx([OutPoint(SPEND.id, 0)], [OTHER])]
    with pytest.raises(FetchError, match=match):
        _fetcher(_edited(node, method, change)).get_history([OURS], 1)


@pytest.mark.parametrize(
    "method", ["getblock", "getrawmempool", "scantxoutset", "getbestblockhash"]
)
def test_a_reply_over_its_bound_is_refused(method: str) -> None:
    """Each reply `get_history` reads is refused past the bound it carries."""
    bound = (
        bitcoin_core._MAX_SMALL_REPLY
        if method == "getbestblockhash"
        else bitcoin_core._MAX_LARGE_REPLY
    )
    node = _chain()
    node.mempool = [_tx([OutPoint(SPEND.id, 0)], [OTHER])]
    padding = "0" * bound
    node.edit = lambda m, _p, result: [result, padding] if m == method else result
    with pytest.raises(FetchError, match=f"more than the max_body_size of {bound}"):
        _fetcher(node).get_history([OURS], 1)


def test_a_block_over_the_clients_default_is_read() -> None:
    """A verbosity 3 block may weigh more than the client's default allows."""
    node = _chain()
    padding = "0" * DEFAULT_MAX_BODY_SIZE

    def pad(method: str, _params: Any, result: Any) -> Any:
        return _set(result, "padding", padding) if method == "getblock" else result

    node.edit = pad
    history = _fetcher(node).get_history([OURS], 3)
    assert [entry.tx.id for entry in history.txs] == [SPEND.id]


def test_the_replies_that_grow_with_the_chain_carry_the_large_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Which bound each call of `get_history` carries, by method."""
    node = _chain()
    node.mempool = [_tx([OutPoint(SPEND.id, 0)], [OTHER])]
    fetcher = _fetcher(node)
    bounds: dict[str, int | None] = {}
    call = fetcher.client.call

    def recording(method: str, params: Any, **kwargs: Any) -> Any:
        bounds[method] = kwargs.get("max_body_size")
        return call(method, params, **kwargs)

    monkeypatch.setattr(fetcher.client, "call", recording)
    fetcher.get_history([OURS], 1)
    assert bounds == {
        "getbestblockhash": bitcoin_core._MAX_SMALL_REPLY,
        "getblock": bitcoin_core._MAX_LARGE_REPLY,
        "getrawmempool": bitcoin_core._MAX_LARGE_REPLY,
        "getrawtransaction": None,
        "scantxoutset": bitcoin_core._MAX_LARGE_REPLY,
    }
