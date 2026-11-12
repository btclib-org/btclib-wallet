# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `ElectrumFetcher.get_history`, against a server in memory.

`FakeServer` answers the methods `get_history` asks from a regtest chain
mined in memory, so each header carries its proof of work and the merkle
root of its transactions, and each branch it answers is one a real server
would. It lists a script's confirmed transactions by height and then by
txid, as electrs does, and not by their position in the block.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import timedelta
from typing import Any

import pytest
from btclib.block.block import Block
from btclib.block.block_header import BlockHeader
from btclib.block.build import build_block, build_coinbase
from btclib.block.genesis import genesis_block
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash256, sha256
from btclib.script.witness import Witness
from btclib.tx import OutPoint, Tx, TxIn, TxOut

from btclib_wallet.exceptions import FetchError, RpcError
from btclib_wallet.fetch.electrum import ElectrumFetcher
from btclib_wallet.fetch.history import BlockRef
from tests.fetch.electrum_test import TESTNET_GENESIS, TESTNET_GENESIS_HEADER
from tests.fetch.history_test import OTHER, OURS, _tx
from tests.fetch.peer_chain_test import REGTEST_BITS, REGTEST_HALVING, mined
from tests.refused_value_test import KEY, SPELLINGS
from tests.secret_free import assert_secret_free

MINE = bytes.fromhex("0014" + "33" * 20)


def _branch(tx_ids: list[bytes], pos: int) -> list[str]:
    """Return the merkle branch of the transaction at `pos`, display order."""
    level = [tx_id[::-1] for tx_id in tx_ids]
    branch: list[str] = []
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        branch.append(level[pos ^ 1][::-1].hex())
        level = [hash256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        pos //= 2
    return branch


class FakeServer:
    """A LineTransport answering `get_history`'s methods from a chain in memory.

    `blocks` holds the transactions of each block above the genesis one,
    its coinbase left out, and `mempool` those of the mempool. `edit` may
    rewrite any result before it is sent.
    """

    def __init__(self, blocks: list[list[Tx]], mempool: list[Tx] | None = None) -> None:
        self.chain: list[Block] = [genesis_block("regtest")]
        for height, txs in enumerate(blocks, 1):
            coinbase = build_coinbase(height, OTHER, halving_interval=REGTEST_HALVING)
            time = self.chain[-1].header.time + timedelta(seconds=1)
            block = build_block(
                self.chain[-1].header.hash, [coinbase, *txs], time, REGTEST_BITS
            )
            block.header = mined(block.header)
            self.chain.append(block)
        self.mempool = mempool or []
        self.max_headers = 2016
        self.methods: list[str] = []
        self.edit: Callable[[str, list[Any], Any], Any] = lambda _m, _p, result: result

    def _history(self, scripthash: str) -> list[dict[str, Any]]:
        """Return what touches the script whose hash is `scripthash`."""
        paid: dict[OutPoint, bytes] = {}
        confirmed: list[tuple[int, str]] = []
        unconfirmed: list[str] = []
        for height, txs in [(h, b.transactions) for h, b in enumerate(self.chain)] + [
            (0, self.mempool)
        ]:
            for tx in txs:
                for vout, tx_out in enumerate(tx.vout):
                    paid[OutPoint(tx.id, vout)] = tx_out.script_pub_key.script
                scripts = [out.script_pub_key.script for out in tx.vout]
                scripts += [paid.get(tx_in.prev_out, b"") for tx_in in tx.vin]
                if any(sha256(script)[::-1].hex() == scripthash for script in scripts):
                    if height:
                        confirmed.append((height, tx.id.hex()))
                    else:
                        unconfirmed.append(tx.id.hex())
        return [{"tx_hash": t, "height": h} for h, t in sorted(confirmed)] + [
            {"tx_hash": t, "height": 0, "fee": 100} for t in unconfirmed
        ]

    def _result(self, method: str, params: list[Any]) -> Any:
        if method == "blockchain.headers.subscribe":
            tip = self.chain[-1].header
            return {"height": len(self.chain) - 1, "hex": tip.serialize().hex()}
        if method == "blockchain.block.header":
            return self.chain[params[0]].header.serialize().hex()
        if method == "blockchain.block.headers":
            start, count = params
            blocks = self.chain[start : start + min(count, self.max_headers)]
            raw = b"".join(block.header.serialize() for block in blocks)
            return {"count": len(blocks), "hex": raw.hex(), "max": self.max_headers}
        if method == "blockchain.scripthash.get_history":
            return self._history(params[0])
        txs = [tx for block in self.chain for tx in block.transactions] + self.mempool
        if method == "blockchain.transaction.get":
            tx = next(tx for tx in txs if tx.id.hex() == params[0])
            return tx.serialize(include_witness=True).hex()
        assert method == "blockchain.transaction.get_merkle"
        tx_ids = [tx.id for tx in self.chain[params[1]].transactions]
        pos = tx_ids.index(bytes.fromhex(params[0]))
        return {"block_height": params[1], "merkle": _branch(tx_ids, pos), "pos": pos}

    def __call__(self, request: bytes, timeout: float) -> bytes:
        """Answer one request line, as a server does."""
        asked = json.loads(request)
        method, params = asked["method"], asked["params"]
        self.methods.append(method)
        if method == "blockchain.transaction.get" and params[0] not in self._tx_ids():
            error = {"code": 2, "message": "transaction not found"}
            return json.dumps({"id": asked["id"], "error": error}).encode()
        result = self.edit(method, params, self._result(method, params))
        return json.dumps({"id": asked["id"], "result": result}).encode()

    def _tx_ids(self) -> set[str]:
        """Return the ids of the transactions of the chain and the mempool."""
        txs = [tx for block in self.chain for tx in block.transactions]
        return {tx.id.hex() for tx in txs + self.mempool}

    def ref(self, height: int) -> BlockRef:
        """Return the block at `height`, as a history names it."""
        return BlockRef(height, self.chain[height].header.hash)


def _fetcher(server: FakeServer) -> ElectrumFetcher:
    """Return a fetcher over `server`, asking it no chain question."""
    return ElectrumFetcher("regtest", transport=server, verify_network=False)


FUNDING = _tx([OutPoint(bytes(32), 0)], [OURS])
SPEND = _tx([OutPoint(FUNDING.id, 0)], [OTHER])
# a block where a txid sorting before another's comes after it
FIRST, SECOND = sorted(
    (_tx([OutPoint(bytes(32), i)], [MINE]) for i in range(1, 9)),
    key=lambda tx: tx.id,
    reverse=True,
)[:2]


def _spending_funding(witness: bytes) -> Tx:
    """Return a transaction spending FUNDING:0 with `witness` as its stack."""
    tx_in = TxIn(OutPoint(FUNDING.id, 0), b"", 0, Witness([witness]))
    return Tx(2, 0, [tx_in], [TxOut(1, OTHER)])


def _chain() -> FakeServer:
    """Return a chain paying and spending OURS, then paying MINE twice."""
    return FakeServer([[FUNDING], [], [SPEND], [FIRST, SECOND]])


def test_get_history_lists_each_transaction_in_chain_order() -> None:
    """Across two scripts and within one block, by height and position."""
    server = _chain()
    history = _fetcher(server).get_history([OURS, MINE])
    assert [(entry.tx.id, entry.block) for entry in history.txs] == [
        (FUNDING.id, server.ref(1)),
        (SPEND.id, server.ref(3)),
        (FIRST.id, server.ref(4)),
        (SECOND.id, server.ref(4)),
    ]
    assert history.start == server.ref(0)
    assert history.tip == server.ref(4)
    # what the server listed second is first in the block
    (listed,) = server._history(sha256(MINE)[::-1].hex())[1:]
    assert listed["tx_hash"] == FIRST.id.hex()


def test_get_history_reads_from_the_start_height_up() -> None:
    """A transaction below `start_height` is left out, and its proof unasked."""
    server = _chain()
    history = _fetcher(server).get_history([OURS], 2)
    assert [entry.tx.id for entry in history.txs] == [SPEND.id]
    assert history.start == server.ref(2)
    assert server.methods.count("blockchain.transaction.get_merkle") == 1
    # FUNDING is asked for to learn that SPEND spends an output of OURS
    assert server.methods.count("blockchain.transaction.get") == 2


def test_get_history_from_above_the_tip_starts_at_the_tip() -> None:
    """A chain ending below `start_height` is read from its tip."""
    server = _chain()
    history = _fetcher(server).get_history([MINE], 9)
    assert history.start == history.tip == server.ref(4)
    assert [entry.tx.id for entry in history.txs] == [FIRST.id, SECOND.id]


def test_get_history_lists_the_mempool_last_and_once() -> None:
    """A mempool transaction touching two scripts is listed once."""
    both = _tx([OutPoint(SPEND.id, 0)], [OURS, MINE])
    server = FakeServer([[FUNDING]], [both])
    history = _fetcher(server).get_history([OURS, MINE])
    assert [(entry.tx.id, entry.block) for entry in history.txs] == [
        (FUNDING.id, server.ref(1)),
        (both.id, None),
    ]


def test_a_mempool_transaction_gone_mid_read_is_the_servers_error() -> None:
    """Listed by `get_history`, gone by `transaction.get`: an `RpcError`."""
    server = FakeServer([[FUNDING]], [SPEND])

    def gone(request: bytes, timeout: float) -> bytes:
        asked = json.loads(request)
        if asked["params"] == [SPEND.id.hex()]:
            error = {"code": 2, "message": "transaction not found"}
            return json.dumps({"id": asked["id"], "error": error}).encode()
        return server(request, timeout)

    fetcher = ElectrumFetcher("regtest", transport=gone, verify_network=False)
    err_msg = "^blockchain.transaction.get: the server answered an error"
    with pytest.raises(RpcError, match=err_msg) as raised:
        fetcher.get_history([OURS])
    assert isinstance(raised.value, FetchError)
    assert raised.value.code == 2


def test_a_transaction_spelled_two_ways_is_listed_once() -> None:
    """Two scripts naming one txid in different case name one transaction."""
    both = _tx([OutPoint(bytes(32), 0)], [OURS, MINE])
    server = FakeServer([[both]])

    def shout(method: str, params: list[Any], result: Any) -> Any:
        if method == "blockchain.scripthash.get_history" and params[0] == (
            sha256(MINE)[::-1].hex()
        ):
            return [{**item, "tx_hash": item["tx_hash"].upper()} for item in result]
        return result

    server.edit = shout
    history = _fetcher(server).get_history([OURS, MINE])
    assert [(entry.tx.id, entry.block) for entry in history.txs] == [
        (both.id, server.ref(1))
    ]


def _edited(
    server: FakeServer, method: str, change: Callable[[Any], Any]
) -> FakeServer:
    """Return `server`, with `change` applied to its results for `method`."""
    server.edit = lambda m, _p, result: change(result) if m == method else result
    return server


def test_a_transaction_touching_none_of_the_scripts_is_left_out() -> None:
    """Neither an output nor an input of each is of OURS (issue #703)."""
    # spending an output of MINE, and an output FUNDING does not have
    of_mine = _tx([OutPoint(SECOND.id, 0)], [OTHER])
    beyond = _tx([OutPoint(FUNDING.id, 5)], [OTHER])
    server = FakeServer([[FUNDING], [], [SPEND], [FIRST, SECOND], [of_mine]], [beyond])
    coinbase = server.chain[4].transactions[0]
    added = [
        {"tx_hash": coinbase.id.hex(), "height": 4},
        {"tx_hash": of_mine.id.hex(), "height": 5},
        {"tx_hash": beyond.id.hex(), "height": 0},
    ]
    server = _edited(
        server, "blockchain.scripthash.get_history", lambda result: result + added
    )
    history = _fetcher(server).get_history([OURS])
    assert [(entry.tx.id, entry.block) for entry in history.txs] == [
        (FUNDING.id, server.ref(1)),
        (SPEND.id, server.ref(3)),
    ]


def test_a_transaction_spending_one_no_server_has_is_refused() -> None:
    """FIRST pays MINE and spends a transaction the server does not serve."""
    server = _edited(
        _chain(),
        "blockchain.scripthash.get_history",
        lambda result: [*result, {"tx_hash": FIRST.id.hex(), "height": 4}],
    )
    err_msg = "^blockchain.transaction.get: the server answered an error"
    with pytest.raises(RpcError, match=err_msg):
        _fetcher(server).get_history([OURS])


def test_a_witness_is_the_servers_word() -> None:
    """A changed witness keeps the txid, and comes back (issue #704)."""
    witnessed, forged = _spending_funding(b"\x01"), _spending_funding(b"\x02")
    assert forged.id == witnessed.id
    assert forged.hash != witnessed.hash
    server = FakeServer([[FUNDING], [witnessed]])

    def forge(method: str, params: list[Any], result: Any) -> Any:
        if method == "blockchain.transaction.get" and params == [witnessed.id.hex()]:
            return forged.serialize(include_witness=True).hex()
        return result

    server.edit = forge
    history = _fetcher(server).get_history([OURS])
    assert [entry.tx.hash for entry in history.txs] == [FUNDING.hash, forged.hash]


def test_a_confirmed_transaction_listed_in_the_mempool_is_unconfirmed() -> None:
    """The server's word that a transaction is not mined stands (issue #709)."""

    def demote(result: Any) -> Any:
        return [
            {**item, "height": 0} if item["tx_hash"] == SPEND.id.hex() else item
            for item in result
        ]

    server = _edited(_chain(), "blockchain.scripthash.get_history", demote)
    history = _fetcher(server).get_history([OURS])
    assert [(entry.tx.id, entry.block) for entry in history.txs] == [
        (FUNDING.id, server.ref(1)),
        (SPEND.id, None),
    ]


def test_a_transaction_listed_at_two_heights_is_refused() -> None:
    """Two scripts may not disagree on where a transaction is."""
    both = _tx([OutPoint(bytes(32), 0)], [OURS, MINE])
    server = FakeServer([[both]])

    def move(method: str, params: list[Any], result: Any) -> Any:
        if method == "blockchain.scripthash.get_history" and params[0] == (
            sha256(MINE)[::-1].hex()
        ):
            return [{"tx_hash": both.id.hex(), "height": 0}]
        return result

    server.edit = move
    with pytest.raises(FetchError, match="listed at two heights"):
        _fetcher(server).get_history([OURS, MINE])


def test_a_transaction_above_the_tip_is_refused() -> None:
    """A block arriving after the tip was read is a tip that moved."""
    server = _edited(
        _chain(),
        "blockchain.scripthash.get_history",
        lambda result: [*result, {"tx_hash": "aa" * 32, "height": 5}],
    )
    with pytest.raises(FetchError, match="the tip moved"):
        _fetcher(server).get_history([OURS])


def test_an_answer_whose_tip_moved_is_refused() -> None:
    """The tip is asked again last."""
    server = _chain()
    moved = iter([4, 3])

    def move(method: str, _params: list[Any], result: Any) -> Any:
        if method == "blockchain.headers.subscribe":
            height = next(moved)
            return {
                "height": height,
                "hex": server.chain[height].header.serialize().hex(),
            }
        return result

    server.edit = move
    with pytest.raises(FetchError, match="the tip moved"):
        _fetcher(server).get_history([OURS])


def test_a_branch_that_proves_nothing_is_refused() -> None:
    """The merkle branch is checked against the header at the height."""
    server = _edited(
        _chain(),
        "blockchain.transaction.get_merkle",
        lambda result: {**result, "merkle": ["00" * 32] * len(result["merkle"])},
    )
    with pytest.raises(FetchError, match="no proof it is in block 1"):
        _fetcher(server).get_history([OURS])


def _forged(server: FakeServer, height: int) -> BlockHeader:
    """Return another header for the block at `height`, with its work.

    It holds the block's transactions, so their branches prove them in it.
    """
    block = server.chain[height]
    time = block.header.time + timedelta(seconds=1)
    header = build_block(
        block.header.previous_block_hash, block.transactions, time, REGTEST_BITS
    ).header
    return mined(header)


def _serving(server: FakeServer, height: int, header: BlockHeader) -> FakeServer:
    """Return `server`, answering `header` at `height` in its chunks."""

    def swap(method: str, params: list[Any], result: Any) -> Any:
        if method != "blockchain.block.headers":
            return result
        start = params[0]
        if not start <= height < start + result["count"]:
            return result
        raw = bytearray.fromhex(result["hex"])
        offset = (height - start) * 80
        raw[offset : offset + 80] = header.serialize()
        return {**result, "hex": raw.hex()}

    server.edit = swap
    return server


def test_get_history_reads_the_chain_from_the_lowest_confirmation() -> None:
    """One chunk from the lowest confirmation to the tip, and no lone header."""
    server = _chain()
    history = _fetcher(server).get_history([MINE], 4)
    assert [entry.block for entry in history.txs] == [server.ref(4)] * 2
    assert "blockchain.block.header" not in server.methods
    assert server.methods.count("blockchain.block.headers") == 1


def test_a_start_at_the_lowest_confirmation_is_taken_from_the_chain() -> None:
    """A lone header the server forges for `start` is never asked for."""
    server = _chain()
    forged = _forged(server, 1).serialize().hex()
    server.edit = lambda m, p, result: (
        forged if m == "blockchain.block.header" and p == [1] else result
    )
    history = _fetcher(server).get_history([OURS], 1)
    assert history.start == server.ref(1)
    assert history.txs[0].block == server.ref(1)
    assert "blockchain.block.header" not in server.methods


def test_a_start_at_the_tip_with_nothing_confirmed_is_the_tip() -> None:
    """No chain to read and no lone header to ask for."""
    server = _chain()
    history = _fetcher(server).get_history([OURS], 9)
    assert history.start == history.tip == server.ref(4)
    assert not history.txs
    assert "blockchain.block.header" not in server.methods
    assert "blockchain.block.headers" not in server.methods


def test_get_history_reads_the_chain_in_the_servers_chunks() -> None:
    """A server answering fewer headers than asked is asked for the rest."""
    server = _chain()
    server.max_headers = 1
    history = _fetcher(server).get_history([OURS, MINE])
    assert [entry.block for entry in history.txs] == [
        server.ref(1),
        server.ref(3),
        server.ref(4),
        server.ref(4),
    ]
    assert server.methods.count("blockchain.block.headers") == 4


def test_a_history_with_nothing_confirmed_reads_no_chain() -> None:
    """Without a confirmed transaction there is no header to chain."""
    server = FakeServer([[]], [FUNDING])
    history = _fetcher(server).get_history([OURS])
    assert [(entry.tx.id, entry.block) for entry in history.txs] == [(FUNDING.id, None)]
    assert "blockchain.block.headers" not in server.methods


@pytest.mark.parametrize("max_headers", [1, 2016])
def test_a_header_with_its_work_but_not_on_the_chain_is_refused(
    max_headers: int,
) -> None:
    """A header the next one does not follow, within a chunk or across two."""
    server = _chain()
    server.max_headers = max_headers
    forged = _forged(server, 1)
    forged.assert_valid_pow(REGTEST_BITS)
    _serving(server, 1, forged)
    with pytest.raises(
        FetchError, match="header 1 of the answer|header 2 does not follow"
    ):
        _fetcher(server).get_history([OURS])


def test_a_chain_that_ends_away_from_the_tip_is_refused() -> None:
    """The last header has to be the one `headers.subscribe` answered."""
    server = _chain()
    _serving(server, 4, _forged(server, 4))
    with pytest.raises(FetchError, match="the chain does not end at the tip"):
        _fetcher(server).get_history([MINE])


def test_a_chain_that_stops_below_the_tip_is_refused() -> None:
    """A server answering no header below the tip is refused, not asked on."""
    server = _edited(
        _chain(),
        "blockchain.block.headers",
        lambda result: {**result, "count": 0, "hex": ""},
    )
    with pytest.raises(FetchError, match="none from 1 up to the tip at 4"):
        _fetcher(server).get_history([OURS])


def test_a_history_that_is_not_one_is_refused() -> None:
    """The codec's refusal leaves as a FetchError naming the request."""
    server = _edited(_chain(), "blockchain.scripthash.get_history", lambda _r: {})
    with pytest.raises(
        FetchError, match="^script history: scripthash.get_history: not a list"
    ):
        _fetcher(server).get_history([OURS])


def test_get_history_checks_its_arguments_before_any_request() -> None:
    """A negative height and a lone script are refused without a call."""
    server = _chain()
    with pytest.raises(BTClibValueError, match="invalid height"):
        _fetcher(server).get_history([OURS], -1)
    with pytest.raises(BTClibTypeError, match="not an iterable of scripts"):
        _fetcher(server).get_history(OURS)  # type: ignore[arg-type]
    assert server.methods == []


def test_get_history_verifies_the_network_first() -> None:
    """A server on another chain is refused before any history is asked."""
    server = _edited(
        _chain(), "blockchain.block.header", lambda _r: TESTNET_GENESIS_HEADER
    )
    endpoint = ElectrumFetcher("regtest", transport=server)
    with pytest.raises(BTClibValueError, match=TESTNET_GENESIS):
        endpoint.get_history([OURS])
    assert server.methods == ["blockchain.block.header"]


def test_a_history_label_carries_no_hash_of_the_script() -> None:
    """A script hash confirms a guess at the script (issue #805)."""
    server = _edited(_chain(), "blockchain.scripthash.get_history", lambda _r: {})
    err_msg = "^script history: scripthash.get_history: not a list$"
    with pytest.raises(FetchError, match=err_msg) as e:
        _fetcher(server).get_history([KEY])
    assert_secret_free(
        e.value, [*SPELLINGS, sha256(KEY).hex(), sha256(KEY)[::-1].hex()]
    )
