# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `EsploraFetcher.get_history`, against an explorer in memory.

`FakeEsplora` answers the paths `get_history` asks from the chain
`tests/fetch/electrum_history_test.py`'s `FakeServer` mines, as electrs
answers them: a script's confirmed transactions newest first, by height
and then by txid, `page` of them at a time.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any
from urllib.request import Request

import pytest
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import sha256
from btclib.tx import OutPoint

from btclib_wallet.exceptions import FetchError
from btclib_wallet.fetch import esplora
from btclib_wallet.fetch.esplora import EsploraFetcher
from tests.fetch.electrum_history_test import (
    FIRST,
    FUNDING,
    MINE,
    SECOND,
    SPEND,
    FakeServer,
)
from tests.fetch.esplora_test import BASE, TESTNET_GENESIS
from tests.fetch.history_test import OURS, _tx


class FakeEsplora:
    """An HttpTransport answering `get_history`'s paths from a chain.

    `edit` may rewrite any reply before it is sent, keyed on what the path
    asks: `tip`, `height`, `block-height`, `chain`, `mempool`, `stats` or
    `txids`.
    """

    def __init__(self, server: FakeServer, page: int = 25) -> None:
        self.server = server
        self.page = page
        self.paths: list[str] = []
        self.edit: Callable[[str, Any], Any] = lambda _kind, reply: reply

    def _entries(self, scripthash: str) -> list[dict[str, Any]]:
        """Return what touches the script, as electrs lists it, newest first."""
        reversed_hash = bytes.fromhex(scripthash)[::-1].hex()
        entries = []
        for item in self.server._history(reversed_hash):
            status: dict[str, Any] = {"confirmed": item["height"] > 0}
            if status["confirmed"]:
                status["block_height"] = item["height"]
                block = self.server.chain[item["height"]]
                status["block_hash"] = block.header.hash.hex()
            entries.append({"txid": item["tx_hash"], "status": status})
        return entries

    def _reply(self, path: str) -> tuple[str, Any]:
        chain = self.server.chain
        parts = path.split("/")[1:]
        if path == "/blocks/tip/hash":
            return "tip", chain[-1].header.hash.hex()
        if path == "/blocks/tip/height":
            return "height", len(chain) - 1
        if parts[0] == "block-height":
            return "block-height", chain[int(parts[1])].header.hash.hex()
        if parts[0] == "block":
            block = next(b for b in chain if b.header.hash.hex() == parts[1])
            return "txids", [tx.id.hex() for tx in block.transactions]
        assert parts[0] == "tx"
        txs = [tx for b in chain for tx in b.transactions] + self.server.mempool
        tx = next(tx for tx in txs if tx.id.hex() == parts[1])
        return "tx", tx.serialize(include_witness=True).hex()

    def _script_reply(self, parts: list[str]) -> tuple[str, Any]:
        entries = self._entries(parts[1])
        mempool = [entry for entry in entries if not entry["status"]["confirmed"]]
        if len(parts) == 2:
            return "stats", {
                "scripthash": parts[1],
                "chain_stats": {"tx_count": len(entries) - len(mempool)},
                "mempool_stats": {"tx_count": len(mempool)},
            }
        if parts[3] == "mempool":
            return "mempool", mempool
        confirmed = sorted(
            (entry for entry in entries if entry["status"]["confirmed"]),
            key=lambda entry: (entry["status"]["block_height"], entry["txid"]),
            reverse=True,
        )
        if len(parts) == 5:
            seen = [entry["txid"] for entry in confirmed].index(parts[4])
            confirmed = confirmed[seen + 1 :]
        return "chain", confirmed[: self.page]

    def __call__(self, request: Request, timeout: float) -> tuple[int, bytes]:
        """Answer one GET, as an explorer does."""
        path = request.full_url.removeprefix(BASE)
        self.paths.append(path)
        parts = path.split("/")[1:]
        if parts[0] == "scripthash":
            kind, reply = self._script_reply(parts)
        else:
            kind, reply = self._reply(path)
        reply = self.edit(kind, reply)
        body = reply if isinstance(reply, str) else json.dumps(reply)
        return 200, body.encode()


def _fetcher(explorer: FakeEsplora) -> EsploraFetcher:
    """Return a fetcher over `explorer`, asking it no chain question."""
    return EsploraFetcher(
        BASE, network="regtest", transport=explorer, verify_network=False
    )


def _explorer(page: int = 25) -> FakeEsplora:
    """Return an explorer of a chain paying OURS and spending it, then MINE."""
    return FakeEsplora(FakeServer([[FUNDING], [], [SPEND], [FIRST, SECOND]]), page)


def _chain_pages(explorer: FakeEsplora) -> list[str]:
    """Return the pages of confirmed transactions asked, in order."""
    return [path for path in explorer.paths if "/txs/chain" in path]


def test_get_history_lists_each_transaction_in_chain_order() -> None:
    """Across two scripts, pages and one block, by height and position."""
    explorer = _explorer(page=1)
    history = _fetcher(explorer).get_history([OURS, MINE])
    server = explorer.server
    assert [(entry.tx.id, entry.block) for entry in history.txs] == [
        (FUNDING.id, server.ref(1)),
        (SPEND.id, server.ref(3)),
        (FIRST.id, server.ref(4)),
        (SECOND.id, server.ref(4)),
    ]
    assert history.start == server.ref(0)
    assert history.tip == server.ref(4)
    # one page a transaction, and an empty page after the last
    ours = sha256(OURS).hex()
    assert _chain_pages(explorer)[:3] == [
        f"/scripthash/{ours}/txs/chain",
        f"/scripthash/{ours}/txs/chain/{SPEND.id.hex()}",
        f"/scripthash/{ours}/txs/chain/{FUNDING.id.hex()}",
    ]


def test_get_history_reads_from_the_start_height_up() -> None:
    """No page is asked past a transaction below `start_height`."""
    explorer = _explorer(page=1)
    history = _fetcher(explorer).get_history([OURS], 2)
    assert [entry.tx.id for entry in history.txs] == [SPEND.id]
    assert history.start == explorer.server.ref(2)
    assert len(_chain_pages(explorer)) == 2


def test_get_history_from_above_the_tip_starts_at_the_tip() -> None:
    """A chain ending below `start_height` is read from its tip."""
    explorer = _explorer()
    history = _fetcher(explorer).get_history([MINE], 9)
    assert history.start == history.tip == explorer.server.ref(4)
    assert [entry.tx.id for entry in history.txs] == [FIRST.id, SECOND.id]


def test_get_history_lists_the_mempool_last_and_once() -> None:
    """A mempool transaction touching two scripts is listed once."""
    both = _tx([OutPoint(SPEND.id, 0)], [OURS, MINE])
    explorer = FakeEsplora(FakeServer([[FUNDING]], [both]))
    history = _fetcher(explorer).get_history([OURS, MINE])
    assert [(entry.tx.id, entry.block) for entry in history.txs] == [
        (FUNDING.id, explorer.server.ref(1)),
        (both.id, None),
    ]


def test_a_mempool_entry_also_confirmed_is_listed_confirmed() -> None:
    """A transaction mined between the two reads is not listed twice."""
    explorer = _explorer()
    explorer.edit = lambda kind, reply: (
        [{"txid": SPEND.id.hex()}] if kind == "mempool" else reply
    )
    history = _fetcher(explorer).get_history([OURS])
    assert [entry.tx.id for entry in history.txs] == [FUNDING.id, SPEND.id]


def test_a_mempool_list_shorter_than_its_count_is_refused() -> None:
    """An explorer caps the list, and the count says what it left out."""
    explorer = FakeEsplora(FakeServer([[FUNDING]], [SPEND]))
    explorer.edit = lambda kind, reply: [] if kind == "mempool" else reply
    with pytest.raises(FetchError, match="0 of 1 mempool transactions listed"):
        _fetcher(explorer).get_history([OURS])


def _with(kind: str, change: Callable[[Any], Any]) -> FakeEsplora:
    """Return an explorer whose replies of `kind` `change` rewrites."""
    explorer = _explorer()
    explorer.edit = lambda k, reply: change(reply) if k == kind else reply
    return explorer


def _status(entry: dict[str, Any], **status: Any) -> dict[str, Any]:
    """Return a chain entry with members of its status replaced."""
    return {**entry, "status": {**entry["status"], **status}}


@pytest.mark.parametrize(
    "kind, change, match",
    [
        ("block-height", lambda _r: "00" * 32, "the tip moved"),
        ("tip", lambda _r: "00" * 32, "the tip moved"),
        ("height", lambda _r: 3, "the tip moved"),
        ("chain", lambda r: [_status(e, block_height=9) for e in r], "the tip moved"),
    ],
)
def test_an_answer_whose_tip_moved_is_refused(
    kind: str, change: Callable[[Any], Any], match: str
) -> None:
    """The tip is read as a hash, a height and the hash at that height."""
    with pytest.raises(FetchError, match=match):
        _fetcher(_with(kind, change)).get_history([OURS])


def test_a_tip_hash_read_again_last_must_not_move() -> None:
    """The last read of `/blocks/tip/hash` is compared with the first."""
    explorer = _explorer()
    hashes = iter([explorer.server.ref(4).block_id.hex(), "00" * 32])
    explorer.edit = lambda kind, reply: next(hashes) if kind == "tip" else reply
    with pytest.raises(FetchError, match="the tip moved"):
        _fetcher(explorer).get_history([OURS])


def test_a_block_not_at_its_height_is_refused() -> None:
    """The block an entry names is the one at its height, or nothing holds."""
    explorer = _explorer()
    tip, genesis, other = (explorer.server.ref(h).block_id.hex() for h in (4, 0, 2))
    # the tip's, the start's, and then the one of the payment's block
    heights = iter([tip, genesis, other])
    explorer.edit = lambda kind, reply: (
        next(heights, reply) if kind == "block-height" else reply
    )
    with pytest.raises(FetchError, match="is not at height 1"):
        _fetcher(explorer).get_history([OURS])


def test_a_transaction_not_in_its_block_is_refused() -> None:
    """`/block/<hash>/txids` must list it."""
    explorer = _with("txids", lambda r: r[:1])
    with pytest.raises(FetchError, match=f"no transaction {FUNDING.id.hex()}"):
        _fetcher(explorer).get_history([OURS])


def test_a_transaction_listed_in_two_blocks_is_refused() -> None:
    """Two scripts may not disagree on where a transaction is."""
    both = _tx([OutPoint(bytes(32), 0)], [OURS, MINE])
    explorer = FakeEsplora(FakeServer([[both], []]))
    mine = sha256(MINE).hex()
    block = explorer.server.ref(2).block_id.hex()

    def move(kind: str, reply: Any) -> Any:
        if kind == "chain" and reply and mine in explorer.paths[-1]:
            return [_status(reply[0], block_height=2, block_hash=block)]
        return reply

    explorer.edit = move
    with pytest.raises(FetchError, match="listed in two blocks"):
        _fetcher(explorer).get_history([OURS, MINE])


@pytest.mark.parametrize(
    "change, match",
    [
        (lambda r: r[::-1], "not newest first"),
        (lambda r: [r[0], r[0]], "listed twice"),
        (lambda _r: {}, "not an array: dict"),
        (lambda r: [_status(r[0], confirmed=False)], "is not confirmed"),
        (lambda r: [_status(r[0], block_height="3")], "invalid block_height: '3'"),
        (lambda r: [{"status": r[0]["status"]}], "no 'txid' member"),
    ],
)
def test_a_page_of_the_chain_that_is_not_one_is_refused(
    change: Callable[[Any], Any], match: str
) -> None:
    """Each page is read whole and checked before any entry is used."""
    with pytest.raises(FetchError, match=match):
        _fetcher(_with("chain", change)).get_history([OURS])


@pytest.mark.parametrize(
    "kind, change, match",
    [
        ("stats", lambda _r: [], "not an object: list"),
        ("stats", lambda r: {**r, "mempool_stats": None}, "not an object"),
        ("stats", lambda r: {**r, "mempool_stats": {}}, "invalid tx_count: None"),
        ("mempool", lambda _r: {}, "not an array: dict"),
        ("txids", lambda _r: {}, "not an array: dict"),
    ],
)
def test_an_answer_that_is_not_one_is_refused(
    kind: str, change: Callable[[Any], Any], match: str
) -> None:
    """The counts, the mempool's list and a block's txids are checked."""
    with pytest.raises(FetchError, match=match):
        _fetcher(_with(kind, change)).get_history([OURS])


def test_get_history_checks_its_arguments_before_any_request() -> None:
    """A negative height and a lone script are refused without a request."""
    explorer = _explorer()
    with pytest.raises(BTClibValueError, match="invalid height"):
        _fetcher(explorer).get_history([OURS], -1)
    with pytest.raises(BTClibTypeError, match="not an iterable of scripts"):
        _fetcher(explorer).get_history(OURS)  # type: ignore[arg-type]
    assert explorer.paths == []


def test_get_history_verifies_the_network_first() -> None:
    """An explorer on another chain is refused before any history is asked."""
    explorer = _with("block-height", lambda _r: TESTNET_GENESIS)
    endpoint = EsploraFetcher(BASE, network="regtest", transport=explorer)
    with pytest.raises(BTClibValueError, match=TESTNET_GENESIS):
        endpoint.get_history([OURS])
    assert explorer.paths == ["/block-height/0"]


def test_the_txids_of_a_block_are_bounded_by_its_weight() -> None:
    """The bound admits a block of the lightest transactions, not one more."""
    lightest = 4_000_000 // (4 * 60)
    compact = (",", ":")
    txids = ["00" * 32] * lightest
    assert len(json.dumps(txids, separators=compact)) <= esplora._MAX_TXIDS_BODY
    txids.append("00" * 32)
    assert len(json.dumps(txids, separators=compact)) > esplora._MAX_TXIDS_BODY
