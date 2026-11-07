# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What the fetchers answer after a reorg, against a live `electrs`.

`CachingFetcher` caches `get_block_header` for ever and says why that is
safe: a reorg can replace the block at a height, and the headers a caller
builds a chain of then fail the `previous_block_hash` link to the stale
one. Here the node mines a block holding a
payment, a longer branch replaces that block, and the payment is replaced
by a conflicting one in the new branch.

`get_history` follows a script through a mempool arrival, a confirmation
and a reorganization, as `tests/integration/history_test.py` follows it
over the node's RPC.

Skipped unless `BTCLIB_INTEGRATION=1` and `BTCLIB_ELECTRS` names the
server's binary.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

import pytest
from btclib.block.block_header import BlockHeader

from btclib_wallet.exceptions import FetchError
from btclib_wallet.fetch.decorators import CachingFetcher
from btclib_wallet.fetch.electrum import ElectrumFetcher
from btclib_wallet.fetch.esplora import EsploraFetcher
from btclib_wallet.fetch.history import ScriptHistory
from tests.integration.conftest import (
    Stack,
    electrs_binary,
    make_fetcher,
    running_stack,
)

pytestmark = pytest.mark.integration


@pytest.fixture
def stack(
    bitcoind_path: str, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[Stack]:
    """Return a stack of its own, which this test is free to reorganize."""
    with running_stack(bitcoind_path, electrs_binary(), tmp_path_factory) as running:
        yield running


@dataclass(frozen=True)
class Spend:
    """A signed spend of one output, and its id."""

    hex: str
    tx_id: str


def _spend(wallet: Any, utxo: dict[str, Any], fee: str) -> Spend:
    """Return a signed spend of `utxo` to a new address, paying `fee`.

    The same output spent twice with different fees gives two transactions
    that cannot both be mined: the dearer one replaces the other in the
    mempool.
    """
    address = str(wallet.call("getnewaddress"))
    amount = f"{Decimal(str(utxo['amount'])) - Decimal(fee):.8f}"
    raw = wallet.call(
        "createrawtransaction",
        [[{"txid": utxo["txid"], "vout": utxo["vout"]}], {address: amount}, 0, True],
    )
    signed = wallet.call("signrawtransactionwithwallet", [raw])["hex"]
    return Spend(signed, str(wallet.call("decoderawtransaction", [signed])["txid"]))


@pytest.mark.parametrize("kind", ["electrum", "esplora"])
def test_fetchers_follow_the_chain_that_replaced_a_block(
    kind: str, stack: Stack
) -> None:
    """The new branch's headers and transactions replace the old ones."""
    node = stack.node
    fetcher = CachingFetcher(make_fetcher(kind, stack))
    utxo = node.call("listunspent")[0]
    old_spend = _spend(node, utxo, "0.0001")
    new_spend = _spend(node, utxo, "0.0002")
    node.call("sendrawtransaction", [old_spend.hex])
    (old_block,) = stack.mine()
    height = int(node.call("getblockcount"))

    # what a caller holds from before: the header at the height, cached
    old_header = fetcher.get_block_header(height)
    assert old_header.hash.hex() == old_block
    assert fetcher.get_tx(old_spend.tx_id).id.hex() == old_spend.tx_id
    if kind == "electrum":
        assert isinstance(fetcher.fetcher, ElectrumFetcher)
        assert fetcher.fetcher.verify_tx(old_spend.tx_id, height)

    # the reorganization: the block goes, its payment is replaced in the
    # mempool by the conflicting one, and the new branch is one block longer
    node.call("invalidateblock", [old_block])
    node.call("sendrawtransaction", [new_spend.hex])
    new_blocks = stack.mine(2)

    assert fetcher.get_block_count() == height + 1
    assert fetcher.get_best_block_id().hex() == new_blocks[-1]
    fresh = fetcher.fetcher.get_block_header(height)
    assert fresh.hash.hex() == new_blocks[0]
    assert fresh.hash != old_header.hash

    # the cache still holds the old header, as its docstring says it will;
    # the link from the new branch's next header is what exposes it
    assert fetcher.get_block_header(height) == old_header
    child = fetcher.get_block_header(height + 1)
    assert isinstance(child, BlockHeader)
    assert child.previous_block_hash == fresh.hash
    assert child.previous_block_hash != fetcher.get_block_header(height).hash

    # the transactions are the new branch's. The replaced one is still a
    # transaction, and `get_tx` does not say whether it is confirmed
    assert fetcher.get_tx(new_spend.tx_id).id.hex() == new_spend.tx_id
    assert fetcher.fetcher.get_tx(old_spend.tx_id).id.hex() == old_spend.tx_id
    if kind == "electrum":
        assert isinstance(fetcher.fetcher, ElectrumFetcher)
        assert fetcher.fetcher.verify_tx(new_spend.tx_id, height)
        with pytest.raises(FetchError, match="tx not found or is unconfirmed"):
            fetcher.fetcher.get_tx_merkle(old_spend.tx_id, height)
    else:
        new_status = stack.http_json(f"/tx/{new_spend.tx_id}/status")
        assert new_status["confirmed"]
        assert new_status["block_hash"] == new_blocks[0]
        assert not stack.http_json(f"/tx/{old_spend.tx_id}/status")["confirmed"]


# how long the server may take to see a mempool transaction: electrs polls
# the node's mempool, where it follows blocks as `Stack.wait_synced` waits
_MEMPOOL_TIMEOUT = 60


def _ids(history: ScriptHistory) -> list[tuple[str, int | None]]:
    """Return each listed transaction's id, and its block's height or None."""
    return [
        (entry.tx.id.hex(), None if entry.block is None else entry.block.height)
        for entry in history.txs
    ]


def _settled(
    fetcher: ElectrumFetcher | EsploraFetcher,
    script: bytes,
    start: int,
    want: list[tuple[str, int | None]],
) -> ScriptHistory:
    """Return the history once it lists `want`, the server having caught up."""
    deadline = time.monotonic() + _MEMPOOL_TIMEOUT
    while True:
        history = fetcher.get_history([script], start)
        if _ids(history) == want:
            return history
        if time.monotonic() > deadline:
            pytest.fail(f"the history is {_ids(history)}, not {want}")
        time.sleep(0.2)


@pytest.mark.parametrize("kind", ["electrum", "esplora"])
def test_the_history_follows_a_confirmation_a_mempool_arrival_and_a_reorg(
    kind: str, stack: Stack
) -> None:
    """Each answer lists the script's transactions on the chain it names."""
    node = stack.node
    fetcher = make_fetcher(kind, stack)
    assert isinstance(fetcher, (ElectrumFetcher, EsploraFetcher))
    address = node.call("getnewaddress")
    script = bytes.fromhex(node.call("getaddressinfo", [address])["scriptPubKey"])
    start = int(node.call("getblockcount"))

    # a payment in the mempool: no block of the chain holds it
    payment = str(node.call("sendtoaddress", [address, "1.0"]))
    history = _settled(fetcher, script, start, [(payment, None)])
    assert history.start == history.tip
    assert history.tip.block_id.hex() == node.call("getbestblockhash")

    # the payment confirmed, and an empty block above it
    (confirming,) = stack.mine()
    stack.mine()
    history = _settled(fetcher, script, start, [(payment, start + 1)])
    assert history.txs[0].block is not None
    assert history.txs[0].block.block_id.hex() == confirming
    assert history.tip.height == start + 2

    # a spend of it in the mempool
    vout = next(
        out["n"]
        for out in node.call("getrawtransaction", [payment, 1])["vout"]
        if out["scriptPubKey"]["hex"] == script.hex()
    )
    utxo = {"txid": payment, "vout": vout, "amount": Decimal("1.0")}
    spend = _spend(node, utxo, "0.0001")
    node.call("sendrawtransaction", [spend.hex])
    _settled(fetcher, script, start, [(payment, start + 1), (spend.tx_id, None)])

    # the spend confirmed: the caller holds this answer's tip
    (spent_in,) = stack.mine()
    held = _settled(
        fetcher, script, start, [(payment, start + 1), (spend.tx_id, start + 3)]
    )
    assert held.tip.block_id.hex() == spent_in

    # the block that held the spend is invalidated and none replaces it: the
    # chain ends below the tip the caller holds, the answer starts at the new
    # tip, and the spend is back in the mempool
    node.call("invalidateblock", [spent_in])
    stack.wait_synced()
    history = _settled(fetcher, script, held.tip.height, [(spend.tx_id, None)])
    assert history.start == history.tip
    assert history.start.height == held.tip.height - 1

    # a block without the spend takes the height back, and is another block
    node.call("generateblock", [stack.reward_address, []])
    stack.wait_synced()
    history = _settled(fetcher, script, held.tip.height, [(spend.tx_id, None)])
    assert history.start.height == held.tip.height
    assert history.start != held.tip
