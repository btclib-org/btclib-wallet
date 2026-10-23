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

Skipped unless `BTCLIB_INTEGRATION=1` and `BTCLIB_ELECTRS` names the
server's binary.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

import pytest
from btclib.block.block_header import BlockHeader

from btclib_wallet.exceptions import FetchError
from btclib_wallet.fetch.decorators import CachingFetcher
from btclib_wallet.fetch.electrum import ElectrumFetcher
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
