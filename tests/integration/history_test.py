# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What `BitcoinCoreFetcher.get_history` answers on a regtest chain.

A payment to a script arrives in the mempool and is confirmed; a spend of
it arrives in the mempool and is confirmed; the block that confirmed the
spend is invalidated, and a block without the spend later takes its
height. The node's wallet pays and spends;
the history is read from the node's blocks, mempool and utxo set.
"""

from __future__ import annotations

import pytest
from bitcoin_core_rpc import BitcoinCoreRpcClient

from btclib_wallet.fetch.bitcoin_core import BitcoinCoreFetcher
from btclib_wallet.fetch.history import ScriptHistory

pytestmark = pytest.mark.integration


def _ids(history: ScriptHistory) -> list[tuple[str, int | None]]:
    """Return each listed transaction's id, and its block's height or None."""
    return [
        (entry.tx.id.hex(), None if entry.block is None else entry.block.height)
        for entry in history.txs
    ]


def test_the_history_follows_a_confirmation_a_mempool_arrival_and_a_reorg(
    node: BitcoinCoreRpcClient,
    wallets: tuple[BitcoinCoreRpcClient, BitcoinCoreRpcClient],
) -> None:
    """Each answer lists the script's transactions on the chain it names."""
    miner = wallets[0]
    miner.call("generatetoaddress", [101, miner.call("getnewaddress")])
    address = miner.call("getnewaddress")
    script = bytes.fromhex(miner.call("getaddressinfo", [address])["scriptPubKey"])
    fetcher = BitcoinCoreFetcher(node, "regtest")
    start = int(node.call("getblockcount"))

    # a payment in the mempool: no block of the chain holds it
    payment = miner.call("sendtoaddress", [address, "1.0"])
    history = fetcher.get_history([script], start)
    assert _ids(history) == [(payment, None)]
    assert history.start == history.tip
    assert history.tip.block_id.hex() == node.call("getbestblockhash")

    # the payment confirmed, and an empty block above it
    (confirming,) = miner.call("generatetoaddress", [1, miner.call("getnewaddress")])
    miner.call("generatetoaddress", [1, miner.call("getnewaddress")])
    history = fetcher.get_history([script], start)
    assert _ids(history) == [(payment, start + 1)]
    assert history.txs[0].block is not None
    assert history.txs[0].block.block_id.hex() == confirming
    assert history.tip.height == start + 2

    # a spend in the mempool, asked from above the block of the output it
    # spends: only the utxo set says the output is the script's
    vout = next(
        out["n"]
        for out in miner.call("getrawtransaction", [payment, 1])["vout"]
        if out["scriptPubKey"]["hex"] == script.hex()
    )
    unsigned = miner.call(
        "createrawtransaction",
        [[{"txid": payment, "vout": vout}], {miner.call("getnewaddress"): "0.999"}],
    )
    signed = miner.call("signrawtransactionwithwallet", [unsigned])["hex"]
    spend = node.call("sendrawtransaction", [signed])
    history = fetcher.get_history([script], start + 2)
    assert _ids(history) == [(spend, None)]

    # the spend confirmed: the caller holds this answer's tip
    (spent_in,) = miner.call("generatetoaddress", [1, miner.call("getnewaddress")])
    held = fetcher.get_history([script], start)
    assert _ids(held) == [(payment, start + 1), (spend, start + 3)]
    assert held.tip.block_id.hex() == spent_in

    # the block that held the spend is invalidated and none replaces it:
    # the chain ends below the tip the caller holds, the answer starts at
    # the new tip, and the spend is back in the mempool
    node.call("invalidateblock", [spent_in])
    history = fetcher.get_history([script], held.tip.height)
    assert history.start == history.tip
    assert history.start.height == held.tip.height - 1
    assert _ids(history) == [(spend, None)]

    # a block without the spend takes the height back, and is another block
    node.call("generateblock", [miner.call("getnewaddress"), []])
    history = fetcher.get_history([script], held.tip.height)
    assert history.start.height == held.tip.height
    assert history.start != held.tip
    assert _ids(history) == [(spend, None)]
    history = fetcher.get_history([script], start)
    assert _ids(history) == [(payment, start + 1), (spend, None)]
