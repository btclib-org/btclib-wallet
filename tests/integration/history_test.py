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
from bitcoin_core_rpc import BitcoinCoreRpcClient, FetchError
from btclib.consensus import MAX_BLOCK_WEIGHT
from btclib.script import ScriptPubKey, Witness, serialize
from btclib.tx import OutPoint, Tx, TxIn, TxOut

from btclib_wallet.fetch import bitcoin_core
from btclib_wallet.fetch.bitcoin_core import BitcoinCoreFetcher
from btclib_wallet.fetch.history import ScriptHistory
from btclib_wallet.fetch.transport import DEFAULT_MAX_BODY_SIZE

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


def test_a_block_of_large_witnesses_renders_within_the_bound(
    node: BitcoinCoreRpcClient,
    wallets: tuple[BitcoinCoreRpcClient, BitcoinCoreRpcClient],
) -> None:
    """`getblock` at verbosity 3 writes each witness octet twice as hex.

    Spends of a p2wsh script that drops 99 pushes of 520 octets fill a
    block with witness. Its rendering weighs more than three octets per
    weight unit and less than five: more than the client's default, and
    within the bound `get_history` reads blocks with.
    """
    miner = wallets[0]
    address = miner.call("getnewaddress")
    miner.call("generatetoaddress", [101, address])
    script = serialize(["OP_2DROP"] * 49 + ["OP_DROP", "OP_1"])
    p2wsh = ScriptPubKey.p2wsh(script, "regtest")
    funding = []
    # a block every ten payments, so that no chain of unconfirmed change
    # outgrows what the mempool accepts
    for _ in range(7):
        funding += [
            miner.call("sendtoaddress", [p2wsh.address, "0.01"]) for _ in range(10)
        ]
        miner.call("generatetoaddress", [1, address])
    vin = []
    for tx_id in funding:
        tx = Tx.parse(node.call("getrawtransaction", [tx_id]))
        vout = next(
            i
            for i, out in enumerate(tx.vout)
            if out.script_pub_key.script == p2wsh.script
        )
        stack = [bytes([i]) * 520 for i in range(99)]
        vin.append(
            TxIn(OutPoint(tx.id, vout), b"", 0xFFFFFFFF, Witness([*stack, script]))
        )
    payee = ScriptPubKey.from_address(address)
    spend = Tx(2, 0, vin, [TxOut(len(vin) * 1_000_000 - 2_000_000, payee)])
    raw = spend.serialize(include_witness=True).hex()
    block = node.call("generateblock", [address, [raw]])["hash"]
    weight = node.call("getblock", [block, 1])["weight"]

    assert 3 * weight > DEFAULT_MAX_BODY_SIZE
    with pytest.raises(FetchError, match="more than the max_body_size"):
        node.call("getblock", [block, 3], max_body_size=3 * weight)
    node.call("getblock", [block, 3], max_body_size=5 * weight)
    assert bitcoin_core._MAX_LARGE_REPLY == 5 * MAX_BLOCK_WEIGHT

    height = node.call("getblock", [block, 1])["height"]
    history = BitcoinCoreFetcher(node, "regtest").get_history([p2wsh], height)
    assert [entry.tx.id for entry in history.txs] == [spend.id]
