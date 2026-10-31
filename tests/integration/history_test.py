# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What `BitcoinCoreFetcher.get_history` answers on a regtest chain.

A payment to a script arrives in the mempool and is confirmed; a spend of
it arrives in the mempool and is confirmed; the block that confirmed the
spend is invalidated, and a block without the spend later takes its
height. The node's wallet pays and spends; the history is read from the
node's blocks, mempool and utxo set.

The rest hold what the bounds on `get_history`'s replies rest on, as
`bitcoin_core`'s comments on them say.
"""

from __future__ import annotations

import pytest
from bitcoin_core_rpc import BitcoinCoreRpcClient, FetchError
from btclib.consensus import MAX_BLOCK_WEIGHT
from btclib.hashes import hash160
from btclib.script import ScriptPubKey, Witness, serialize
from btclib.script.sig_hash import ALL, legacy
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from ecc.curves import secp256k1
from ecc.curves.curve import mult
from ecc.curves.sec_point import bytes_from_point
from ecc.ecc.dsa import sign_

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


def _fund(
    miner: BitcoinCoreRpcClient, scripts: list[bytes], value: int
) -> list[OutPoint]:
    """Pay `value` to each script from the miner's wallet, and confirm it.

    The template spends one of the wallet's coins, so that its serialization
    is not read as one with a witness; `fundrawtransaction` adds the rest.
    """
    coin = max(miner.call("listunspent", [1]), key=lambda utxo: utxo["amount"])
    prev_out = OutPoint(bytes.fromhex(coin["txid"]), coin["vout"])
    template = Tx(
        2,
        0,
        [TxIn(prev_out, b"", 0xFFFFFFFD)],
        [TxOut(value, script) for script in scripts],
        check_validity=False,
    )
    unsigned = template.serialize(include_witness=False, check_validity=False)
    funded = miner.call("fundrawtransaction", [unsigned.hex()])["hex"]
    signed = miner.call("signrawtransactionwithwallet", [funded])["hex"]
    tx_id = bytes.fromhex(miner.call("sendrawtransaction", [signed]))
    miner.call("generatetoaddress", [1, miner.call("getnewaddress")])
    return [
        OutPoint(tx_id, i)
        for i, tx_out in enumerate(Tx.parse(signed).vout)
        if tx_out.script_pub_key.script in scripts and tx_out.value == value
    ]


def test_a_block_of_bare_multisig_spends_renders_within_the_bound(
    node: BitcoinCoreRpcClient,
    wallets: tuple[BitcoinCoreRpcClient, BitcoinCoreRpcClient],
) -> None:
    """A block of bare multisig spends renders under five octets per WU.

    A standard transaction spends bare 1-of-3 multisig outputs of
    uncompressed keys, each input signed with at most 60 octets: the nonce
    (n + 1) / 2 gives an r with leading zero octets. Each input then renders
    its previous output's long script three times, as `asm`, `hex` and
    `desc`, against the few weight units of a short signature.
    """
    miner = wallets[0]
    address = miner.call("getnewaddress")
    miner.call("generatetoaddress", [101, address])
    prv_key = 0x1234567
    keys = [bytes_from_point(mult(prv_key + i), compressed=False) for i in range(3)]
    bare = serialize(["OP_1", *keys, "OP_3", "OP_CHECKMULTISIG"])
    # 190 outputs a funding transaction: a bare multisig output counts 80
    # of the 16,000 sigops a standard transaction may carry
    prev_outs = _fund(miner, [bare] * 190, 20_000)
    payee = ScriptPubKey.from_address(address).script
    vin = [TxIn(prev_out, b"", 0xFFFFFFFF) for prev_out in prev_outs]
    spend = Tx(2, 0, vin, [TxOut(len(vin) * 20_000 - 400_000, payee)])
    hash_type = ALL
    for i, tx_in in enumerate(spend.vin):
        msg_hash = legacy(bare, spend, i, hash_type)
        sig = sign_(msg_hash, prv_key, (secp256k1.n + 1) // 2, grind=False)
        der = sig.serialize() + bytes([hash_type])
        assert len(der) <= 60
        tx_in.script_sig = serialize(["OP_0", der])
    raw = spend.serialize(include_witness=True).hex()
    assert node.call("testmempoolaccept", [[raw]])[0]["allowed"]
    block = node.call("generateblock", [address, [raw]])["hash"]
    weight = node.call("getblock", [block, 1])["weight"]

    with pytest.raises(FetchError, match="more than the max_body_size"):
        node.call("getblock", [block, 3], max_body_size=4 * weight)
    node.call("getblock", [block, 3], max_body_size=5 * weight)


_TRUE = b"\x51"
_P2SH_TRUE = b"\xa9\x14" + hash160(_TRUE) + b"\x87"


@pytest.mark.parametrize("shape", ["chain", "fan-out"])
def test_a_mempool_entry_costs_the_node_at_least_the_floor(
    node: BitcoinCoreRpcClient,
    wallets: tuple[BitcoinCoreRpcClient, BitcoinCoreRpcClient],
    shape: str,
) -> None:
    """Small entries in a cluster of 64 cost the node at least the floor.

    `getmempoolinfo` counts the node's memory, and the cluster is at the
    limit of 64. A chain is 64 entries that each spend a P2SH output of
    `OP_TRUE` and pay one, 85 octets, and the cluster's usage over its
    entries is held at or above the floor. A fan-out is a parent paying 63
    such outputs and the 63 children spending them, and the children's
    usage, read after the parent's, over 63 is held at or above it.
    """
    miner = wallets[0]
    miner.call("generatetoaddress", [101, miner.call("getnewaddress")])
    (root,) = _fund(miner, [_P2SH_TRUE], 100_000)
    before = node.call("getmempoolinfo")

    def spend(prev_outs: list[OutPoint], outputs: int, value: int) -> list[OutPoint]:
        vin = [TxIn(prev_out, b"\x01\x51", 0xFFFFFFFD) for prev_out in prev_outs]
        tx = Tx(2, 0, vin, [TxOut(value, _P2SH_TRUE)] * outputs)
        raw = tx.serialize(include_witness=False).hex()
        tx_id = bytes.fromhex(node.call("sendrawtransaction", [raw]))
        return [OutPoint(tx_id, i) for i in range(outputs)]

    if shape == "chain":
        prev_out, value = root, 100_000
        for _ in range(64):
            value -= 1_000
            (prev_out,) = spend([prev_out], 1, value)
    else:
        children = spend([root], 63, 1_500)
        before = node.call("getmempoolinfo")
        for prev_out in children:
            spend([prev_out], 1, 1_000)
    after = node.call("getmempoolinfo")

    entries = after["size"] - before["size"]
    assert entries == (64 if shape == "chain" else 63)
    usage = after["usage"] - before["usage"]
    assert usage / entries >= bitcoin_core._MEMPOOL_ENTRY_USAGE
    miner.call("generatetoaddress", [1, miner.call("getnewaddress")])


def test_a_scan_reports_a_p2wpkh_output_in_under_400_octets(
    node: BitcoinCoreRpcClient,
    wallets: tuple[BitcoinCoreRpcClient, BitcoinCoreRpcClient],
) -> None:
    """What `scantxoutset` answers per P2WPKH unspent, envelope included."""
    miner = wallets[0]
    miner.call("generatetoaddress", [101, miner.call("getnewaddress")])
    address = miner.call("getnewaddress", ["", "bech32"])
    script = bytes.fromhex(miner.call("getaddressinfo", [address])["scriptPubKey"])
    _fund(miner, [script] * 200, 5_000)
    scan = ["start", [f"raw({script.hex()})"]]
    reply = node.call("scantxoutset", scan, max_body_size=200 * 400)
    assert len(reply["unspents"]) == 200
