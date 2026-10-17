# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Core relays script-path and timelocked spends built by the wallet.

The transaction, descriptor metadata, signatures and final witness are
the package's own. Core funds the output and judges the broadcast; it
does not construct or sign the transaction that spends it.
"""

from __future__ import annotations

import pytest
from bitcoin_core_rpc import BitcoinCoreRpcClient
from btclib.exceptions import RpcError
from btclib.fee import FeeRate
from btclib.network import NETWORKS
from btclib.script import Witness
from btclib.tx import OutPoint, Tx, TxIn, TxOut

from btclib_wallet.bip32.bip32 import rootxprv_from_seed
from btclib_wallet.descriptors import (
    Descriptor,
    SpendContext,
    TrDescriptor,
    miniscript_solver,
    parse,
)
from btclib_wallet.fetch.bitcoin_core import BitcoinCoreFetcher
from btclib_wallet.psbt.psbt import Psbt, extract_tx, finalize
from btclib_wallet.psbt.psbt_size import SCHNORR_SIG_SIZE, SIG_SIZE
from btclib_wallet.psbt_signer import SoftwareSigner
from btclib_wallet.silent_payments import NUMS_H
from btclib_wallet.tx_builder import build_psbt
from tests.integration.conftest import broadcast

pytestmark = pytest.mark.integration


@pytest.fixture
def funded_miner(
    wallets: tuple[BitcoinCoreRpcClient, BitcoinCoreRpcClient],
) -> BitcoinCoreRpcClient:
    """Return a miner with mature coins before a lock height is chosen."""
    miner = wallets[0]
    miner.call("generatetoaddress", [101, miner.call("getnewaddress")])
    return miner


def _signer_and_key(account: int) -> tuple[SoftwareSigner, str]:
    """Return a signer and a descriptor key carrying its derivation origin."""
    root = rootxprv_from_seed(bytes(range(16)), NETWORKS["regtest"].bip32_prv)
    signer = SoftwareSigner(root)
    path = f"84h/1h/{account}h"
    key = f"[{signer.master_fingerprint.hex()}/{path}]{signer.xpub(path)}/0/0"
    return signer, key


def _signed_spend(
    node: BitcoinCoreRpcClient,
    miner: BitcoinCoreRpcClient,
    descriptor: Descriptor,
    signer: SoftwareSigner,
    *,
    sequence: int = 0xFFFFFFFF,
    lock_time: int = 0,
) -> Psbt:
    """Fund the descriptor and build, update, sign and finalize its spend."""
    funding_id = miner.call("sendtoaddress", [descriptor.address(), "0.5"])
    miner.call("generatetoaddress", [1, miner.call("getnewaddress")])
    funding = Tx.parse(node.call("getrawtransaction", [funding_id]))
    script_pub_key = descriptor.script_pub_key().script
    output_index = next(
        i
        for i, tx_out in enumerate(funding.vout)
        if tx_out.script_pub_key.script == script_pub_key
    )
    prevout = funding.vout[output_index]
    destination = parse(f"addr({miner.call('getnewaddress')})", "regtest")
    payment = TxOut(prevout.value - 1_000, destination.script_pub_key())
    request = Psbt.from_tx(
        Tx(
            version=2,
            lock_time=lock_time,
            vin=[TxIn(OutPoint(funding.id, output_index), sequence=sequence)],
            vout=[payment],
        )
    )
    request.inputs[0].non_witness_utxo = funding
    request.inputs[0].witness_utxo = prevout
    request = descriptor.update_psbt_input(request, 0)
    # The chosen descriptor branch supplies the size the generic builder
    # cannot infer from a script-path or miniscript input alone.
    keys = descriptor.key_expressions
    sig_size = SIG_SIZE
    if isinstance(descriptor, TrDescriptor):
        keys, sig_size = keys[1:], SCHNORR_SIG_SIZE
    _, witness = descriptor.satisfy(
        {key.sec(network=descriptor.network): bytes(sig_size) for key in keys},
        spend=SpendContext(sequence=sequence, locktime=lock_time, version=2),
    )
    witness_sizes = [len(item) for item in witness.stack]
    funded = build_psbt(
        request.inputs,
        [payment],
        fee_rate=FeeRate(sats_per_kvbyte=1000),
        change_script_pub_key=None,
        lock_time=lock_time,
        sizer=lambda _psbt_in, _tx_in: witness_sizes,
    )
    signed = signer.sign_psbt(funded.psbt)
    return finalize(signed, solver=miniscript_solver)


def _mine_spend(
    node: BitcoinCoreRpcClient, miner: BitcoinCoreRpcClient, psbt: Psbt
) -> None:
    """Broadcast through the fetcher and prove the spend is in a block."""
    tx_id = broadcast(node, psbt)
    (block_hash,) = miner.call("generatetoaddress", [1, miner.call("getnewaddress")])
    assert tx_id in node.call("getblock", [block_hash])["tx"]
    transaction = node.call("getrawtransaction", [tx_id, True])
    assert transaction["blockhash"] == block_hash
    assert transaction["confirmations"] == 1


def test_core_relays_a_taproot_script_path_spend(
    node: BitcoinCoreRpcClient, funded_miner: BitcoinCoreRpcClient
) -> None:
    """A leaf signature and control block survive Core's independent check."""
    signer, key = _signer_and_key(3)
    # BIP341's H point has no known private key: the spend must use a leaf.
    descriptor = parse(f"tr({NUMS_H.hex()},pk({key}))", "regtest")
    assert isinstance(descriptor, TrDescriptor)
    signed = _signed_spend(node, funded_miner, descriptor, signer)
    assert not signed.inputs[0].taproot_key_spend_signature
    signature, script, control_block = signed.inputs[0].final_script_witness.stack
    assert script in [leaf for leaf, _ in descriptor.taproot_leaf_scripts().values()]
    assert control_block in descriptor.taproot_leaf_scripts()

    # A different witness on this transaction must fail at the node, not
    # merely at the package's own script engine.
    invalid = extract_tx(signed)
    invalid.vin[0].script_witness = Witness(
        [bytes(len(signature)), script, control_block]
    )
    with pytest.raises(RpcError) as refused:
        BitcoinCoreFetcher(node, "regtest").broadcast(invalid)
    assert refused.value.code == -26
    _mine_spend(node, funded_miner, signed)


def test_core_relays_an_older_spend_only_when_its_sequence_matures(
    node: BitcoinCoreRpcClient, funded_miner: BitcoinCoreRpcClient
) -> None:
    """The same signed CSV spend is refused before its input is old enough."""
    delay = 6
    signer, key = _signer_and_key(4)
    descriptor = parse(f"wsh(and_v(v:pk({key}),older({delay})))", "regtest")
    signed = _signed_spend(node, funded_miner, descriptor, signer, sequence=delay)
    assert signed.tx.vin[0].sequence == delay
    with pytest.raises(RpcError) as refused:
        broadcast(node, signed)
    assert refused.value.code == -26

    # BIP68 evaluates the next block: at depth delay-1 the input is still
    # too young, and one more block opens the same transaction.
    funded_miner.call(
        "generatetoaddress", [delay - 2, funded_miner.call("getnewaddress")]
    )
    with pytest.raises(RpcError) as refused:
        broadcast(node, signed)
    assert refused.value.code == -26
    funded_miner.call("generatetoaddress", [1, funded_miner.call("getnewaddress")])
    _mine_spend(node, funded_miner, signed)


def test_core_relays_an_after_spend_only_when_its_lock_height_passes(
    node: BitcoinCoreRpcClient, funded_miner: BitcoinCoreRpcClient
) -> None:
    """The same signed CLTV spend becomes final at its next-block boundary."""
    lock_height = int(node.call("getblockcount")) + 5
    signer, key = _signer_and_key(5)
    descriptor = parse(f"wsh(and_v(v:pk({key}),after({lock_height})))", "regtest")
    signed = _signed_spend(
        node,
        funded_miner,
        descriptor,
        signer,
        sequence=0xFFFFFFFE,
        lock_time=lock_height,
    )
    assert signed.tx.lock_time == lock_height
    assert signed.tx.vin[0].sequence == 0xFFFFFFFE
    with pytest.raises(RpcError) as refused:
        broadcast(node, signed)
    assert refused.value.code == -26

    height = int(node.call("getblockcount"))
    funded_miner.call(
        "generatetoaddress",
        [lock_height - height - 1, funded_miner.call("getnewaddress")],
    )
    with pytest.raises(RpcError) as refused:
        broadcast(node, signed)
    assert refused.value.code == -26
    funded_miner.call("generatetoaddress", [1, funded_miner.call("getnewaddress")])
    _mine_spend(node, funded_miner, signed)
