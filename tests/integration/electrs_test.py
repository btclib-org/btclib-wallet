# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""`ElectrumFetcher` and `EsploraFetcher` against a live `electrs`.

The unit tests answer from recorded replies, and a recorded reply cannot
drift: a renamed field, a changed error shape or a different byte order
is found here or in production. Each question both fetchers answer is
asked of both, and compared with what the node itself says; what only one
of them can do -- a merkle branch, a broadcast -- is asked of that one.

Skipped unless `BTCLIB_INTEGRATION=1` and `BTCLIB_ELECTRS` names the
server's binary; `conftest.py` has why there is no `PATH` fallback. The
reorg is `electrs_reorg_test.py`, on a stack of its own.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from decimal import Decimal

import pytest
from btclib.amount import sats_from_btc
from btclib.exceptions import BTClibValueError
from btclib.tx import OutPoint, Tx, TxIn, TxOut

from btclib_wallet.exceptions import FetchError, HttpError
from btclib_wallet.fetch.electrum import ElectrumFetcher
from btclib_wallet.fetch.esplora import EsploraFetcher
from btclib_wallet.fetch.fetcher import NetworkVerifyingFetcher
from tests.integration.conftest import (
    Stack,
    electrs_binary,
    make_fetcher,
    running_stack,
)

pytestmark = pytest.mark.integration


@dataclass(frozen=True)
class Payment:
    """A confirmed payment: its id, the output paid and the block it is in."""

    tx_id: str
    vout: int
    height: int
    block_id: str


@pytest.fixture(scope="module")
def stack(
    bitcoind_path: str, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[Stack]:
    """Return a stack with a few blocks above the first 101."""
    with running_stack(bitcoind_path, electrs_binary(), tmp_path_factory) as running:
        running.mine(3)
        yield running


@pytest.fixture(scope="module")
def payment(stack: Stack) -> Payment:
    """Pay an address of the node's wallet, and mine the payment."""
    address = str(stack.node.call("getnewaddress"))
    tx_id = str(stack.node.call("sendtoaddress", [address, "1.25"]))
    (block_id,) = stack.mine()
    vout = next(
        out["n"]
        for out in stack.node.call("getrawtransaction", [tx_id, 2])["vout"]
        if out["value"] == Decimal("1.25")
    )
    height = int(stack.node.call("getblockcount"))
    return Payment(tx_id, vout, height, block_id)


@pytest.fixture(params=["electrum", "esplora"])
def kind(request: pytest.FixtureRequest) -> str:
    """Name each fetcher in turn."""
    return str(request.param)


@pytest.fixture
def fetcher(kind: str, stack: Stack, payment: Payment) -> NetworkVerifyingFetcher:
    """Return the fetcher of this kind, on a chain holding the payment."""
    assert payment.height > 0
    return make_fetcher(kind, stack)


def test_the_server_serves_this_chain(kind: str, stack: Stack) -> None:
    """`assert_network` passes for regtest and refuses a mainnet label."""
    make_fetcher(kind, stack).assert_network()
    wrong = make_fetcher(kind, stack, "mainnet")
    with pytest.raises(BTClibValueError, match="genesis"):
        wrong.assert_network()


def test_the_tip_is_the_nodes(fetcher: NetworkVerifyingFetcher, stack: Stack) -> None:
    """`get_block_count` and `get_best_block_id` are `bitcoind`'s own."""
    assert fetcher.get_block_count() == stack.node.call("getblockcount")
    assert fetcher.get_best_block_id().hex() == stack.node.call("getbestblockhash")


def test_headers_are_the_nodes_and_chain_together(
    fetcher: NetworkVerifyingFetcher, stack: Stack
) -> None:
    """The eighty bytes at a height are Core's; the tip and height 1 link up."""
    tip = int(stack.node.call("getblockcount"))
    headers = {h: fetcher.get_block_header(h) for h in (0, 1, 50, tip - 1, tip)}
    for height, header in headers.items():
        block_id = str(stack.node.call("getblockhash", [height]))
        assert header.serialize().hex() == stack.node.call(
            "getblockheader", [block_id, False]
        )
        assert header.hash.hex() == block_id
    assert headers[tip].previous_block_hash == headers[tip - 1].hash
    assert headers[1].previous_block_hash == headers[0].hash


def test_a_transaction_is_the_nodes(
    fetcher: NetworkVerifyingFetcher, stack: Stack, payment: Payment
) -> None:
    """`get_tx` and `get_tx_out` return what Core serialized."""
    tx = fetcher.get_tx(payment.tx_id)
    assert tx.id.hex() == payment.tx_id
    raw = stack.node.call("getrawtransaction", [payment.tx_id])
    assert tx.serialize(include_witness=True).hex() == raw
    assert fetcher.get_tx_out(OutPoint(tx.id, payment.vout)) == tx.vout[payment.vout]


def test_an_unknown_transaction_is_a_fetch_error(
    fetcher: NetworkVerifyingFetcher,
) -> None:
    """A txid nothing has is refused as a `FetchError`, not as a crash."""
    with pytest.raises(FetchError):
        fetcher.get_tx("ab" * 32)


def test_electrum_quotes_the_nodes_relay_fee_on_regtest(stack: Stack) -> None:
    """On regtest `electrs` answers the node's relay fee for every target."""
    relay = sats_from_btc(Decimal(str(stack.node.call("getnetworkinfo")["relayfee"])))
    quote = ElectrumFetcher("regtest", transport=stack.electrum).estimate_fee(2)
    assert quote.target == 2
    assert quote.rate.sats_per_kvbyte == relay


def test_esplora_has_no_fee_estimate_on_a_chain_without_history(stack: Stack) -> None:
    """`/fee-estimates` is an empty object, which is refused, not quoted."""
    assert stack.http_json("/fee-estimates") == {}
    with pytest.raises(FetchError, match="fee-estimates"):
        EsploraFetcher(stack.http_url, network="regtest").estimate_fee(2)


def test_electrum_proves_a_confirmation(stack: Stack, payment: Payment) -> None:
    """The merkle branch ends at the root of the block's header."""
    fetcher = ElectrumFetcher("regtest", transport=stack.electrum)
    proof = fetcher.get_tx_merkle(payment.tx_id, payment.height)
    assert proof.block_height == payment.height
    assert fetcher.verify_tx(payment.tx_id, payment.height)
    # electrs refuses a height the transaction is not confirmed at, above
    # the payment's block as below it; a block is mined so that one exists
    stack.mine()
    for height in (payment.height - 1, payment.height + 1):
        with pytest.raises(FetchError, match="invalid confirmation height"):
            fetcher.get_tx_merkle(payment.tx_id, height)


def test_esplora_broadcasts_and_the_node_mines_it(stack: Stack) -> None:
    """`POST /tx` hands the node a transaction it relays, mines and returns."""
    fetcher = EsploraFetcher(stack.http_url, network="regtest")
    address = str(stack.node.call("getnewaddress"))
    funded = stack.node.call(
        "fundrawtransaction",
        [stack.node.call("createrawtransaction", [[], {address: "0.5"}])],
    )["hex"]
    signed = stack.node.call("signrawtransactionwithwallet", [funded])["hex"]
    tx = Tx.parse(signed)
    assert fetcher.broadcast(tx) == tx.id
    assert tx.id.hex() in stack.node.call("getrawmempool")
    stack.mine()
    assert fetcher.get_tx(tx.id).serialize(True) == tx.serialize(True)


def test_esplora_reports_a_rejected_broadcast(stack: Stack) -> None:
    """A transaction spending nothing that exists is a 400 with the reason."""
    fetcher = EsploraFetcher(stack.http_url, network="regtest")
    tx = Tx(
        vin=[TxIn(OutPoint(bytes.fromhex("11" * 32), 0))],
        vout=[TxOut(1000, bytes.fromhex("0014" + "22" * 20))],
    )
    with pytest.raises(HttpError, match="bad-txns-inputs-missingorspent") as raised:
        fetcher.broadcast(tx)
    assert raised.value.status == 400
