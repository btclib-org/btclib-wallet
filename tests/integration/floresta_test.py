# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""`ElectrumFetcher` against a live `florestad`, plain and over TLS.

The unit tests answer from recorded replies, and a recorded reply cannot
drift. The fetcher reaches Floresta only through a transport that adds
`"jsonrpc": "2.0"` (`conftest.py`'s `JsonRpc2Transport` says why).
Every question the fetcher asks is asked here of Floresta's Electrum
server on both of its ports, and compared with what the node itself says.
The merkle branch is checked against the root in the block the node holds,
the header chunk against the single headers, and the two history methods
against each other.

Skipped unless `BTCLIB_INTEGRATION=1` and `BTCLIB_FLORESTAD` and
`BTCLIB_UTREEXOD` name the binaries; `conftest.py` has why there is a
second program.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Iterator
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

import pytest
from btclib.exceptions import BTClibValueError
from btclib.tx import OutPoint

from btclib_wallet import electrum
from btclib_wallet.exceptions import FetchError
from btclib_wallet.fetch.electrum import ElectrumFetcher
from tests.integration.conftest import (
    FlorestaStack,
    floresta_binaries,
    running_floresta_stack,
)

pytestmark = pytest.mark.integration

# how long the server is given to scan for a script it was just asked about
_SCAN_TIMEOUT = 60.0


@dataclass(frozen=True)
class Payment:
    """A confirmed payment: its id and output, its block, the script paid."""

    tx_id: str
    vout: int
    height: int
    block_id: str
    script: str
    scripthash: str


@pytest.fixture(scope="module")
def stack(
    bitcoind_path: str, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[FlorestaStack]:
    """Return a stack with a few blocks above the first 101."""
    florestad, utreexod = floresta_binaries()
    with running_floresta_stack(
        bitcoind_path, florestad, utreexod, tmp_path_factory
    ) as running:
        running.mine(3)
        yield running


def scripthash_of(script: str) -> str:
    """Return the Electrum scripthash of a script: its sha256, reversed."""
    return hashlib.sha256(bytes.fromhex(script)).digest()[::-1].hex()


def history(stack: FlorestaStack, script: str, want: int) -> list[dict[str, Any]]:
    """Return `scriptpubkey.get_history` once it has `want` entries.

    The first question about a script is answered `null`, and queues the
    script for a scan, so it is asked again until it answers a list.

    The pause is longer than a second on purpose: Floresta hands the
    blocks it has connected to its wallet only when no request has come
    in for a second (`floresta-electrum`'s `main_loop`), so a client
    asking more often than that never sees a new block's transactions.
    """
    deadline = time.monotonic() + _SCAN_TIMEOUT
    while True:
        answer = stack.request("blockchain.scriptpubkey.get_history", [script])
        if answer is not None and len(answer) >= want:
            return list(answer)
        if time.monotonic() > deadline:
            pytest.fail(f"no {want} entries for the script in {_SCAN_TIMEOUT} s")
        time.sleep(1.5)


@pytest.fixture(scope="module")
def payment(stack: FlorestaStack) -> Payment:
    """Make the server watch an address, pay it, and mine the payment."""
    address = str(stack.node.call("getnewaddress"))
    script = str(stack.node.call("getaddressinfo", [address])["scriptPubKey"])
    assert history(stack, script, 0) == []
    tx_id = str(stack.node.call("sendtoaddress", [address, "1.25"]))
    (block_id,) = stack.mine()
    vout = next(
        out["n"]
        for out in stack.node.call("getrawtransaction", [tx_id, 2])["vout"]
        if out["value"] == Decimal("1.25")
    )
    height = int(stack.node.call("getblockcount"))
    assert [entry["tx_hash"] for entry in history(stack, script, 1)] == [tx_id]
    return Payment(tx_id, vout, height, block_id, script, scripthash_of(script))


@pytest.fixture(params=["plain", "tls"])
def tls(request: pytest.FixtureRequest) -> bool:
    """Name each of the server's ports in turn."""
    return bool(request.param == "tls")


@pytest.fixture
def fetcher(tls: bool, stack: FlorestaStack, payment: Payment) -> ElectrumFetcher:
    """Return the fetcher on this port, on a chain holding the payment."""
    assert payment.height > 0
    transport = stack.tls if tls else stack.electrum
    return ElectrumFetcher("regtest", transport=transport)


def test_the_server_serves_this_chain(fetcher: ElectrumFetcher) -> None:
    """`assert_network` passes for regtest and refuses a mainnet label."""
    fetcher.assert_network()
    wrong = ElectrumFetcher("mainnet", transport=fetcher.transport)
    with pytest.raises(BTClibValueError, match="genesis"):
        wrong.assert_network()


def test_the_tip_is_the_nodes(fetcher: ElectrumFetcher, stack: FlorestaStack) -> None:
    """`get_block_count` and `get_best_block_id` are `bitcoind`'s own."""
    assert fetcher.get_block_count() == stack.node.call("getblockcount")
    assert fetcher.get_best_block_id().hex() == stack.node.call("getbestblockhash")


def test_headers_are_the_nodes(fetcher: ElectrumFetcher, stack: FlorestaStack) -> None:
    """The eighty bytes at a height are Core's."""
    tip = int(stack.node.call("getblockcount"))
    for height in (0, 1, 50, tip - 1, tip):
        block_id = str(stack.node.call("getblockhash", [height]))
        header = fetcher.get_block_header(height)
        assert header.serialize().hex() == stack.node.call(
            "getblockheader", [block_id, False]
        )
        assert header.hash.hex() == block_id


def test_a_chunk_of_headers_is_the_single_headers(
    fetcher: ElectrumFetcher, stack: FlorestaStack
) -> None:
    """`block.headers` answers what `block.header` does, a header at a time."""
    tip = int(stack.node.call("getblockcount"))
    chunk = fetcher.get_block_headers(0, tip + 1)
    assert len(chunk) == tip + 1
    assert chunk == [fetcher.get_block_header(height) for height in range(tip + 1)]
    assert fetcher.get_block_headers(tip - 1, 2) == chunk[-2:]


def test_a_chunk_past_the_tip_is_refused(
    fetcher: ElectrumFetcher, stack: FlorestaStack
) -> None:
    """Floresta answers an error for a range reaching above its tip."""
    tip = int(stack.node.call("getblockcount"))
    with pytest.raises(FetchError):
        fetcher.get_block_headers(tip, 2)


def test_a_transaction_is_the_nodes(
    fetcher: ElectrumFetcher, stack: FlorestaStack, payment: Payment
) -> None:
    """`get_tx` and `get_tx_out` return what Core serialized."""
    tx = fetcher.get_tx(payment.tx_id)
    assert tx.id.hex() == payment.tx_id
    raw = stack.node.call("getrawtransaction", [payment.tx_id])
    assert tx.serialize(include_witness=True).hex() == raw
    assert fetcher.get_tx_out(OutPoint(tx.id, payment.vout)) == tx.vout[payment.vout]


def test_an_unknown_transaction_is_a_fetch_error(fetcher: ElectrumFetcher) -> None:
    """A txid nothing has is refused as a `FetchError`, not as a crash."""
    with pytest.raises(FetchError):
        fetcher.get_tx("ab" * 32)


def test_the_fee_estimate_is_floresta_s_fixed_rate(fetcher: ElectrumFetcher) -> None:
    """Floresta answers 0.0001 BTC/kvB for every target."""
    quote = fetcher.estimate_fee(2)
    assert quote.target == 2
    assert quote.rate.sats_per_kvbyte == int(Decimal("0.0001") * 10**8)


def test_the_merkle_branch_ends_at_the_blocks_root(
    fetcher: ElectrumFetcher, stack: FlorestaStack, payment: Payment
) -> None:
    """The branch hashes up to the merkle root of the block the node holds."""
    proof = fetcher.get_tx_merkle(payment.tx_id, payment.height)
    assert proof.block_height == payment.height
    block = stack.node.call("getblock", [payment.block_id])
    assert payment.tx_id in block["tx"]
    header = fetcher.get_block_header(payment.height)
    assert header.merkle_root.hex() == block["merkleroot"]
    electrum.assert_merkle_proof(payment.tx_id, proof, header)
    assert fetcher.verify_tx(payment.tx_id, payment.height)


def test_the_two_history_methods_agree(
    stack: FlorestaStack, payment: Payment, tls: bool
) -> None:
    """`scriptpubkey.get_history` is `scripthash.get_history` for the script."""
    by_script = stack.request(
        "blockchain.scriptpubkey.get_history", [payment.script], tls=tls
    )
    by_hash = stack.request(
        "blockchain.scripthash.get_history", [payment.scripthash], tls=tls
    )
    assert by_script == by_hash
    assert [entry["tx_hash"] for entry in by_hash] == [payment.tx_id]
    assert [entry["height"] for entry in by_hash] == [payment.height]
