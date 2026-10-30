# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""`CompactFilterFetcher` against a node serving BIP157 over p2p.

The unit tests answer the fetcher from a script; only a node can say that
the messages it sends are ones Bitcoin Core answers, that a filter Core
built hashes to the filter header Core serves, and that the headers Core
mines pass the retarget rules. The node is this module's own, started with
`-blockfilterindex -peerblockfilters` and listening on an ephemeral p2p
port, because the session's node of the conftest beside this does not
listen at all.

Skipped unless `BTCLIB_INTEGRATION=1` and a `bitcoind` is available.
"""

from __future__ import annotations

import re
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from bitcoin_core_rpc import BitcoinCoreRpcClient
from btclib.p2p import GetData, Message
from typing_extensions import override

from btclib_wallet.exceptions import FetchError
from btclib_wallet.fetch.compact_filters import CompactFilterFetcher
from btclib_wallet.fetch.peer_transport import TcpPeerTransport
from tests.integration.conftest import (
    PortTaken,
    _free_port,
    _start,
    _stop,
    _wait_for,
    start_on_free_ports,
)

pytestmark = pytest.mark.integration

# what bitcoind writes to its `debug.log` when it cannot bind its p2p port
# (src/net.cpp); the conftest's `_wait_for` reads only the rpc port's
_P2P_PORT_TAKEN = re.compile(
    r"Unable to bind to \S+ on this computer\. .+ is probably already running"
)

# how long the block filter index is given to catch up with the chain
_INDEX_TIMEOUT = 30.0


def _start_peer_node(
    bitcoind_path: str, datadir: Path
) -> tuple[subprocess.Popen[bytes], BitcoinCoreRpcClient, int]:
    """Return a node, a client of it and its p2p port, once it answers.

    Both ports are picked on every call, so that a call is a fresh try
    for `start_on_free_ports`. The node is stopped again where it does
    not get there, so that the next try does not leave it behind.
    """
    rpc_port, p2p_port = _free_port(), _free_port()
    debug_log = datadir / "regtest" / "debug.log"
    # a try that failed left its log behind, and its complaint must not be
    # read as this one's
    debug_log.unlink(missing_ok=True)
    process = _start(
        [
            bitcoind_path,
            "-regtest",
            f"-datadir={datadir}",
            f"-rpcport={rpc_port}",
            "-rpcbind=127.0.0.1",
            # without it bitcoind ignores `-rpcbind`, as the conftest's
            # `_bitcoind_args` says
            "-rpcallowip=127.0.0.1",
            f"-port={p2p_port}",
            f"-bind=127.0.0.1:{p2p_port}",
            "-listen=1",
            "-natpmp=0",
            "-discover=0",
            "-listenonion=0",
            "-fallbackfee=0.0002",
            "-blockfilterindex=1",
            "-peerblockfilters=1",
            "-printtoconsole=0",
        ],
        datadir / "stdout.log",
    )
    client = BitcoinCoreRpcClient(
        f"http://127.0.0.1:{rpc_port}", cookie_path=datadir / "regtest" / ".cookie"
    )
    try:
        _wait_for(client, process, debug_log)
    except BaseException as failure:
        _stop(process)
        # `_wait_for` knows only the rpc port's complaint; the p2p
        # listener has its own
        if (
            isinstance(failure, pytest.fail.Exception)
            and debug_log.exists()
            and _P2P_PORT_TAKEN.search(
                debug_log.read_text(encoding="utf-8", errors="replace")
            )
        ):
            raise PortTaken from None
        raise
    return process, client, p2p_port


@pytest.fixture(scope="module")
def peer_node(
    bitcoind_path: str, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[tuple[BitcoinCoreRpcClient, int]]:
    """Yield a regtest node's rpc client and its p2p port.

    `-peerblockfilters` is what makes the node advertise
    `NODE_COMPACT_FILTERS` and answer `getcfilters`, and it needs
    `-blockfilterindex` to have filters to serve. The p2p port is bound to
    the loopback address only, and `-listenonion`, `-natpmp` and
    `-discover` are off for the reason the conftest gives.
    """
    datadir = tmp_path_factory.mktemp("regtest-p2p")
    process, client, p2p_port = start_on_free_ports(
        lambda: _start_peer_node(bitcoind_path, datadir)
    )
    try:
        yield client, p2p_port
    finally:
        _stop(process)


class RecordingPeer(TcpPeerTransport):
    """A TCP peer remembering the hashes of the blocks it asks for."""

    def __init__(self, host: str, port: int) -> None:
        super().__init__(host, port)
        self.requested: list[bytes] = []

    @override
    def send(self, message: Message, timeout: float) -> None:
        """Record the blocks a `getdata` asks for, then send it."""
        if message.command == GetData.command:
            self.requested += [
                item.hash for item in GetData.parse(message.payload).items
            ]
        super().send(message, timeout)


def _wait_for_index(node: BitcoinCoreRpcClient) -> None:
    """Poll until the filter index has reached the chain's tip."""
    deadline = time.monotonic() + _INDEX_TIMEOUT
    while time.monotonic() < deadline:
        info = node.call("getindexinfo")["basic block filter index"]
        if info["synced"] and info["best_block_height"] == node.call("getblockcount"):
            return
        time.sleep(0.1)
    pytest.fail(f"the filter index did not catch up within {_INDEX_TIMEOUT} s")


def test_the_blocks_that_touch_a_script_are_the_ones_downloaded(
    peer_node: tuple[BitcoinCoreRpcClient, int],
) -> None:
    """A payment and a spend are found, and nothing else is downloaded.

    The watched script is paid in one block and spent in another, and a
    BIP158 filter holds the scripts a block spends as well as the ones it
    creates, so both blocks match. Between and around them are blocks
    that touch neither.
    """
    node, p2p_port = peer_node
    node.call("createwallet", ["miner"])
    node.call("createwallet", ["watched"])
    miner, watched = node.for_wallet("miner"), node.for_wallet("watched")
    mining_address = miner.call("getnewaddress")
    address = watched.call("getnewaddress", ["", "bech32"])
    script = bytes.fromhex(watched.call("getaddressinfo", [address])["scriptPubKey"])

    miner.call("generatetoaddress", [101, mining_address])
    miner.call("sendtoaddress", [address, "1.5"])
    miner.call("generatetoaddress", [1, mining_address])
    paid = node.call("getblockcount")
    miner.call("generatetoaddress", [3, mining_address])
    watched.call("sendtoaddress", [mining_address, "0.5"])
    miner.call("generatetoaddress", [1, mining_address])
    spent = node.call("getblockcount")
    miner.call("generatetoaddress", [3, mining_address])
    _wait_for_index(node)

    peer = RecordingPeer("127.0.0.1", p2p_port)
    with CompactFilterFetcher("regtest", transport=peer) as fetcher:
        blocks = fetcher.scan_blocks([script])

        assert list(blocks) == [paid, spent]
        assert peer.requested == [blocks[paid].header.hash, blocks[spent].header.hash]
        for height, block in blocks.items():
            assert block.header.hash.hex() == node.call("getblockhash", [height])
        assert fetcher.get_block_count() == node.call("getblockcount")
        assert fetcher.get_best_block_id().hex() == node.call("getbestblockhash")
        assert fetcher.get_block_header(paid).hash == blocks[paid].header.hash

        # only the range asked for is scanned
        assert list(fetcher.scan_blocks([script], spent)) == [spent]
        assert fetcher.scan_blocks([script], paid + 1, spent - 1) == {}

        with pytest.raises(FetchError, match="cannot serve a transaction"):
            fetcher.get_tx(blocks[paid].transactions[0].id)

        # the chain the peer follows changes under the fetcher, which
        # follows it: the filter headers it held above the fork are gone.
        # The new blocks pay another address, or they would be the very
        # blocks just invalidated
        old_tip = node.call("getbestblockhash")
        node.call("invalidateblock", [old_tip])
        node.call("invalidateblock", [node.call("getbestblockhash")])
        miner.call("generatetoaddress", [3, miner.call("getnewaddress")])
        assert node.call("getbestblockhash") != old_tip
        _wait_for_index(node)
        assert fetcher.get_best_block_id().hex() == node.call("getbestblockhash")
        assert list(fetcher.scan_blocks([script])) == [paid, spent]
