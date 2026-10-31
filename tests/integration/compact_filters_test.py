# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""`CompactFilterFetcher` against nodes serving BIP157 over p2p.

The unit tests answer the fetcher from a script; only a node can say that
the messages it sends are ones Bitcoin Core answers, that a filter Core
built hashes to the filter header Core serves, and that the headers Core
mines pass the retarget rules. The nodes are this module's own, started
with `-blockfilterindex -peerblockfilters` and listening on an ephemeral
p2p port, because the session's node of the conftest beside this does not
listen at all. Two of them serve one chain, and a transport over one of
the two lies about a filter, to check the cross-check between peers.

Skipped unless `BTCLIB_INTEGRATION=1` and a `bitcoind` is available.
"""

from __future__ import annotations

import re
import subprocess
import time
from collections.abc import Iterator
from functools import partial
from pathlib import Path

import pytest
from bitcoin_core_rpc import BitcoinCoreRpcClient
from btclib.exceptions import FetchError
from btclib.p2p import BlockFilterType, CFHeaders, CFilter, GetData, Message
from btclib.p2p.limits import CFCHECKPT_INTERVAL
from typing_extensions import override

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

# how long the block filter index is given to catch up with the chain,
# and a second node to reach the first one's tip
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


def _wait_for_tip(node: BitcoinCoreRpcClient, tip: str) -> None:
    """Poll until the node's best block is `tip`."""
    deadline = time.monotonic() + _INDEX_TIMEOUT
    while time.monotonic() < deadline:
        if node.call("getbestblockhash") == tip:
            return
        time.sleep(0.1)
    pytest.fail(f"the node did not reach {tip} within {_INDEX_TIMEOUT} s")


@pytest.fixture(scope="module")
def two_peer_nodes(
    bitcoind_path: str, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[tuple[tuple[BitcoinCoreRpcClient, int], ...]]:
    """Yield two regtest nodes, each as its rpc client and its p2p port.

    Started as `peer_node` is, and not yet connected to each other.
    """
    started = []
    try:
        for name in ("regtest-p2p-a", "regtest-p2p-b"):
            datadir = tmp_path_factory.mktemp(name)
            started.append(
                start_on_free_ports(partial(_start_peer_node, bitcoind_path, datadir))
            )
        yield tuple((client, port) for _, client, port in started)
    finally:
        for process, _, _ in started:
            _stop(process)


@pytest.fixture(scope="module")
def shared_chain(
    two_peer_nodes: tuple[tuple[BitcoinCoreRpcClient, int], ...],
) -> tuple[bytes, int, int]:
    """Return a watched script and the heights that pay it and spend it.

    The first node mines the chain and the second syncs it over p2p, so
    that the two serve the same blocks and the same filters.
    """
    (first, first_port), (second, _) = two_peer_nodes
    first.call("createwallet", ["miner"])
    first.call("createwallet", ["watched"])
    miner, watched = first.for_wallet("miner"), first.for_wallet("watched")
    mining_address = miner.call("getnewaddress")
    address = watched.call("getnewaddress", ["", "bech32"])
    script = bytes.fromhex(watched.call("getaddressinfo", [address])["scriptPubKey"])
    miner.call("generatetoaddress", [101, mining_address])
    miner.call("sendtoaddress", [address, "1.5"])
    miner.call("generatetoaddress", [1, mining_address])
    paid = first.call("getblockcount")
    miner.call("generatetoaddress", [3, mining_address])
    watched.call("sendtoaddress", [mining_address, "0.5"])
    miner.call("generatetoaddress", [1, mining_address])
    spent = first.call("getblockcount")
    miner.call("generatetoaddress", [3, mining_address])
    second.call("addnode", [f"127.0.0.1:{first_port}", "onetry"])
    _wait_for_tip(second, first.call("getbestblockhash"))
    _wait_for_index(first)
    _wait_for_index(second)
    return script, paid, spent


class LyingPeer(TcpPeerTransport):
    """A TCP peer that serves the filter of the block below `height` for it.

    The filter headers it serves chain from that filter, as the node's
    would if it held that filter, so the lie holds together: only the
    block can tell it apart. The chain is shorter than a checkpoint
    interval, so the `cfcheckpt` the node serves is empty and needs no
    lie.
    """

    def __init__(
        self, host: str, port: int, node: BitcoinCoreRpcClient, height: int
    ) -> None:
        super().__init__(host, port)
        tip = node.call("getblockcount")
        assert tip < CFCHECKPT_INTERVAL
        self.hashes = [
            bytes.fromhex(node.call("getblockhash", [h])) for h in range(tip + 1)
        ]
        self.filters = [
            bytes.fromhex(node.call("getblockfilter", [h.hex()])["filter"])
            for h in self.hashes
        ]
        self.filters[height] = self.filters[height - 1]
        self.height_of = {h: i for i, h in enumerate(self.hashes)}
        self.filter_hashes = [self.cfilter(i).basic_filter.hash for i in range(tip + 1)]
        self.filter_headers = []
        previous = bytes(32)
        for i in range(tip + 1):
            previous = self.cfilter(i).basic_filter.header(previous)
            self.filter_headers.append(previous)

    def cfilter(self, height: int) -> CFilter:
        """Return the `cfilter` this peer serves for the block at `height`."""
        return CFilter(BlockFilterType.BASIC, self.hashes[height], self.filters[height])

    @override
    def receive(self, timeout: float) -> Message:
        """Return the node's next message, with its filter lies told."""
        message = super().receive(timeout)
        if message.command == CFHeaders.command:
            reply = CFHeaders.parse(message.payload)
            stop = self.height_of[reply.stop_hash]
            start = stop - len(reply.filter_hashes) + 1
            headers = CFHeaders(
                reply.filter_type,
                reply.stop_hash,
                self.filter_headers[start - 1] if start else bytes(32),
                self.filter_hashes[start : stop + 1],
            )
            return Message(message.magic, message.command, headers.serialize())
        if message.command == CFilter.command:
            block_hash = CFilter.parse(message.payload).block_hash
            filter_ = self.cfilter(self.height_of[block_hash])
            return Message(message.magic, message.command, filter_.serialize())
        return message


@pytest.mark.parametrize("liar_serves", [False, True], ids=["cross-checks", "serves"])
def test_a_peer_serving_a_wrong_filter_is_dropped_and_the_payment_found(
    two_peer_nodes: tuple[tuple[BitcoinCoreRpcClient, int], ...],
    shared_chain: tuple[bytes, int, int],
    liar_serves: bool,
) -> None:
    """Two nodes serve one chain, and one of them a filter that hides a payment.

    The fetcher finds where their filter headers part, downloads the block,
    and drops the peer whose filter leaves out the block's outputs. Where
    that peer was the one serving the chain, the honest one takes over.
    """
    (first, first_port), (second, second_port) = two_peer_nodes
    script, paid, spent = shared_chain
    honest = TcpPeerTransport("127.0.0.1", first_port)
    lying = LyingPeer("127.0.0.1", second_port, second, paid)
    lie = lying.cfilter(paid).basic_filter
    assert not lie.match(script)
    serving, other = (lying, honest) if liar_serves else (honest, lying)
    with CompactFilterFetcher(
        "regtest", transport=serving, cross_check=[other]
    ) as fetcher:
        blocks = fetcher.scan_blocks([script])
        assert list(blocks) == [paid, spent]
        assert fetcher.transport is honest
        assert fetcher.cross_check == []
        for height, block in blocks.items():
            assert block.header.hash.hex() == first.call("getblockhash", [height])
