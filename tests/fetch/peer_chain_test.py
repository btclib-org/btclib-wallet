# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A regtest chain and a peer serving it over BIP157, both built in memory.

`Chain` mines blocks at regtest's difficulty, which costs a couple of hash
evaluations each, and keeps with every block the BIP158 filter and the
BIP157 filter header Bitcoin Core would serve for it. `ScriptedPeer` is a
`PeerTransport` answering the messages `CompactFilterFetcher` sends from a
`Chain`, and each of its `reply_*` methods is a place a test overrides to
make the peer say something else.

No socket is opened: the peer is the transport.
"""

from __future__ import annotations

from collections import deque
from datetime import timedelta

from bitcoin_core_rpc import FetchError as RpcFetchError
from btclib.block.block import Block
from btclib.block.block_filter import BasicBlockFilter
from btclib.block.block_header import BlockHeader
from btclib.block.build import build_block, build_coinbase
from btclib.block.genesis import genesis_block
from btclib.block.mining import mine
from btclib.network import NETWORKS
from btclib.p2p import (
    BlockFilterType,
    BlockPayload,
    CFHeaders,
    CFilter,
    GetCFHeaders,
    GetCFilters,
    GetData,
    GetHeaders,
    Headers,
    Message,
    Ping,
    ServiceFlags,
    Verack,
    Version,
    magic_from_network,
)
from typing_extensions import override

from btclib_wallet.fetch.peer_transport import PeerTransport

REGTEST_BITS = b"\x20\x7f\xff\xff"
REGTEST_HALVING = NETWORKS["regtest"].consensus.subsidy_halving_interval

# two scripts, one for a wallet and one for the miner of every other block
WALLET = b"\x00\x14" + bytes(range(20))
OTHER = b"\x00\x14" + bytes(range(1, 21))


def mined(header: BlockHeader) -> BlockHeader:
    """Return the header solved, regtest's target being a coin toss."""
    solved = mine(header)
    assert solved is not None
    return solved


class Chain:
    """Blocks of regtest from the genesis block, with their filters.

    `height` is the tip's.
    """

    def __init__(self, blocks: list[Block] | None = None) -> None:
        self.blocks = [genesis_block("regtest")] if blocks is None else blocks
        # the scripts a block's inputs spend are in its filter, and `OTHER` is
        # what a spend here is said to have spent
        self.filters = [
            BasicBlockFilter.from_block(
                b, [OTHER] * sum(len(tx.vin) for tx in b.transactions[1:])
            )
            for b in self.blocks
        ]
        self.filter_headers: list[bytes] = []
        previous = bytes(32)
        for filter_ in self.filters:
            previous = filter_.header(previous)
            self.filter_headers.append(previous)

    @property
    def height(self) -> int:
        """Return the height of the tip."""
        return len(self.blocks) - 1

    @property
    def hashes(self) -> list[bytes]:
        """Return the block hashes by height."""
        return [block.header.hash for block in self.blocks]

    def extend(
        self,
        count: int,
        pay: frozenset[int] = frozenset(),
        *,
        salt: bytes = b"",
        bits: bytes = REGTEST_BITS,
    ) -> Chain:
        """Return a chain `count` blocks longer, the old one untouched.

        `pay` is the heights whose coinbase pays `WALLET`; every other
        coinbase pays `OTHER`.

        `salt` is in the coinbase of each new block, so that two chains
        forking at one height have different blocks above it.
        """
        blocks = list(self.blocks)
        for height in range(len(blocks), len(blocks) + count):
            script = WALLET if height in pay else OTHER
            coinbase = build_coinbase(
                height, script, halving_interval=REGTEST_HALVING, extra_nonce=salt
            )
            time = blocks[-1].header.time + timedelta(seconds=1)
            block = build_block(blocks[-1].header.hash, [coinbase], time, bits)
            block.header = mined(block.header)
            blocks.append(block)
        return Chain(blocks)

    def fork(self, height: int) -> Chain:
        """Return the chain cut back to `height`."""
        return Chain(self.blocks[: height + 1])


def services(*, filters: bool = True, network: bool = True) -> int:
    """Return the service flags a full node advertises."""
    flags = ServiceFlags.NODE_WITNESS
    if network:
        flags |= ServiceFlags.NODE_NETWORK
    if filters:
        flags |= ServiceFlags.NODE_COMPACT_FILTERS
    return int(flags)


class ScriptedPeer(PeerTransport):
    """A peer answering BIP157 requests from a `Chain`.

    Everything sent is kept in `sent`, in order. What a request is
    answered with is a list of messages put in `inbox`, built by the
    `reply_*` method for its command; `noise` is sent before the answer
    to `version`.
    """

    def __init__(
        self,
        chain: Chain,
        *,
        magic: bytes | None = None,
        peer_services: int | None = None,
        max_headers: int = 2000,
    ) -> None:
        self.chain = chain
        self.magic = magic_from_network("regtest") if magic is None else magic
        self.services = services() if peer_services is None else peer_services
        self.max_headers = max_headers
        self.sent: list[Message] = []
        self.getheaders: list[Message] = []
        self.inbox: deque[Message] = deque()
        self.closed = 0
        self.versions = 0
        self.noise: list[Message] = []

    # the transport

    @override
    def send(self, message: Message, timeout: float) -> None:
        """Keep the message and queue the answer to it."""
        self.sent.append(message)
        if message.command == "getheaders":
            self.getheaders.append(message)
        replies = {
            "version": self.reply_version,
            "getheaders": self.reply_getheaders,
            "getcfheaders": self.reply_getcfheaders,
            "getcfilters": self.reply_getcfilters,
            "getdata": self.reply_getdata,
        }.get(message.command)
        if replies is not None:
            self.inbox.extend(replies(message.payload))

    @override
    def receive(self, timeout: float) -> Message:
        """Return the next queued message, or fail as a silent peer does."""
        if not self.inbox:
            raise RpcFetchError("timeout expired")
        return self.inbox.popleft()

    @override
    def close(self) -> None:
        """Count the closes."""
        self.closed += 1

    # what it says

    def message(self, command: str, payload: bytes = b"") -> Message:
        """Return a message of this peer's network."""
        return Message(self.magic, command, payload)

    def requests(self, command: str) -> list[Message]:
        """Return the messages sent with this command."""
        return [m for m in self.sent if m.command == command]

    def reply_version(self, _payload: bytes) -> list[Message]:
        """Answer `version` with the peer's own, then `verack`."""
        self.versions += 1
        version = Version(services=self.services, user_agent=b"/scripted/")
        return [
            *self.noise,
            self.message("version", version.serialize()),
            self.message("verack", Verack().serialize()),
        ]

    def reply_getheaders(self, payload: bytes) -> list[Message]:
        """Answer with the headers after the first locator hash held."""
        locator = GetHeaders.parse(payload).locator
        heights = {h: i for i, h in enumerate(self.chain.hashes)}
        start = next((heights[h] for h in locator if h in heights), 0) + 1
        headers = [b.header for b in self.chain.blocks[start:][: self.max_headers]]
        return [self.message("headers", Headers(headers).serialize())]

    def reply_getcfheaders(self, payload: bytes) -> list[Message]:
        """Answer with the filter hashes of the range asked for."""
        request = GetCFHeaders.parse(payload)
        stop = self.chain.hashes.index(request.stop_hash)
        start = request.start_height
        previous = self.chain.filter_headers[start - 1] if start else bytes(32)
        hashes = [f.hash for f in self.chain.filters[start : stop + 1]]
        reply = CFHeaders(BlockFilterType.BASIC, request.stop_hash, previous, hashes)
        return [self.message("cfheaders", reply.serialize())]

    def reply_getcfilters(self, payload: bytes) -> list[Message]:
        """Answer with one `cfilter` per block of the range asked for."""
        request = GetCFilters.parse(payload)
        stop = self.chain.hashes.index(request.stop_hash)
        return [
            self.message("cfilter", self.cfilter(height).serialize())
            for height in range(request.start_height, stop + 1)
        ]

    def cfilter(self, height: int) -> CFilter:
        """Return the `cfilter` of the block at `height`."""
        return CFilter(
            BlockFilterType.BASIC,
            self.chain.hashes[height],
            self.chain.filters[height].serialize(),
        )

    def reply_getdata(self, payload: bytes) -> list[Message]:
        """Answer with the blocks asked for, with their witnesses."""
        by_hash = {b.header.hash: b for b in self.chain.blocks}
        return [
            self.message("block", self.block_payload(by_hash[i.hash]))
            for i in GetData.parse(payload).items
        ]

    @staticmethod
    def block_payload(block: Block) -> bytes:
        """Return the `block` payload, unchecked: it is not mainnet's target."""
        payload = BlockPayload(block, True, check_validity=False)
        return payload.serialize(check_validity=False)

    def ping(self, nonce: int) -> Message:
        """Return a `ping` of this peer's network."""
        return self.message("ping", Ping(nonce).serialize())
