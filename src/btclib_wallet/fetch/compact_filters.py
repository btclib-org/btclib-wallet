# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A BIP157/158 light client: the blocks that touch a wallet, from one peer.

`CompactFilterFetcher` asks a peer for the header chain and for the BIP157
filter header of every block, then for the BIP158 filter of every block in
the range being scanned, and downloads only the blocks whose filter may
hold one of the scripts it was given.

`btclib.p2p` is the codec of the messages and `btclib.block.block_filter`
the filter; `PeerTransport` is the socket. This module is the protocol
over them.

**What is checked, and what one peer can still do** is stated once, in
`SECURITY.md`, under *A backend is trusted, and not every backend alike*.

**Not defended against.** Bitcoin Core answers nothing to a
`getcfheaders` or `getcfilters` for blocks its filter index has not
reached (`ProcessGetCFHeaders` and `ProcessGetCFilters` of
`net_processing.cpp`), so a call times out while the peer builds its
index, and briefly after each new block. A reorganization whose fork
point is a full `headers` message or more above the locator hash below it
is not followed: the peer then sends a batch of headers already held, and
the synchronization stops.

**What a filter client cannot serve.** `get_tx` raises `FetchError`: Bitcoin
Core serves a transaction by id only from its mempool and from its latest
block (`FindTxForGetData` of `net_processing.cpp`), and a filter client
holds the transactions of the blocks it downloaded and no others.
`get_tx_out` is the interface's derivation from `get_tx` and raises with
it. The blocks `scan_blocks` returns are where a wallet reads its
transactions.
`get_block_count`, `get_best_block_id` and `get_block_header` are served
from the header chain, which is synchronized on each call.

**One peer, one thread.** The connection is opened by the first call and
greeted with a `version` exchange; a `FetchError` closes it, and the next
call opens it again and keeps the chain already held. Bitcoin Core drops
a connection idle for its `TIMEOUT_INTERVAL` (`CConnman::InactivityCheck`
of `net.cpp`), and the fetcher answers no ping between calls, so the
first call after an idle stretch raises `FetchError` and the next one
reconnects. A peer is refused unless it advertises
`NODE_COMPACT_FILTERS` and `NODE_NETWORK`. Calls are not safe to make from
two threads.

**`verify_network`** asks the peer for the headers after the genesis block
of the fetcher's network and refuses a chain whose first header does not
follow it. A peer with no block after the genesis block has nothing to
compare, and passes.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from copy import copy
from time import monotonic, time
from types import TracebackType
from typing import Self

from btclib.alias import Octets
from btclib.block.block import Block
from btclib.block.block_header import BlockHeader
from btclib.block.genesis import genesis_block
from btclib.block.header_context import next_bits_required
from btclib.block.proof_of_work import block_work
from btclib.exceptions import (
    BTClibTypeError,
    BTClibValueError,
    FetchError,
)
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
    Inventory,
    InventoryType,
    Message,
    NotFound,
    Payload,
    Ping,
    Pong,
    ServiceFlags,
    Verack,
    Version,
    magic_from_network,
)
from btclib.p2p.limits import (
    MAX_GETCFHEADERS_SIZE,
    MAX_GETCFILTERS_SIZE,
    MAX_HEADERS_RESULTS,
    PROTOCOL_VERSION,
)
from btclib.script import ScriptPubKey
from btclib.tx import Tx
from btclib.utils import bytes_from_octets, is_integer, is_octets
from typing_extensions import override

from btclib_wallet.fetch.fetcher import (
    NetworkVerifyingFetcher,
    block_header_height,
    client_errors,
    fetch_errors,
    tx_for_network,
    tx_id_hex,
)
from btclib_wallet.fetch.peer_transport import PeerTransport
from btclib_wallet.fetch.transport import DEFAULT_TIMEOUT, valid_timeout

__all__ = [
    "CompactFilterFetcher",
]

_USER_AGENT = b"/btclib-wallet/"

_BASIC = BlockFilterType.BASIC

_NO_FILTER_HEADER = bytes(32)

# the default max_blocks of scan_blocks, whose docstring says why; a block
# is up to 4 MB
_MAX_BLOCKS = 100


class CompactFilterFetcher(NetworkVerifyingFetcher):
    """The blocks that touch some scripts, found by BIP158 filters.

    `scan_blocks` is the reason to use it, and `sync` is the part of it
    that costs: the headers and the filter headers of the whole chain,
    kept for the life of the fetcher. `SECURITY.md` says what is checked
    and what a single peer can still do.

    The `Fetcher` questions that a header chain answers are served from
    it: `get_block_count`, `get_best_block_id` and `get_block_header`.
    `get_tx` and `get_tx_out` are not served.

    `transport` is required, keyword-only, and has no default, as it is
    for `ElectrumFetcher`: which peer sees this client is not this
    package's decision. `TcpPeerTransport(host, port)` is the one shipped.
    It is a context manager that closes the connection on exit.

    `timeout` is the seconds each exchange with the peer may take -- the
    greeting, one request and all of its answers, or one block of a
    download -- and not a whole `scan_blocks`, which makes many.
    """

    def __init__(
        self,
        network: str = "mainnet",
        *,
        transport: PeerTransport,
        verify_network: bool = True,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        super().__init__(network, verify_network=verify_network)
        if not all(
            callable(getattr(transport, name, None))
            for name in ("send", "receive", "close")
        ):
            raise BTClibTypeError(f"not a peer transport: {transport!r}")
        self.transport = transport
        # checked here for a transport of the caller's that checks nothing
        self.timeout = valid_timeout(timeout)
        self._magic = magic_from_network(self.network)
        self._consensus = NETWORKS[self.network].consensus
        genesis = genesis_block(self.network).header
        # the header chain, by height, and the inverse of its hashes
        self._headers = [genesis]
        self._hashes = [genesis.hash]
        # the cumulative work up to and including each block
        self._work = [block_work(genesis.bits)]
        # the chain a fork displaced in this synchronization: its fork
        # height, its headers and its work
        self._displaced: tuple[int, list[BlockHeader], int] | None = None
        self._height_of = {genesis.hash: 0}
        # the filter header of each block, by height, as far as synchronized
        self._filter_headers: list[bytes] = []
        self._greeted = False

    def __enter__(self) -> Self:
        """Return this fetcher."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the connection."""
        self.close()

    def close(self) -> None:
        """Close the connection to the peer, keeping the chain held."""
        self._greeted = False
        with client_errors():
            self.transport.close()

    # the connection

    def _deadline(self) -> float:
        """Return the instant a request begun now has to be answered by."""
        return monotonic() + self.timeout

    def _send(self, payload: Payload) -> None:
        """Send one payload to the peer, framed for this network."""
        message = payload.to_message(self._magic)
        with client_errors():
            self.transport.send(message, self.timeout)

    def _next(self, deadline: float) -> Message:
        """Return the next message of the peer, refusing another network's."""
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise FetchError("the peer did not answer in time")
        with client_errors():
            message = self.transport.receive(remaining)
        if message.magic != self._magic:
            err_msg = f"message start {message.magic.hex()} is not"
            err_msg += f" {self.network}'s {self._magic.hex()}"
            raise FetchError(err_msg)
        return message

    def _receive(self, commands: tuple[str, ...], deadline: float) -> Message:
        """Return the next message whose command is one of `commands`.

        Whatever else a peer sends -- `inv`, `addr`, `feefilter` -- is
        dropped, except a `ping`, which is answered: a peer that is not
        answered closes the connection.
        """
        while True:
            message = self._next(deadline)
            if message.command in commands:
                return message
            if message.command == Ping.command:
                with fetch_errors("ping"):
                    nonce = Ping.parse(message.payload).nonce
                self._send(Pong(nonce))

    def _greet(self) -> None:
        """Exchange `version` and `verack` with the peer.

        A peer that does not advertise `NODE_COMPACT_FILTERS` is refused:
        it would not answer the filter requests. So is one that does not
        advertise `NODE_NETWORK`: a pruned peer serves filters and then
        disconnects on a request for an old block.
        """
        deadline = self._deadline()
        self._send(
            Version(
                timestamp=int(time()),
                nonce=secrets.randbits(64),
                user_agent=_USER_AGENT,
                relay=False,
            )
        )
        have_version = have_verack = False
        while not (have_version and have_verack):
            message = self._receive((Version.command, Verack.command), deadline)
            if message.command == Verack.command:
                have_verack = True
                continue
            with fetch_errors("version"):
                services = Version.parse(message.payload).services
            if not services & ServiceFlags.NODE_COMPACT_FILTERS:
                raise FetchError("the peer does not serve compact block filters")
            if not services & ServiceFlags.NODE_NETWORK:
                raise FetchError("the peer does not serve the whole chain")
            self._send(Verack())
            have_version = True
        self._greeted = True

    @contextmanager
    def _session(self) -> Iterator[None]:
        """Greet the peer if it is not greeted, and drop it on a failure.

        A `FetchError` can leave the stream in the middle of a message,
        and a peer that sent a wrong answer is not asked again on the
        same connection.
        """
        try:
            if not self._greeted:
                self._greet()
            yield
        except FetchError:
            self.close()
            raise

    # the header chain

    def _parent_of(self, header: BlockHeader) -> BlockHeader:
        """Return the header a header held names as its parent."""
        return self._headers[self._height_of[header.previous_block_hash]]

    def _truncate(self, height: int) -> None:
        """Forget the chain from `height` on, as a reorganization does."""
        for dropped in self._hashes[height:]:
            del self._height_of[dropped]
        del self._headers[height:]
        del self._hashes[height:]
        del self._work[height:]
        del self._filter_headers[height:]

    def _append(self, header: BlockHeader) -> None:
        """Add a checked header to the tip of the chain."""
        header_hash = header.hash
        self._height_of[header_hash] = len(self._hashes)
        self._headers.append(header)
        self._hashes.append(header_hash)
        self._work.append(self._work[-1] + block_work(header.bits))

    def _locator(self) -> list[bytes]:
        """Return the hashes a peer finds the last common block from.

        The tip, then ever sparser blocks back to genesis, which is
        `btclib.p2p.inventory`'s `CBlockLocator` shape.
        """
        locator = []
        height = len(self._hashes) - 1
        step = 1
        while height > 0:
            locator.append(self._hashes[height])
            if len(locator) > 10:
                step *= 2
            height -= step
        locator.append(self._hashes[0])
        return locator

    def _request_headers(self, locator: list[bytes]) -> list[BlockHeader]:
        """Return the headers following the last block of the locator held."""
        deadline = self._deadline()
        self._send(GetHeaders(PROTOCOL_VERSION, locator))
        message = self._receive((Headers.command,), deadline)
        with fetch_errors("headers"):
            return list(Headers.parse(message.payload).headers)

    def _check_header(self, header: BlockHeader, parent_height: int) -> None:
        """Refuse a header that does not owe the chain what it claims.

        Work enough for its own bits, and the bits the retarget rules ask
        of a block on this parent.
        """
        parent = self._headers[parent_height]
        with fetch_errors(f"header {parent_height + 1}"):
            header.assert_valid_pow(self._consensus.pow_limit_bits)
            required = next_bits_required(
                header, parent, parent_height, self._parent_of, self._consensus
            )
            if header.bits != required:
                err_msg = f"bits {header.bits.hex()} instead of {required.hex()}"
                raise BTClibValueError(err_msg)

    def _displace(self, height: int) -> None:
        """Remember the chain held from `height` on, before a fork replaces it.

        A second fork in one synchronization below the first one reaches
        into the chain the first left, which is the original down to the
        first fork's height and the displaced chain's own tail above it.
        """
        if self._displaced is None:
            self._displaced = (height, self._headers[height:], self._work[-1])
        elif height < self._displaced[0]:
            fork, tail, work = self._displaced
            self._displaced = (height, self._headers[height:fork] + tail, work)

    def _connect(self, batch: list[BlockHeader]) -> int:
        """Add a batch of headers to the chain, returning how many were new.

        The first header's parent has to be held. A header already held is
        passed over, and a header that differs from the one held at its
        height replaces it and everything above it.
        """
        parent_height = self._height_of.get(batch[0].previous_block_hash)
        if parent_height is None:
            raise FetchError("headers that do not connect to the chain held")
        added = 0
        for header in batch:
            height = parent_height + 1
            header_hash = header.hash
            if header.previous_block_hash != self._hashes[parent_height]:
                raise FetchError(f"header {height} does not follow the one before it")
            if height < len(self._hashes) and self._hashes[height] == header_hash:
                parent_height = height
                continue
            self._check_header(header, parent_height)
            if height < len(self._hashes):
                self._displace(height)
                self._truncate(height)
            self._append(header)
            added += 1
            parent_height = height
        return added

    def _fetch_headers(self) -> None:
        """Ask for headers until the peer sends none that are new."""
        while True:
            batch = self._request_headers(self._locator())
            if not batch or not self._connect(batch):
                return
            if len(batch) < MAX_HEADERS_RESULTS:
                return

    def _restore(self) -> None:
        """Put back the chain a fork displaced, if one did."""
        if self._displaced is not None:
            height, headers, _ = self._displaced
            self._truncate(height)
            for header in headers:
                self._append(header)
            self._displaced = None

    def _assert_enough_work(self) -> None:
        """Refuse a chain that is not worth following.

        A chain, and the chain it displaced if it displaced one, both with
        less work than the network's minimum are refused and dropped, so
        that they do not stay in memory and grow. A fork with no more work
        than the chain it displaced, which has the minimum, is refused and
        that chain put back; equal work is refused too, as Bitcoin Core
        keeps the chain it saw first.
        """
        minimum = self._consensus.minimum_chain_work
        displaced_work = 0 if self._displaced is None else self._displaced[2]
        if max(self._work[-1], displaced_work) < minimum:
            err_msg = f"a chain of work {self._work[-1]}, below the {minimum}"
            err_msg += f" of {self.network}"
            self._displaced = None
            self._truncate(1)
            raise FetchError(err_msg)
        if self._displaced is not None and self._work[-1] <= displaced_work:
            raise FetchError("a fork with no more work than the chain held")

    def _sync_headers(self) -> int:
        """Follow the peer's chain if it has more work than the one held.

        Returns the height of the tip. A fork is followed as it arrives. The
        chain held is put back if anything interrupts the fork, or if the
        fork ends with no more work and the chain held has the network's
        minimum work.
        """
        self._displaced = None
        followed = False
        try:
            self._fetch_headers()
            self._assert_enough_work()
            followed = True
        finally:
            if not followed:
                self._restore()
        self._displaced = None
        return len(self._hashes) - 1

    # the filter headers and the filters

    def _sync_filter_headers(self) -> None:
        """Ask for the filter header of every block that has none yet."""
        while len(self._filter_headers) < len(self._hashes):
            start = len(self._filter_headers)
            stop = min(start + MAX_GETCFHEADERS_SIZE, len(self._hashes)) - 1
            deadline = self._deadline()
            self._send(GetCFHeaders(_BASIC, start, self._hashes[stop]))
            message = self._receive((CFHeaders.command,), deadline)
            with fetch_errors("cfheaders"):
                reply = CFHeaders.parse(message.payload)
            previous = self._filter_headers[start - 1] if start else _NO_FILTER_HEADER
            if (
                reply.filter_type != _BASIC
                or reply.stop_hash != self._hashes[stop]
                or reply.previous_filter_header != previous
                or len(reply.filter_hashes) != stop - start + 1
            ):
                raise FetchError("cfheaders that do not answer the request")
            self._filter_headers.extend(reply.filter_headers)

    def _sync(self) -> int:
        """Synchronize the headers and the filter headers, returning the tip."""
        tip = self._sync_headers()
        self._sync_filter_headers()
        return tip

    def _matching_heights(
        self, start: int, stop: int, elements: list[bytes]
    ) -> list[int]:
        """Return the heights from `start` to `stop` that may hold an element.

        The range is at most `MAX_GETCFILTERS_SIZE` blocks. Each filter is
        checked against the filter header held before it is read.
        """
        deadline = self._deadline()
        self._send(GetCFilters(_BASIC, start, self._hashes[stop]))
        heights = []
        for height in range(start, stop + 1):
            message = self._receive((CFilter.command,), deadline)
            with fetch_errors(f"cfilter {height}"):
                reply = CFilter.parse(message.payload)
                if (
                    reply.filter_type != _BASIC
                    or reply.block_hash != self._hashes[height]
                ):
                    raise BTClibValueError("not the filter asked for")
                filter_ = reply.basic_filter
                previous = (
                    self._filter_headers[height - 1] if height else _NO_FILTER_HEADER
                )
                if filter_.header(previous) != self._filter_headers[height]:
                    raise BTClibValueError("does not match its filter header")
                if filter_.match_any(elements):
                    heights.append(height)
        return heights

    def _blocks(self, heights: list[int]) -> dict[int, Block]:
        """Download the blocks at `heights`, each checked against the chain.

        Each block has a deadline of its own: a window can be many blocks of
        some megabytes each.
        """
        deadline = self._deadline()
        wanted = {self._hashes[height]: height for height in heights}
        self._send(
            GetData([Inventory(InventoryType.MSG_WITNESS_BLOCK, h) for h in wanted])
        )
        blocks = {}
        while wanted:
            message = self._receive((BlockPayload.command, NotFound.command), deadline)
            if message.command == NotFound.command:
                raise FetchError("the peer does not hold a block its filter matched")
            with fetch_errors("block"):
                block = BlockPayload.parse(message.payload, check_validity=False).block
                height = wanted.pop(block.header.hash, -1)
                if height < 0:
                    raise BTClibValueError("a block that was not asked for")
                block.assert_valid_structure()
            blocks[height] = Block(
                block.header,
                [tx_for_network(tx, self.network) for tx in block.transactions],
                check_validity=False,
            )
            deadline = self._deadline()
        return dict(sorted(blocks.items()))

    # the interface

    def sync(self) -> int:
        """Synchronize headers and filter headers; return the tip height.

        `scan_blocks` does this itself; calling it first spends the time
        before the scripts are known.
        """
        self._verify_once()
        with self._session():
            return self._sync()

    def scan_blocks(
        self,
        scripts: Iterable[Octets | ScriptPubKey],
        start_height: int = 0,
        stop_height: int | None = None,
        *,
        max_blocks: int = _MAX_BLOCKS,
    ) -> dict[int, Block]:
        """Return the blocks, by height, whose filter may hold one of `scripts`.

        Both ends are included, and the end defaults to the tip. A filter
        answers "may": about one block in 784931 per script that does not
        touch the wallet is downloaded all the same, and a block that does
        touch it spends from the script or pays to it, which the caller
        finds by reading the transactions.

        A filter holds the output scripts of a block and the scripts of
        the outputs it spends. The scripts are `ScriptPubKey` objects or
        their octets.

        `max_blocks` bounds the blocks one call downloads and holds: a
        peer serving filters that match every block would otherwise
        decide how much memory the call takes. Filters are read
        `MAX_GETCFILTERS_SIZE` heights at a time, and the matching blocks
        of each batch are downloaded before the next batch is read. The
        call raises `FetchError` before downloading a batch whose matches
        would pass the bound, by which time the earlier batches' blocks
        are downloaded. A caller with more matches raises `max_blocks` or
        scans in ranges.
        """
        if not is_integer(max_blocks):
            raise BTClibTypeError(
                f"invalid max_blocks type: {type(max_blocks).__name__}"
            )
        if max_blocks < 1:
            raise BTClibValueError(f"invalid max_blocks: {max_blocks}")
        elements = _elements_from_scripts(scripts)
        first = block_header_height(start_height)
        last = None if stop_height is None else block_header_height(stop_height)
        if last is not None and last < first:
            raise BTClibValueError(f"stop height {last} below start height {first}")
        self._verify_once()
        with self._session():
            tip = self._sync()
            stop = tip if last is None else last
            if stop > tip:
                raise FetchError(f"the peer's chain ends at {tip}, not {stop}")
            blocks: dict[int, Block] = {}
            for start in range(first, stop + 1, MAX_GETCFILTERS_SIZE):
                end = min(start + MAX_GETCFILTERS_SIZE, stop + 1) - 1
                heights = self._matching_heights(start, end, elements)
                if len(blocks) + len(heights) > max_blocks:
                    err_msg = "the filters match more than the max_blocks of"
                    err_msg += f" {max_blocks} blocks"
                    raise FetchError(err_msg)
                if heights:
                    blocks.update(self._blocks(heights))
            return blocks

    @override
    def get_tx(self, tx_id: Octets) -> Tx:
        """Raise: a filter client cannot serve a transaction by id alone.

        The module docstring says why; `scan_blocks` is how a transaction
        is found.
        """
        err_msg = f"transaction {tx_id_hex(tx_id)}: a compact filter client"
        err_msg += " cannot serve a transaction by its id, use scan_blocks"
        raise FetchError(err_msg)

    @override
    def get_block_count(self) -> int:
        """Return the height of the peer's chain tip, via `getheaders`."""
        self._verify_once()
        with self._session():
            return self._sync_headers()

    @override
    def get_best_block_id(self) -> bytes:
        """Return the id of the tip of the peer's chain, via `getheaders`."""
        self._verify_once()
        with self._session():
            self._sync_headers()
        return self._hashes[-1]

    @override
    def get_block_header(self, height: int) -> BlockHeader:
        """Return the header at this height, from the header chain.

        Its work and its bits are checked on arrival. `SECURITY.md` says
        what is not checked and what the peer can still do.
        """
        height = block_header_height(height)
        self._verify_once()
        with self._session():
            tip = self._sync_headers()
        if height > tip:
            raise FetchError(f"no block at height {height}: the tip is {tip}")
        return copy(self._headers[height])

    @override
    def assert_network(self) -> None:
        """Raise unless the peer's chain starts from this network's genesis.

        One `getheaders` from the genesis block, whose first answer has to
        name it as its parent. A peer with no block after the genesis block
        has nothing to compare, and passes.
        """
        with self._session():
            batch = self._request_headers([self._hashes[0]])
        expected = NETWORKS[self.network].genesis_block
        if batch and batch[0].previous_block_hash != expected:
            err_msg = "the peer serves a chain whose first block follows"
            err_msg += f" {batch[0].previous_block_hash.hex()}, not the genesis"
            err_msg += f" {expected.hex()} this {self.network} fetcher was built for"
            raise BTClibValueError(err_msg)


def _elements_from_scripts(scripts: Iterable[Octets | ScriptPubKey]) -> list[bytes]:
    """Return the octets of each script, refusing none and a lone script."""
    # every Octets is itself iterable, and one script passed for a list of
    # them would be read as a list of one-octet scripts
    if is_octets(scripts) or isinstance(scripts, ScriptPubKey):
        raise BTClibTypeError(f"not an iterable of scripts: {type(scripts).__name__}")
    if not isinstance(scripts, Iterable):
        raise BTClibTypeError(f"not an iterable of scripts: {type(scripts).__name__}")
    elements = [
        script.script if isinstance(script, ScriptPubKey) else bytes_from_octets(script)
        for script in scripts
    ]
    if not elements:
        raise BTClibValueError("no scripts to look for")
    return elements
