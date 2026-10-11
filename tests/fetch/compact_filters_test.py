# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `CompactFilterFetcher`, against a peer scripted from a chain.

`tests/fetch/peer_chain_test.py` mines a regtest chain in memory and answers
the BIP157 requests from it, as Bitcoin Core does. Each test that wants
the peer to lie replaces one of its `reply_*` methods; nothing opens a
socket. `tests/integration/compact_filters_test.py` is where a real node
is asked.
"""

from __future__ import annotations

import itertools
from collections.abc import Callable, Iterable
from dataclasses import replace
from typing import Any

import pytest
from bitcoin_core_rpc import FetchError as RpcFetchError
from btclib.block.block import Block
from btclib.block.block_header import BlockHeader
from btclib.block.build import build_coinbase
from btclib.exceptions import BTClibTypeError, BTClibValueError, FetchError
from btclib.p2p import (
    BlockFilterType,
    CFHeaders,
    CFilter,
    GetCFHeaders,
    GetCFilters,
    GetData,
    GetHeaders,
    Headers,
    Message,
    Pong,
    Version,
)
from btclib.script import ScriptPubKey

from btclib_wallet.fetch import compact_filters
from btclib_wallet.fetch.compact_filters import CompactFilterFetcher
from tests.fetch.peer_chain_test import (
    OTHER,
    REGTEST_HALVING,
    WALLET,
    Chain,
    ScriptedPeer,
    services,
)

# more blocks above the genesis block than the eleven the locator takes one
# by one, with the wallet paid in blocks 3 and 11
CHAIN = Chain().extend(14, frozenset({3, 11}))
TIP = CHAIN.height
PAID = [3, 11]
GENESIS_SCRIPT = CHAIN.blocks[0].transactions[0].vout[0].script_pub_key.script


def build(
    chain: Chain = CHAIN, **kwargs: Any
) -> tuple[CompactFilterFetcher, ScriptedPeer]:
    """Return a regtest fetcher and the peer it talks to."""
    peer = ScriptedPeer(chain)
    return CompactFilterFetcher("regtest", transport=peer, **kwargs), peer


def says(peer: ScriptedPeer, method: str, replies: list[Message]) -> None:
    """Make the peer answer a request with these messages instead."""
    setattr(peer, method, lambda _payload: replies)


def headers_message(peer: ScriptedPeer, *headers: BlockHeader) -> list[Message]:
    """Return a `headers` message with these headers."""
    return [peer.message("headers", Headers(list(headers)).serialize())]


def says_with(peer: ScriptedPeer, method: str, reply: Callable[[bytes], Any]) -> None:
    """Make the peer answer a request by calling `reply` instead."""
    setattr(peer, method, reply)


def unsolved(header: BlockHeader) -> BlockHeader:
    """Return the header with a nonce that does not solve it."""
    for nonce in itertools.count():
        candidate = replace(header, nonce=nonce)
        try:
            candidate.assert_valid_pow(b"\x20\x7f\xff\xff")
        except BTClibValueError:
            return candidate
    raise AssertionError  # pragma: no cover -- the loop above never ends


# construction


def test_a_transport_has_three_methods_and_a_timeout_is_a_duration() -> None:
    """A bad transport, timeout or network is refused at construction."""
    with pytest.raises(BTClibTypeError, match="not a peer transport"):
        CompactFilterFetcher("regtest", transport=object())  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="non-numeric timeout"):
        build(timeout="soon")
    with pytest.raises(BTClibValueError, match="timeout is not a positive"):
        build(timeout=0)
    with pytest.raises(BTClibValueError, match="unknown network"):
        CompactFilterFetcher("bogus", transport=ScriptedPeer(CHAIN))


def test_construction_opens_nothing() -> None:
    """Nothing is sent until the first question."""
    _, peer = build()
    assert peer.sent == []


# the interface a header chain answers


def test_the_header_chain_answers_what_a_fetcher_is_asked() -> None:
    """The tip and the headers come from the chain the peer served."""
    fetcher, _ = build()
    assert fetcher.get_block_count() == TIP
    assert fetcher.get_best_block_id() == CHAIN.hashes[-1]
    assert fetcher.get_block_header(5) == CHAIN.blocks[5].header
    assert fetcher.get_block_header(0) == CHAIN.blocks[0].header
    assert fetcher.sync() == TIP


def test_a_header_is_handed_over_as_a_copy() -> None:
    """Changing a returned header leaves the chain held unchanged."""
    fetcher, _ = build()
    header = fetcher.get_block_header(5)
    header.nonce += 1
    assert fetcher.get_block_header(5) == CHAIN.blocks[5].header


def test_a_height_past_the_tip_is_a_fetch_error() -> None:
    """The peer has no block above its tip."""
    fetcher, _ = build()
    with pytest.raises(FetchError, match="no block at height 15"):
        fetcher.get_block_header(TIP + 1)


def test_a_height_is_checked_before_the_peer_is_asked() -> None:
    """A height that is no height is refused without a message."""
    fetcher, peer = build()
    with pytest.raises(BTClibValueError, match="invalid height"):
        fetcher.get_block_header(-1)
    with pytest.raises(BTClibTypeError, match="invalid height type"):
        fetcher.get_block_header("5")  # type: ignore[arg-type]
    assert peer.sent == []


def test_a_transaction_by_id_is_not_served() -> None:
    """`get_tx` and `get_tx_out` raise, and ask the peer nothing."""
    fetcher, peer = build()
    tx_id = CHAIN.blocks[3].transactions[0].id
    with pytest.raises(FetchError, match="cannot serve a transaction"):
        fetcher.get_tx(tx_id)
    with pytest.raises(FetchError, match="cannot serve a transaction"):
        fetcher.get_tx_out(CHAIN.blocks[3].transactions[0].vin[0].prev_out)
    assert peer.sent == []


def test_a_transaction_id_is_still_checked() -> None:
    """A malformed id is refused as for any other fetcher."""
    fetcher, _ = build()
    with pytest.raises(BTClibValueError, match="invalid"):
        fetcher.get_tx(b"short")


# scanning


def test_only_the_blocks_whose_filter_matches_are_downloaded() -> None:
    """One `getdata` names the matching blocks and no other."""
    fetcher, peer = build()
    blocks = fetcher.scan_blocks([WALLET])
    assert list(blocks) == PAID
    for height, block in blocks.items():
        assert block.header == CHAIN.blocks[height].header
        assert block.transactions[0].id == CHAIN.blocks[height].transactions[0].id
    (getdata,) = peer.requests("getdata")
    assert [item.hash for item in GetData.parse(getdata.payload).items] == [
        CHAIN.hashes[3],
        CHAIN.hashes[11],
    ]


def test_the_outputs_of_a_block_are_labelled_with_the_fetchers_network() -> None:
    """The scripts of a block carry the network of the fetcher."""
    fetcher, _ = build()
    out = fetcher.scan_blocks([WALLET])[3].transactions[0].vout[0]
    assert out.script_pub_key.network == "regtest"


@pytest.mark.parametrize(
    "scripts, expected",
    [
        ([WALLET], PAID),
        ([OTHER, WALLET.hex()], list(range(1, TIP + 1))),
        (iter([ScriptPubKey(WALLET, "regtest")]), PAID),
    ],
    ids=["octets", "hex", "script_pub_key"],
)
def test_a_script_is_octets_hex_or_a_script_pub_key(
    scripts: Iterable[Any], expected: list[int]
) -> None:
    """Each spelling of a script finds what the octets find."""
    fetcher, _ = build()
    assert list(fetcher.scan_blocks(scripts)) == expected


def test_a_range_is_scanned_from_both_ends_included() -> None:
    """A block at either end of the range is scanned."""
    fetcher, peer = build()
    assert list(fetcher.scan_blocks([WALLET], 4)) == [11]
    assert list(fetcher.scan_blocks([WALLET], 0, 3)) == [3]
    assert list(fetcher.scan_blocks([WALLET], 3, 11)) == PAID
    peer.sent.clear()
    assert fetcher.scan_blocks([WALLET], 4, 10) == {}
    assert peer.requests("getdata") == []


def test_a_start_past_the_tip_scans_nothing() -> None:
    """A range above the tip is empty, and no filter is asked for."""
    fetcher, peer = build()
    assert fetcher.scan_blocks([WALLET], TIP + 1) == {}
    assert peer.requests("getcfilters") == []


def test_a_stop_past_the_tip_is_a_fetch_error() -> None:
    """A stop height above the peer's tip is refused."""
    fetcher, _ = build()
    with pytest.raises(FetchError, match="chain ends at 14, not 15"):
        fetcher.scan_blocks([WALLET], 0, TIP + 1)


def test_a_range_and_the_scripts_are_checked_before_the_peer_is_asked() -> None:
    """Wrong arguments are refused without a message to the peer."""
    fetcher, peer = build()
    with pytest.raises(BTClibValueError, match="below start height"):
        fetcher.scan_blocks([WALLET], 5, 4)
    with pytest.raises(BTClibValueError, match="invalid height"):
        fetcher.scan_blocks([WALLET], -1)
    with pytest.raises(BTClibTypeError, match="invalid height type"):
        fetcher.scan_blocks([WALLET], 0, "5")  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError, match="no scripts"):
        fetcher.scan_blocks([])
    with pytest.raises(BTClibTypeError, match="not an iterable of scripts: bytes"):
        fetcher.scan_blocks(WALLET)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="not an iterable of scripts: str"):
        fetcher.scan_blocks(WALLET.hex())
    with pytest.raises(BTClibTypeError, match="ScriptPubKey"):
        fetcher.scan_blocks(ScriptPubKey(WALLET, "regtest"))  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid max_blocks type"):
        fetcher.scan_blocks([WALLET], max_blocks="1")  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError, match="invalid max_blocks: 0"):
        fetcher.scan_blocks([WALLET], max_blocks=0)
    with pytest.raises(BTClibTypeError, match="not an iterable of scripts: int"):
        fetcher.scan_blocks(5)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid octets type: int"):
        fetcher.scan_blocks([5])  # type: ignore[list-item]
    assert peer.sent == []


@pytest.mark.parametrize("length", [12, 14])
def test_a_chain_longer_than_a_message_is_asked_for_in_several(
    monkeypatch: pytest.MonkeyPatch, length: int
) -> None:
    """Requests are batched: 12 blocks fill the last headers reply, 14 not."""
    chain = Chain(CHAIN.blocks[: length + 1])
    monkeypatch.setattr(compact_filters, "MAX_HEADERS_RESULTS", 4)
    monkeypatch.setattr(compact_filters, "MAX_GETCFHEADERS_SIZE", 5)
    monkeypatch.setattr(compact_filters, "MAX_GETCFILTERS_SIZE", 3)
    peer = ScriptedPeer(chain, max_headers=4)
    fetcher = CompactFilterFetcher("regtest", transport=peer)
    assert list(fetcher.scan_blocks([WALLET])) == PAID
    ranges = [
        GetCFilters.parse(m.payload).start_height for m in peer.requests("getcfilters")
    ]
    assert ranges == list(range(0, length + 1, 3))
    starts = [
        GetCFHeaders.parse(m.payload).start_height
        for m in peer.requests("getcfheaders")
    ]
    assert starts == list(range(0, length + 1, 5))


def test_a_locator_thins_out_towards_the_genesis_block() -> None:
    """The locator is `CBlockLocator`'s: dense at the tip, sparse below."""
    fetcher, peer = build()
    # the second request is the first made with the chain held
    fetcher.sync()
    fetcher.sync()
    locator = GetHeaders.parse(peer.requests("getheaders")[-1].payload).locator
    # eleven blocks one by one from the tip, then twice as far apart each time
    assert list(locator[:11]) == CHAIN.hashes[TIP:3:-1]
    assert list(locator[11:]) == [CHAIN.hashes[2], CHAIN.hashes[0]]


# the peer and the connection


def test_the_peer_is_greeted_once_and_not_again() -> None:
    """One `version` and `verack` exchange serves every later question."""
    fetcher, peer = build()
    fetcher.sync()
    fetcher.scan_blocks([WALLET])
    assert peer.versions == 1
    assert [m.command for m in peer.sent[:2]] == ["version", "verack"]
    version = Version.parse(peer.sent[0].payload)
    assert version.relay is False
    assert version.nonce != 0
    assert version.user_agent == b"/btclib-wallet/"
    assert all(m.magic == peer.magic for m in peer.sent)


def test_a_ping_is_answered_and_other_messages_are_dropped() -> None:
    """A `ping` is answered with its nonce and an unknown message ignored."""
    fetcher, peer = build()
    peer.noise = [peer.ping(77), peer.message("sendcmpct", b"\x00" * 9)]
    assert fetcher.get_block_count() == TIP
    assert [m.payload for m in peer.requests("pong")] == [Pong(77).serialize()]


def test_a_ping_with_no_nonce_is_a_fetch_error() -> None:
    """A `ping` that does not parse is the peer's failure."""
    fetcher, peer = build()
    peer.noise = [peer.message("ping")]
    with pytest.raises(FetchError, match="ping"):
        fetcher.get_block_count()


def test_verack_may_come_before_version() -> None:
    """The handshake ends when both have come, in either order."""
    fetcher, peer = build()
    original = peer.reply_version

    def verack_first(payload: bytes) -> list[Message]:
        version, verack = original(payload)
        return [verack, version]

    setattr(peer, "reply_version", verack_first)  # noqa: B010
    assert fetcher.get_block_count() == TIP
    assert len(peer.requests("verack")) == 1


def test_a_peer_without_compact_filters_is_refused() -> None:
    """A peer that does not advertise `NODE_COMPACT_FILTERS` is dropped."""
    peer = ScriptedPeer(CHAIN, peer_services=services(filters=False))
    fetcher = CompactFilterFetcher("regtest", transport=peer)
    with pytest.raises(FetchError, match="does not serve compact block filters"):
        fetcher.get_block_count()
    assert peer.closed == 1


def test_a_pruned_peer_is_refused() -> None:
    """A peer that does not advertise `NODE_NETWORK` is dropped."""
    peer = ScriptedPeer(CHAIN, peer_services=services(network=False))
    fetcher = CompactFilterFetcher("regtest", transport=peer)
    with pytest.raises(FetchError, match="does not serve the whole chain"):
        fetcher.get_block_count()
    assert peer.closed == 1


def test_a_version_that_does_not_parse_is_a_fetch_error() -> None:
    """A `version` that does not parse is the peer's failure."""
    fetcher, peer = build()
    says(peer, "reply_version", [peer.message("version", b"junk")])
    with pytest.raises(FetchError, match="version"):
        fetcher.get_block_count()


def test_a_message_of_another_network_is_a_fetch_error() -> None:
    """A message start that is not the network's is refused."""
    peer = ScriptedPeer(CHAIN, magic=b"\xf9\xbe\xb4\xd9")
    fetcher = CompactFilterFetcher("regtest", transport=peer)
    with pytest.raises(FetchError, match="message start f9beb4d9 is not regtest's"):
        fetcher.get_block_count()


def test_a_silent_peer_is_a_fetch_error_and_the_next_call_greets_again() -> None:
    """A failure closes the connection, and the next call opens one."""
    fetcher, peer = build()
    fetcher.get_block_count()
    original = peer.reply_getheaders
    says(peer, "reply_getheaders", [])
    with pytest.raises(FetchError, match="timeout expired"):
        fetcher.get_block_count()
    assert peer.closed == 1
    peer.reply_getheaders = original  # type: ignore[method-assign]
    assert fetcher.get_block_count() == TIP
    assert peer.versions == 2


def test_a_transport_that_cannot_send_is_a_fetch_error() -> None:
    """A transport's error is translated to btclib's `FetchError`."""
    fetcher, peer = build()

    def refuse(_message: Message, _timeout: float) -> None:
        raise RpcFetchError("no connection")

    setattr(peer, "send", refuse)  # noqa: B010
    with pytest.raises(FetchError, match="no connection"):
        fetcher.get_block_count()
    assert peer.closed == 1


def test_an_answer_that_takes_longer_than_the_timeout_is_a_fetch_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exchange has one deadline, and a peer answering after it fails."""
    ticks = itertools.count()
    monkeypatch.setattr(compact_filters, "monotonic", lambda: next(ticks) * 1000.0)
    fetcher, _ = build(timeout=5)
    with pytest.raises(FetchError, match="did not answer in time"):
        fetcher.get_block_count()


def test_the_connection_is_closed_with_the_context_and_the_chain_is_kept() -> None:
    """Leaving the context closes the connection and keeps the headers."""
    peer = ScriptedPeer(CHAIN)
    with CompactFilterFetcher("regtest", transport=peer) as fetcher:
        assert fetcher.get_block_count() == TIP
    assert peer.closed == 1
    asked = len(peer.requests("getheaders"))
    assert fetcher.get_block_header(5) == CHAIN.blocks[5].header
    assert peer.versions == 2
    assert len(peer.requests("getheaders")) == asked + 1


def test_a_transport_that_cannot_close_is_a_fetch_error() -> None:
    """A transport's error on closing is translated too."""
    fetcher, peer = build()

    def refuse() -> None:
        raise RpcFetchError("stuck")

    peer.close = refuse  # type: ignore[method-assign]
    with pytest.raises(FetchError, match="stuck"):
        fetcher.close()


# the chain the peer is on


def test_a_chain_that_does_not_start_at_the_genesis_block_is_refused() -> None:
    """`verify_network` refuses a chain of another genesis for good."""
    fetcher, peer = build()
    orphan = replace(CHAIN.blocks[1].header, previous_block_hash=b"\x11" * 32)
    says(
        peer,
        "reply_getheaders",
        [peer.message("headers", Headers([orphan]).serialize())],
    )
    with pytest.raises(BTClibValueError, match="genesis"):
        fetcher.get_block_count()
    requests = len(peer.sent)
    with pytest.raises(BTClibValueError, match="genesis"):
        fetcher.get_best_block_id()
    assert len(peer.sent) == requests


@pytest.mark.parametrize(
    "ask",
    [lambda f: f.sync(), lambda f: f.scan_blocks([WALLET])],
    ids=["sync", "scan_blocks"],
)
def test_sync_and_scan_blocks_verify_the_network_first(
    ask: Callable[[CompactFilterFetcher], object],
) -> None:
    """The two questions only this fetcher has are held to the same rule."""
    fetcher, peer = build()
    orphan = replace(CHAIN.blocks[1].header, previous_block_hash=b"\x11" * 32)
    says(peer, "reply_getheaders", headers_message(peer, orphan))
    with pytest.raises(BTClibValueError, match="genesis"):
        ask(fetcher)
    assert len(peer.requests("getheaders")) == 1
    assert peer.requests("getcfheaders") == []


def test_a_chain_of_one_block_has_nothing_to_compare() -> None:
    """A peer with only the genesis block passes, and its block is scanned."""
    peer = ScriptedPeer(Chain())
    fetcher = CompactFilterFetcher("regtest", transport=peer)
    assert fetcher.sync() == 0
    assert fetcher.get_best_block_id() == CHAIN.hashes[0]
    assert fetcher.scan_blocks([WALLET]) == {}
    assert list(fetcher.scan_blocks([GENESIS_SCRIPT])) == [0]


def test_the_network_may_be_left_unasked() -> None:
    """`verify_network=False` asks the peer nothing beyond the question."""
    fetcher, peer = build(verify_network=False)
    fetcher.get_block_count()
    assert len(peer.requests("getheaders")) == 1


def test_the_network_is_asked_for_by_name() -> None:
    """`assert_network` asks from the genesis block, on a synced fetcher too."""
    fetcher, peer = build(verify_network=False)
    assert fetcher.get_block_count() == TIP
    fetcher.assert_network()
    request = peer.requests("getheaders")[-1]
    locator = GetHeaders.parse(request.payload).locator
    assert list(locator) == [CHAIN.hashes[0]]


def test_headers_that_connect_to_nothing_held_are_refused() -> None:
    """Headers whose parent is not held are the peer's failure."""
    fetcher, peer = build(verify_network=False)
    orphan = replace(CHAIN.blocks[1].header, previous_block_hash=b"\x11" * 32)
    says(peer, "reply_getheaders", headers_message(peer, orphan))
    with pytest.raises(FetchError, match="do not connect"):
        fetcher.get_block_count()


def test_headers_out_of_order_are_refused() -> None:
    """A header that does not follow the one before it is refused."""
    fetcher, peer = build(verify_network=False)
    first, third = CHAIN.blocks[1].header, CHAIN.blocks[3].header
    says(peer, "reply_getheaders", headers_message(peer, first, third))
    with pytest.raises(FetchError, match="header 2 does not follow"):
        fetcher.get_block_count()


def test_a_header_without_the_work_it_claims_is_refused() -> None:
    """A header that its own bits do not satisfy is refused."""
    fetcher, peer = build(verify_network=False)
    says(
        peer,
        "reply_getheaders",
        headers_message(peer, unsolved(CHAIN.blocks[1].header)),
    )
    with pytest.raises(FetchError, match="header 1"):
        fetcher.get_block_count()


def test_a_header_with_other_bits_than_the_rules_ask_is_refused() -> None:
    """A header with work but not the bits the retarget rules ask is refused."""
    harder = CHAIN.fork(2).extend(1, bits=b"\x1f\x7f\xff\xff")
    fetcher, _ = build(harder, verify_network=False)
    with pytest.raises(FetchError, match="header 3: bits 1f7fffff instead of 207fffff"):
        fetcher.get_block_count()


def test_headers_the_chain_already_holds_add_nothing() -> None:
    """Headers already held end the synchronization."""
    fetcher, peer = build()
    fetcher.get_block_count()
    known = [b.header for b in CHAIN.blocks[10:]]
    says(peer, "reply_getheaders", headers_message(peer, *known))
    assert fetcher.get_block_count() == TIP


def test_a_peer_behind_the_chain_held_adds_nothing() -> None:
    """A peer on a shorter chain leaves the chain held as it is."""
    fetcher, peer = build()
    fetcher.get_block_count()
    peer.chain = CHAIN.fork(12)
    assert fetcher.get_block_count() == TIP


def test_a_reorganization_replaces_the_chain_above_the_fork() -> None:
    """Headers and filter headers above a fork are replaced by the peer's."""
    fetcher, peer = build()
    fetcher.sync()
    assert list(fetcher.scan_blocks([WALLET])) == PAID
    old_block = fetcher.get_block_header(11)
    peer.chain = CHAIN.fork(9).extend(7, frozenset({11}), salt=b"other")
    assert fetcher.get_block_count() == 16
    assert fetcher.get_best_block_id() == peer.chain.hashes[-1]
    assert fetcher.get_block_header(9) == CHAIN.blocks[9].header
    assert fetcher.get_block_header(11) != old_block
    # the filter headers above the fork went with the headers, and the new
    # ones are checked against what the peer then serves
    blocks = fetcher.scan_blocks([WALLET])
    assert list(blocks) == PAID
    assert blocks[11].header == peer.chain.blocks[11].header


def test_a_fork_with_less_work_is_refused_and_the_chain_held_is_put_back() -> None:
    """A shorter fork is not followed, and nothing of the chain is lost."""
    fetcher, peer = build()
    fetcher.sync()
    peer.chain = CHAIN.fork(9).extend(3, salt=b"shorter")
    with pytest.raises(FetchError, match="no more work"):
        fetcher.get_block_count()
    peer.chain = CHAIN
    assert fetcher.get_block_header(11) == CHAIN.blocks[11].header
    assert fetcher.get_best_block_id() == CHAIN.hashes[-1]
    assert list(fetcher.scan_blocks([WALLET])) == PAID


def test_a_fork_with_equal_work_is_refused() -> None:
    """The chain seen first is kept, as Bitcoin Core keeps it."""
    fetcher, peer = build()
    fetcher.get_block_count()
    peer.chain = CHAIN.fork(9).extend(5, salt=b"other")
    with pytest.raises(FetchError, match="no more work"):
        fetcher.get_block_count()
    peer.chain = CHAIN
    assert fetcher.get_best_block_id() == CHAIN.hashes[-1]


def test_a_fork_that_fails_half_way_is_put_back() -> None:
    """A fork is followed as its headers arrive, and undone on failure."""
    fetcher, peer = build()
    fetcher.get_block_count()
    fork = CHAIN.fork(9).extend(3, salt=b"broken")
    second = unsolved(fork.blocks[11].header)
    says(
        peer,
        "reply_getheaders",
        headers_message(peer, fork.blocks[10].header, second),
    )
    with pytest.raises(FetchError, match="header 11"):
        fetcher.get_block_count()
    del peer.reply_getheaders  # the peer is honest again
    assert fetcher.get_block_header(11) == CHAIN.blocks[11].header
    assert fetcher.get_block_header(TIP) == CHAIN.blocks[TIP].header


@pytest.mark.parametrize(
    "second_fork",
    [CHAIN.fork(5).extend(3, salt=b"b").blocks[6:9], None],
    ids=["below the first", "above the first"],
)
def test_a_second_fork_in_one_synchronization_is_undone_with_the_first(
    monkeypatch: pytest.MonkeyPatch, second_fork: list[Block] | None
) -> None:
    """The chain put back is the one held before either fork."""
    monkeypatch.setattr(compact_filters, "MAX_HEADERS_RESULTS", 3)
    first = CHAIN.fork(9).extend(3, salt=b"a")
    if second_fork is None:
        second_fork = first.fork(11).extend(1, salt=b"b").blocks[12:13]
    fetcher, peer = build(verify_network=False)
    fetcher.get_block_count()
    batches = iter([first.blocks[10:13], second_fork])

    def reply(_payload: bytes) -> list[Message]:
        headers = [block.header for block in next(batches, [])]
        return headers_message(peer, *headers)

    says_with(peer, "reply_getheaders", reply)
    with pytest.raises(FetchError, match="no more work"):
        fetcher.get_block_count()
    del peer.reply_getheaders
    assert fetcher.get_block_header(11) == CHAIN.blocks[11].header
    assert fetcher.get_block_header(TIP) == CHAIN.blocks[TIP].header
    assert fetcher.get_block_count() == TIP


@pytest.mark.parametrize("fork_at", [9, 0], ids=["from the middle", "from genesis"])
def test_a_fork_below_the_minimum_work_takes_the_displaced_chain_with_it(
    fork_at: int,
) -> None:
    """Nothing of either chain stays, and an honest peer is followed again."""
    fetcher, peer = build()
    fetcher.get_block_count()
    honest = fetcher._consensus
    setattr(fetcher, "_consensus", replace(honest, minimum_chain_work=10**80))  # noqa: B010
    peer.chain = CHAIN.fork(fork_at).extend(16 - fork_at, salt=b"cheap")
    with pytest.raises(FetchError, match="below the 1000000"):
        fetcher.get_block_count()
    assert len(fetcher._hashes) == 1
    setattr(fetcher, "_consensus", honest)  # noqa: B010
    peer.chain = CHAIN
    assert fetcher.get_block_count() == TIP
    assert fetcher.get_block_header(1) == CHAIN.blocks[1].header


def test_a_fork_interrupted_half_way_is_put_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Anything that interrupts a synchronization leaves the chain held."""
    monkeypatch.setattr(compact_filters, "MAX_HEADERS_RESULTS", 3)
    fetcher, peer = build(verify_network=False)
    fetcher.get_block_count()
    fork = CHAIN.fork(9).extend(3, salt=b"interrupted")
    asked = []

    def reply(_payload: bytes) -> list[Message]:
        asked.append(1)
        if len(asked) > 1:
            raise KeyboardInterrupt
        return headers_message(peer, *[b.header for b in fork.blocks[10:13]])

    says_with(peer, "reply_getheaders", reply)
    with pytest.raises(KeyboardInterrupt):
        fetcher.get_block_count()
    del peer.reply_getheaders
    assert fetcher.get_block_header(TIP) == CHAIN.blocks[TIP].header
    assert fetcher.get_block_header(11) == CHAIN.blocks[11].header


def test_a_chain_below_the_minimum_work_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A chain the network's minimum work outweighs is not followed."""
    fetcher, _ = build()
    required = replace(fetcher._consensus, minimum_chain_work=10**80)
    monkeypatch.setattr(fetcher, "_consensus", required)
    with pytest.raises(FetchError, match="below the 1000000"):
        fetcher.get_block_count()
    assert len(fetcher._hashes) == 1
    with pytest.raises(FetchError, match="below the 1000000"):
        fetcher.scan_blocks([WALLET])


# filter headers


def lying_about_cfheaders(peer: ScriptedPeer, **changes: Any) -> None:
    """Make the peer's `cfheaders` answers differ from the truth in a field."""
    honest = peer.reply_getcfheaders

    def lie(payload: bytes) -> list[Message]:
        reply = CFHeaders.parse(honest(payload)[0].payload)
        return [peer.message("cfheaders", replace(reply, **changes).serialize())]

    peer.reply_getcfheaders = lie  # type: ignore[method-assign]


@pytest.mark.parametrize(
    "changes",
    [
        {"filter_type": 1},
        {"stop_hash": b"\x22" * 32},
        {"previous_filter_header": b"\x22" * 32},
        {"filter_hashes": ()},
    ],
    ids=["type", "stop hash", "previous header", "count"],
)
def test_cfheaders_that_do_not_answer_the_request_are_refused(
    changes: dict[str, Any],
) -> None:
    """A `cfheaders` answering another request is refused."""
    fetcher, peer = build()
    lying_about_cfheaders(peer, **changes)
    with pytest.raises(FetchError, match="cfheaders that do not answer"):
        fetcher.sync()


def test_cfheaders_that_do_not_parse_are_refused() -> None:
    """A `cfheaders` that does not parse is the peer's failure."""
    fetcher, peer = build()
    says(peer, "reply_getcfheaders", [peer.message("cfheaders", b"")])
    with pytest.raises(FetchError, match="cfheaders"):
        fetcher.sync()


# filters


def cfilters_with(peer: ScriptedPeer, make: Callable[[int], CFilter]) -> None:
    """Make the peer answer `getcfilters` with `make(height)` per block."""

    def reply(payload: bytes) -> list[Message]:
        request = GetCFilters.parse(payload)
        stop = peer.chain.hashes.index(request.stop_hash)
        return [
            peer.message("cfilter", make(height).serialize())
            for height in range(request.start_height, stop + 1)
        ]

    peer.reply_getcfilters = reply  # type: ignore[method-assign]


@pytest.mark.parametrize(
    "make, why",
    [
        (
            lambda peer: lambda h: replace(peer.cfilter(h), filter_type=1),
            "not the filter asked for",
        ),
        (
            lambda peer: lambda h: replace(peer.cfilter(h), block_hash=bytes(32)),
            "not the filter asked for",
        ),
        (
            lambda peer: (
                lambda h: CFilter(
                    BlockFilterType.BASIC,
                    peer.chain.hashes[h],
                    peer.chain.filters[h - 1].serialize(),
                )
            ),
            "does not match its filter header",
        ),
        (
            lambda peer: lambda h: replace(peer.cfilter(h), filter_bytes=b"\xff\xff"),
            "cfilter",
        ),
    ],
    ids=["type", "block", "filter header", "bytes"],
)
def test_a_filter_that_is_not_the_one_asked_for_is_refused(
    make: Callable[[ScriptedPeer], Callable[[int], CFilter]], why: str
) -> None:
    """A filter of another block or not hashing to its header is refused."""
    fetcher, peer = build()
    cfilters_with(peer, make(peer))
    with pytest.raises(FetchError, match=why):
        fetcher.scan_blocks([WALLET])


def test_filters_that_stop_short_are_a_fetch_error() -> None:
    """A peer sending fewer filters than asked for fails the scan."""
    fetcher, peer = build()
    honest = peer.reply_getcfilters
    peer.reply_getcfilters = lambda payload: honest(payload)[:-1]  # type: ignore[method-assign]
    with pytest.raises(FetchError, match="timeout expired"):
        fetcher.scan_blocks([WALLET])


# blocks


def test_a_peer_that_does_not_hold_a_block_is_a_fetch_error() -> None:
    """A `notfound` for a block its filter matched fails the scan."""
    fetcher, peer = build()
    says(peer, "reply_getdata", [peer.message("notfound", b"\x00")])
    with pytest.raises(FetchError, match="does not hold a block"):
        fetcher.scan_blocks([WALLET])


def test_a_block_that_was_not_asked_for_is_refused() -> None:
    """A block outside the request is refused."""
    fetcher, peer = build()
    says(
        peer,
        "reply_getdata",
        [peer.message("block", peer.block_payload(CHAIN.blocks[5]))],
    )
    with pytest.raises(FetchError, match="not asked for"):
        fetcher.scan_blocks([WALLET])


def test_a_block_that_is_not_what_its_header_commits_to_is_refused() -> None:
    """A block whose transactions miss the header's merkle root is refused."""
    fetcher, peer = build()
    other = build_coinbase(3, OTHER, halving_interval=REGTEST_HALVING, extra_nonce=b"?")
    forged = Block(CHAIN.blocks[3].header, [other], check_validity=False)
    says(peer, "reply_getdata", [peer.message("block", peer.block_payload(forged))])
    with pytest.raises(FetchError, match="merkle root"):
        fetcher.scan_blocks([WALLET])


def test_a_block_that_does_not_parse_is_refused() -> None:
    """A `block` that does not parse is the peer's failure."""
    fetcher, peer = build()
    says(peer, "reply_getdata", [peer.message("block", b"\x00")])
    with pytest.raises(FetchError, match="block"):
        fetcher.scan_blocks([WALLET])


def test_a_block_is_returned_as_it_was_sent() -> None:
    """Relabelling the outputs does not change a byte of the block."""
    fetcher, _ = build()
    block = fetcher.scan_blocks([WALLET])[3]
    assert block.serialize(check_validity=False) == CHAIN.blocks[3].serialize(
        check_validity=False
    )


def test_a_scan_that_matches_more_blocks_than_the_bound_is_refused() -> None:
    """A peer cannot make a call hold more blocks than the caller allows."""
    fetcher, peer = build()
    with pytest.raises(FetchError, match="more than the max_blocks of 1 blocks"):
        fetcher.scan_blocks([WALLET], max_blocks=1)
    assert peer.requests("getdata") == []
    assert list(fetcher.scan_blocks([WALLET], max_blocks=2)) == PAID


def test_the_bound_counts_the_blocks_of_every_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Earlier windows count; the passing window's blocks are not downloaded."""
    monkeypatch.setattr(compact_filters, "MAX_GETCFILTERS_SIZE", 5)
    fetcher, peer = build()
    with pytest.raises(FetchError, match="max_blocks of 1"):
        fetcher.scan_blocks([WALLET], max_blocks=1)
    assert len(peer.requests("getdata")) == 1


def test_each_block_has_a_deadline_of_its_own(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Blocks that take longer than the timeout in all, each within it, pass."""
    fetcher, peer = build(timeout=5)
    now = [0.0]
    monkeypatch.setattr(compact_filters, "monotonic", lambda: now[0])
    receive = peer.receive

    def slow(timeout: float) -> Message:
        message = receive(timeout)
        if message.command == "block":
            if timeout < 4.0:  # pragma: no cover -- without the reset only
                raise RpcFetchError("timeout expired")
            now[0] += 4.0
        return message

    setattr(peer, "receive", slow)  # noqa: B010
    assert list(fetcher.scan_blocks([WALLET])) == PAID
    assert now[0] == 8.0
