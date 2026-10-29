# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the header checks of `CompactFilterFetcher`.

A chain without the work to be held is downloaded twice, by btclib's
`HeadersSyncState`, whose own tests are btclib's; these test the fetcher
around it. The headers that are held are checked on the checks of
`ContextualCheckBlockHeader`, except its version check. The peers are
the scripted ones of `tests/fetch/peer_chain_test.py`.
"""

from __future__ import annotations

import secrets
from dataclasses import replace
from datetime import timedelta

import pytest
from btclib import consensus
from btclib.block.block import Block
from btclib.block.block_header import BlockHeader
from btclib.block.build import build_block, build_coinbase
from btclib.block.genesis import genesis_block
from btclib.block.proof_of_work import (
    block_work,
)
from btclib.exceptions import FetchError
from btclib.network import NETWORKS
from btclib.p2p import GetHeaders, Headers, Message
from btclib.p2p.headers_sync import HeadersSyncState
from typing_extensions import override

from btclib_wallet.fetch import compact_filters
from btclib_wallet.fetch.compact_filters import CompactFilterFetcher
from tests.fetch.peer_chain_test import (
    OTHER,
    REGTEST_BITS,
    REGTEST_HALVING,
    Chain,
    ScriptedPeer,
    mined,
)

GENESIS = genesis_block("regtest").header
GENESIS_TIME = int(GENESIS.time.timestamp())
CONSENSUS = NETWORKS["regtest"].consensus

# a commitment every fourth header, and six held back in the second pass
PARAMS = consensus.HeadersSyncParams(4, 6)
EASY = REGTEST_BITS


def work_of(chain: Chain) -> int:
    """Return the work of the chain, the genesis block included."""
    return sum(block_work(block.header.bits) for block in chain.blocks)


def presync_fetcher(
    monkeypatch: pytest.MonkeyPatch,
    chain: Chain,
    minimum: int,
    *,
    batch: int,
    offset: int = 0,
) -> tuple[CompactFilterFetcher, ScriptedPeer]:
    """Return a fetcher that wants `minimum` work and a peer of `chain`.

    The headers come `batch` at a time, the commitments are every fourth
    header from the first one, and six headers are held back.
    """
    monkeypatch.setattr(compact_filters, "MAX_HEADERS_RESULTS", batch)
    monkeypatch.setattr(secrets, "randbelow", lambda _n: offset)
    peer = ScriptedPeer(chain, max_headers=batch)
    fetcher = CompactFilterFetcher("regtest", transport=peer, verify_network=False)
    monkeypatch.setattr(
        fetcher, "_consensus", replace(CONSENSUS, minimum_chain_work=minimum)
    )
    monkeypatch.setattr(fetcher, "_headers_sync_params", PARAMS)
    return fetcher, peer


def clock(monkeypatch: pytest.MonkeyPatch, seconds: int) -> None:
    """Make the fetcher's clock read this many seconds past the genesis time."""
    monkeypatch.setattr(compact_filters, "time", lambda: float(GENESIS_TIME + seconds))


class EndlessPeer(ScriptedPeer):
    """A peer whose chain has no end, and whose headers are the cheapest."""

    def __init__(self, batch: int) -> None:
        super().__init__(Chain(), max_headers=batch)
        self.known = {GENESIS.hash: GENESIS}
        self.served = 0

    @override
    def reply_getheaders(self, payload: bytes) -> list[Message]:
        """Answer with the next headers of a chain that grows as it is asked."""
        # the fetcher has had ten times what it needs, and a test that waits for
        # a peer that never ends is a test that hangs
        assert self.served < 10 * 350, "the peer was asked for headers for ever"
        locator = GetHeaders.parse(payload).locator
        last = next(self.known[h] for h in locator if h in self.known)
        headers = []
        for _ in range(self.max_headers):
            candidate = BlockHeader(
                4,
                last.hash,
                len(self.known).to_bytes(32, "big"),
                last.time + timedelta(seconds=1),
                EASY,
            )
            last = mined(candidate)
            self.known[last.hash] = last
            headers.append(last)
        self.served += len(headers)
        return [self.message("headers", Headers(headers).serialize())]


@pytest.mark.parametrize("network", NETWORKS)
def test_each_network_syncs_with_its_row_of_btclib_s_parameters(network: str) -> None:
    """The fetcher of a network reads that network's `HEADERS_SYNC_PARAMS`."""
    fetcher = CompactFilterFetcher(
        network, transport=ScriptedPeer(Chain()), verify_network=False
    )
    assert fetcher._headers_sync_params is consensus.HEADERS_SYNC_PARAMS[network]


# the endless peer


def test_an_endless_chain_of_low_work_is_bounded_and_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The peer serves headers for as long as it is asked; the fetcher stops.

    The clock is set so that a chain from the genesis block can have 30
    commitments, one every ten headers. Nothing of the chain is held.
    """
    peer = EndlessPeer(50)
    fetcher = CompactFilterFetcher("regtest", transport=peer, verify_network=False)
    monkeypatch.setattr(compact_filters, "MAX_HEADERS_RESULTS", 50)
    monkeypatch.setattr(secrets, "randbelow", lambda _n: 0)
    monkeypatch.setattr(
        fetcher, "_consensus", replace(CONSENSUS, minimum_chain_work=10**80)
    )
    monkeypatch.setattr(
        fetcher, "_headers_sync_params", consensus.HeadersSyncParams(10, 20)
    )
    clock(monkeypatch, -7200 + 50)
    with pytest.raises(
        FetchError, match="headers 301 to 350 are not a chain the rules"
    ):
        fetcher.get_block_count()
    # the 31st commitment is the header 310, in the seventh batch
    assert peer.served == 350
    assert fetcher._headers == [GENESIS]
    assert len(peer.getheaders) == 7


def test_a_chain_that_ends_before_it_has_the_work_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A last batch that is not full ends the first pass, and the sync."""
    chain = Chain().extend(30)
    fetcher, peer = presync_fetcher(monkeypatch, chain, work_of(chain) + 1, batch=7)
    with pytest.raises(FetchError, match=r"a chain of work \d+, below the \d+"):
        fetcher.get_block_count()
    assert fetcher._headers == [GENESIS]
    assert len(peer.getheaders) == 5


# the two passes


def test_a_chain_with_the_work_is_downloaded_twice_and_held_the_second_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nothing is held in the first pass, and the second holds six back."""
    chain = Chain().extend(30)
    fetcher, peer = presync_fetcher(monkeypatch, chain, work_of(chain), batch=7)
    held = []
    honest = peer.reply_getheaders

    def record(payload: bytes) -> list[Message]:
        held.append(len(fetcher._hashes))
        return honest(payload)

    monkeypatch.setattr(peer, "reply_getheaders", record)
    assert fetcher.get_block_count() == 30
    assert fetcher._headers == [b.header for b in chain.blocks]
    # five requests for the first pass, five for the second, and then no
    # more since the last batch was not full
    assert held == [1] * 6 + [2, 9, 16, 23]
    # the second pass asks from the block the first one began at
    first_of_second = GetHeaders.parse(peer.getheaders[5].payload).locator
    assert list(first_of_second) == [chain.hashes[0], chain.hashes[0]]
    assert len(peer.getheaders) == 10


def test_a_buffer_longer_than_a_batch_holds_nothing_of_the_first_batches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The first batches of the second pass release nothing.

    So on every network, whose buffer is longer than a full batch.
    """
    chain = Chain().extend(30)
    fetcher, peer = presync_fetcher(monkeypatch, chain, work_of(chain), batch=7)
    monkeypatch.setattr(
        fetcher, "_headers_sync_params", consensus.HeadersSyncParams(4, 10)
    )
    held = []
    honest = peer.reply_getheaders

    def record(payload: bytes) -> list[Message]:
        held.append(len(fetcher._hashes))
        return honest(payload)

    monkeypatch.setattr(peer, "reply_getheaders", record)
    assert fetcher.get_block_count() == 30
    assert fetcher._headers == [b.header for b in chain.blocks]
    assert held == [1] * 7 + [5, 12, 19]


def test_a_second_pass_that_is_another_chain_is_refused_before_it_is_held(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A peer that shows a chain with the work and serves another is caught.

    The commitment of the first header kept is a bit of a salted hash, and
    here the two chains differ in that bit.
    """
    # the hash a commitment is taken of is in Core's byte order, the
    # reverse of the order `BlockHeader.hash` displays
    monkeypatch.setattr(
        HeadersSyncState, "_commitment", lambda _self, raw_hash: raw_hash[-1] & 1
    )
    shown = Chain().extend(30)
    other = next(
        c
        for c in (Chain().extend(30, salt=bytes([i])) for i in range(1, 64))
        if (c.hashes[4][0] & 1) != (shown.hashes[4][0] & 1)
    )
    fetcher, peer = presync_fetcher(monkeypatch, shown, work_of(shown), batch=7)
    honest = peer.reply_getheaders

    def switch(payload: bytes) -> list[Message]:
        if len(peer.getheaders) > 5:
            peer.chain = other
        return honest(payload)

    monkeypatch.setattr(peer, "reply_getheaders", switch)
    with pytest.raises(FetchError, match="headers 1 to 7 are not the chain first"):
        fetcher.get_block_count()
    assert fetcher._headers == [GENESIS]


@pytest.mark.parametrize("served", [7, 10])
def test_a_second_pass_that_ends_before_the_work_is_refused(
    monkeypatch: pytest.MonkeyPatch, served: int
) -> None:
    """A peer that serves only part of the chain it showed is caught.

    The second pass has its first batch, and then no header or three more,
    short of the work.
    """
    shown = Chain().extend(30)
    fetcher, peer = presync_fetcher(monkeypatch, shown, work_of(shown), batch=7)
    honest = peer.reply_getheaders

    def stop(payload: bytes) -> list[Message]:
        if len(peer.getheaders) > 6:
            peer.chain = Chain(shown.blocks[: served + 1])
        return honest(payload)

    monkeypatch.setattr(peer, "reply_getheaders", stop)
    with pytest.raises(FetchError, match="stopped serving the chain it showed"):
        fetcher.get_block_count()
    assert len(fetcher._hashes) < 31


def test_a_clock_hours_behind_the_chain_start_starts_no_sync(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The sync refuses the clock, and the fetcher fails the call."""
    chain = Chain().extend(30)
    fetcher, peer = presync_fetcher(monkeypatch, chain, work_of(chain), batch=7)
    clock(monkeypatch, -3 * 3600)
    with pytest.raises(FetchError, match="headers sync: the clock is more than"):
        fetcher.get_block_count()
    assert fetcher._headers == [GENESIS]
    assert len(peer.getheaders) == 1


def test_headers_past_the_work_proved_need_no_commitment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A peer that extended its chain between the passes is followed."""
    shown = Chain().extend(30)
    longer = shown.extend(10)
    fetcher, peer = presync_fetcher(monkeypatch, shown, work_of(shown), batch=7)
    honest = peer.reply_getheaders

    def grow(payload: bytes) -> list[Message]:
        if len(peer.getheaders) > 5:
            peer.chain = longer
        return honest(payload)

    monkeypatch.setattr(peer, "reply_getheaders", grow)
    assert fetcher.get_block_count() == 40
    assert fetcher._headers == [b.header for b in longer.blocks]


def test_a_low_work_header_is_checked_for_its_work_before_the_first_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The work a header claims is the work it has, or the batch is refused."""
    chain = Chain().extend(30)
    fetcher, peer = presync_fetcher(monkeypatch, chain, work_of(chain), batch=7)
    first = chain.blocks[1].header
    bad = replace(first, nonce=next(n for n in range(99) if not _solves(first, n)))
    monkeypatch.setattr(
        peer,
        "reply_getheaders",
        lambda _p: [peer.message("headers", Headers([bad]).serialize())],
    )
    with pytest.raises(FetchError, match="header 1"):
        fetcher.get_block_count()


def _solves(header: BlockHeader, nonce: int) -> bool:
    """Return whether the header with this nonce meets regtest's target."""
    candidate = replace(header, nonce=nonce)
    return candidate.hash <= candidate.target


def test_a_header_of_a_later_batch_is_checked_for_its_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every batch of a pass is checked for the work its headers claim."""
    chain = Chain().extend(30)
    fetcher, peer = presync_fetcher(monkeypatch, chain, work_of(chain), batch=7)
    honest = peer.reply_getheaders

    def corrupt(payload: bytes) -> list[Message]:
        if len(peer.getheaders) < 2:
            return honest(payload)
        header = chain.blocks[8].header
        bad = replace(
            header, nonce=next(n for n in range(99) if not _solves(header, n))
        )
        return [peer.message("headers", Headers([bad]).serialize())]

    monkeypatch.setattr(peer, "reply_getheaders", corrupt)
    with pytest.raises(FetchError, match="header 8"):
        fetcher.get_block_count()


def test_the_chain_held_is_left_by_a_fork_of_low_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fork that has not the work of the tip, less 144 blocks, is refused.

    The minimum is three blocks, the chain held has 150, and the fork has
    five: it has more than the minimum, and less than the tip's work less 144
    blocks'.
    """
    chain = Chain().extend(150)
    fetcher, peer = presync_fetcher(monkeypatch, chain, 0, batch=2000)
    fetcher.get_block_count()
    minimum = sum(block_work(b.header.bits) for b in chain.blocks[:3])
    monkeypatch.setattr(
        fetcher, "_consensus", replace(CONSENSUS, minimum_chain_work=minimum)
    )
    peer.chain = Chain().extend(5, salt=b"low")
    with pytest.raises(FetchError, match=r"a chain of work \d+, below the \d+"):
        fetcher.get_block_count()
    assert len(fetcher._hashes) == 151
    assert fetcher._displaced is None


def test_a_fork_from_near_the_tip_is_not_presynced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fork needs the tip's work, less 144 blocks': not much."""
    chain = Chain().extend(150)
    fetcher, peer = presync_fetcher(monkeypatch, chain, 0, batch=2000)
    fetcher.get_block_count()
    peer.chain = chain.fork(145).extend(3, salt=b"near")
    with pytest.raises(FetchError, match="no more work"):
        fetcher.get_block_count()
    assert len(fetcher._hashes) == 151


def test_headers_already_held_are_not_a_low_work_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Old headers of the chain held are passed over, whatever work they add."""
    chain = Chain().extend(14)
    fetcher, peer = presync_fetcher(monkeypatch, chain, 0, batch=2000)
    fetcher.get_block_count()
    monkeypatch.setattr(
        fetcher, "_consensus", replace(CONSENSUS, minimum_chain_work=fetcher._work[-1])
    )
    known = [b.header for b in chain.blocks[10:13]]
    monkeypatch.setattr(
        peer,
        "reply_getheaders",
        lambda _p: [peer.message("headers", Headers(known).serialize())],
    )
    assert fetcher.get_block_count() == 14


def test_a_fork_below_the_minimum_work_is_refused_before_any_of_it_is_held(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The chain held stays, and nothing is displaced."""
    chain = Chain().extend(14)
    fetcher, peer = presync_fetcher(monkeypatch, chain, 0, batch=2000)
    fetcher.get_block_count()
    monkeypatch.setattr(
        fetcher, "_consensus", replace(CONSENSUS, minimum_chain_work=fetcher._work[-1])
    )
    peer.chain = chain.fork(9).extend(3, salt=b"cheap")
    with pytest.raises(FetchError, match=r"a chain of work \d+, below the \d+"):
        fetcher.get_block_count()
    assert len(fetcher._hashes) == 15
    assert fetcher._displaced is None
    peer.chain = chain
    assert fetcher.get_block_count() == 14


def interrupted(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[CompactFilterFetcher, ScriptedPeer, Chain]:
    """Return a fetcher whose download stopped half way, and its peer.

    The peer served a chain of work the fetcher wants and then went silent
    in the second pass, after the fetcher held some of it. A caller takes
    the silence away with `monkeypatch.delattr`, never `del`: the undo at
    teardown then finds the attribute `monkeypatch` set.
    """
    chain = Chain().extend(30)
    fetcher, peer = presync_fetcher(monkeypatch, chain, work_of(chain), batch=7)
    honest = peer.reply_getheaders

    def silent(payload: bytes) -> list[Message]:
        return honest(payload) if len(peer.getheaders) <= 8 else []

    monkeypatch.setattr(peer, "reply_getheaders", silent)
    with pytest.raises(FetchError, match="did not answer|timeout"):
        fetcher.get_block_count()
    assert 1 < len(fetcher._hashes) < 31
    return fetcher, peer, chain


def test_what_an_interrupted_download_held_is_dropped_when_nothing_follows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A chain held without the minimum work does not stay for a silent peer."""
    fetcher, peer, _ = interrupted(monkeypatch)
    monkeypatch.setattr(
        peer, "reply_getheaders", lambda _p: [peer.message("headers", b"\x00")]
    )
    with pytest.raises(FetchError, match=r"a chain of work \d+, below the \d+ of"):
        fetcher.get_block_count()
    assert fetcher._headers == [GENESIS]


def test_an_interrupted_download_goes_on_from_what_it_held(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The second try begins at the tip held, and ends with the whole chain."""
    fetcher, peer, chain = interrupted(monkeypatch)
    monkeypatch.delattr(peer, "reply_getheaders")
    assert fetcher.get_block_count() == 30
    assert fetcher._headers == [b.header for b in chain.blocks]


def test_a_chain_with_the_work_replaces_a_chain_held_without_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fork with the minimum work displaces what an interrupted try held."""
    fetcher, peer, chain = interrupted(monkeypatch)
    monkeypatch.delattr(peer, "reply_getheaders")
    fork = chain.fork(1).extend(30, salt=b"fork")
    monkeypatch.setattr(
        fetcher,
        "_consensus",
        replace(CONSENSUS, minimum_chain_work=work_of(fork)),
    )
    peer.chain = fork
    assert fetcher.get_block_count() == 31
    assert fetcher._headers == [b.header for b in fork.blocks]


# the headers held


def timed_chain(offsets: list[int]) -> Chain:
    """Return a chain whose block `n` is `offsets[n - 1]` seconds on."""
    blocks: list[Block] = [genesis_block("regtest")]
    for height, offset in enumerate(offsets, 1):
        coinbase = build_coinbase(height, OTHER, halving_interval=REGTEST_HALVING)
        time = GENESIS.time + timedelta(seconds=offset)
        block = build_block(blocks[-1].header.hash, [coinbase], time, EASY)
        block.header = mined(block.header)
        blocks.append(block)
    return Chain(blocks)


def test_a_header_not_after_the_median_time_past_is_refused() -> None:
    """The median of the eleven blocks before is the earliest a block can be."""
    # the median of the times of blocks 2 to 12 is 7 seconds past the genesis
    # block's: 8 is after it, 7 is not
    after = timed_chain([*range(1, 13), 8])
    ok_fetcher = CompactFilterFetcher(
        "regtest", transport=ScriptedPeer(after), verify_network=False
    )
    assert ok_fetcher.get_block_count() == 13
    late = timed_chain([*range(1, 13), 7])
    fetcher = CompactFilterFetcher(
        "regtest", transport=ScriptedPeer(late), verify_network=False
    )
    past = GENESIS_TIME + 7
    with pytest.raises(
        FetchError, match=f"header 13: time {past} is not after .* {past}"
    ):
        fetcher.get_block_count()


def test_a_header_more_than_two_hours_ahead_of_the_clock_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two hours ahead is allowed, and a second more is not."""
    clock(monkeypatch, 100)
    allowed = timed_chain([1, 2, 100 + 7200])
    fetcher = CompactFilterFetcher(
        "regtest", transport=ScriptedPeer(allowed), verify_network=False
    )
    assert fetcher.get_block_count() == 3
    early = timed_chain([1, 2, 100 + 7201])
    fetcher = CompactFilterFetcher(
        "regtest", transport=ScriptedPeer(early), verify_network=False
    )
    with pytest.raises(FetchError, match="header 3: invalid timestamp"):
        fetcher.get_block_count()


def test_the_first_header_of_a_period_is_not_far_behind_its_parent_where_bip94_is(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BIP94 bounds how far a period's first block is behind its parent."""
    # a period of four blocks; block 3's median time past is 2000, so a
    # block 4 at 2200 is after it and 800 seconds behind its parent
    chain = timed_chain([1000, 2000, 3000, 2200])
    short = replace(CONSENSUS, pow_target_timespan=4 * CONSENSUS.pow_target_spacing)
    for enforced, expected in ((False, 4), (True, None)):
        consensus = replace(short, enforce_bip94=enforced)
        fetcher = CompactFilterFetcher(
            "regtest", transport=ScriptedPeer(chain), verify_network=False
        )
        monkeypatch.setattr(fetcher, "_consensus", consensus)
        if expected is None:
            with pytest.raises(FetchError, match="timewarp"):
                fetcher.get_block_count()
        else:
            assert fetcher.get_block_count() == expected


def test_the_total_work_may_be_the_threshold_exactly() -> None:
    """A chain with exactly the work is held at once; with one more, not."""
    chain = Chain().extend(14)
    for minimum, held in ((work_of(chain), True), (work_of(chain) + 1, False)):
        peer = ScriptedPeer(chain)
        fetcher = CompactFilterFetcher("regtest", transport=peer, verify_network=False)
        fetcher._consensus = replace(CONSENSUS, minimum_chain_work=minimum)
        if held:
            assert fetcher.get_block_count() == 14
            # held as it came: no second pass
            assert len(peer.getheaders) == 1
        else:
            with pytest.raises(FetchError, match="below the"):
                fetcher.get_block_count()


def test_a_batch_ending_on_a_held_header_is_checked_for_its_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A header without work before a held one is refused; nothing changes."""
    chain = Chain().extend(5)
    peer = ScriptedPeer(chain)
    fetcher = CompactFilterFetcher("regtest", transport=peer, verify_network=False)
    fetcher.sync()
    parent = chain.blocks[1].header
    first = BlockHeader(
        4, parent.hash, bytes(32), parent.time + timedelta(seconds=1), EASY
    )
    unsolved = next(
        h
        for h in (replace(first, nonce=n) for n in range(99))
        if not _solves(h, h.nonce)
    )
    held = chain.blocks[3].header
    batch = Headers([unsolved, held]).serialize()
    monkeypatch.setattr(
        peer, "reply_getheaders", lambda _p: [peer.message("headers", batch)]
    )
    with pytest.raises(FetchError, match="header 2"):
        fetcher.get_block_count()
    assert fetcher._hashes == chain.hashes
    assert len(fetcher._filter_headers) == 6
