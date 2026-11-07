# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `btclib_wallet.fetch.history.start_height_for_time`.

`TimedFetcher` serves a chain of headers that carry nothing but their
times, and the times go backwards where a test needs them to.
"""

from __future__ import annotations

import bisect
from datetime import UTC, datetime, timedelta, timezone

import pytest
from btclib.alias import Octets
from btclib.block.block_header import BlockHeader
from btclib.block.limits import MAX_FUTURE_BLOCK_TIME
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.tx import Tx
from typing_extensions import override

from btclib_wallet.fetch.fetcher import Fetcher
from btclib_wallet.fetch.history import start_height_for_time

# the header times of the chain, by height, in seconds since the epoch:
# height 2 is earlier than height 1, as consensus allows
TIMES = [1_000_000, 1_020_000, 1_015_000, 1_030_000]


class TimedFetcher(Fetcher):
    """A Fetcher of headers at `times`, recording each height asked."""

    def __init__(self, times: list[int]) -> None:
        super().__init__("regtest")
        self.headers = [
            BlockHeader(time=datetime.fromtimestamp(t, UTC), check_validity=False)
            for t in times
        ]
        self.asked: list[int] = []

    @override
    def get_tx(self, tx_id: Octets) -> Tx:
        """Not asked by `start_height_for_time`."""
        raise NotImplementedError

    @override
    def get_block_count(self) -> int:
        """Answer the height of the last header."""
        return len(self.headers) - 1

    @override
    def get_best_block_id(self) -> bytes:
        """Not asked by `start_height_for_time`."""
        raise NotImplementedError

    @override
    def get_block_header(self, height: int) -> BlockHeader:
        """Answer the header at `height`, and record the height."""
        self.asked.append(height)
        return self.headers[height]


def born(seconds: int) -> datetime:
    """Return a birth time `seconds` after the epoch, in UTC."""
    return datetime.fromtimestamp(seconds, UTC)


def test_the_fetcher_stub_answers_only_headers() -> None:
    """What `start_height_for_time` never asks raises if it is asked."""
    fetcher = TimedFetcher(TIMES)
    with pytest.raises(NotImplementedError):
        fetcher.get_tx(b"")
    with pytest.raises(NotImplementedError):
        fetcher.get_best_block_id()


@pytest.mark.parametrize(
    "seconds, height",
    [
        # every block is late enough
        (0, 0),
        # height 1 reaches the time, and height 2, earlier, is after it
        (1_020_000, 1),
        # exactly two hours after height 1: still height 1
        (1_020_000 + MAX_FUTURE_BLOCK_TIME, 1),
        # a second later, height 2 does not reach the time either
        (1_020_000 + MAX_FUTURE_BLOCK_TIME + 1, 3),
        (1_030_000 + MAX_FUTURE_BLOCK_TIME, 3),
    ],
)
def test_the_first_block_whose_running_maximum_reaches_the_time(
    seconds: int, height: int
) -> None:
    """Core's start of a rescan: the running maximum time, two hours back."""
    assert start_height_for_time(TimedFetcher(TIMES), born(seconds)) == height


def test_a_block_after_the_answer_may_be_earlier_than_the_time() -> None:
    """Height 2 is earlier than the time, and after the height answered.

    A wallet born between the times of heights 2 and 1 starts at 1. A
    binary search over the times reads height 2 first, finds it earlier
    than the time, and answers 3, past the block at 1 that the wallet
    may be paid in.
    """
    seconds = 1_018_000 + MAX_FUTURE_BLOCK_TIME
    earliest = seconds - MAX_FUTURE_BLOCK_TIME
    assert TIMES[2] < earliest < TIMES[1]
    assert bisect.bisect_left(TIMES, earliest) == 3
    assert start_height_for_time(TimedFetcher(TIMES), born(seconds)) == 1


def test_no_block_reaches_the_time() -> None:
    """A wallet born after the tip, two hours included, has no history yet."""
    fetcher = TimedFetcher(TIMES)
    assert (
        start_height_for_time(fetcher, born(TIMES[3] + MAX_FUTURE_BLOCK_TIME + 1))
        is None
    )
    assert fetcher.asked == [0, 1, 2, 3]


def test_the_headers_are_read_up_to_the_answer() -> None:
    """One header per height, from 0, and none past the height answered."""
    fetcher = TimedFetcher(TIMES)
    assert start_height_for_time(fetcher, born(TIMES[1])) == 1
    assert fetcher.asked == [0, 1]


def test_a_time_in_another_zone_is_the_same_instant() -> None:
    """A birth time is an instant, whatever zone it is written in."""
    east = timezone(timedelta(hours=5))
    time = born(1_020_000 + MAX_FUTURE_BLOCK_TIME + 1).astimezone(east)
    assert start_height_for_time(TimedFetcher(TIMES), time) == 3


def test_the_earliest_time_there_is() -> None:
    """Two hours before `datetime.min` is no datetime, and no error either."""
    time = datetime.min.replace(tzinfo=UTC)
    assert start_height_for_time(TimedFetcher(TIMES), time) == 0


def test_a_time_with_no_zone_is_refused() -> None:
    """A naive time would be read as the machine's local time."""
    with pytest.raises(BTClibValueError, match="a time with no time zone"):
        start_height_for_time(TimedFetcher(TIMES), datetime(2009, 1, 3))


def test_what_is_no_datetime_is_refused() -> None:
    """A timestamp in seconds is not a datetime."""
    with pytest.raises(BTClibTypeError, match="not a datetime: int"):
        start_height_for_time(TimedFetcher(TIMES), 1_020_000)  # type: ignore[arg-type]


def test_what_is_no_fetcher_is_refused() -> None:
    """Refused before anything is asked of it."""
    with pytest.raises(BTClibTypeError, match="not a Fetcher: list"):
        start_height_for_time(TIMES, born(0))  # type: ignore[arg-type]
