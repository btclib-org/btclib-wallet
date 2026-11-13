# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The interface a chain backend answers to list the history of some scripts.

Kept apart from `Fetcher`, as `Broadcaster`, `FeeEstimator` and
`BalanceReader` are, because not every backend can answer it.
`BitcoinCoreFetcher`, `BitcoinCoreRestFetcher`, `ElectrumFetcher` and
`EsploraFetcher` satisfy it.

Not `runtime_checkable`, for the reason `Broadcaster` is not: the
contract below is not what `isinstance(x, HistoryReader)` would verify.

`start_height_for_time` is where a history read starts for a wallet
born at a known time, from any `Fetcher`.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from btclib.alias import Octets
from btclib.block.limits import MAX_FUTURE_BLOCK_TIME
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.script import ScriptPubKey
from btclib.tx import Tx
from btclib.utils import bytes_from_octets, is_octets

from btclib_wallet.fetch.fetcher import Fetcher

__all__ = [
    "BlockRef",
    "HistoryReader",
    "HistoryTx",
    "ScriptHistory",
    "history_scripts",
    "start_height_for_time",
]


@dataclass(frozen=True)
class BlockRef:
    """A block of the chain an answer was read on: its height and its id.

    `block_id` is in display order, as `Fetcher.get_best_block_id`
    returns it.
    """

    height: int
    block_id: bytes


@dataclass(frozen=True)
class HistoryTx:
    """A transaction paying to or spending from a script, and where it is.

    `block` is the block that confirms it, or `None` for a transaction
    the mempool held when it was read.
    """

    tx: Tx
    block: BlockRef | None


@dataclass(frozen=True)
class ScriptHistory:
    """The transactions that touch some scripts, and the chain they are on.

    `start` is the block the call started from and `tip` the last block,
    both of the one chain every confirmed entry of `txs` is on.
    `HistoryReader` says how a caller reads the two.
    """

    start: BlockRef
    tip: BlockRef
    txs: tuple[HistoryTx, ...]


def history_scripts(scripts: Iterable[Octets | ScriptPubKey]) -> frozenset[bytes]:
    """Return the octets of each script, refusing none and a lone script.

    The scripts are `ScriptPubKey` objects or their octets, as
    `CompactFilterFetcher.scan_blocks` takes them. An empty script is
    refused: BIP158 puts none in a filter, and `scantxoutset` refuses
    `raw()` with nothing in it.
    """
    # every Octets is itself iterable, and one script passed for a list of
    # them would be read as a list of one-octet scripts
    if is_octets(scripts) or isinstance(scripts, ScriptPubKey):
        raise BTClibTypeError(f"not an iterable of scripts: {type(scripts).__name__}")
    if not isinstance(scripts, Iterable):
        raise BTClibTypeError(f"not an iterable of scripts: {type(scripts).__name__}")
    elements = frozenset(
        script.script if isinstance(script, ScriptPubKey) else bytes_from_octets(script)
        for script in scripts
    )
    if not elements:
        raise BTClibValueError("no scripts to look for")
    if b"" in elements:
        raise BTClibValueError("an empty script to look for")
    return elements


class HistoryReader(Protocol):
    """A backend able to list the transactions that touch some scripts.

    One method and one contract, binding on every implementation of it:

    - the scripts are checked by `history_scripts`, and `start_height` by
      `fetcher.block_header_height`, before any request;
    - a transaction is listed when one of its outputs pays to one of the
      scripts or one of its inputs spends such an output, once however
      many it touches;
    - `start` is the block at `start_height`, or the tip where the chain
      ends below that height;
    - the confirmed ones are those of the blocks from `start` to the tip,
      in chain order, and each carries its block; the mempool's follow,
      each with `block` set to `None`, in no order this promises. The
      mempool is read after the blocks, and an answer is not a snapshot
      of it;
    - the answer holds on one chain. A backend that sees its tip move
      while it reads raises `FetchError`, and the caller asks again.

    `start` is what tells a reorganization from new history. A caller
    that read up to a tip asks again from that tip's height. Where the
    new answer's `start` is that tip, the earlier answer's confirmed
    entries still hold, this one's confirmed entries in blocks after
    `start` extend them, and its mempool entries replace the earlier
    ones. Where `start` is another block, at that height or below it on a
    shorter chain, a reorganization replaced that tip, and the caller
    asks again from a lower height.
    """

    def get_history(
        self, scripts: Iterable[Octets | ScriptPubKey], start_height: int = 0
    ) -> ScriptHistory:
        """Return the history of `scripts`, from `start` to the tip."""
        ...


def start_height_for_time(fetcher: Fetcher, time: datetime) -> int | None:
    """Return the first height a wallet born at `time` has history from.

    Core starts a rescan from a key's birth time this way:
    `RescanFromTime` (src/wallet/wallet.cpp) subtracts `TIMESTAMP_WINDOW`,
    which is `MAX_FUTURE_BLOCK_TIME`, two hours (src/chain.h), and
    `FindEarliestAtLeast` (src/chain.cpp) returns the first block whose
    running maximum time is at least that. The running maximum first
    reaches a time at the first block whose own time does, so that block
    is the one returned. Header times need not rise with height, so a
    block after it may carry an earlier time, and a binary search over
    the times can return a later height.

    `None` where no block up to the tip qualifies: nothing on the chain
    can hold history of the wallet yet.

    The headers are read from height 0 up, one `get_block_header` call
    each, up to the height returned or to the tip `get_block_count`
    answers first.

    Refused: a `fetcher` that is no `Fetcher` and a `time` that is no
    `datetime` (`BTClibTypeError`), and a `time` with no time zone
    (`BTClibValueError`), which a block time cannot be compared with.
    """
    if not isinstance(fetcher, Fetcher):
        raise BTClibTypeError(f"not a Fetcher: {type(fetcher).__name__}")
    if not isinstance(time, datetime):
        raise BTClibTypeError(f"not a datetime: {type(time).__name__}")
    if time.utcoffset() is None:
        raise BTClibValueError("a time with no time zone")
    # compared as seconds, since a datetime near `datetime.min` has no
    # datetime two hours earlier
    earliest = time.timestamp() - MAX_FUTURE_BLOCK_TIME
    tip = fetcher.get_block_count()
    return next(
        (
            height
            for height in range(tip + 1)
            if fetcher.get_block_header(height).time.timestamp() >= earliest
        ),
        None,
    )
