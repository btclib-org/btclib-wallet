# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The btclib fetcher backed by a `BitcoinCoreRestClient`.

Core's `-rest` interface is off by default and authenticates nobody who
reaches it -- `BitcoinCoreRestClient`'s own docstring says so, and a node
operator who turns it on knows that before btclib is reached for at all.
This module is what a caller who has been handed such an endpoint, and no
credentials, speaks to a real node with: `BitcoinCoreFetcher` needs a
cookie file or a user and password, and every other backend here speaks
to a block explorer rather than to a node.

The client's own surface is two methods, `get_bin` and `get_json`, and no
method per resource -- `path` is the caller's own, built from Core's
`doc/REST-interface.md` and appended after `/rest` unread. That is why
this is a class of its own rather than `EsploraFetcher` with a second
`base_url`: `EsploraFetcher` speaks HTTP itself and takes a `base_url`
with no client in front of it, where this fetcher takes a *client*, the
same shape `BitcoinCoreFetcher` takes a `BitcoinCoreRpcClient` in. One
class cannot take both a `base_url` and a client without one of the two
arguments being dead in every call.

Past the constructor this checks what `BitcoinCoreFetcher` checks, and
takes the same arguments to do it: `rest_chaininfo` hands
`/chaininfo.json` whatever `getblockchaininfo` answers, written out
unmodified, so `chain` and `signet_challenge` are both members of it and
`verify_network` and `signet_challenge` mean here exactly what they mean
there. What differs is authentication -- `-rest` needs no cookie and
refuses nobody, which is what this class is for -- and the endpoints the
questions are asked at, none of which is shared with `EsploraFetcher`
either: a transaction and a header are read as octets from a `.bin`
endpoint, where Esplora answers text -- hex, save for the chain tip's
height, which is a decimal number -- and the tip's height and hash are
members of a `/chaininfo.json` reply rather than endpoints of their own.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from bitcoin_core_rpc import (
    BitcoinCoreRestClient,
    chain_from_network,
    magic_from_chain,
    magic_from_signet_challenge,
)
from btclib.alias import Octets
from btclib.block.block_header import BlockHeader
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.script import ScriptPubKey
from btclib.tx import OutPoint, Tx
from btclib.utils import bytes_from_octets
from typing_extensions import override

from btclib_wallet.exceptions import HttpError
from btclib_wallet.fetch.bitcoin_core import (
    _MAX_LARGE_REPLY,
    _MAX_MEMPOOL_REPLY,
    _block_history,
    _core_history,
    _member,
    _mempool_touching,
)
from btclib_wallet.fetch.fetcher import (
    NetworkVerifyingFetcher,
    block_header_from_raw,
    block_header_height,
    client_errors,
    fetch_errors,
    tx_from_raw,
    tx_id_hex,
)
from btclib_wallet.fetch.history import BlockRef, ScriptHistory, history_scripts

__all__ = [
    "BitcoinCoreRestClient",
    "BitcoinCoreRestFetcher",
]

# `signet_challenge` is the member that decides this bound, and the only
# one a node operator chooses the size of: it is a script, rendered here
# as twice its bytes in hex. Core size-checks it nowhere -- it assigns
# whatever `-signetchallenge` spelled -- but a script above
# `MAX_SCRIPT_SIZE`, 10000 bytes, validates no block past the genesis one,
# whose solution `CheckSignetBlockSolution` accepts unread -- so twice
# that is the largest challenge a signet that can extend its chain has. A
# bound
# admitting one therefore admits every other member with room to spare,
# and is still nowhere near a block, which is what a bound on an
# untrusted reply is for. The alternative, a bound the default signet
# fits and a custom one does not, would fail `verify_network` on exactly
# the deployment `signet_challenge` exists to check
_MAX_CHAININFO_BODY = 32768
# `/blockhashbyheight/<HEIGHT>.bin` answers exactly thirty-two raw bytes,
# there being no rendering of a hash shorter or longer than the hash
# itself
_MAX_HASH_BODY = 32
# `/headers/<HASH>.bin?count=1` answers exactly one serialized header,
# eighty raw bytes, the query parameter being what holds Core to exactly
# one rather than its default of five
_MAX_HEADER_BODY = 80
# the most outputs one `/getutxos` request names: Core's
# `MAX_GETUTXOS_OUTPOINTS` (src/rest.cpp, bitcoin/bitcoin@f0de87f040)
_MAX_GETUTXOS_OUTPOINTS = 15


def _field(reply: Any, name: str) -> Any:
    """Return one member of a chaininfo reply, refusing what is not one.

    `get_json` answers whatever the body parses to -- an object, an
    array, or a bare scalar, nothing about the shape asked at that layer
    -- so indexing straight into `reply` would raise `KeyError` or
    `TypeError` depending on what came back, neither of which
    `fetch_errors` reads as a source's own failure. Raising `TypeError`
    for both is what keeps the diagnosis inside `fetch_errors`, the same
    class `int` and `bytes_from_octets` already raise it as.
    """
    if not isinstance(reply, dict) or name not in reply:
        raise TypeError(f"no {name!r} member in the chaininfo reply: {reply!r}")
    return reply[name]


class BitcoinCoreRestFetcher(NetworkVerifyingFetcher):
    """Every `Fetcher` question, answered by a node over `-rest`.

    The client is a constructor argument rather than connection
    arguments repeated here, the same reason `BitcoinCoreFetcher` takes a
    `BitcoinCoreRpcClient`: one class owns the endpoint, this one owns
    the mapping onto btclib types.

    `network` labels the outputs `get_tx` returns, and `assert_network`
    holds the node to it.

    `signet_challenge` is which signet, and means what it means on
    `BitcoinCoreFetcher`: Core answers `signet` for the default signet
    and for every custom one alike, so the name settles nothing and the
    magic the challenge derives is the identity. Both questions are
    answered by `/chaininfo.json`, the one document `get_block_count`
    already reads.

    `get_tx_out` is not overridden, and stays the `Fetcher` base's
    derivation from `get_tx`. `BitcoinCoreRestClient`'s own docstring is
    where the reason is argued -- `/getutxos` reads the UTXO set, so a
    spent output and one that never existed answer it identically -- and
    is not repeated here.

    Also a `HistoryReader`: `get_history` reads the blocks and the
    mempool, as `BitcoinCoreFetcher.get_history` does over the RPC.
    """

    def __init__(
        self,
        client: BitcoinCoreRestClient,
        network: str = "mainnet",
        *,
        verify_network: bool = True,
        signet_challenge: str | bytes | None = None,
    ) -> None:
        super().__init__(network, verify_network=verify_network)
        if not isinstance(client, BitcoinCoreRestClient):
            err_msg = f"not a BitcoinCoreRestClient: {type(client).__name__}"  # type: ignore[unreachable]
            raise BTClibTypeError(err_msg)
        if signet_challenge is not None:
            if chain_from_network(self.network) != "signet":
                err_msg = f"a signet_challenge for {self.network},"
                err_msg += " which is no signet"
                raise BTClibValueError(err_msg)
            if not verify_network:
                err_msg = (
                    "a signet_challenge is what verify_network"
                    " compares, and checks nothing with it off"
                )
                raise BTClibValueError(err_msg)
            # derived here and thrown away, so that a challenge that is no
            # script fails at the line that wrote it rather than at the
            # first fetch
            with client_errors():
                magic_from_signet_challenge(signet_challenge)
        self.client = client
        self.signet_challenge = signet_challenge

    @override
    def assert_network(self) -> None:
        """Raise unless the node serves the chain, and the signet, this labels.

        One request, `/chaininfo.json`. `rest_chaininfo` writes out what
        `getblockchaininfo` answers and adds nothing, so the members read
        here are the ones `BitcoinCoreRpcClient.assert_chain` reads over
        the JSON-RPC server, and the two comparisons are its two: `chain`
        against `chain_from_network(self.network)`, Core naming the chain
        `main` where btclib names it `mainnet`; then, on signet alone,
        the magic `signet_challenge` derives, since Core answers `signet`
        for every signet and the name therefore separates none of them.

        A node too old to report its challenge answers a reply this
        cannot read, so a `FetchError`: one it cannot answer for, and not
        a pass.
        """
        expected = chain_from_network(self.network)
        expected_magic: bytes | None = None
        if self.signet_challenge is not None:
            expected_magic = magic_from_signet_challenge(self.signet_challenge)
        elif expected == "signet":
            expected_magic = magic_from_chain(expected)

        with fetch_errors("chaininfo"):
            reply = self._get_json("/chaininfo.json", max_body_size=_MAX_CHAININFO_BODY)
            reported = _field(reply, "chain")
            if not isinstance(reported, str):
                raise TypeError(f"no string 'chain' member: {reported!r}")
        if reported != expected:
            err_msg = f"node at {self.client.url} reports chain {reported!r},"
            err_msg += f" not the {expected!r} this fetcher was built for"
            raise BTClibValueError(err_msg)
        if expected_magic is None:
            return

        with fetch_errors("chaininfo"):
            challenge = _field(reply, "signet_challenge")
            if not isinstance(challenge, str):
                raise TypeError(f"no string 'signet_challenge' member: {challenge!r}")
            node_magic = magic_from_signet_challenge(challenge)
        if node_magic != expected_magic:
            err_msg = f"node at {self.client.url} is on a signet this fetcher"
            err_msg += " is not: its challenge derives magic"
            err_msg += f" {node_magic.hex()}, where {expected_magic.hex()}"
            err_msg += " was expected"
            raise BTClibValueError(err_msg)

    def _get_bin(self, path: str, *, max_body_size: int | None) -> bytes:
        """Return the raw body of one `-rest` request, translating its errors.

        `max_body_size=None` is what a caller passes to leave the
        client's own default -- wide enough for a block -- in place; a
        private method takes no default of its own, so every call site
        names its choice rather than one being silently implied.
        """
        bound = {} if max_body_size is None else {"max_body_size": max_body_size}
        with client_errors():
            return self.client.get_bin(path, **bound)

    def _get_json(self, path: str, *, max_body_size: int) -> Any:
        """Return the parsed body of one `-rest` request, errors translated.

        `max_body_size` is `int` here where `_get_bin`'s is `int | None`:
        every `.json` path this fetcher reads has a bound of its own, so
        no call site wants the client's own default -- what `_get_bin`'s
        `None` exists to ask for, a raw transaction being bounded by
        nothing else.
        """
        with client_errors():
            return self.client.get_json(path, max_body_size=max_body_size)

    @override
    def get_tx(self, tx_id: Octets) -> Tx:
        """Return the transaction with this id.

        `/tx/<TX-HASH>.bin` returns the serialization, which `tx_from_raw`
        recomputes the id from -- the same check `BitcoinCoreFetcher` and
        `EsploraFetcher` both perform, and the same reason a node answers
        for a transaction in its mempool, and for any other only with
        `-txindex`.
        """
        self._verify_once()
        hex_ = tx_id_hex(tx_id)
        raw = self._get_bin(f"/tx/{hex_}.bin", max_body_size=None)
        return tx_from_raw(raw, hex_, self.network)

    @override
    def get_block_count(self) -> int:
        """Return the height of the node's best chain tip."""
        self._verify_once()
        with fetch_errors("chaininfo"):
            reply = self._get_json("/chaininfo.json", max_body_size=_MAX_CHAININFO_BODY)
            return int(_field(reply, "blocks"))

    @override
    def get_best_block_id(self) -> bytes:
        """Return the hash of the node's best chain tip, display order."""
        self._verify_once()
        with fetch_errors("chaininfo"):
            reply = self._get_json("/chaininfo.json", max_body_size=_MAX_CHAININFO_BODY)
            return bytes_from_octets(_field(reply, "bestblockhash"), 32)

    @override
    def get_block_header(self, height: int) -> BlockHeader:
        """Return the header of the block at this height, checked on arrival.

        Two calls, `-rest` answering `/headers` by hash and not by
        height: `/blockhashbyheight/<HEIGHT>.bin` maps the height first,
        and `/headers/<BLOCK-HASH>.bin?count=1` then answers the
        serialization of exactly one header -- the query parameter and
        not `/headers/<COUNT>/<BLOCK-HASH>`, which `doc/REST-interface.md`
        marks deprecated, though not removed, since Core 24.0.

        `/blockhashbyheight`'s `.bin` answers Core's internal byte order,
        the reverse of the display order every hash in a `-rest` url is
        -- `uint256::GetHex()`, which `FromHex` inverts, is documented as
        reversing that internal order for exactly this reason. Reversed
        here before the hex is built, the same reversal
        `BlockHeader.parse` performs on a header's own hash fields on the
        way in.
        """
        self._verify_once()
        height = block_header_height(height)
        with fetch_errors("blockhashbyheight"):
            raw_hash = self._get_bin(
                f"/blockhashbyheight/{height}.bin", max_body_size=_MAX_HASH_BODY
            )
            block_hash = bytes_from_octets(raw_hash, 32)[::-1].hex()
        raw = self._get_bin(
            f"/headers/{block_hash}.bin?count=1", max_body_size=_MAX_HEADER_BODY
        )
        return block_header_from_raw(raw, height, network=self.network)

    def get_history(
        self, scripts: Iterable[Octets | ScriptPubKey], start_height: int = 0
    ) -> ScriptHistory:
        """Return the history of `scripts`, from `start` to the tip.

        `-rest` has no query keyed on a script, so this reads what a
        script is in, as `BitcoinCoreFetcher.get_history` does. The
        blocks are `/block/<hash>.json`, the rendering `getblock` gives
        at verbosity 3, with the output each input spends, and under the
        same bound. The mempool is `/mempool/contents.json`, then
        `/tx/<txid>.bin` for each transaction; one the node no longer has
        by then is skipped. The outputs a mempool input spends are read
        from the chain by `/getutxos`, which names the tip it was read
        at, and an answer read at another tip is a `FetchError`.
        `/chaininfo.json` is asked first and last, and a tip that moved
        is a `FetchError`.

        The cost is a request per block from `start_height` up, one per
        mempool transaction and one per fifteen of their inputs.
        """
        elements = history_scripts(scripts)
        first = block_header_height(start_height)
        self._verify_once()
        tip_hex = self._best_block_hex()
        return _core_history(
            tip_hex,
            first,
            lambda block_hex, height: self._history_block(block_hex, height, elements),
            lambda: self._history_mempool(elements, tip_hex),
            self._best_block_hex,
        )

    def _best_block_hex(self) -> str:
        """Return the hash of the node's best chain tip, as hex."""
        with fetch_errors("chaininfo"):
            reply = self._get_json("/chaininfo.json", max_body_size=_MAX_CHAININFO_BODY)
            return bytes_from_octets(_field(reply, "bestblockhash"), 32).hex()

    def _history_block(
        self, block_hex: str, height: int | None, elements: frozenset[bytes]
    ) -> tuple[BlockRef, list[Tx], str]:
        """Read one block, as `_block_history` returns it."""
        reply = self._get_json(
            f"/block/{block_hex}.json", max_body_size=_MAX_LARGE_REPLY
        )
        source = f"block {block_hex}"
        return _block_history(reply, block_hex, height, elements, self.network, source)

    def _history_mempool(self, elements: frozenset[bytes], tip_hex: str) -> list[Tx]:
        """Return the mempool's transactions touching `elements`."""
        path = "/mempool/contents.json?verbose=false"
        reply = self._get_json(path, max_body_size=_MAX_MEMPOOL_REPLY)
        with fetch_errors("mempool"):
            if not isinstance(reply, list):
                raise BTClibTypeError(f"not an array: {type(reply).__name__}")
            tx_ids = list(dict.fromkeys(tx_id_hex(tx_id) for tx_id in reply))
        mempool: list[Tx] = []
        for tx_id in tx_ids:
            try:
                raw = self._get_bin(f"/tx/{tx_id}.bin", max_body_size=None)
            except HttpError as e:
                if e.status != 404:
                    raise
                continue
            mempool.append(tx_from_raw(raw, tx_id, self.network))
        return _mempool_touching(
            mempool, elements, lambda: self._history_unspent(mempool, elements, tip_hex)
        )

    def _history_unspent(
        self, mempool: list[Tx], elements: frozenset[bytes], tip_hex: str
    ) -> set[OutPoint]:
        """Return the chain's outputs to `elements` that `mempool` spends."""
        inside = {tx.id for tx in mempool}
        asked = sorted(
            {
                tx_in.prev_out
                for tx in mempool
                for tx_in in tx.vin
                if tx_in.prev_out.tx_id not in inside
            },
            key=lambda out: (out.tx_id, out.vout),
        )
        ours: set[OutPoint] = set()
        for i in range(0, len(asked), _MAX_GETUTXOS_OUTPOINTS):
            batch = asked[i : i + _MAX_GETUTXOS_OUTPOINTS]
            path = "/".join(f"{out.tx_id.hex()}-{out.vout}" for out in batch)
            reply = self._get_json(
                f"/getutxos/{path}.json", max_body_size=_MAX_LARGE_REPLY
            )
            with fetch_errors("getutxos"):
                answered = _member(reply, "chaintipHash")
                if answered != tip_hex:
                    raise BTClibValueError(f"read at {answered}, not at {tip_hex}")
                bitmap = _member(reply, "bitmap")
                if not isinstance(bitmap, str) or len(bitmap) != len(batch):
                    raise BTClibValueError(f"invalid bitmap: {bitmap!r}")
                hits = [
                    out for out, bit in zip(batch, bitmap, strict=True) if bit == "1"
                ]
                utxos = _member(reply, "utxos")
                if not isinstance(utxos, list) or len(utxos) != len(hits):
                    raise BTClibValueError("not an output for each hit")
                for out, utxo in zip(hits, utxos, strict=True):
                    script = _member(_member(utxo, "scriptPubKey"), "hex")
                    if bytes.fromhex(script) in elements:
                        ours.add(out)
        return ours
