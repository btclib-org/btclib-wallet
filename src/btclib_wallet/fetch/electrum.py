# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The btclib fetcher backed by an Electrum server.

`btclib_wallet.electrum` is the codec -- the JSON-RPC framing, the shapes of the
methods this fetcher asks, and the merkle-branch check -- and holds
no socket; this module is the `Fetcher` over it, taking a `transport` and
turning each question into a request line and a line back into a btclib
type, the way `EsploraFetcher` and `BitcoinCoreRestFetcher` do over their
own transports.

**`transport` is required, keyword-only, and has no default.**
`LineTransport` (`btclib_wallet.fetch.transport`) carries no host, so a
transport that reaches a server is one constructed with that server's
host -- `TlsLineTransport(host, port)` is the one shipped -- and a default
transport would be a default server, which the next paragraph refuses.

**No `base_url` and no default server.** Unlike `EsploraFetcher`, which
takes a required url with no default, this fetcher takes none at all:
`transport` is the whole of how it reaches a server, and which server
that is is `transport`'s own business. `EsploraFetcher.base_url`'s
reasoning -- `BLOCKSTREAM_INFO` is offered as a value to pass and never
as a default, because which host sees every address a caller looks up is
not btclib's decision to make on anyone's behalf -- applies here with
even less room. Electrum's own shipped server list carries each host's
ports, its pruning and the protocol version it speaks, and nothing about
the certificate it presents, so which of its entries a transport
verifying against a public CA store reaches is not a question the list
answers. Electrum's own client does not ask it either: where the
CA-signed handshake fails it pins the certificate that server presented
and connects with `check_hostname` off (`electrum/interface.py`,
`Interface._get_ssl_context`), so being listed says what protocol
version a server speaks and not that its certificate is one a strict
transport accepts. Entries share registrable domains, so the list names
fewer operators than hosts, and a caller running their own server is
invisible to it entirely. Naming any one entry as a constant would
repeat the mistake `BLOCKSTREAM_INFO` already refuses.

**A question the interface does not declare, answered by nothing else in
this package.** `get_tx_merkle`, `verify_tx` and `get_block_headers` are
not on `Fetcher`. For the first two, adding a return type no other backend
can honor is what the interface's abstract methods, each with a return type
of its own, already exist to avoid. For all three, both the issue and issue
btclib-org/btclib#1193 hold the interface itself unchanged.
What `Fetcher`'s own class docstring calls "evidence beside
the data" is what the first two are -- a merkle branch checked against a header
this fetcher fetched on its own, which is a different kind of answer from the
other backends' word for it, and the reason this backend exists.
"""

from __future__ import annotations

from collections.abc import Iterable

from btclib.alias import Octets
from btclib.block.block_header import BlockHeader
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.fee import FeeRate
from btclib.hashes import sha256
from btclib.network import NETWORKS
from btclib.script import ScriptPubKey
from btclib.tx import Tx
from btclib.utils import is_integer
from typing_extensions import override

from btclib_wallet import electrum
from btclib_wallet.exceptions import FetchError
from btclib_wallet.fetch.fee_estimator import FeeQuote, valid_confirmation_target
from btclib_wallet.fetch.fetcher import (
    NetworkVerifyingFetcher,
    block_header_from_raw,
    block_header_height,
    client_errors,
    fetch_errors,
    tx_from_raw,
    tx_id_hex,
)
from btclib_wallet.fetch.history import (
    BlockRef,
    HistoryTx,
    ScriptHistory,
    history_scripts,
)
from btclib_wallet.fetch.transport import DEFAULT_TIMEOUT, LineTransport, valid_timeout

__all__ = [
    "ElectrumFetcher",
]


class ElectrumFetcher(NetworkVerifyingFetcher):
    """Every `Fetcher` question, and a merkle branch, from an Electrum server.

    `get_tx` is `blockchain.transaction.get`, the raw hex decoded and
    handed to `tx_from_raw`, which recomputes the id the same way every
    other backend does. `get_block_count` and `get_best_block_id` are
    both `blockchain.headers.subscribe`, asked once each: the protocol
    answers the tip's height together with its header rather than a
    separate hash field, so the id `get_best_block_id` returns is not the
    server's word -- it is `BlockHeader.hash` of the header
    `block_header_from_raw` has already checked, the same check
    `get_block_header` runs.
    `get_block_header` is `blockchain.block.header`, `cp_height` left
    unsent.

    `get_block_headers` is `blockchain.block.headers`: up to a server's
    own maximum of consecutive headers in one answer, each checked as
    `get_block_header` checks one, and each chained to the one before it.

    `get_tx_merkle` is `blockchain.transaction.get_merkle`, returning the
    branch and position `btclib_wallet.electrum.MerkleProof` carries.
    `verify_tx` fetches the header at the height asked for with
    `get_block_header` -- the caller's own height, not the proof's
    unchecked `block_height` -- and checks the branch against it with
    `btclib_wallet.electrum.verify_merkle_proof`, answering `False` for a
    malformed branch or a wrong position the way
    `btclib.block.merkle_proof.verify` does, and still raising for
    anything `get_block_header` itself refuses.

    Also a `FeeEstimator`: `estimate_fee` is `blockchain.estimatefee`,
    answered for the target asked -- the protocol carries no field
    equivalent to Core's `blocks`, so unlike the other two backends this
    one cannot report a clamp the server may have applied underneath it.

    Also a `HistoryReader`: `get_history` is
    `blockchain.scripthash.get_history`, and its own docstring says what
    it checks and what it takes on the server's word.

    Not a `RelayFeeReader`: `blockchain.relayfee` answers the minimum
    relay rate alone. Protocol 1.6 adds `mempool.get_info`, which answers
    all three rates, and neither electrs nor Floresta, at the commits
    their integration workflows pin, serves it.

    `get_tx_out` is not overridden, and stays the `Fetcher` base's
    derivation from `get_tx`.
    """

    def __init__(
        self,
        network: str = "mainnet",
        *,
        transport: LineTransport,
        verify_network: bool = True,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        super().__init__(network, verify_network=verify_network)
        if not callable(transport):
            raise BTClibTypeError(f"not a callable transport: {transport!r}")
        self.transport = transport
        # checked here for a transport of the caller's that checks nothing
        self.timeout = valid_timeout(timeout)
        self._next_id = 0

    def _next_request_id(self) -> int:
        """Return a fresh request id, one higher than the last.

        A counter and not a constant: `decode_response` refuses a reply
        that answers a different id, so two requests sharing one id could
        not be told apart by anything this codec checks.
        """
        self._next_id += 1
        return self._next_id

    def _round_trip(self, request: bytes) -> bytes:
        """Send one request line and return the line answering it.

        The one call site that reaches `self.transport`, so a translation
        of what it raises is written once. `LineTransport`'s own
        docstring is where the exception contract this wraps is stated.
        """
        with client_errors():
            return self.transport(request, self.timeout)

    def _tip(self) -> electrum.HeaderTip:
        """Return the chain tip `blockchain.headers.subscribe` answers."""
        request_id = self._next_request_id()
        line = self._round_trip(electrum.headers_subscribe_request(request_id))
        with fetch_errors("headers.subscribe"):
            return electrum.headers_subscribe_response(line, request_id)

    def _raw_header_at(self, height: int) -> bytes:
        """Return the eighty bytes the server answers for this height.

        Unchecked, asking nothing else. `assert_network` reaches the
        genesis header through this and not through `get_block_header`,
        which calls `_verify_once`.
        """
        request_id = self._next_request_id()
        line = self._round_trip(electrum.block_header_request(request_id, height))
        with fetch_errors(f"block header {height}"):
            return electrum.block_header_response(line, request_id)

    def _header_at(self, height: int) -> BlockHeader:
        """Return the header at this height, checked, asking nothing else.

        `block_header_from_raw` is what checks the eighty bytes, so the
        header `get_block_header` returns is one that passed its checks,
        and not the server's word.
        """
        raw = self._raw_header_at(height)
        return block_header_from_raw(raw, height, network=self.network)

    @override
    def get_tx(self, tx_id: Octets) -> Tx:
        """Return the transaction with this id, via `transaction.get`."""
        self._verify_once()
        hex_ = tx_id_hex(tx_id)
        request_id = self._next_request_id()
        line = self._round_trip(electrum.transaction_get_request(request_id, hex_))
        with fetch_errors(f"transaction {hex_}"):
            raw = electrum.transaction_get_response(line, request_id)
        return tx_from_raw(raw, hex_, self.network)

    @override
    def get_block_count(self) -> int:
        """Return the height of the chain tip, via `headers.subscribe`."""
        self._verify_once()
        return self._tip().height

    @override
    def get_best_block_id(self) -> bytes:
        """Return the id of the chain tip, recomputed from its own header.

        `headers.subscribe` answers the header itself rather than a
        separate hash field, so this is not the server's word: it is
        `block_header_from_raw`'s check on the bytes it sent, and then
        the hash of the header that passed it.
        """
        self._verify_once()
        tip = self._tip()
        header = block_header_from_raw(tip.header, tip.height, network=self.network)
        return header.hash

    @override
    def get_block_header(self, height: int) -> BlockHeader:
        """Return the header at this height, via `blockchain.block.header`."""
        self._verify_once()
        return self._header_at(block_header_height(height))

    def get_block_headers(self, start_height: int, count: int) -> list[BlockHeader]:
        """Return up to `count` consecutive headers from `start_height`.

        `blockchain.block.headers`, through `btclib_wallet.electrum`'s
        `block_headers_request` and `block_headers_response`, whose
        docstring says which answer shape is read and what it refuses. A
        server may answer fewer than asked, by its own maximum or by
        reaching its tip, so the list can be shorter than `count`, or
        empty. Each header is then checked by `block_header_from_raw`, and
        each must name the hash of the one before it as its
        `previous_block_hash`. The first header's parent is not checked:
        the chunk carries no header below it.
        """
        self._verify_once()
        start_height = block_header_height(start_height)
        if not is_integer(count):
            raise BTClibTypeError(f"invalid count type: {type(count).__name__}")
        if count < 1:
            raise BTClibValueError(f"invalid count: {count}")
        request_id = self._next_request_id()
        line = self._round_trip(
            electrum.block_headers_request(request_id, start_height, count)
        )
        source = f"block headers {start_height}+{count}"
        with fetch_errors(source):
            raws = electrum.block_headers_response(line, request_id, count)
        headers = [
            block_header_from_raw(raw, start_height + i, network=self.network)
            for i, raw in enumerate(raws)
        ]
        for i in range(1, len(headers)):
            if headers[i].previous_block_hash != headers[i - 1].hash:
                err_msg = f"{source}: header {start_height + i} does not follow"
                err_msg += f" header {start_height + i - 1}"
                raise FetchError(err_msg)
        return headers

    @override
    def assert_network(self) -> None:
        """Raise unless the server serves the chain this fetcher labels with.

        One request and one comparison: `blockchain.block.header` at
        height 0 -- the same method `get_block_header` asks for every
        other height, asked here for the block every chain starts from --
        against `NETWORKS[self.network].genesis_block`. What is compared
        is `BlockHeader.hash` of the eighty bytes the server sent, checked
        for length alone, so this backend answers the question the way it
        answers `get_best_block_id`: by hashing a header rather than by
        reading a hash the server chose. The proof of work is left out
        because `block_header_from_raw` checks it against this fetcher's
        own network: a server on a chain with an easier proof-of-work
        limit, regtest's or signet's, would fail it before the comparison,
        with the `FetchError` that `FallbackFetcher` falls through, where
        a genesis mismatch is the `BTClibValueError` it stops on.
        `server.features` carries a `genesis_hash` member and is what
        Electrum's own client compares (`electrum/interface.py`); the header
        is asked for instead because it makes the server produce eighty bytes
        that hash to the genesis rather than repeat a string, and because it
        needs no codec function `btclib_wallet.electrum` does not already have.

        Worth the call, because the failure it catches is silent, the
        same one `BitcoinCoreFetcher.assert_network`'s docstring names: a
        fetcher labelled `mainnet` over a server on another chain renders
        a mainnet address for every output it fetches, for coins that are
        not there. It is sharper here than elsewhere, because `verify_tx`
        checks a branch against a header fetched from that same server:
        a caller on the wrong chain is otherwise handed a proof that is
        valid and about a chain they did not mean.

        What a genesis hash cannot separate is two signets, and
        `EsploraFetcher.assert_network`'s docstring is where that is
        written down. This class takes no `signet_challenge` of its own,
        for the reason that class takes none: nothing among the methods
        `btclib_wallet.electrum` speaks is a signet's challenge to compare
        against.
        """
        raw = self._raw_header_at(0)
        with fetch_errors("block header 0"):
            reported = BlockHeader.parse(raw, check_validity=False).hash
        expected = NETWORKS[self.network].genesis_block
        if reported != expected:
            err_msg = "the server serves a chain whose genesis is"
            err_msg += f" {reported.hex()}, not the {expected.hex()}"
            err_msg += f" this {self.network} fetcher was built for"
            raise BTClibValueError(err_msg)

    def get_tx_merkle(self, tx_id: Octets, height: int) -> electrum.MerkleProof:
        """Return the branch proving `tx_id` confirmed at `height`.

        `blockchain.transaction.get_merkle`, the one question no other
        backend here can answer at all.
        """
        self._verify_once()
        hex_ = tx_id_hex(tx_id)
        height = block_header_height(height)
        request_id = self._next_request_id()
        line = self._round_trip(
            electrum.transaction_get_merkle_request(request_id, hex_, height)
        )
        with fetch_errors(f"transaction {hex_} merkle"):
            return electrum.transaction_get_merkle_response(line, request_id)

    def verify_tx(self, tx_id: Octets, height: int) -> bool:
        """Return whether `tx_id` is proven confirmed at `height`.

        Fetches the header at `height` and the branch separately, then
        checks the second against the first's merkle root -- see this
        class's own docstring for what each half already checks on its
        own.
        """
        header = self.get_block_header(height)
        proof = self.get_tx_merkle(tx_id, height)
        return electrum.verify_merkle_proof(tx_id, proof, header)

    def _tip_ref(self) -> BlockRef:
        """Return the chain tip, its id the hash of its checked header."""
        tip = self._tip()
        header = block_header_from_raw(tip.header, tip.height, network=self.network)
        return BlockRef(tip.height, header.hash)

    def get_history(
        self, scripts: Iterable[Octets | ScriptPubKey], start_height: int = 0
    ) -> ScriptHistory:
        """Return the history of `scripts`, from `start` to the tip.

        `blockchain.scripthash.get_history` for each script, which lists
        its transactions from the genesis block on, each confirmed one
        with the height of its block and no more. So the block of each
        is the header at that height, and `get_tx_merkle` gives its
        position there, which orders the transactions of one block. The
        branch is checked against the header, as `verify_tx` checks it,
        and a branch that fails is a `FetchError`. Each header is checked
        for its proof of work, and is not linked to the tip by its
        parents. `blockchain.headers.subscribe` is asked first and last,
        and a tip that moved is a `FetchError`.

        What the server lists is unverified beyond that. It can leave a
        transaction out, and it reports the mempool's with nothing to
        check them against: their signatures are not verified, and a
        transaction it reports may never confirm. A mempool transaction
        the server no longer has when it is asked for is the server's
        `RpcError`, a `FetchError`, and the caller asks again.

        The cost is a request per script, per block holding one of the
        transactions, and two per transaction. A server refuses a script
        with more history than it serves, as an `RpcError`.
        """
        elements = history_scripts(scripts)
        first = block_header_height(start_height)
        self._verify_once()
        tip = self._tip_ref()
        first = min(first, tip.height)
        start = tip
        if first < tip.height:
            start = BlockRef(first, self._header_at(first).hash)
        heights = self._listed(elements)
        if any(height > tip.height for height in heights.values() if height):
            raise FetchError("the tip moved while the history was read")
        confirmed = self._proven(
            {tx_id: h for tx_id, h in heights.items() if h is not None and h >= first}
        )
        txs = [HistoryTx(self.get_tx(tx_id), ref) for tx_id, ref in confirmed]
        txs += [
            HistoryTx(self.get_tx(tx_id), None)
            for tx_id, height in heights.items()
            if height is None
        ]
        if self._tip_ref() != tip:
            raise FetchError("the tip moved while the history was read")
        return ScriptHistory(start=start, tip=tip, txs=tuple(txs))

    def _listed(self, elements: frozenset[bytes]) -> dict[str, int | None]:
        """Return the height of each transaction the scripts list.

        `None` is the mempool's. Each script is asked by its sha256,
        reversed, as the protocol spells a script hash.
        """
        heights: dict[str, int | None] = {}
        for script in sorted(elements):
            for item in self._script_history(sha256(script)[::-1].hex()):
                height = item.height if item.height > 0 else None
                if heights.setdefault(item.tx_id, height) != height:
                    err_msg = f"transaction {item.tx_id}: listed at two heights"
                    raise FetchError(err_msg)
        return heights

    def _proven(self, heights: dict[str, int]) -> list[tuple[str, BlockRef]]:
        """Return each transaction and its block, in chain order.

        Each is proven in the header at its height by its merkle branch,
        whose position orders the transactions of one block.
        """
        headers: dict[int, BlockHeader] = {}
        confirmed: list[tuple[int, int, str]] = []
        for tx_id, height in heights.items():
            if height not in headers:
                headers[height] = self._header_at(height)
            proof = self.get_tx_merkle(tx_id, height)
            if not electrum.verify_merkle_proof(tx_id, proof, headers[height]):
                err_msg = f"transaction {tx_id}: no proof it is in block {height}"
                raise FetchError(err_msg)
            confirmed.append((height, proof.pos, tx_id))
        return [
            (tx_id, BlockRef(height, headers[height].hash))
            for height, _, tx_id in sorted(confirmed)
        ]

    def _script_history(self, scripthash: str) -> tuple[electrum.HistoryItem, ...]:
        """Return what `blockchain.scripthash.get_history` lists."""
        request_id = self._next_request_id()
        line = self._round_trip(
            electrum.scripthash_get_history_request(request_id, scripthash)
        )
        with fetch_errors(f"scripthash {scripthash}"):
            return electrum.scripthash_get_history_response(line, request_id)

    def estimate_fee(self, target: int) -> FeeQuote:
        """Return a fee rate expected to confirm within `target` blocks.

        `blockchain.estimatefee`. `-1`, the protocol's own way of saying
        no estimate is available, is a decline and raised as a
        `FetchError` rather than reaching `FeeRate` -- no sentinel
        reaches the return type, the way `Broadcaster`'s third contract
        bullet already requires of a refusal. Servers commonly proxy this
        answer from a node's own `estimatesmartfee`, so it is read in the
        same BTC/kvB unit `FeeRate.from_btc_per_kvbyte` already converts.
        """
        self._verify_once()
        target = valid_confirmation_target(target)
        request_id = self._next_request_id()
        line = self._round_trip(electrum.estimate_fee_request(request_id, target))
        with fetch_errors("blockchain.estimatefee"):
            result = electrum.estimate_fee_response(line, request_id)
            if result == -1:
                err_msg = f"blockchain.estimatefee: no estimate for target {target}"
                raise FetchError(err_msg)
            rate = FeeRate.from_btc_per_kvbyte(result, round_up=True)
            return FeeQuote(rate=rate, target=target)
