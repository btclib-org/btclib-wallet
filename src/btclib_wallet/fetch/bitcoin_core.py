# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The btclib fetcher backed by a `BitcoinCoreRpcClient`.

The client itself is the `bitcoin-core-rpc` package: zero dependencies of
its own, nothing but the standard library behind it, and no part of
btclib. What this module adds is the integration -- the answers turned
into btclib transactions, and the chain the node serves compared with the
network those transactions are labelled for.

The names it re-exports are the package's own, unchanged, so that
`from btclib_wallet.fetch.bitcoin_core import BitcoinCoreRpcClient` keeps
resolving. Their behaviour is the package's too, exceptions included: a
`client.call` reached that way raises `bitcoin_core_rpc.RpcError`, not
`btclib.exceptions.RpcError`. The `Fetcher` interface is where btclib's
own exceptions are promised, and `_call` below is the line that makes it
true.
"""

from collections.abc import Iterable, Mapping, Sequence
from typing import Any, cast

from bitcoin_core_rpc import (
    COOKIE_USER,
    DEFAULT_DATADIR,
    BitcoinCoreRpcClient,
    RPCErrorCode,
    chain_from_network,
    cookie_auth,
    magic_from_signet_challenge,
)
from btclib.alias import Octets
from btclib.block.block_header import BlockHeader
from btclib.consensus import MAX_BLOCK_WEIGHT
from btclib.exceptions import BTClibTypeError, BTClibValueError, FetchError, RpcError
from btclib.fee import FeeRate
from btclib.script import ScriptPubKey
from btclib.tx import OutPoint, Tx
from btclib.utils import bytes_from_octets, is_integer
from typing_extensions import override

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

__all__ = [
    "COOKIE_USER",
    "DEFAULT_DATADIR",
    "BitcoinCoreFetcher",
    "BitcoinCoreRpcClient",
    "chain_from_network",
    "cookie_auth",
]

# What a reply that is a number or a hash may weigh: the JSON envelope and a
# value of a few dozen octets. `getrawtransaction` keeps the client's default
# (`DEFAULT_MAX_BODY_SIZE`).
_MAX_SMALL_REPLY = 1024

# What a block or a scan may weigh as `get_history` reads it: five octets per
# weight unit of the heaviest block. `tests/integration/history_test.py` holds
# `getblock` at verbosity 3, against the Core release the integration job
# runs, under five octets per weight unit for a block of standard spends of
# bare 1-of-3 multisig outputs of uncompressed keys with short signatures, and
# between three and five for a block of large witnesses, each witness octet
# written twice as hex. A block whose rendering passes the bound is refused
# as a `FetchError`.
#
# Nothing in the node bounds a scan: it reports every unspent output the
# scripts hold. The same test module holds a P2WPKH one, its share of the
# envelope included, under 400 octets, so the bound admits at least 50,000 of
# them, fewer for longer scripts, and a larger scan is refused as a
# `FetchError`. The scan shares the block's bound rather than taking one of
# its own, no limit of the node's being there to derive one from.
_MAX_LARGE_REPLY = 5 * MAX_BLOCK_WEIGHT

# A floor on the octets of the node's memory a mempool entry costs, as
# `getmempoolinfo` counts them. `tests/integration/history_test.py` holds two
# clusters at the limit of 64 at or above it: a chain of small entries, over
# all of its entries, and the small children of one parent, over the children
# alone. Shapes the tests do not build may cost less, and the floor is not
# shown to hold for them.
_MEMPOOL_ENTRY_USAGE = 800

# What the mempool's txids may weigh at `-maxmempool`'s default of 300 MB,
# which counts the node's memory and not the transactions' size: as many
# entries as fit at the floor above, each txid 67 octets of reply, the 64 hex
# digits with their quotes and comma. A bound of its own, since it passes the
# block's, and raising the block's to it would loosen the bound on blocks and
# scans for nothing. The reply of a node with a larger `-maxmempool` can pass
# it, and is refused as a `FetchError`.
_MAX_MEMPOOL_REPLY = 300_000_000 // _MEMPOOL_ENTRY_USAGE * 67

# the modes `estimatesmartfee` takes, which Core matches without regard to
# ASCII case (`FeeModeMap` and `FeeModeFromString`, src/common/messages.cpp)
_ESTIMATE_MODES = ("unset", "economical", "conservative")


class BitcoinCoreFetcher(NetworkVerifyingFetcher):
    """Every `Fetcher` question, answered by a node over its RPC.

    Also a `Broadcaster`: `broadcast` sends `sendrawtransaction`, which
    `-rest` -- and so `BitcoinCoreRestFetcher` -- has no equivalent of.
    Holding a fetcher is not broadcasting; a caller has to call the
    method, and `broadcast`'s own docstring is where its non-idempotence
    is stated, at the point a caller meets it.

    Also a `FeeEstimator`: `estimate_fee` sends `estimatesmartfee`, which
    `-rest` has no equivalent of either -- fee estimation is RPC only.

    Also a `HistoryReader`: `get_history` reads the blocks and the
    mempool, and asks nothing of the node's wallet.

    The client is a constructor argument rather than a set of connection
    arguments repeated here: one class owns the endpoint and credentials,
    this one owns the mapping onto btclib types, and a caller who already has
    a client does not build a second.

    `network` is btclib's chain label and belongs here, not to the connection:
    it is what the outputs of a fetched transaction are labelled with. The
    client knows a URL and no chain, so the label is a claim until the node
    is asked, and `assert_network` is the question.

    `signet_challenge` is which signet, for the one label that names more
    than one chain: Core answers `signet` for the default signet and for
    every custom one alike, so a fetcher on a signet of its own passes the
    challenge and `assert_network` holds the node to it. Hex or the bytes
    it spells, as `-signetchallenge` takes it. It is what a custom signet
    needs from this class and the whole of it -- the addresses of one are
    signet's, `NETWORKS` describing the encoding and not the chain -- so it
    is refused with a network that is no signet, and refused with
    `verify_network` off, either being a check that would not be made.

    `estimate_mode` is `estimatesmartfee`'s own parameter, fixed at
    construction rather than taken per call: it is not part of
    `FeeEstimator`'s contract -- Core's alone among the three backends --
    so a caller who cares chooses it once, the way `signet_challenge` is
    chosen once, rather than a signature every `estimate_fee` call would
    otherwise have to widen for one backend's option. Defaults to Core's
    own default, `economical`, and a string that is none of Core's modes
    is refused here rather than by the node.
    """

    def __init__(
        self,
        client: BitcoinCoreRpcClient,
        network: str = "mainnet",
        *,
        verify_network: bool = True,
        signet_challenge: str | bytes | None = None,
        estimate_mode: str = "economical",
    ) -> None:
        super().__init__(network, verify_network=verify_network)
        if not isinstance(client, BitcoinCoreRpcClient):
            raise BTClibTypeError(
                f"not a BitcoinCoreRpcClient: {type(client).__name__}"
            )
        if not isinstance(estimate_mode, str):
            err_msg = f"non-string estimate_mode: {type(estimate_mode).__name__}"  # type: ignore[unreachable]
            raise BTClibTypeError(err_msg)
        if not estimate_mode.isascii() or estimate_mode.lower() not in _ESTIMATE_MODES:
            raise BTClibValueError(f"invalid estimate_mode: {estimate_mode!r}")
        if signet_challenge is not None:
            if chain_from_network(self.network) != "signet":
                err_msg = f"a signet_challenge for {self.network},"
                err_msg += " which is no signet"
                raise BTClibValueError(err_msg)
            if not verify_network:
                err_msg = "a signet_challenge is what verify_network"
                err_msg += " compares, and checks nothing with it off"
                raise BTClibValueError(err_msg)
            # derived here and thrown away, so that a challenge that is no
            # script fails at the line that wrote it rather than at the
            # first fetch: what the check itself uses is the challenge, the
            # comparison being of the node's derived magic against this one
            with client_errors():
                magic_from_signet_challenge(signet_challenge)
        self.client = client
        self.signet_challenge = signet_challenge
        self.estimate_mode = estimate_mode

    def _call(
        self,
        method: str,
        params: Sequence[Any] | Mapping[str, Any] | None,
        *,
        max_body_size: int | None,
    ) -> Any:
        """Invoke one rpc method, raising btclib's exceptions for it.

        The one line of this class that crosses into `bitcoin_core_rpc`,
        which is why every method below goes through it: the package
        declares a `FetchError` of its own, and what a `Fetcher` promises
        its caller is `btclib.exceptions`'. `client_errors` carries the
        `status` and the `code` across.

        `max_body_size` is omitted rather than passed as None when a
        caller does not set it, so the client's own default applies.
        """
        bound = {} if max_body_size is None else {"max_body_size": max_body_size}
        with client_errors():
            return self.client.call(method, params, **bound)

    @override
    def get_tx(self, tx_id: Octets) -> Tx:
        """Return the transaction with this id.

        `getrawtransaction` with no verbosity returns the serialization. Those
        bytes are what `Tx.parse` recomputes the id from, so a transaction
        arriving wrong announces itself. A node answers for a transaction in
        its mempool, one of its wallet's, and -- only with `-txindex` -- any
        other. Without the index the error is RPC code -5.
        """
        self._verify_once()
        hex_ = tx_id_hex(tx_id)
        raw = self._call("getrawtransaction", [hex_], max_body_size=None)
        return tx_from_raw(raw, hex_, self.network)

    @override
    def get_block_count(self) -> int:
        """Return the height of the node's best chain tip."""
        self._verify_once()
        with fetch_errors("getblockcount"):
            reply = self._call("getblockcount", None, max_body_size=_MAX_SMALL_REPLY)
            return int(reply)

    @override
    def get_best_block_id(self) -> bytes:
        """Return the hash of the node's best chain tip, display order."""
        self._verify_once()
        with fetch_errors("getbestblockhash"):
            reply = self._call("getbestblockhash", None, max_body_size=_MAX_SMALL_REPLY)
            return bytes_from_octets(reply, 32)

    @override
    def get_block_header(self, height: int) -> BlockHeader:
        """Return the header of the block at this height, checked on arrival.

        Two calls, Core answering `getblockheader` by hash and not by
        height: `getblockhash` maps the height first, and `getblockheader`
        with verbosity `false` returns the serialization rather than a
        rendering of it -- the same shape `getrawtransaction` answers
        `get_tx` with.
        """
        self._verify_once()
        height = block_header_height(height)
        with fetch_errors("getblockhash"):
            reply = self._call("getblockhash", [height], max_body_size=_MAX_SMALL_REPLY)
            block_hash = bytes_from_octets(reply, 32).hex()
        raw = self._call(
            "getblockheader", [block_hash, False], max_body_size=_MAX_SMALL_REPLY
        )
        return block_header_from_raw(raw, height, network=self.network)

    @override
    def assert_network(self) -> None:
        """Raise unless the node serves the chain this fetcher labels with.

        Worth the call, because the failure it catches is silent.
        A client built for a testnet node -- an explicit url, no port
        default in the way -- under a fetcher labelled `mainnet` renders a
        mainnet address for every output it fetches, for coins that are
        not there. `getblockchaininfo` answers that in one round trip;
        what it needs is a vocabulary to be compared through, which is
        `chain_from_network`, Core naming the chain `main` where
        btclib names it `mainnet`.

        Signet is the case a name cannot settle: Core reports `signet` for
        the default one and for every custom one alike, so two nodes
        sharing nothing but the shape of a challenge answer the same
        string. The challenge is what tells them apart, and this fetcher's
        is the constructor's `signet_challenge`, or the default signet with
        none given.

        Both comparisons are the client's `assert_chain`, this method being
        the translation into btclib's vocabulary and btclib's exceptions:
        `chain_from_network` on the way in, `client_errors` on the way out.
        The check itself belongs beside the protocol it reads, and lived
        here only while `bitcoin_core_rpc` did not have it.
        """
        # every network of NETWORKS is a chain of Core's -- the catalogue is
        # fixed at import and `tests/fetch/bitcoin_core_test.py` holds the
        # two vocabularies to covering each other -- so the translation
        # cannot fail for a name this fetcher was allowed to carry
        with client_errors():
            self.client.assert_chain(
                chain_from_network(self.network),
                signet_challenge=self.signet_challenge,
            )

    def broadcast(self, tx: Tx, *, maxfeerate: float | None = None) -> bytes:
        """Announce `tx` to the node, and return the txid it confirmed.

        `_verify_once` is called first, as every other method here calls
        it -- but a broadcast to a node on the wrong chain is the worst
        version of the silent failure `verify_network` exists to catch: a
        fetch answering with the wrong data is corrected on the next
        read, where a signed transaction fanned out to the wrong network's
        peers cannot be called back.

        `sendrawtransaction` with the wire serialization, witness
        included -- what a peer relays and eventually mines, not the
        stripped form `Tx.id` hashes. `maxfeerate` is forwarded exactly as
        given, an absent one leaving the parameter out of the call rather
        than substituting a value of this method's choosing: Core's own
        default (`DEFAULT_MAX_RAW_TX_FEE_RATE`) refuses a fee a caller may
        have deliberately chosen, so a default written here would refuse
        it on the caller's behalf.

        The id is computed from `tx` before the request, the way
        `tx_from_raw` recomputes one from a fetched serialization: a
        success naming a different txid is a `FetchError`, the node
        having confirmed some other transaction. One request and no
        retry -- after a timeout this method cannot tell a transaction
        that never reached the mempool from one that did and whose
        acknowledgement was merely lost on the way back, so trying again
        could announce the same signed spend twice for no information
        gained. That decision is the caller's, made with whatever else it
        can ask the node.
        """
        self._verify_once()
        txid = tx.id
        hex_ = tx.serialize(include_witness=True).hex()
        params: list[Any] = [hex_] if maxfeerate is None else [hex_, maxfeerate]
        reply = self._call("sendrawtransaction", params, max_body_size=_MAX_SMALL_REPLY)
        with fetch_errors("sendrawtransaction"):
            answered = bytes_from_octets(reply, 32)
        if answered != txid:
            err_msg = f"broadcast {txid.hex()}: the node confirmed {answered.hex()}"
            raise FetchError(err_msg)
        return answered

    def estimate_fee(self, target: int) -> FeeQuote:
        """Return a fee rate expected to confirm within `target` blocks.

        `estimatesmartfee`, with `self.estimate_mode` as its second
        parameter. A reply naming no `feerate` -- "only present if no
        errors were encountered" -- is a decline and not a rate, raised
        as a `FetchError` carrying the node's own `errors`, unreshaped.
        `blocks` is the target the node actually estimated for, clamped
        to at least 2 and at most its own maximum usable target, and is
        what the returned `FeeQuote.target` reports -- not necessarily
        `target` itself.
        """
        self._verify_once()
        target = valid_confirmation_target(target)
        with fetch_errors("estimatesmartfee"):
            reply = self._call(
                "estimatesmartfee",
                [target, self.estimate_mode],
                max_body_size=_MAX_SMALL_REPLY,
            )
            if not isinstance(reply, dict):
                raise BTClibTypeError(f"not an object: {reply!r}")
            feerate = reply.get("feerate")
            if feerate is None:
                errors = reply.get("errors") or ["no estimate for this target"]
                err_msg = f"estimatesmartfee: {'; '.join(str(e) for e in errors)}"
                raise FetchError(err_msg)
            blocks = reply.get("blocks")
            if not is_integer(blocks):
                raise BTClibTypeError(f"invalid blocks: {blocks!r}")
            rate = FeeRate.from_btc_per_kvbyte(feerate, round_up=True)
            return FeeQuote(rate=rate, target=cast(int, blocks))

    def get_history(
        self, scripts: Iterable[Octets | ScriptPubKey], start_height: int = 0
    ) -> ScriptHistory:
        """Return the history of `scripts`, from `start` to the tip.

        Core keeps no index by script, so this reads what a script is in.
        The blocks are `getblock` at verbosity 3, which names the script of
        the output each input spends, walked down from the tip through
        `previousblockhash`: the walk stays on the chain of the tip it read
        first, whatever the node switches to meanwhile. A block with no undo
        data, such as a pruned one, is a `FetchError`. So is a block whose
        rendering passes `_MAX_LARGE_REPLY`: it stops every call whose
        range spans it. A scan past that bound, and a mempool reply past
        `_MAX_MEMPOOL_REPLY`, such as one from a node with a larger
        `-maxmempool`, are each a `FetchError` too.

        The mempool is `getrawmempool`, then `getrawtransaction` for each
        transaction; one the node no longer has by then is skipped. A
        mempool input names an output and not its script, so the outputs
        it may spend are those the scripts hold unspent, `scantxoutset`'s
        answer, and those the mempool's own transactions pay to them.

        Core runs one `scantxoutset` at a time, so a call while another
        scan runs on the node raises `RpcError` with code -8. The scan
        runs under the client's timeout, and one the timeout cuts short
        goes on in the node until it ends: a call made meanwhile meets
        that -8 too.

        `getbestblockhash` is asked again last. A tip that moved is a
        `FetchError`, and so is a `scantxoutset` read at another tip: a
        transaction mined meanwhile would be in no block read and is
        reported from the mempool, or not at all.

        The cost is a call per block from `start_height` up and a call per
        mempool transaction, and `scantxoutset`, asked where the mempool
        holds any, reads the whole utxo set.
        """
        elements = history_scripts(scripts)
        first = block_header_height(start_height)
        self._verify_once()
        tip_id = self._best_block_hex()
        blocks: list[tuple[BlockRef, list[Tx]]] = []
        block_hex, height = tip_id, None
        while True:
            ref, txs, parent = self._history_block(block_hex, height, elements)
            if height is None:
                first = min(first, ref.height)
            blocks.append((ref, txs))
            if ref.height == first:
                break
            block_hex, height = parent, ref.height - 1
        confirmed = [HistoryTx(tx, ref) for ref, txs in reversed(blocks) for tx in txs]
        unconfirmed = [
            HistoryTx(tx, None) for tx in self._history_mempool(elements, tip_id)
        ]
        if self._best_block_hex() != tip_id:
            raise FetchError("the tip moved while the history was read")
        return ScriptHistory(
            start=blocks[-1][0],
            tip=blocks[0][0],
            txs=(*confirmed, *unconfirmed),
        )

    def _best_block_hex(self) -> str:
        """Return the hash of the node's best chain tip, as hex."""
        with fetch_errors("getbestblockhash"):
            reply = self._call("getbestblockhash", None, max_body_size=_MAX_SMALL_REPLY)
            return bytes_from_octets(reply, 32).hex()

    def _history_block(
        self, block_hex: str, height: int | None, elements: frozenset[bytes]
    ) -> tuple[BlockRef, list[Tx], str]:
        """Return a block, its transactions touching `elements`, and its parent.

        `height` is the one the walk expects, or `None` for the tip. The
        parent is `""` for the genesis block.
        """
        reply = self._call("getblock", [block_hex, 3], max_body_size=_MAX_LARGE_REPLY)
        with fetch_errors(f"getblock {block_hex}"):
            answered = _member(reply, "hash")
            if answered != block_hex:
                raise BTClibValueError(f"the answer is block {answered}")
            answered = _member(reply, "height")
            if not is_integer(answered) or (height is not None and answered != height):
                raise BTClibValueError(f"the answer is at height {answered}")
            txs = [
                tx_from_raw(_member(entry, "hex"), _member(entry, "txid"), self.network)
                for entry in _member(reply, "tx")
                if _touches(entry, elements)
            ]
            parent = str(reply.get("previousblockhash", ""))
            ref = BlockRef(cast(int, answered), bytes_from_octets(block_hex, 32))
        return ref, txs, parent

    def _history_mempool(self, elements: frozenset[bytes], tip_id: str) -> list[Tx]:
        """Return the mempool's transactions touching `elements`."""
        reply = self._call("getrawmempool", None, max_body_size=_MAX_MEMPOOL_REPLY)
        with fetch_errors("getrawmempool"):
            if not isinstance(reply, list):
                raise BTClibTypeError(f"not an array: {type(reply).__name__}")
            tx_ids = [tx_id_hex(tx_id) for tx_id in reply]
        mempool: list[Tx] = []
        for tx_id in tx_ids:
            try:
                raw = self._call("getrawtransaction", [tx_id], max_body_size=None)
            except RpcError as e:
                if e.code != RPCErrorCode.INVALID_ADDRESS_OR_KEY:
                    raise
                continue
            mempool.append(tx_from_raw(raw, tx_id, self.network))
        if not mempool:
            return []
        ours = {
            OutPoint(tx.id, vout)
            for tx in mempool
            for vout, tx_out in enumerate(tx.vout)
            if tx_out.script_pub_key.script in elements
        }
        ours |= self._history_unspent(elements, tip_id)
        return [
            tx
            for tx in mempool
            if any(tx_out.script_pub_key.script in elements for tx_out in tx.vout)
            or any(tx_in.prev_out in ours for tx_in in tx.vin)
        ]

    def _history_unspent(
        self, elements: frozenset[bytes], tip_id: str
    ) -> set[OutPoint]:
        """Return the outputs `elements` hold unspent at the tip `tip_id`."""
        descriptors = [f"raw({script.hex()})" for script in sorted(elements)]
        reply = self._call(
            "scantxoutset", ["start", descriptors], max_body_size=_MAX_LARGE_REPLY
        )
        with fetch_errors("scantxoutset"):
            if _member(reply, "success") is not True:
                raise BTClibValueError("the scan did not complete")
            answered = _member(reply, "bestblock")
            if answered != tip_id:
                raise BTClibValueError(f"read at {answered}, not at {tip_id}")
            return {
                OutPoint(_member(utxo, "txid"), _member(utxo, "vout"))
                for utxo in _member(reply, "unspents")
            }


def _member(reply: Any, name: str) -> Any:
    """Return one member of a json object, refusing what is not one.

    `TypeError` for a missing member as for a reply that is no object,
    which `fetch_errors` reads as the node's own failure, as
    `bitcoin_core_rest._field` does.
    """
    if not isinstance(reply, dict) or name not in reply:
        raise TypeError(f"no {name!r} member")
    return reply[name]


def _touches(entry: Any, elements: frozenset[bytes]) -> bool:
    """Answer whether a transaction `getblock` renders touches `elements`.

    A coinbase input spends nothing; any other input without `prevout` is
    in a block whose undo data the node does not have.
    """
    for tx_out in _member(entry, "vout"):
        script = _member(_member(tx_out, "scriptPubKey"), "hex")
        if bytes.fromhex(script) in elements:
            return True
    for tx_in in _member(entry, "vin"):
        if "coinbase" in tx_in:
            continue
        script = _member(_member(_member(tx_in, "prevout"), "scriptPubKey"), "hex")
        if bytes.fromhex(script) in elements:
            return True
    return False
