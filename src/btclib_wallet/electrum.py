# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The Electrum server protocol: newline-delimited JSON-RPC, no socket.

Not to be confused with `btclib_wallet.mnemonic.electrum`, Electrum's seed
scheme: this module is the wire protocol an Electrum *server* speaks,
unrelated beyond sharing the project's name.

`btclib_wallet.fetch.electrum` is the one place that goes and asks an
Electrum server anything, and this module is what turns a question into a
request line and a line into an answer, opening nothing. It sits outside
`btclib_wallet.fetch`, for the reason that package's docstring gives.

**Framing.** `encode_request` writes one JSON-RPC request, an id and a
newline the server splits messages on; `decode_response` reads one reply
line back, matched to the id of the request it answers, and refuses a
line that is not a well-formed answer to it -- not JSON, not an object,
answering the wrong id, or carrying neither a `result` nor an `error`.
Protocol-basics.rst encourages JSON-RPC 2.0 without requiring it, so no
`jsonrpc` member is sent and both an object `error` and a bare one are
read back, which is the one place this module still meets the elder
convention.

**The methods a fetcher over this protocol needs.**
`blockchain.transaction.get` for a raw transaction,
`blockchain.headers.subscribe` for the chain tip's height and header,
`blockchain.block.header` for the header at a height,
`blockchain.block.headers` for a chunk of consecutive headers,
`blockchain.transaction.get_merkle` for the branch and position that
proves a transaction confirmed, `blockchain.estimatefee` for a fee
rate quoted for a confirmation target, `blockchain.scripthash.get_balance`
for confirmed satoshis and a signed mempool delta, and
`blockchain.scripthash.get_history` for the transactions that touch a
script. Each has a function
to build the request and one to read the matching response -- shapes,
not a client: nothing here keeps a connection or retries. The balance
batch helpers put several requests on one line and match their answers
by id, refusing a batch with a missing, repeated or unasked answer.

**The merkle proof.** `assert_merkle_proof` and `verify_merkle_proof`
check what `transaction_get_merkle_response` returns against a
`BlockHeader` the caller already holds, and are what
`btclib_wallet.fetch.Fetcher`'s own class docstring means by "returns
evidence beside the data": the branch and position are not evidence until
they are checked against a root, and that check is
`btclib.block.merkle_proof.assert_as_valid`, unmodified -- this module
supplies the shapes either side of it and reimplements neither the
arithmetic nor CVE-2017-12842's hardening.
"""

from __future__ import annotations

import contextlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, NoReturn, cast

from btclib.alias import Octets
from btclib.block.block_header import BlockHeader
from btclib.block.merkle_proof import assert_as_valid
from btclib.block.merkle_proof import verify as verify_merkle_branch
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import bytes_from_octets, is_integer

from btclib_wallet._refusal import _RPC_CODES, _message_text
from btclib_wallet.exceptions import RpcError

__all__ = [
    "HeaderTip",
    "HistoryItem",
    "MerkleProof",
    "ScriptBalance",
    "assert_merkle_proof",
    "block_header_request",
    "block_header_response",
    "block_headers_request",
    "block_headers_response",
    "decode_response",
    "encode_request",
    "estimate_fee_request",
    "estimate_fee_response",
    "headers_subscribe_request",
    "headers_subscribe_response",
    "scripthash_get_balance_batch_request",
    "scripthash_get_balance_batch_response",
    "scripthash_get_balance_request",
    "scripthash_get_balance_response",
    "scripthash_get_history_request",
    "scripthash_get_history_response",
    "transaction_get_merkle_request",
    "transaction_get_merkle_response",
    "transaction_get_request",
    "transaction_get_response",
    "verify_merkle_proof",
]


# Exactly what is sent: `bytes.fromhex` would skip whitespace, and the
# string and not its decoding goes on the wire.
_TX_ID = re.compile(r"[0-9a-fA-F]{64}")


# Every method the Electrum protocol names, those it removed included:
# docs/protocol-methods.rst and docs/protocol-removed.rst of
# spesmilo/electrum-protocol@b3db795. `RpcError` names the method asked, so
# a method outside them is refused before it could print a key
_METHODS = frozenset(
    {
        "blockchain.address.get_balance",
        "blockchain.address.get_history",
        "blockchain.address.get_mempool",
        "blockchain.address.listunspent",
        "blockchain.address.subscribe",
        "blockchain.block.get_chunk",
        "blockchain.block.get_header",
        "blockchain.block.header",
        "blockchain.block.headers",
        "blockchain.estimatefee",
        "blockchain.headers.subscribe",
        "blockchain.numblocks.subscribe",
        "blockchain.outpoint.get_status",
        "blockchain.outpoint.subscribe",
        "blockchain.outpoint.unsubscribe",
        "blockchain.relayfee",
        "blockchain.scripthash.get_balance",
        "blockchain.scripthash.get_history",
        "blockchain.scripthash.get_mempool",
        "blockchain.scripthash.listunspent",
        "blockchain.scripthash.subscribe",
        "blockchain.scripthash.unsubscribe",
        "blockchain.scriptpubkey.get_balance",
        "blockchain.scriptpubkey.get_history",
        "blockchain.scriptpubkey.get_mempool",
        "blockchain.scriptpubkey.listunspent",
        "blockchain.scriptpubkey.subscribe",
        "blockchain.scriptpubkey.unsubscribe",
        "blockchain.transaction.broadcast",
        "blockchain.transaction.broadcast_package",
        "blockchain.transaction.get",
        "blockchain.transaction.get_merkle",
        "blockchain.transaction.id_from_pos",
        "blockchain.transaction.testmempoolaccept",
        "blockchain.utxo.get_address",
        "mempool.get_fee_histogram",
        "mempool.get_info",
        "mempool.recent",
        "server.add_peer",
        "server.banner",
        "server.donation_address",
        "server.features",
        "server.peers.subscribe",
        "server.ping",
        "server.version",
    }
)


def _assert_integer(value: object, what: str, *, non_negative: bool) -> None:
    """Refuse what is not an integer, a bool not being one.

    Where `non_negative`, refuse what is below zero too.
    """
    if not is_integer(value):
        raise BTClibTypeError(f"invalid {what} type: {type(value).__name__}")
    if non_negative and cast(int, value) < 0:
        raise BTClibValueError(f"invalid {what}: {_message_text(value)} < 0")


def _assert_scripthash(scripthash: str) -> None:
    """Refuse what is not a script hash as 64 hexadecimal characters."""
    if not isinstance(scripthash, str):
        raise BTClibTypeError(f"invalid scripthash type: {type(scripthash).__name__}")
    if not _TX_ID.fullmatch(scripthash):
        raise BTClibValueError("invalid scripthash: expected 64 hex characters")


def _assert_tx_id(tx_id: str) -> None:
    """Refuse what is not a transaction hash as a hexadecimal string."""
    if not isinstance(tx_id, str):
        raise BTClibTypeError(f"invalid tx_id type: {type(tx_id).__name__}")
    if not _TX_ID.fullmatch(tx_id):
        raise BTClibValueError(f"invalid tx_id: {_message_text(tx_id)}")


def encode_request(request_id: int, method: str, params: Any = ()) -> bytes:
    """Return one JSON-RPC request line, newline-terminated.

    The newline is part of the wire shape and not a transport's to add:
    `LineTransport` (`btclib_wallet.fetch.transport`) takes and returns exactly
    one such line, so a caller building one by hand -- outside the
    per-method helpers below -- still gets the framing right.

    Refused: a `request_id` that is not an integer, a `method` that is not a
    string, `params` that is not a list or a tuple (`BTClibTypeError`), and
    a request JSON cannot write: `params` holding an unwritable object
    (`BTClibTypeError`), or a `NaN`, an infinity, an integer too large or
    a nesting too deep (`BTClibValueError`).
    """
    _assert_integer(request_id, "request_id", non_negative=False)
    if not isinstance(method, str):
        raise BTClibTypeError(f"invalid method type: {type(method).__name__}")
    if not isinstance(params, (list, tuple)):
        raise BTClibTypeError(f"invalid params type: {type(params).__name__}")
    request = {"id": request_id, "method": method, "params": list(params)}
    # the refusal is raised after the `except` block, so that it chains no
    # error of json's: their notes quote the dict keys of `params`
    refusal: BTClibTypeError | BTClibValueError
    try:
        line = json.dumps(request, allow_nan=False)
    except TypeError as e:
        refusal = BTClibTypeError(f"request not JSON: {e}")
    except (ValueError, RecursionError) as e:
        refusal = BTClibValueError(f"request not JSON: {e}")
    else:
        return line.encode("utf-8") + b"\n"
    raise refusal


def _raise_rpc_error(error: object, method: str) -> NoReturn:
    """Raise a JSON-RPC `error` member as `RpcError`: its code and `method`.

    Shared by the sites that read one: an ordinary reply whose id matches
    the request, the JSON-RPC 2.0 reply whose `id` is `null` because the
    server could not parse the request enough to answer it at all, and a
    batch refused whole.

    The server's `message` and `data` are dropped. Section 7 of the
    btclib-org standard, *A refusal carries no secret*, does not relay
    another program's error text that can quote a key: a server's text
    can quote the request, and a key passed in the wrong place is a valid
    scripthash or tx id.

    A code that is no integer, or lies outside `_RPC_CODES`, is 0: JSON
    bounds no integer, so a code can hold the scalar of a key.
    """
    code = error.get("code") if isinstance(error, dict) else None
    if not (is_integer(code) and code in _RPC_CODES):
        code = 0
    raise RpcError(f"{method}: the server answered an error", cast(int, code))


def _refuse_constant(name: str) -> NoReturn:
    """Refuse `NaN`, `Infinity` and `-Infinity`, which RFC 8259 lacks."""
    raise BTClibValueError(f"not JSON: {name}")


# The deepest answer Electrum's own client reads, `server.peers.subscribe`,
# nests 4 levels, the reply object counted. `json.loads` kills the
# interpreter, where it should raise, from about 3000 levels in a thread
# with a 512 KiB stack (CPython 3.12 and 3.13).
_MAX_NESTING = 16

# A string, whatever it holds. `_too_deep` appends two quotes, so that a
# string left open still closes, this never fails and the scan stays linear.
_STRING = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"', re.DOTALL)
_NOT_BRACKET = re.compile(r"[^\[\]{}]+")


def _too_deep(text: str) -> bool:
    """Return True if `text` nests brackets deeper than `_MAX_NESTING`.

    A bracket inside a string does not count. The scan stops at the first
    excess.
    """
    depth = 0
    for bracket in _NOT_BRACKET.sub("", _STRING.sub("", f'{text}""')):
        if bracket in "[{":
            depth += 1
            if depth > _MAX_NESTING:
                return True
        else:
            depth -= 1
    return False


def decode_response(line: bytes, request_id: int, method: str) -> Any:
    """Return the `result` of one response line, matched to `request_id`.

    `line` is bytes, UTF-8 as Electrum sends it, decoded once so that the
    nesting check and the parser read the same text. A `str`, another
    encoding or another type is refused.

    Refuses a line that is not one: not JSON (`NaN` and `Infinity`
    included), nested more than 16 levels deep -- checked before
    `json.loads` runs, which can kill the interpreter on a deeper one --
    not an object, an id that is not this request's own integer id, or
    neither a `result` nor an `error` member. An `error` member is raised
    as `RpcError` rather than returned, carrying the error object's `code`
    where it fits `_RPC_CODES`, and `method`, the name of the request this
    line answers, and nothing else of the server's (`_raise_rpc_error`
    says why). A server that still answers the elder, non-object form of
    an error -- a bare string result under protocol 1.0 -- is read the
    same way, with code 0: the protocol carries no code for that shape,
    and 0 is no code Core or Electrum ever assigns one of their own. A
    `method` that is not a string is refused (`BTClibTypeError`), and so
    is one the protocol does not name (`BTClibValueError`).

    A request the server could not parse enough to answer at all is
    answered under JSON-RPC 2.0 with `"id": null`, so a `null` id
    carrying an `error` member is read as that error before the id is
    checked against `request_id` -- a `null` id with no `error` member
    falls through to the ordinary mismatch below instead, `null` being
    an id no request of this module's own ever carries. An id equal to
    `request_id` under Python's `==` but not itself an integer --
    `true`, `1.0` -- does not match either: JSON's booleans and floats
    compare equal to the integers they neighbour, and this module
    already refuses a bool as a number of any other kind (`is_integer`).
    """
    if not isinstance(method, str):
        raise BTClibTypeError(f"invalid method type: {type(method).__name__}")
    if method not in _METHODS:
        raise BTClibValueError(f"unknown method: {_message_text(method)}")
    return _response_result(_decode_line(line), request_id, method)


def _decode_line(line: bytes) -> Any:
    """Read one bounded-depth JSON value, shared by single and batch replies."""
    if not isinstance(line, (bytes, bytearray)):
        raise BTClibValueError(f"not a JSON-RPC line: {_message_text(line)}")
    # each refusal below is raised after `suppress`, so that no
    # `__context__` holds the codec's error or the parser's: both hold the
    # line
    text: str | None = None
    with contextlib.suppress(UnicodeDecodeError):
        text = line.decode("utf-8")
    if text is None:
        err_msg = f"not a JSON-RPC line: {_message_text(line)}, not UTF-8"
        raise BTClibValueError(err_msg)
    if _too_deep(text):
        raise BTClibValueError(f"not a JSON-RPC line: nested beyond {_MAX_NESTING}")
    with contextlib.suppress(TypeError, ValueError, RecursionError):
        return json.loads(text, parse_constant=_refuse_constant)
    raise BTClibValueError(f"not a JSON-RPC line: {_message_text(line)}, not JSON")


def _response_result(reply: object, request_id: int, method: str) -> Any:
    """Read one response object, preserving single or batch reply errors."""
    if not isinstance(reply, dict):
        raise BTClibTypeError(f"not a JSON-RPC response object: {_message_text(reply)}")
    reply_id = reply.get("id")
    error = reply.get("error")
    if reply_id is None and error is not None:
        _raise_rpc_error(error, method)
    if not (is_integer(reply_id) and reply_id == request_id):
        err_msg = f"response id {_message_text(reply_id)}"
        err_msg += f" does not answer request {_message_text(request_id)}"
        raise BTClibValueError(err_msg)
    if error is not None:
        _raise_rpc_error(error, method)
    if "result" not in reply:
        raise BTClibValueError(f"neither a result nor an error: {_message_text(reply)}")
    return reply["result"]


def _request_ids(line: bytes) -> frozenset[int]:
    """Return the ids of the request, or of the batch, `line` carries.

    What a transport keeping one connection matches the answer by. Each
    request carries an integer id, and those of a batch are distinct. A
    line without one, a notification included, is refused, since no line
    would answer it, and so is a line that is no request, described and
    not quoted.
    """
    message = _decode_line(line)
    ids: set[int] = set()
    for member in message if isinstance(message, list) else [message]:
        if not isinstance(member, dict):
            raise BTClibValueError(f"not a JSON-RPC message: {_message_text(member)}")
        request_id = member.get("id")
        if request_id is None:
            raise BTClibValueError(f"no request id: {_message_text(line)}")
        if not is_integer(request_id):
            raise BTClibValueError(f"not an integer id: {_message_text(request_id)}")
        if request_id in ids:
            raise BTClibValueError(f"repeated request id: {_message_text(request_id)}")
        ids.add(request_id)
    if not ids:
        raise BTClibValueError(f"no request id: {_message_text(line)}")
    return frozenset(ids)


def _reply_ids(line: bytes) -> frozenset[int] | None:
    """Return the request ids a line the server sent answers, or `None`.

    `None` is a notification: an object with a `method` and no id, or a
    `null` one, as the elder JSON-RPC writes it. A response is an object
    with no `method`, an integer id, and a `result` or an `error`. One with
    a `null` id and an `error` answers a request the server could not
    parse, and no id: the empty set. A batch is a nonempty array of
    responses with distinct ids. A line that is none of these is refused,
    described and not quoted.
    """
    message = _decode_line(line)
    if isinstance(message, dict) and message.get("id") is None:
        if "method" in message:
            return None
        if "error" in message:
            return frozenset()
    ids: set[int] = set()
    for member in message if isinstance(message, list) else [message]:
        if not (
            isinstance(member, dict)
            and "method" not in member
            and ("result" in member or "error" in member)
        ):
            raise BTClibValueError(f"not a JSON-RPC response: {_message_text(member)}")
        reply_id = member.get("id")
        if not is_integer(reply_id):
            raise BTClibValueError(f"not an integer id: {_message_text(reply_id)}")
        if reply_id in ids:
            raise BTClibValueError(f"repeated response id: {_message_text(reply_id)}")
        ids.add(cast(int, reply_id))
    if not ids:
        raise BTClibValueError("not a JSON-RPC response: an empty batch")
    return frozenset(ids)


@dataclass(frozen=True)
class ScriptBalance:
    """Confirmed satoshis and the signed mempool delta for a script hash.

    `unconfirmed` can be negative when a transaction in the mempool spends
    confirmed outputs. It is a change to `confirmed`, not another total.
    """

    confirmed: int
    unconfirmed: int


def scripthash_get_balance_request(request_id: int, scripthash: str) -> bytes:
    """Return a `blockchain.scripthash.get_balance` request.

    `scripthash` is the script's SHA256 hash in Electrum's reversed-byte
    hexadecimal spelling. Whitespace is refused rather than sent on the wire.
    """
    _assert_scripthash(scripthash)
    return encode_request(request_id, "blockchain.scripthash.get_balance", [scripthash])


def _script_balance(result: object) -> ScriptBalance:
    """Read the balance fields without coercing a bool or a rounded amount."""
    if not isinstance(result, dict):
        raise BTClibTypeError("scripthash.get_balance: not an object")
    confirmed = result.get("confirmed")
    unconfirmed = result.get("unconfirmed")
    _assert_integer(confirmed, "confirmed balance", non_negative=False)
    _assert_integer(unconfirmed, "unconfirmed balance", non_negative=False)
    if cast(int, confirmed) < 0:
        raise BTClibValueError("scripthash.get_balance: negative confirmed balance")
    return ScriptBalance(cast(int, confirmed), cast(int, unconfirmed))


def scripthash_get_balance_response(line: bytes, request_id: int) -> ScriptBalance:
    """Return the balances a matching `scripthash.get_balance` reply carries."""
    _assert_integer(request_id, "request_id", non_negative=False)
    return _script_balance(
        decode_response(line, request_id, "blockchain.scripthash.get_balance")
    )


def scripthash_get_balance_batch_request(requests: Mapping[int, str]) -> bytes:
    """Return one request line asking for several script hashes.

    The mapping keys are distinct request ids. A batch is nonempty; the
    caller bounds its size to what its server accepts, and uses the single
    request helper for servers that do not support batching.
    """
    if not isinstance(requests, Mapping):
        raise BTClibTypeError("balance batch: requests is not a mapping")
    if not requests:
        raise BTClibValueError("balance batch: no requests")
    lines = (
        scripthash_get_balance_request(request_id, script_hash).rstrip(b"\n")
        for request_id, script_hash in requests.items()
    )
    return b"[" + b",".join(lines) + b"]\n"


def _balance_request_ids(request_ids: object) -> set[int]:
    """Validate the nonempty, distinct integer ids a batch must answer."""
    if not isinstance(request_ids, Sequence) or isinstance(request_ids, (str, bytes)):
        raise BTClibTypeError("balance batch: request_ids is not a sequence")
    expected: set[int] = set()
    for request_id in request_ids:
        _assert_integer(request_id, "request_id", non_negative=False)
        if request_id in expected:
            raise BTClibValueError("balance batch: repeated request id")
        expected.add(request_id)
    if not expected:
        raise BTClibValueError("balance batch: no requests")
    return expected


def scripthash_get_balance_batch_response(
    line: bytes, request_ids: Sequence[int]
) -> tuple[ScriptBalance, ...]:
    """Return a complete batch's balances in the order of `request_ids`.

    Replies may arrive in any order. Missing, repeated or unasked ids are
    refused; an error for any request raises `RpcError`, so a partial batch
    never looks like a complete balance snapshot. The server's answers do
    not promise an atomic chain or mempool snapshot.
    """
    expected = _balance_request_ids(request_ids)
    replies = _decode_line(line)
    # A server may reject the whole batch with one JSON-RPC error object.
    if isinstance(replies, dict) and replies.get("id") is None:
        error = replies.get("error")
        if error is not None:
            _raise_rpc_error(error, "blockchain.scripthash.get_balance")
    if not isinstance(replies, list):
        raise BTClibTypeError("balance batch: not a response array")
    balances: dict[int, ScriptBalance] = {}
    for reply in replies:
        if not isinstance(reply, dict):
            raise BTClibTypeError("balance batch: not a response object")
        request_id = reply.get("id")
        _assert_integer(request_id, "response id", non_negative=False)
        if request_id not in expected:
            raise BTClibValueError("balance batch: unasked response id")
        if request_id in balances:
            raise BTClibValueError("balance batch: repeated response id")
        balances[request_id] = _script_balance(
            _response_result(reply, request_id, "blockchain.scripthash.get_balance")
        )
    if balances.keys() != expected:
        raise BTClibValueError("balance batch: missing response id")
    return tuple(balances[request_id] for request_id in request_ids)


@dataclass(frozen=True)
class HistoryItem:
    """One transaction `blockchain.scripthash.get_history` answered.

    `tx_id` is in lower-case hex, however the server spelled it, so one
    transaction is one id. `height` is that of the block confirming it,
    or one of the two mempool heights: `0` where every input spends a
    confirmed output and `-1` where one does not.
    """

    tx_id: str
    height: int


def scripthash_get_history_request(request_id: int, scripthash: str) -> bytes:
    """Return a `blockchain.scripthash.get_history` request.

    `scripthash` is refused as `scripthash_get_balance_request` refuses it.
    """
    _assert_scripthash(scripthash)
    return encode_request(request_id, "blockchain.scripthash.get_history", [scripthash])


def scripthash_get_history_response(
    line: bytes, request_id: int
) -> tuple[HistoryItem, ...]:
    """Return the transactions a `scripthash.get_history` reply lists, in order.

    The checks are those of Electrum's own client
    (`get_history_for_scripthash` of `electrum/interface.py`): the
    confirmed entries come first, their heights never falling, then the
    mempool's, and no transaction is listed twice. The `fee` of a mempool
    entry is unread.

    Refused: a result that is not a list, an entry that is not an object,
    a `height` that is not an integer or a `tx_hash` that is not a string
    (`BTClibTypeError`); a height below `-1`, a `tx_hash` that is not 64
    hex characters, an entry out of that order and a repeated `tx_hash`
    (`BTClibValueError`).
    """
    result = decode_response(line, request_id, "blockchain.scripthash.get_history")
    if not isinstance(result, list):
        raise BTClibTypeError("scripthash.get_history: not a list")
    items: list[HistoryItem] = []
    for entry in result:
        if not isinstance(entry, dict):
            raise BTClibTypeError("scripthash.get_history: an entry is not an object")
        height = entry.get("height")
        tx_id = entry.get("tx_hash")
        _assert_integer(height, "height", non_negative=False)
        _assert_tx_id(cast(str, tx_id))
        height = cast(int, height)
        if height < -1:
            err_msg = "scripthash.get_history: invalid height:"
            err_msg += f" {_message_text(height)} < -1"
            raise BTClibValueError(err_msg)
        previous = items[-1].height if items else 1
        if height > 0 and (previous < 1 or height < previous):
            raise BTClibValueError("scripthash.get_history: an entry out of order")
        items.append(HistoryItem(cast(str, tx_id).lower(), height))
    if len({item.tx_id for item in items}) != len(items):
        raise BTClibValueError("scripthash.get_history: a transaction listed twice")
    return tuple(items)


def transaction_get_request(request_id: int, tx_id: str) -> bytes:
    """Return the `blockchain.transaction.get` request for `tx_id`.

    Refused: a `tx_id` that is not a string (`BTClibTypeError`) or not 64
    hex characters (`BTClibValueError`).
    """
    _assert_tx_id(tx_id)
    return encode_request(request_id, "blockchain.transaction.get", [tx_id])


def transaction_get_response(line: bytes, request_id: int) -> bytes:
    """Return the raw transaction `blockchain.transaction.get` answered.

    The result is the serialization as a hex string, `verbose` left at
    its default `false`; decoded to bytes here so a caller -- and
    `btclib_wallet.fetch.fetcher.tx_from_raw`, which every other backend hands
    the same octets to -- reads the transaction and not a string it has
    to already know is hex.
    """
    result = decode_response(line, request_id, "blockchain.transaction.get")
    if not isinstance(result, str):
        err_msg = f"transaction.get: not a hex string: {_message_text(result)}"
        raise BTClibTypeError(err_msg)
    return bytes_from_octets(result)


@dataclass(frozen=True)
class HeaderTip:
    """The chain tip `blockchain.headers.subscribe` answered.

    `header` is the raw eighty-byte serialization, decoded here so a
    caller checks it with `BlockHeader.parse` rather than hex-decoding it
    a second time.
    """

    height: int
    header: bytes


def headers_subscribe_request(request_id: int) -> bytes:
    """Return the `blockchain.headers.subscribe` request.

    A subscription in the protocol's own vocabulary, but this codec
    speaks one request and one response: the notifications a live
    subscription goes on to deliver are a connection's to read off the
    wire, which nothing here holds, and are no part of what
    `decode_response` matches by id.
    """
    return encode_request(request_id, "blockchain.headers.subscribe")


def headers_subscribe_response(line: bytes, request_id: int) -> HeaderTip:
    """Return the chain tip `blockchain.headers.subscribe` answered."""
    result = decode_response(line, request_id, "blockchain.headers.subscribe")
    if not isinstance(result, dict):
        err_msg = f"headers.subscribe: not an object: {_message_text(result)}"
        raise BTClibTypeError(err_msg)
    height = result.get("height")
    header = result.get("hex")
    if not is_integer(height):
        err_msg = f"headers.subscribe: invalid height: {_message_text(height)}"
        raise BTClibTypeError(err_msg)
    if not isinstance(header, str):
        err_msg = f"headers.subscribe: invalid hex: {_message_text(header)}"
        raise BTClibTypeError(err_msg)
    return HeaderTip(cast(int, height), bytes_from_octets(header))


def block_header_request(request_id: int, height: int) -> bytes:
    """Return the `blockchain.block.header` request for `height`.

    `cp_height` left unsent, at its protocol default of zero: with it,
    the answer is the raw header hex alone, rather than a second, unasked
    merkle proof -- the `{"branch", "header", "root"}` checkpoint shape --
    this codec has no method for and
    `btclib_wallet.fetch.Fetcher.get_block_header`'s own checks, run on
    the header this returns, have no use for.

    Refused: a `height` that is not an integer (`BTClibTypeError`) or is
    negative (`BTClibValueError`).
    """
    _assert_integer(height, "height", non_negative=True)
    return encode_request(request_id, "blockchain.block.header", [height])


def block_header_response(line: bytes, request_id: int) -> bytes:
    """Return the raw header `blockchain.block.header` answered."""
    result = decode_response(line, request_id, "blockchain.block.header")
    if not isinstance(result, str):
        err_msg = f"block.header: not a hex string: {_message_text(result)}"
        raise BTClibTypeError(err_msg)
    return bytes_from_octets(result)


def block_headers_request(request_id: int, start_height: int, count: int) -> bytes:
    """Return the `blockchain.block.headers` request for `count` headers.

    `cp_height` is left unsent, at its protocol default of zero, so the
    answer carries no checkpoint `root` and `branch`.

    Refused: a `start_height` or a `count` that is not an integer
    (`BTClibTypeError`) or is negative (`BTClibValueError`).
    """
    _assert_integer(start_height, "start_height", non_negative=True)
    _assert_integer(count, "count", non_negative=True)
    return encode_request(request_id, "blockchain.block.headers", [start_height, count])


def block_headers_response(line: bytes, request_id: int, count: int) -> list[bytes]:
    """Return the raw headers `blockchain.block.headers` answered.

    The parameter `count` is the number of headers asked for. The answer
    is read in the shape from before protocol 1.6 (1.5 was skipped): one
    object with the members `count`, `hex` and `max`. Floresta, the
    server this is for, answers `server.version` with "1.4" and
    `blockchain.block.headers` in this shape (`electrum_protocol.rs`,
    floresta-electrum, commit b998d80). From 1.6 the headers come as a
    `headers` list instead, which this does not read.
    protocol-methods.rst documents only the 1.6 shape;
    protocol-changes.rst's 1.6 entry records the change.

    A server answers fewer headers than asked when it reaches its tip or
    its own `max`, so the list can be shorter than the parameter, or
    empty. Refused: a parameter `count` that is not an integer
    (`BTClibTypeError`) or is negative (`BTClibValueError`), before the
    line is read; an answer that is not an object
    (`BTClibTypeError`); an answered `count` that is not an integer
    (`BTClibTypeError`) or not from 0 to the parameter
    (`BTClibValueError`); a `hex` that is not a string
    (`BTClibTypeError`), not hex, or not 80 bytes for each header
    answered (`BTClibValueError`). `max` is unread.
    """
    if not is_integer(count):
        err_msg = f"block.headers: invalid count asked: {_message_text(count)}"
        raise BTClibTypeError(err_msg)
    if count < 0:
        err_msg = f"block.headers: invalid count asked: {_message_text(count)}"
        raise BTClibValueError(err_msg)
    result = decode_response(line, request_id, "blockchain.block.headers")
    if not isinstance(result, dict):
        raise BTClibTypeError(f"block.headers: not an object: {_message_text(result)}")
    answered = result.get("count")
    if not is_integer(answered):
        err_msg = f"block.headers: invalid count: {_message_text(answered)}"
        raise BTClibTypeError(err_msg)
    n = cast(int, answered)
    if not 0 <= n <= count:
        err_msg = f"block.headers: invalid count: {_message_text(answered)}"
        raise BTClibValueError(err_msg)
    hex_ = result.get("hex")
    if not isinstance(hex_, str):
        raise BTClibTypeError(f"block.headers: not a hex string: {_message_text(hex_)}")
    raw = bytes_from_octets(hex_)
    if len(raw) != n * 80:
        err_msg = f"block.headers: hex of {len(raw)} bytes,"
        err_msg += " not 80 for each header counted"
        raise BTClibValueError(err_msg)
    return [raw[i * 80 : (i + 1) * 80] for i in range(n)]


@dataclass(frozen=True)
class MerkleProof:
    """The branch `blockchain.transaction.get_merkle` answered.

    `branch` and the transaction id it is checked against are both in
    display order -- the order `assert_merkle_proof` below, `Tx.id` and a
    block explorer all already use. `block_height` is the server's own
    claim of which block, unchecked here: it is what a caller passes to
    `btclib_wallet.fetch.Fetcher.get_block_header` to fetch the header
    this proof is checked against, so a wrong claim there is a wrong
    header fetched, and the branch check below is what refuses it.
    """

    block_height: int
    branch: tuple[bytes, ...]
    pos: int


def transaction_get_merkle_request(request_id: int, tx_id: str, height: int) -> bytes:
    """Return the `blockchain.transaction.get_merkle` request.

    Refused: a `tx_id` as `transaction_get_request` refuses it, and a
    `height` that is not an integer (`BTClibTypeError`).
    """
    _assert_tx_id(tx_id)
    _assert_integer(height, "height", non_negative=False)
    return encode_request(
        request_id, "blockchain.transaction.get_merkle", [tx_id, height]
    )


def transaction_get_merkle_response(line: bytes, request_id: int) -> MerkleProof:
    """Return the merkle proof `blockchain.transaction.get_merkle` answered."""
    result = decode_response(line, request_id, "blockchain.transaction.get_merkle")
    if not isinstance(result, dict):
        err_msg = f"transaction.get_merkle: not an object: {_message_text(result)}"
        raise BTClibTypeError(err_msg)
    block_height = result.get("block_height")
    branch = result.get("merkle")
    pos = result.get("pos")
    if not is_integer(block_height):
        err_msg = "transaction.get_merkle: invalid block_height:"
        err_msg += f" {_message_text(block_height)}"
        raise BTClibTypeError(err_msg)
    if not isinstance(branch, list):
        err_msg = f"transaction.get_merkle: invalid merkle: {_message_text(branch)}"
        raise BTClibTypeError(err_msg)
    if not is_integer(pos):
        err_msg = f"transaction.get_merkle: invalid pos: {_message_text(pos)}"
        raise BTClibTypeError(err_msg)
    return MerkleProof(
        cast(int, block_height),
        tuple(bytes_from_octets(sibling, 32) for sibling in branch),
        cast(int, pos),
    )


def assert_merkle_proof(tx_id: Octets, proof: MerkleProof, header: BlockHeader) -> None:
    """Raise unless `proof` proves `tx_id` is in the tree `header` commits to.

    `btclib.block.merkle_proof.assert_as_valid`, unmodified: this is the
    shape the answer arrives in, checked against the header a caller
    fetched on its own, not a second implementation of the arithmetic.
    """
    assert_as_valid(tx_id, proof.branch, proof.pos, header.merkle_root)


def verify_merkle_proof(tx_id: Octets, proof: MerkleProof, header: BlockHeader) -> bool:
    """Return True if `proof` proves `tx_id` is in the tree `header` commits to.

    See `assert_merkle_proof`, which this wraps the same way
    `btclib.block.merkle_proof.verify` wraps `assert_as_valid`.
    """
    return verify_merkle_branch(tx_id, proof.branch, proof.pos, header.merkle_root)


def estimate_fee_request(request_id: int, target: int) -> bytes:
    """Return the `blockchain.estimatefee` request for `target` blocks.

    Refused: a `target` that is not an integer (`BTClibTypeError`).
    """
    _assert_integer(target, "target", non_negative=False)
    return encode_request(request_id, "blockchain.estimatefee", [target])


def estimate_fee_response(line: bytes, request_id: int) -> float:
    """Return the BTC/kB rate `blockchain.estimatefee` answered, or -1.

    `-1` is the protocol's own way of saying no estimate is available,
    and is returned rather than raised here: this module reads what the
    wire carries, and deciding that "no answer" is a refusal is
    `btclib_wallet.fetch.electrum.ElectrumFetcher.estimate_fee`'s to make, the
    same split `decode_response` already draws for a JSON-RPC `error`
    member. Any other answer, below 0 or not finite, is refused.
    """
    result = decode_response(line, request_id, "blockchain.estimatefee")
    if isinstance(result, bool) or not isinstance(result, (int, float)):
        raise BTClibTypeError(f"estimatefee: not a number: {_message_text(result)}")
    if (isinstance(result, float) and not math.isfinite(result)) or not (
        result >= 0 or result == -1
    ):
        err_msg = f"estimatefee: not a rate or -1: {_message_text(result)}"
        raise BTClibValueError(err_msg)
    return result
