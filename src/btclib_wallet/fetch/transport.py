# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The transports a fetcher does its I/O with, and the network policy of each.

Two seams here, one per wire shape; a p2p peer's is
`btclib_wallet.fetch.peer_transport`. `HttpTransport` is re-exported under
btclib's name with its implementations; `LineTransport` is declared here,
with its implementations.

The HTTP half's implementation is `bitcoin_core_rpc`'s: a bounded read, no
redirect followed and no proxy taken from the environment, in a package
that depends on nothing beyond the standard library. btclib depends on it
for the rpc client and reaches the same transport through it, rather than
keeping a second copy of that bounded-read and redirect policy in step
with the first.

Aliases and not wrappers: `EsploraFetcher` passes `transport=` straight
through to `http_request`, and a caller substituting one for a test needs
the object those two agree on. `HttpTransport` is that seam, and this is
btclib's name for it.

The HTTP implementations differ in how they hold the connection.
`urlopen_transport` is the default: one connection per call, opened and
handed to the node to close. `SessionTransport` keeps one connection per
`(scheme, host, port)` open
across calls instead, which is worth choosing over many calls against one
node -- a walker fetching many transactions, a client polling one --
where the reused connection, and on `https` the reused TLS handshake, is
what the default pays for on every call. It has a `close()` and works as
a context manager; nothing here calls either on a caller's behalf.

What does *not* come through unchanged is the exceptions. `http_request`
raises the package's `FetchError` and `HttpError`, which are not the
classes `btclib_wallet.exceptions` declares;
`btclib_wallet.fetch.fetcher.client_errors` is what translates them, and every
call into this module from inside this package is wrapped in it.

**`LineTransport` is not an alias of anything.** `bitcoin_core_rpc`'s own
transport is HTTP, and the Electrum protocol `btclib_wallet.electrum` speaks is
newline-delimited JSON-RPC over a raw TCP or TLS socket, which that package does
not carry. `ElectrumFetcher` (`btclib_wallet.fetch.electrum`) takes one request
line, already terminated by `btclib_wallet.electrum.encode_request`'s own
newline, and a timeout in seconds, and returns the answering line with its
delimiter consumed rather than included -- bytes on both sides, the shape
`btclib_wallet.electrum`'s own framing already produces and reads, so the
boundary needs no encoding step of its own, the same reason `HttpTransport` is
bytes in and bytes out. A transport that cannot answer raises
`bitcoin_core_rpc`'s own `FetchError` or a subclass of it,
the vocabulary `HttpTransport` already raises through this same package;
`btclib_wallet.fetch.fetcher.client_errors` is what refuses it as this
package's `FetchError`, its text not relayed, at every `ElectrumFetcher`
call the way it is at every other backend's.

**`LineTransport` carries no host, so each implementation is an object
that does.** One constructed with a host and a port is the callable
`ElectrumFetcher` takes, and that fetcher has no default for it: a
default transport would have to be a default server, which
`ElectrumFetcher`'s own docstring refuses.

The line implementations differ in how they hold the connection, as the
HTTP ones do. `TlsLineTransport` and `TcpLineTransport` open one
connection per call. `PersistentTlsLineTransport` keeps one TLS
connection across calls, which is worth choosing for many calls against
one server, a scan among them: the connect and the handshake are paid
once. It has a `close()` and works as a context manager.
"""

from __future__ import annotations

import select
import ssl
from collections.abc import Callable
from contextlib import suppress
from socket import create_connection, socket
from threading import Lock
from time import monotonic
from typing import Self

from bitcoin_core_rpc import (
    DEFAULT_MAX_BODY_SIZE,
    DEFAULT_TIMEOUT,
    MAX_ERROR_BODY_SIZE,
    FetchError,
    HttpTransport,
    SessionTransport,
    http_request,
    urlopen_transport,
)
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import is_integer

from btclib_wallet._refusal import _message_text, _quoted
from btclib_wallet.electrum import _reply_ids, _request_ids
from btclib_wallet.exceptions import FetchError as _PackageFetchError

LineTransport = Callable[[bytes, float], bytes]

__all__ = [
    "DEFAULT_MAX_BODY_SIZE",
    "DEFAULT_TIMEOUT",
    "MAX_ERROR_BODY_SIZE",
    "MAX_TIMEOUT",
    "HttpTransport",
    "LineTransport",
    "PersistentTlsLineTransport",
    "SessionTransport",
    "TcpLineTransport",
    "TlsLineTransport",
    "http_request",
    "urlopen_transport",
    "valid_timeout",
]


class _TransportError(_PackageFetchError, FetchError):
    """A failure of a transport this package ships, in both vocabularies.

    `bitcoin_core_rpc`'s `FetchError` is what `LineTransport` and
    `PeerTransport` raise, and this package's `FetchError` is what
    `client_errors` lets through as it is: the text is composed here,
    where the census of `tests/refusal_census_test.py` reads it, and not
    by another program.
    """


# how much one read asks for: a recv allocates what it is asked for, so a
# limit widened for one large answer is not paid on every small one
_READ_CHUNK = 64 * 1024

_MAX_PORT = 65535

# how many request ids one connection of `PersistentTlsLineTransport`
# carries before it is replaced, so that the ids it keeps stay bounded;
# each replacement costs a handshake
_MAX_IDS_PER_CONNECTION = 1000

# the longest timeout, in seconds, a socket waits for on every platform
# this package supports. CPython on Windows builds without poll(), and its
# socket module refuses a timeout past INT_MAX milliseconds with an
# OverflowError. PyPy's rsocket hands poll() the timeout as a C int of
# milliseconds, and on macOS, where it takes select() instead, a timeval
# that select() refuses past 10**8 seconds with EINVAL. The whole seconds
# within INT_MAX milliseconds are the bound, the same on every platform,
# so a timeout one of them takes is not refused by another; it is over
# 24 days
MAX_TIMEOUT = 2_147_483


def valid_timeout(timeout: float) -> float:
    """Return `timeout`, refusing what no socket will wait for.

    A bool is not a duration, `timeout=True` being one second.

    The bound is `MAX_TIMEOUT`, a timeout a socket takes on every
    platform: past it, a socket raises an `OverflowError`, which is no
    `OSError`, or an `OSError` its caller reads as the connection failing.
    Compared rather than asked of `isfinite`, which raises that same
    `OverflowError` for an int too large for a float: comparing an int
    with a float is exact, and a nan passes no comparison. The value is
    not rendered, an int past `str`'s digit limit raising a `ValueError`
    of its own.
    """
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise BTClibTypeError(f"non-numeric timeout: {type(timeout).__name__}")
    if not 0 < timeout <= MAX_TIMEOUT:
        err_msg = f"timeout is not a positive number of seconds up to {MAX_TIMEOUT}"
        raise BTClibValueError(err_msg)
    return timeout


def _time_left(deadline: float, timeout: float, where: str) -> float:
    """Return the seconds left before `deadline`, refusing none or fewer.

    What each socket operation is given as its own timeout, so that the
    operations together cannot outlast the one deadline the call took.
    Never more than `timeout`, the one the call took: where two reads of
    the clock are equal, `(t + timeout) - t` can round to a little above
    it.
    """
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise _TransportError(f"{where}: timeout expired before an answer arrived")
    return min(remaining, timeout)


def _read_line(
    connection: socket,
    buffer: bytearray,
    max_line_size: int,
    where: str,
    deadline: float,
    timeout: float,
) -> bytes:
    """Return the next line, its newline dropped, from `buffer` or the socket.

    `buffer` holds what earlier reads delivered past the last line, and
    keeps what this one delivers past its own. It never holds more than
    one octet past `max_line_size`: each read asks for at most what would
    take it there, which is what tells a line at the limit from one over
    it.
    """
    while True:
        end = buffer.find(b"\n")
        if end != -1:
            line = bytes(buffer[:end])
            del buffer[: end + 1]
            return line
        if len(buffer) > max_line_size:
            err_msg = f"{where}: line longer than the max_line_size of {_quoted(max_line_size)}"
            raise _TransportError(err_msg)
        connection.settimeout(_time_left(deadline, timeout, where))
        if chunk := connection.recv(min(_READ_CHUNK, max_line_size + 1 - len(buffer))):
            buffer.extend(chunk)
        else:
            raise _TransportError(f"{where}: connection closed before a whole line")


def _valid_endpoint(host: str, port: int, max_line_size: int) -> None:
    """Refuse a host, a port or a line limit no line transport can use.

    The checks a line transport makes where it is constructed.
    """
    if not isinstance(host, str):
        raise BTClibTypeError(f"non-string host: {_message_text(host)}")
    if not host:
        raise BTClibValueError("empty host")
    encoded = False
    # what `create_connection`, and the TLS handshake where there is one,
    # encode the host with, and a `UnicodeError` rather than an `OSError`
    # there. The refusal is raised after `suppress`, so that it chains no
    # codec error: one holds the host
    with suppress(UnicodeError):
        encoded = bool(host.encode("idna"))
    if not encoded:
        raise BTClibValueError(f"invalid host: {_quoted(host)}")
    if not is_integer(port):
        raise BTClibTypeError(f"non-integer port: {_message_text(port)}")
    if not 0 < port <= _MAX_PORT:
        raise BTClibValueError(f"invalid port: {_message_text(port)}")
    if not is_integer(max_line_size):
        raise BTClibTypeError(
            f"non-integer max_line_size: {_message_text(max_line_size)}"
        )
    if max_line_size < 1:
        raise BTClibValueError(f"invalid max_line_size: {_message_text(max_line_size)}")


def _tls_context(context: ssl.SSLContext | None) -> ssl.SSLContext:
    """Return `context`, or the default one where it is `None`.

    The default is `ssl.create_default_context()` with its
    `minimum_version` set to TLS 1.2.
    """
    if context is not None and not isinstance(context, ssl.SSLContext):
        raise BTClibTypeError(f"not an ssl.SSLContext: {_message_text(context)}")
    if context is None:
        context = ssl.create_default_context()
        # CPython's default context sets this floor itself and PyPy's
        # leaves it to OpenSSL, so the transport states it
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _valid_request(request: bytes) -> None:
    """Refuse a request that is not one line of bytes, ending at its newline."""
    if not isinstance(request, bytes):
        raise BTClibTypeError(f"non-bytes request: {_message_text(request)}")
    if request.count(b"\n") != 1 or not request.endswith(b"\n"):
        raise BTClibValueError(
            f"not one newline-terminated line: {_message_text(request)}"
        )


def _exchange(
    host: str,
    port: int,
    context: ssl.SSLContext | None,
    max_line_size: int,
    request: bytes,
    timeout: float,
) -> bytes:
    """Send one request line and return the line answering it.

    The call of the transports opening one connection per call: over TLS
    where `context` is given, over plain TCP where it is `None`. What
    follows the answer's newline -- a notification the server pushed after
    it -- is read or not and discarded either way, the connection closing
    behind this call.
    """
    _valid_request(request)
    valid_timeout(timeout)

    where = f"{_quoted(host)}:{_quoted(port)}"
    deadline = monotonic() + timeout
    failure = ""
    try:
        with create_connection((host, port), timeout=timeout) as sock:
            connection = sock
            if context is not None:
                sock.settimeout(_time_left(deadline, timeout, where))
                connection = context.wrap_socket(sock, server_hostname=host)
            with connection:
                connection.settimeout(_time_left(deadline, timeout, where))
                connection.sendall(request)
                return _read_line(
                    connection, bytearray(), max_line_size, where, deadline, timeout
                )
    except OSError as e:
        # `ssl.SSLError`, `socket.gaierror` and `TimeoutError` all derive
        # from it, which makes it every way the exchange did not happen.
        # Named by its class and raised after the block, so it is not
        # chained: a certificate that does not match names the host
        failure = type(e).__name__
    raise _TransportError(f"no answer from {where}: {failure}")


class TlsLineTransport:
    """A `LineTransport` over TLS to one server, verifying its certificate.

    Constructed with the host and port it connects to, so the instance is
    the server: `ElectrumFetcher(transport=TlsLineTransport(host, port))`
    is the whole of naming one. Construction opens nothing.

    **One connection per call.** Each call connects, performs the TLS
    handshake, sends the one request line, reads the one line answering
    it, and closes. Nothing is kept between calls, so concurrent calls
    share the `ssl.SSLContext` and nothing else.
    `PersistentTlsLineTransport` keeps the connection instead.

    **The network policy**, the one `urlopen_transport` keeps for HTTP:

    - a bounded read: the line is refused, not truncated, once it passes
      `max_line_size` octets without a newline. The default is
      `DEFAULT_MAX_BODY_SIZE`, sized for a whole block as hex, so
      `blockchain.transaction.get` fits for any transaction a block holds;
    - a timeout over the whole exchange -- connect, handshake, send and
      read -- rather than per socket operation: each operation is given
      what is left of one deadline, so a server dripping a line one octet
      at a time cannot hold the call open past it;
    - no proxy from the environment: `socket.create_connection` reads no
      proxy variable, so the connection goes to the host named here;
    - TLS verified by default: `context` defaults to
      `ssl.create_default_context()` with its `minimum_version` set to
      TLS 1.2, a context requiring a certificate chaining to the default CA
      certificates it loads and matching `host`.

    A server whose certificate those do not trust -- a server of
    one's own with a self-signed certificate, say -- is reached by passing
    a `context` that trusts that certificate,
    `ssl.create_default_context(cafile=...)`, which keeps both checks on;
    the TLS 1.2 floor on it is that caller's to set, a supplied context
    being used as given.
    No flag here turns verification off; what a context a caller supplies
    accepts is that caller's decision, as a transport of their own would
    be. Plain TCP is `TcpLineTransport`.

    Everything that goes wrong below the answer -- an unresolvable host, a
    refused connection, a handshake the certificate fails, a timeout, a
    connection closed before a whole line, a line over the limit -- is
    `bitcoin_core_rpc`'s `FetchError`, the contract `LineTransport` states,
    which `ElectrumFetcher` translates into this package's own.
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        context: ssl.SSLContext | None = None,
        max_line_size: int = DEFAULT_MAX_BODY_SIZE,
    ) -> None:
        _valid_endpoint(host, port, max_line_size)
        self._host = host
        self._port = port
        self._context = _tls_context(context)
        self._max_line_size = max_line_size

    @property
    def host(self) -> str:
        """Return the host this transport connects to."""
        return self._host

    @property
    def port(self) -> int:
        """Return the port this transport connects to."""
        return self._port

    @property
    def context(self) -> ssl.SSLContext:
        """Return the context the TLS handshake is verified against."""
        return self._context

    @property
    def max_line_size(self) -> int:
        """Return the octets an answering line may hold before it is refused."""
        return self._max_line_size

    def __call__(self, request: bytes, timeout: float) -> bytes:
        """Send one request line and return the line answering it.

        `request` is one line, its newline the last octet and the only
        one: a second would be a second request, whose answer this call
        would never read.
        """
        return _exchange(
            self._host,
            self._port,
            self._context,
            self._max_line_size,
            request,
            timeout,
        )


class TcpLineTransport:
    """A `LineTransport` over plain TCP to one server.

    **The connection is neither encrypted nor authenticated.** Anyone on
    the path between the caller and the server reads every request, and
    so every address and transaction asked about, and can answer in the
    server's place. It is for a server on the caller's own machine or
    network; any other is reached with `TlsLineTransport`.

    The rest is `TlsLineTransport`'s, with no TLS: construction, one
    connection per call, the network policy and what a failure raises.
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        max_line_size: int = DEFAULT_MAX_BODY_SIZE,
    ) -> None:
        _valid_endpoint(host, port, max_line_size)
        self._host = host
        self._port = port
        self._max_line_size = max_line_size

    @property
    def host(self) -> str:
        """Return the host this transport connects to."""
        return self._host

    @property
    def port(self) -> int:
        """Return the port this transport connects to."""
        return self._port

    @property
    def max_line_size(self) -> int:
        """Return the octets an answering line may hold before it is refused."""
        return self._max_line_size

    def __call__(self, request: bytes, timeout: float) -> bytes:
        """Send one request line and return the line answering it.

        `request` is what `TlsLineTransport.__call__` takes.
        """
        return _exchange(
            self._host, self._port, None, self._max_line_size, request, timeout
        )


def _readable(connection: socket) -> bool:
    """Return whether `connection` has something to read, without waiting.

    `select.poll` where the platform has it, and `select.select` only where
    it does not, which is Windows: elsewhere `select.select` refuses a
    descriptor at or above `FD_SETSIZE`, which a process holding that many
    files reaches.
    """
    if hasattr(select, "poll"):
        poller = select.poll()
        poller.register(connection, select.POLLIN)
        return bool(poller.poll(0))
    readable, _, _ = select.select([connection], [], [], 0)
    return bool(readable)


def _line_ids(line: bytes, where: str) -> frozenset[int] | None:
    """Return the request ids a line the server sent answers, or `None`.

    `None` is a notification. A line that is no JSON-RPC message is a
    `FetchError`, raised after `suppress` so that it chains no codec
    error.
    """
    ids: frozenset[int] | None = frozenset()
    refused = True
    with suppress(BTClibValueError):
        ids = _reply_ids(line)
        refused = False
    if refused:
        raise _TransportError(f"{where}: a line that is no JSON-RPC message")
    return ids


class PersistentTlsLineTransport:
    """A `LineTransport` over one TLS connection, kept across calls.

    Constructed as `TlsLineTransport` is, with the same checks, and
    keeping its network policy: the bounded line, no proxy from the
    environment, TLS verified by default, and one deadline over each call.
    The first call opens the connection and later calls reuse it, so many
    calls against one server pay the connect and the handshake once.

    **Each answer is matched to its request by the JSON-RPC id.** A
    request carries an integer id, as `encode_request` writes it, or a
    batch carries several. The line returned is the first whose ids are
    the request's, or the error with a `null` id that answers a request
    the server could not parse. A notification read before it -- a line
    the server pushes after `blockchain.headers.subscribe` -- is set
    aside. Any other line is a `FetchError`.

    **No answer is read from a stale connection.** A call that fails once
    it holds the connection closes it, a line over the limit and a
    deadline passed among the failures, so the late answer to an
    abandoned request is never read: the next call opens a new
    connection. A call that finds something to read on the kept
    connection before it sends -- the server closed it, or pushed a
    notification since the last answer -- opens a new one too, and so
    does a request with an id already sent on the connection, since what
    is checked before sending cannot see a copy of an earlier answer that
    arrives after it. Fetchers sharing a transport count their ids each
    from 1. A connection that has carried `_MAX_IDS_PER_CONNECTION` ids
    is replaced too, so that the ids kept of it stay bounded.

    **Calls are made one at a time.** A call holds the connection until it
    returns, and the wait for it counts against that call's deadline, as
    does each line it reads, those already buffered included.

    **The caller closes it**, with `close()` or a `with` block. A call
    after that opens a new connection.

    Everything that goes wrong below the answer is a `FetchError`, as for
    `TlsLineTransport`.
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        context: ssl.SSLContext | None = None,
        max_line_size: int = DEFAULT_MAX_BODY_SIZE,
    ) -> None:
        _valid_endpoint(host, port, max_line_size)
        self._host = host
        self._port = port
        self._context = _tls_context(context)
        self._max_line_size = max_line_size
        self._lock = Lock()
        self._connection: ssl.SSLSocket | None = None
        # what the connection delivered past the last line read
        self._buffer = bytearray()
        # the request ids sent on the connection
        self._sent: set[int] = set()

    @property
    def host(self) -> str:
        """Return the host this transport connects to."""
        return self._host

    @property
    def port(self) -> int:
        """Return the port this transport connects to."""
        return self._port

    @property
    def context(self) -> ssl.SSLContext:
        """Return the context the TLS handshake is verified against."""
        return self._context

    @property
    def max_line_size(self) -> int:
        """Return the octets an answering line may hold before it is refused."""
        return self._max_line_size

    @property
    def is_open(self) -> bool:
        """Return whether a connection is open."""
        return self._connection is not None

    def __enter__(self) -> Self:
        """Return this transport."""
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Close the connection."""
        self.close()

    def close(self) -> None:
        """Close the connection, if there is one, once no call holds it."""
        with self._lock:
            self._close()

    def _close(self) -> None:
        """Close the connection, if there is one, the lock held."""
        self._buffer.clear()
        self._sent.clear()
        if self._connection is not None:
            connection, self._connection = self._connection, None
            # refused after `suppress`, so that it chains nothing
            with suppress(OSError):
                connection.close()
                return
            raise _TransportError(
                f"closing {_quoted(self._host)}:{_quoted(self._port)}"
            )

    def _discard(self) -> None:
        """Close the connection after a failure, which stays the one raised."""
        with suppress(FetchError):
            self._close()

    def __call__(self, request: bytes, timeout: float) -> bytes:
        """Send one request line and return the line answering it.

        `request` is what `TlsLineTransport.__call__` takes, and carries a
        JSON-RPC id: a request with none is refused, since no line would
        answer it.
        """
        _valid_request(request)
        ids = _request_ids(request)
        valid_timeout(timeout)

        where = f"{_quoted(self._host)}:{_quoted(self._port)}"
        deadline = monotonic() + timeout
        if not self._lock.acquire(timeout=timeout):
            raise _TransportError(f"{where}: timeout expired before an answer arrived")
        failure = ""
        try:
            return self._answer(request, ids, where, deadline, timeout)
        except OSError as e:
            # `ssl.SSLError`, `socket.gaierror` and `TimeoutError` all derive
            # from it, which makes it every way the exchange did not happen.
            # Named by its class and raised after the block, as
            # `_exchange` does
            failure = type(e).__name__
        finally:
            self._lock.release()
        raise _TransportError(f"no answer from {where}: {failure}")

    def _answer(
        self,
        request: bytes,
        ids: frozenset[int],
        where: str,
        deadline: float,
        timeout: float,
    ) -> bytes:
        """Send `request` and return the line answering it, the lock held.

        Closes the connection on any failure.
        """
        try:
            connection = self._connected(ids, where, deadline, timeout)
            self._sent |= ids
            connection.settimeout(_time_left(deadline, timeout, where))
            connection.sendall(request)
            return self._read_answer(connection, ids, where, deadline, timeout)
        except BaseException:
            self._discard()
            raise

    def _read_answer(
        self,
        connection: ssl.SSLSocket,
        ids: frozenset[int],
        where: str,
        deadline: float,
        timeout: float,
    ) -> bytes:
        """Return the first line answering `ids`, notifications set aside."""
        while True:
            line = _read_line(
                connection, self._buffer, self._max_line_size, where, deadline, timeout
            )
            answered = _line_ids(line, where)
            # after the line is read, which a buffered one costs no
            # socket wait for, and before an answer is accepted
            _time_left(deadline, timeout, where)
            if answered is not None:
                if not answered or answered == ids:
                    return line
                raise _TransportError(f"{where}: a line answering another request")

    def _connected(
        self, ids: frozenset[int], where: str, deadline: float, timeout: float
    ) -> ssl.SSLSocket:
        """Return the kept connection, or a new one where that is unfit.

        Unfit where it has data, has carried one of `ids` before, or has
        carried as many ids as it may.
        """
        connection = self._connection
        if connection is not None and (
            self._buffer
            or connection.pending()
            or _readable(connection)
            or not self._sent.isdisjoint(ids)
            or len(self._sent) >= _MAX_IDS_PER_CONNECTION
        ):
            self._close()
            connection = None
        if connection is None:
            sock = create_connection(
                (self._host, self._port), timeout=_time_left(deadline, timeout, where)
            )
            try:
                sock.settimeout(_time_left(deadline, timeout, where))
                connection = self._context.wrap_socket(sock, server_hostname=self._host)
            except BaseException:
                # a close that fails would put its OSError in the place of
                # what the handshake raised, which the refusal names
                with suppress(OSError):
                    sock.close()
                raise
            self._connection = connection
        return connection
