# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `TlsLineTransport` and `TcpLineTransport`, over a fake connection.

No socket is opened: `create_connection` is replaced in the module under
test and returns a scripted socket, and the context handed to
`TlsLineTransport` is an `ssl.SSLContext` whose `wrap_socket` returns a
scripted connection rather than performing a handshake. What that leaves
untested is the handshake itself, which is `ssl`'s; what it tests is
everything this module decides around it -- the deadline, the bounded
read, and what a failure becomes -- over TLS and over plain TCP.
"""

from __future__ import annotations

import json
import socket
import ssl
import threading
from math import inf, nextafter
from typing import Any, Self

import pytest
from bitcoin_core_rpc import FetchError as RpcFetchError
from btclib.exceptions import BTClibTypeError, BTClibValueError
from typing_extensions import override

from btclib_wallet.exceptions import FetchError
from btclib_wallet.fetch import transport as transport_module
from btclib_wallet.fetch.electrum import ElectrumFetcher
from btclib_wallet.fetch.transport import (
    DEFAULT_MAX_BODY_SIZE,
    DEFAULT_TIMEOUT,
    MAX_TIMEOUT,
    TcpLineTransport,
    TlsLineTransport,
    valid_timeout,
)
from tests.fetch import TIP_HEADER_RAW, TIP_HEIGHT

HOST = "electrum.example"
PORT = 50002
REQUEST = b'{"id": 1, "method": "server.ping", "params": []}\n'

# the two line transports, for the tests of what they share
KINDS = ["tls", "tcp"]


class FakeConnection:
    """A socket answering `recv` from a script, recording everything else.

    Stands in for both the TCP socket `create_connection` returns and the
    TLS one `wrap_socket` returns: each chunk is consumed in order, an
    `Exception` among them is raised in its place, and an exhausted
    script reads as the peer closing the connection.
    """

    def __init__(self, *chunks: bytes | Exception) -> None:
        self.chunks = list(chunks)
        self.sent = b""
        self.timeouts: list[float] = []
        self.asked: list[int] = []
        self.closed = False

    def settimeout(self, timeout: float) -> None:
        """Record the timeout each operation was given."""
        self.timeouts.append(timeout)

    def sendall(self, data: bytes) -> None:
        """Record what was sent."""
        self.sent += data

    def recv(self, size: int) -> bytes:
        """Answer the next scripted chunk, or b'' once there are none."""
        self.asked.append(size)
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if isinstance(chunk, Exception):
            raise chunk
        assert len(chunk) <= size
        return chunk

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.closed = True


class FakeContext(ssl.SSLContext):
    """An `ssl.SSLContext` whose handshake is a scripted connection."""

    tls: FakeConnection
    failure: Exception | None
    server_hostname: str | None

    @override
    def wrap_socket(  # type: ignore[override]
        self, sock: Any, server_hostname: str | None = None, **_: Any
    ) -> FakeConnection:
        """Return the scripted TLS connection, or raise the scripted failure."""
        self.wrapped = sock
        self.server_hostname = server_hostname
        if self.failure is not None:
            raise self.failure
        return self.tls


def fake_context(
    *chunks: bytes | Exception, failure: Exception | None = None
) -> FakeContext:
    """Return a context whose TLS connection answers with these chunks."""
    context = FakeContext(ssl.PROTOCOL_TLS_CLIENT)
    context.tls = FakeConnection(*chunks)
    context.failure = failure
    return context


class Calls(list[tuple[tuple[str, int], float, FakeConnection]]):
    """The calls `create_connection` took, and what the next one returns.

    `socket` is the socket the next call returns, `failure` what it raises
    instead, once the call is recorded.
    """

    def __init__(self) -> None:
        super().__init__()
        self.socket = FakeConnection()
        self.failure: Exception | None = None


@pytest.fixture
def tcp(monkeypatch: pytest.MonkeyPatch) -> Calls:
    """Replace `create_connection`, recording each call and its socket.

    Every test that reaches `__call__` takes this, so a test that forgot
    it would be the one test here that opens a real socket.
    """
    calls = Calls()

    def create_connection(address: tuple[str, int], timeout: float) -> FakeConnection:
        sock = calls.socket
        calls.socket = FakeConnection()
        calls.append((address, timeout, sock))
        if calls.failure is not None:
            raise calls.failure
        return sock

    monkeypatch.setattr(transport_module, "create_connection", create_connection)
    return calls


def line_transport(
    kind: str,
    calls: Calls,
    *chunks: bytes | Exception,
    failure: Exception | None = None,
    max_line_size: int = DEFAULT_MAX_BODY_SIZE,
) -> tuple[TlsLineTransport | TcpLineTransport, FakeConnection]:
    """Return a transport of `kind` and the connection answering its call.

    Over TLS that connection is the one the handshake returns, and
    `failure` is what the handshake raises; over TCP it is the socket
    `create_connection` returns, and `failure` is what the connect raises.
    """
    if kind == "tls":
        context = fake_context(*chunks, failure=failure)
        transport = TlsLineTransport(
            HOST, PORT, context=context, max_line_size=max_line_size
        )
        return transport, context.tls
    calls.socket = FakeConnection(*chunks)
    calls.failure = failure
    return TcpLineTransport(HOST, PORT, max_line_size=max_line_size), calls.socket


def timeouts_set(sock: FakeConnection, connection: FakeConnection) -> list[float]:
    """Return every timeout set, on the socket and on the TLS one over it."""
    if connection is sock:
        return sock.timeouts
    return sock.timeouts + connection.timeouts


def test_the_default_context_verifies_the_certificate_and_the_host() -> None:
    """The strict posture: a chain to the trust store, and the host checked."""
    context = TlsLineTransport(HOST, PORT).context
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2


def test_the_transport_sets_the_default_context_floor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TLS 1.2 is the floor where the interpreter's default sets none.

    PyPy's `create_default_context()` leaves `minimum_version` at
    `MINIMUM_SUPPORTED`, which is what the replacement answers with here.
    """

    def create_default_context() -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        return context

    monkeypatch.setattr(ssl, "create_default_context", create_default_context)
    context = TlsLineTransport(HOST, PORT).context
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2


@pytest.mark.parametrize("cls", [TlsLineTransport, TcpLineTransport])
def test_construction_keeps_what_it_was_given(
    cls: type[TlsLineTransport | TcpLineTransport],
) -> None:
    """The host, the port and the line limit, the limit defaulted."""
    transport = cls(HOST, PORT, max_line_size=10)
    assert transport.host == HOST
    assert transport.port == PORT
    assert transport.max_line_size == 10
    assert cls(HOST, PORT).max_line_size == DEFAULT_MAX_BODY_SIZE


def test_the_context_passed_is_the_one_used() -> None:
    """Not a copy or a default."""
    context = fake_context()
    assert TlsLineTransport(HOST, PORT, context=context).context is context


@pytest.mark.parametrize("kind", KINDS)
def test_one_line_is_sent_and_one_line_read(kind: str, tcp: Calls) -> None:
    """The answer without its newline; what follows it is not returned."""
    answer = b'{"id": 1, "result": null}'
    notification = b'{"method": "blockchain.headers.subscribe"}\n'
    transport, connection = line_transport(kind, tcp, answer + b"\n" + notification)
    line = transport(REQUEST, 7.0)
    assert line == answer
    [(address, timeout, sock)] = tcp
    assert address == (HOST, PORT)
    assert timeout == 7.0
    assert connection.sent == REQUEST
    assert connection.closed
    assert sock.closed


def test_the_handshake_is_over_the_socket_and_names_the_host(tcp: Calls) -> None:
    """TLS wraps the connected socket, and nothing goes out in the clear."""
    context = fake_context(b"{}\n")
    TlsLineTransport(HOST, PORT, context=context)(REQUEST, 1.0)
    [(_, _, sock)] = tcp
    assert context.wrapped is sock
    assert context.server_hostname == HOST
    assert not sock.sent


@pytest.mark.parametrize(
    "kind, expected",
    [("tls", [2.5, 2.0, 1.5, 1.0, 0.5]), ("tcp", [2.5, 2.0, 1.5, 1.0])],
)
def test_every_operation_gets_what_is_left_of_one_deadline(
    kind: str, expected: list[float], tcp: Calls, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No operation is given more than what is left of the one deadline.

    Over TLS the handshake is one more operation than over TCP.
    """
    clock = iter([100.0, 100.5, 101.0, 101.5, 102.0, 102.5])
    monkeypatch.setattr(transport_module, "monotonic", lambda: next(clock))
    transport, connection = line_transport(kind, tcp, b'{"id"', b": 1}", b"\n")
    transport(REQUEST, 3.0)
    [(_, _, sock)] = tcp
    assert timeouts_set(sock, connection) == expected


@pytest.mark.parametrize("kind", KINDS)
def test_no_operation_is_given_more_than_the_timeout(
    kind: str, tcp: Calls, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two equal reads of the clock leave no more time than the timeout.

    At this reading `(t + 3) - t` is a little over 3 in floating point.
    """
    now = 4094.001074717207
    assert (now + 3.0) - now > 3.0
    monkeypatch.setattr(transport_module, "monotonic", lambda: now)
    transport, connection = line_transport(kind, tcp, b'{"id": 1}\n')
    transport(REQUEST, 3.0)
    [(_, _, sock)] = tcp
    timeouts = timeouts_set(sock, connection)
    assert timeouts
    assert all(0 < timeout <= 3.0 for timeout in timeouts)


@pytest.mark.parametrize("kind", KINDS)
def test_a_line_arriving_in_pieces_is_joined(kind: str, tcp: Calls) -> None:
    """A line is what ends at the newline, not what one read returns."""
    transport, _ = line_transport(kind, tcp, b'{"id": 1, ', b'"result": ', b"true}\n")
    assert transport(REQUEST, 1.0) == b'{"id": 1, "result": true}'


@pytest.mark.parametrize("kind", KINDS)
def test_the_deadline_is_over_the_whole_exchange(
    kind: str, tcp: Calls, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A server dripping a line cannot hold the call past its timeout."""
    clock = iter([100.0, 100.5, 101.0, 101.5, 102.5])
    monkeypatch.setattr(transport_module, "monotonic", lambda: next(clock))
    transport, _ = line_transport(kind, tcp, b"{", b"}")
    with pytest.raises(RpcFetchError, match="timeout expired"):
        transport(REQUEST, 2.0)


@pytest.mark.parametrize("kind", KINDS)
def test_a_line_at_the_limit_is_an_answer(kind: str, tcp: Calls) -> None:
    """`max_line_size` counts the line, the newline not included."""
    transport, _ = line_transport(kind, tcp, b"12345", b"\n", max_line_size=5)
    assert transport(REQUEST, 1.0) == b"12345"


@pytest.mark.parametrize("kind", KINDS)
def test_a_line_over_the_limit_is_refused(kind: str, tcp: Calls) -> None:
    """Refused rather than truncated, and never read far past the limit."""
    transport, connection = line_transport(
        kind, tcp, b"123", b"456", b"\n", max_line_size=5
    )
    with pytest.raises(RpcFetchError, match="max_line_size of 5"):
        transport(REQUEST, 1.0)
    assert connection.asked == [6, 3]


@pytest.mark.parametrize("kind", KINDS)
def test_a_read_asks_for_no_more_than_a_chunk(kind: str, tcp: Calls) -> None:
    """A large limit is not what one read allocates."""
    transport, connection = line_transport(kind, tcp, b"{}\n")
    transport(REQUEST, 1.0)
    assert connection.asked == [transport_module._READ_CHUNK]


@pytest.mark.parametrize("kind", KINDS)
def test_a_connection_closed_before_the_newline_is_a_fetch_error(
    kind: str, tcp: Calls
) -> None:
    """A partial line is not an answer, however much of one arrived."""
    transport, _ = line_transport(kind, tcp, b'{"id": 1, "result"')
    with pytest.raises(RpcFetchError, match="closed before a whole line"):
        transport(REQUEST, 1.0)


@pytest.mark.parametrize(
    "kind, failure",
    [
        ("tls", ConnectionRefusedError("connection refused")),
        ("tls", TimeoutError("timed out")),
        ("tls", ssl.SSLCertVerificationError("certificate verify failed")),
        ("tcp", ConnectionRefusedError("connection refused")),
        ("tcp", TimeoutError("timed out")),
        ("tcp", socket.gaierror("name or service not known")),
    ],
)
def test_what_goes_wrong_below_the_answer_is_a_fetch_error(
    kind: str, failure: Exception, tcp: Calls
) -> None:
    """The contract `LineTransport` states, the cause kept."""
    transport, _ = line_transport(kind, tcp, failure=failure)
    with pytest.raises(RpcFetchError, match=f"no answer from {HOST}:{PORT}") as e:
        transport(REQUEST, 1.0)
    assert e.value.__cause__ is failure


@pytest.mark.parametrize("kind", KINDS)
def test_a_failed_read_is_a_fetch_error(kind: str, tcp: Calls) -> None:
    """A reset after the connection is the same answer as a refused connect."""
    reset = ConnectionResetError("reset")
    transport, connection = line_transport(kind, tcp, b"{", reset)
    with pytest.raises(RpcFetchError, match="reset") as e:
        transport(REQUEST, 1.0)
    assert e.value.__cause__ is reset
    assert connection.closed


@pytest.mark.parametrize("kind", KINDS)
def test_electrum_fetcher_translates_what_the_transport_raises(
    kind: str, tcp: Calls
) -> None:
    """A failed transport is this package's `FetchError` to the caller."""
    transport, _ = line_transport(kind, tcp, b"")
    endpoint = ElectrumFetcher(transport=transport, verify_network=False)
    with pytest.raises(FetchError, match="closed before a whole line"):
        endpoint.get_block_count()


@pytest.mark.parametrize("kind", KINDS)
def test_electrum_fetcher_answers_over_it(kind: str, tcp: Calls) -> None:
    """The fetcher and this transport agree on the line at the boundary."""
    reply = {"id": 1, "result": {"height": TIP_HEIGHT, "hex": TIP_HEADER_RAW}}
    transport, connection = line_transport(
        kind, tcp, json.dumps(reply).encode() + b"\n"
    )
    endpoint = ElectrumFetcher(transport=transport, verify_network=False)
    assert endpoint.get_block_count() == TIP_HEIGHT
    assert json.loads(connection.sent)["method"] == "blockchain.headers.subscribe"
    [(_, timeout, _)] = tcp
    assert timeout == DEFAULT_TIMEOUT


@pytest.mark.parametrize("cls", [TlsLineTransport, TcpLineTransport])
@pytest.mark.parametrize(
    "args, kwargs, error, match",
    [
        ((b"host", PORT), {}, BTClibTypeError, "non-string host"),
        (("", PORT), {}, BTClibValueError, "empty host"),
        (("a..b", PORT), {}, BTClibValueError, "invalid host"),
        ((HOST, True), {}, BTClibTypeError, "non-integer port"),
        ((HOST, "50002"), {}, BTClibTypeError, "non-integer port"),
        ((HOST, 0), {}, BTClibValueError, "invalid port"),
        ((HOST, 65536), {}, BTClibValueError, "invalid port"),
        ((HOST, PORT), {"max_line_size": 1.5}, BTClibTypeError, "max_line_size"),
        ((HOST, PORT), {"max_line_size": 0}, BTClibValueError, "max_line_size"),
    ],
)
def test_construction_validates_its_arguments(
    cls: type[TlsLineTransport | TcpLineTransport],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    error: type[Exception],
    match: str,
) -> None:
    """A malformed argument is refused where it is given, not at the call."""
    with pytest.raises(error, match=match):
        cls(*args, **kwargs)


def test_a_context_that_is_not_one_is_refused() -> None:
    """Only an `ssl.SSLContext` is a context."""
    with pytest.raises(BTClibTypeError, match="SSLContext"):
        TlsLineTransport(HOST, PORT, context=object())  # type: ignore[arg-type]


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize(
    "request_, timeout, error, match",
    [
        ("{}\n", 1.0, BTClibTypeError, "non-bytes request"),
        (b"", 1.0, BTClibValueError, "one newline-terminated line"),
        (b"{}", 1.0, BTClibValueError, "one newline-terminated line"),
        (b"{}\n{}\n", 1.0, BTClibValueError, "one newline-terminated line"),
        (b"{}\n{}", 1.0, BTClibValueError, "one newline-terminated line"),
        (REQUEST, True, BTClibTypeError, "non-numeric timeout"),
        (REQUEST, "1", BTClibTypeError, "non-numeric timeout"),
        (REQUEST, 0, BTClibValueError, "not a positive number of seconds"),
        (REQUEST, float("nan"), BTClibValueError, "not a positive number of seconds"),
        (REQUEST, float("inf"), BTClibValueError, "not a positive number of seconds"),
        # past what a socket waits for, and a float's next step past it
        (
            REQUEST,
            MAX_TIMEOUT + 1,
            BTClibValueError,
            "not a positive number of seconds",
        ),
        (
            REQUEST,
            nextafter(MAX_TIMEOUT, inf),
            BTClibValueError,
            "not a positive number of seconds",
        ),
        # ints no float holds, the second past `str`'s digit limit too: ids
        # of their own, pytest rendering neither otherwise
        pytest.param(
            REQUEST,
            10**400,
            BTClibValueError,
            "not a positive number of seconds",
            id="timeout-10**400",
        ),
        pytest.param(
            REQUEST,
            10**5000,
            BTClibValueError,
            "not a positive number of seconds",
            id="timeout-10**5000",
        ),
    ],
)
def test_a_call_validates_its_arguments_before_connecting(
    kind: str,
    tcp: Calls,
    request_: Any,
    timeout: Any,
    error: type[Exception],
    match: str,
) -> None:
    """Refused before anything is opened, so no connection is attempted."""
    transport, _ = line_transport(kind, tcp, b"{}\n")
    with pytest.raises(error, match=match):
        transport(request_, timeout)
    assert not tcp


def test_the_bound_is_a_timeout_a_socket_takes() -> None:
    """`MAX_TIMEOUT` passes, and a socket waits with it: no refusal is late.

    The step past it is refused above, as a `BTClibValueError`, where a
    socket would raise an `OverflowError` or an `OSError` of its own. A
    socket that takes the timeout can still refuse it when it waits, as
    PyPy's select() does on macOS, so a read is made with it too.
    `threading`'s own bound is no lower on any platform.
    """
    assert valid_timeout(MAX_TIMEOUT) == MAX_TIMEOUT
    assert MAX_TIMEOUT <= threading.TIMEOUT_MAX
    reader, writer = socket.socketpair()
    with reader, writer:
        reader.settimeout(MAX_TIMEOUT)
        writer.sendall(b"x")
        assert reader.recv(1) == b"x"
