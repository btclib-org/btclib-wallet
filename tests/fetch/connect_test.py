# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the connect every transport of `btclib_wallet.fetch` opens.

A host can resolve to several addresses, which are tried in turn, and
the deadline of the call bounds them all. `socket.getaddrinfo` is
replaced by a resolver answering a scripted list of addresses, and
`socket.socket` by a socket whose connect fails or waits out its timeout
on a clock the test moves, so no socket is opened and no time passes.
"""

from __future__ import annotations

import contextlib
import gc
import platform
import socket
import weakref
from collections.abc import Callable
from typing import Any

import pytest
from bitcoin_core_rpc import FetchError
from btclib.p2p import Ping

from btclib_wallet.fetch import peer_transport
from btclib_wallet.fetch import transport as transport_module
from btclib_wallet.fetch.peer_transport import TcpPeerTransport, V2PeerTransport
from btclib_wallet.fetch.transport import (
    PersistentTlsLineTransport,
    TcpLineTransport,
    TlsLineTransport,
    _open_connection,
)

HOST = "multi.example"
PORT = 50002
TIMEOUT = 5.0
REQUEST = b'{"id": 1, "method": "server.ping", "params": []}\n'
MESSAGE = Ping(7).to_message(b"\xfa\xbf\xb5\xda")

# what a connect to an address does: wait out its timeout, fail after
# that many seconds, connect, or raise that exception at once; "ipv6" is
# an address of a family no socket can be made for
Outcome = str | float | BaseException


class RefusedError(ConnectionRefusedError):
    """A refused connect, which a weak reference can watch."""


class Network:
    """The clock, and the addresses the host resolves to and what each does."""

    def __init__(self, *outcomes: Outcome, lookup: float = 0.0) -> None:
        self.now = 1000.0
        self.lookup = lookup
        self.outcomes = {f"192.0.2.{i}": o for i, o in enumerate(outcomes, 1)}
        self.attempts: list[FakeSocket] = []
        self.refusals: list[weakref.ref[RefusedError]] = []

    def clock(self) -> float:
        """Return the time on the clock."""
        return self.now

    def getaddrinfo(
        self, host: str, port: int, family: int, kind: int
    ) -> list[tuple[Any, ...]]:
        """Return the scripted addresses, the lookup taking `lookup` seconds."""
        assert (host, port, family, kind) == (HOST, PORT, 0, socket.SOCK_STREAM)
        self.now += self.lookup
        return [
            (
                socket.AF_INET6 if outcome == "ipv6" else socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (ip, port),
            )
            for ip, outcome in self.outcomes.items()
        ]

    def refusal(self, ip: str) -> RefusedError:
        """Return a refusal of `ip`, watched once raised.

        Made here, so that no frame the raise passes through holds it.
        """
        refused = RefusedError(f"{ip} refused")
        self.refusals.append(weakref.ref(refused))
        return refused

    def socket(self, *args: Any) -> FakeSocket:
        """Return a socket recording its attempt, refusing an IPv6 one."""
        if args[0] == socket.AF_INET6:
            raise OSError("Address family not supported by protocol")
        sock = FakeSocket(self, args)
        self.attempts.append(sock)
        return sock


class FakeSocket:
    """A socket whose connect does what the network scripts for its address."""

    def __init__(self, network: Network, args: tuple[Any, ...]) -> None:
        self.network = network
        self.args = args
        self.timeout: float | None = None
        self.closed = False

    def settimeout(self, timeout: float) -> None:
        """Record the timeout of the connect."""
        self.timeout = timeout

    def connect(self, sockaddr: tuple[str, int]) -> None:
        """Wait, fail or connect, as scripted for `sockaddr`."""
        network = self.network
        outcome = network.outcomes[sockaddr[0]]
        if isinstance(outcome, BaseException):
            raise outcome
        if outcome == "timeout":
            assert self.timeout is not None
            network.now += self.timeout
            raise TimeoutError("timed out")
        if isinstance(outcome, float):
            network.now += outcome
            raise network.refusal(sockaddr[0])

    def close(self) -> None:
        """Record the close."""
        self.closed = True


@pytest.fixture
def network(monkeypatch: pytest.MonkeyPatch) -> Callable[..., Network]:
    """Return a maker of the network the connect runs on.

    The resolver and the socket are replaced in the `socket` module, which
    `_open_connection` reads them from.
    """

    def make(*outcomes: Outcome, lookup: float = 0.0) -> Network:
        net = Network(*outcomes, lookup=lookup)
        monkeypatch.setattr(socket, "getaddrinfo", net.getaddrinfo)
        monkeypatch.setattr(socket, "socket", net.socket)
        monkeypatch.setattr(transport_module, "monotonic", net.clock)
        monkeypatch.setattr(peer_transport, "monotonic", net.clock)
        return net

    return make


def tls_line() -> None:
    """Make one call of a `TlsLineTransport`."""
    TlsLineTransport(HOST, PORT)(REQUEST, TIMEOUT)


def tcp_line() -> None:
    """Make one call of a `TcpLineTransport`."""
    TcpLineTransport(HOST, PORT)(REQUEST, TIMEOUT)


def persistent_line() -> None:
    """Make one call of a `PersistentTlsLineTransport`."""
    PersistentTlsLineTransport(HOST, PORT)(REQUEST, TIMEOUT)


def tcp_peer() -> None:
    """Send one message over a `TcpPeerTransport`."""
    TcpPeerTransport(HOST, PORT).send(MESSAGE, TIMEOUT)


def v2_peer() -> None:
    """Send one message over a `V2PeerTransport`, where it can be built."""
    pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    V2PeerTransport(HOST, PORT).send(MESSAGE, TIMEOUT)


CALLS = [tls_line, tcp_line, persistent_line, tcp_peer, v2_peer]


@pytest.mark.parametrize(
    "outcomes, timeouts",
    [
        (["timeout", "timeout", "timeout"], [TIMEOUT]),
        ([1.0, "timeout", "timeout"], [TIMEOUT, TIMEOUT - 1]),
    ],
    ids=["every-address-waits", "a-refusal-then-a-wait"],
)
@pytest.mark.parametrize("call", CALLS, ids=lambda call: call.__name__)
def test_the_deadline_bounds_every_address_tried(
    network: Callable[..., Network],
    call: Callable[[], None],
    outcomes: list[Outcome],
    timeouts: list[float],
) -> None:
    """Each attempt gets what is left of the deadline, none once it passed."""
    net = network(*outcomes)
    start = net.now
    with pytest.raises(FetchError, match="timeout expired"):
        call()
    assert net.now - start <= TIMEOUT
    assert [sock.timeout for sock in net.attempts] == timeouts
    assert all(sock.closed for sock in net.attempts)


def test_a_lookup_that_outlasts_the_deadline_starts_no_attempt(
    network: Callable[..., Network],
) -> None:
    """The deadline is checked once the resolver returns."""
    net = network("timeout", lookup=TIMEOUT)
    with pytest.raises(FetchError, match="timeout expired"):
        _open_connection((HOST, PORT), net.now + TIMEOUT, TIMEOUT, "here")
    assert net.attempts == []


def test_the_first_address_that_connects_is_the_socket(
    network: Callable[..., Network],
) -> None:
    """An address that fails is closed and the next one is tried."""
    net = network(1.0, "connect", "timeout")
    sock: object = _open_connection((HOST, PORT), net.now + TIMEOUT, TIMEOUT, "here")
    first, second = net.attempts
    assert sock is second
    assert (first.closed, second.closed) == (True, False)
    assert (first.timeout, second.timeout) == (TIMEOUT, TIMEOUT - 1)
    assert first.args == (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)


def test_a_family_no_socket_is_made_for_is_one_more_address_that_fails(
    network: Callable[..., Network],
) -> None:
    """An IPv6 address on a machine without IPv6 leaves the next one tried."""
    net = network("ipv6", "connect")
    sock: object = _open_connection((HOST, PORT), net.now + TIMEOUT, TIMEOUT, "here")
    (connected,) = net.attempts
    assert sock is connected


def test_where_no_socket_can_be_made_the_last_error_is_raised(
    network: Callable[..., Network],
) -> None:
    """The error of making the socket, where no connect was begun."""
    net = network("ipv6")
    with pytest.raises(OSError, match="Address family not supported"):
        _open_connection((HOST, PORT), net.now + TIMEOUT, TIMEOUT, "here")
    assert net.attempts == []


def test_where_no_address_connects_the_last_error_is_raised(
    network: Callable[..., Network],
) -> None:
    """As `socket.create_connection` raises it."""
    net = network(1.0, 1.0)
    with pytest.raises(ConnectionRefusedError, match=r"192\.0\.2\.2 refused"):
        _open_connection((HOST, PORT), net.now + TIMEOUT, TIMEOUT, "here")


def test_a_host_resolving_to_no_address_is_an_os_error(
    network: Callable[..., Network],
) -> None:
    """As `socket.create_connection` raises it."""
    net = network()
    with pytest.raises(OSError, match="getaddrinfo returns an empty list"):
        _open_connection((HOST, PORT), net.now + TIMEOUT, TIMEOUT, "here")


def test_an_interrupted_connect_leaves_no_socket_open(
    network: Callable[..., Network],
) -> None:
    """A `KeyboardInterrupt` closes the socket it interrupts, and goes on."""
    net = network(KeyboardInterrupt(), "connect")
    with pytest.raises(KeyboardInterrupt):
        _open_connection((HOST, PORT), net.now + TIMEOUT, TIMEOUT, "here")
    (interrupted,) = net.attempts
    assert interrupted.closed


@pytest.mark.skipif(
    platform.python_implementation() == "PyPy",
    reason="PyPy frees an object only when its collector runs",
)
@pytest.mark.parametrize(
    "outcomes",
    [(1.0, "connect"), (1.0, 1.0), (4.0, 1.0, "timeout")],
    ids=["connected", "every-address-refused", "deadline-passed"],
)
def test_no_error_is_kept_once_the_call_ends(
    network: Callable[..., Network], outcomes: tuple[Outcome, ...]
) -> None:
    """Each refusal is freed when the call ends, without the collector."""
    net = network(*outcomes)
    gc.disable()
    try:
        with contextlib.suppress(OSError, FetchError):
            _open_connection((HOST, PORT), net.now + TIMEOUT, TIMEOUT, "here")
        assert net.refusals
        assert [ref() for ref in net.refusals] == [None] * len(net.refusals)
    finally:
        gc.enable()
