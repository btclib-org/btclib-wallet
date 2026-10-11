# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `TcpPeerTransport`, over a socket that is a script.

`FakeSocket` stands where `socket.create_connection` returns: it hands
out the octets it was given, in the pieces it was given them in, and
records what is written. No socket is opened.
`tests/integration/compact_filters_test.py` is where a real one is.
"""

from __future__ import annotations

import itertools
from collections.abc import Callable
from typing import Any

import pytest
from bitcoin_core_rpc import FetchError
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.p2p import Ping
from btclib.p2p.limits import MAX_PROTOCOL_MESSAGE_LENGTH

from btclib_wallet.fetch import peer_transport
from btclib_wallet.fetch import transport as fetch_transport
from btclib_wallet.fetch.peer_transport import TcpPeerTransport

MAGIC = b"\xfa\xbf\xb5\xda"
MESSAGE = Ping(7).to_message(MAGIC)
WIRE = MESSAGE.serialize()


class FakeSocket:
    """A connection reading from a script and writing to a list."""

    def __init__(
        self,
        chunks: list[bytes],
        *,
        error: Exception | None = None,
        send_error: Exception | None = None,
    ) -> None:
        self.chunks = chunks
        self.error = error
        self.send_error = send_error
        self.written = bytearray()
        self.timeouts: list[float] = []
        self.closed = 0

    def settimeout(self, timeout: float) -> None:
        """Record the timeout."""
        self.timeouts.append(timeout)

    def recv(self, size: int) -> bytes:
        """Return at most `size` octets of the next chunk."""
        if self.chunks:
            chunk = self.chunks.pop(0)
            if len(chunk) > size:
                self.chunks.insert(0, chunk[size:])
            return chunk[:size]
        if self.error is not None:
            raise self.error
        return b""

    def sendall(self, data: bytes) -> None:
        """Record the octets, or fail."""
        if self.send_error is not None:
            raise self.send_error
        self.written += data

    def close(self) -> None:
        """Count the closes."""
        self.closed += 1


def set_clock(monkeypatch: pytest.MonkeyPatch, clock: Callable[[], float]) -> None:
    """Replace the clock of the deadline and of the time left before it."""
    monkeypatch.setattr(peer_transport, "monotonic", clock)
    monkeypatch.setattr(fetch_transport, "monotonic", clock)


def connect_to(
    monkeypatch: pytest.MonkeyPatch, fake: FakeSocket | Exception
) -> list[tuple[Any, float]]:
    """Make `create_connection` return `fake`, or raise it; log the calls."""
    calls: list[tuple[Any, float]] = []

    def create_connection(address: Any, timeout: float) -> FakeSocket:
        calls.append((address, timeout))
        if isinstance(fake, Exception):
            raise fake
        return fake

    monkeypatch.setattr(peer_transport, "create_connection", create_connection)
    return calls


def peer() -> TcpPeerTransport:
    """Return a transport to a peer that does not exist."""
    return TcpPeerTransport("peer.example", 18444)


# construction


@pytest.mark.parametrize(
    "host, port, error, why",
    [
        (b"peer", 18444, BTClibTypeError, "non-string host"),
        ("", 18444, BTClibValueError, "empty host"),
        ("a..b", 18444, BTClibValueError, "invalid host"),
        ("a" * 64 + ".org", 18444, BTClibValueError, "invalid host"),
        ("peer", "18444", BTClibTypeError, "non-integer port"),
        ("peer", True, BTClibTypeError, "non-integer port"),
        ("peer", 0, BTClibValueError, "invalid port: 0"),
        ("peer", 65536, BTClibValueError, "invalid port: 65536"),
    ],
)
def test_a_host_and_a_port_are_checked(
    host: Any, port: Any, error: type[Exception], why: str
) -> None:
    """A host that is no name and a port that is no port are refused."""
    with pytest.raises(error, match=why):
        TcpPeerTransport(host, port)


def test_construction_opens_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """The transport names its peer and is not connected."""
    calls = connect_to(monkeypatch, FakeSocket([]))
    transport = peer()
    assert (transport.host, transport.port) == ("peer.example", 18444)
    assert not transport.is_open
    assert calls == []


# sending


def test_the_first_send_connects_and_a_later_one_does_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Messages are written whole, to the one connection."""
    fake = FakeSocket([])
    calls = connect_to(monkeypatch, fake)
    transport = peer()
    transport.send(MESSAGE, 5)
    transport.send(MESSAGE, 5)
    assert fake.written == WIRE * 2
    assert [address for address, _ in calls] == [("peer.example", 18444)]
    assert transport.is_open


def test_a_message_and_a_timeout_are_checked_before_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A wrong argument is refused without a connection."""
    calls = connect_to(monkeypatch, FakeSocket([]))
    with pytest.raises(BTClibTypeError, match="non-Message"):
        peer().send(WIRE, 5)  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError, match="timeout"):
        peer().send(MESSAGE, 0)
    assert calls == []


@pytest.mark.parametrize(
    "fake",
    [OSError("unreachable"), TimeoutError("timed out")],
    ids=["refused", "timeout"],
)
def test_a_connection_that_cannot_be_made_is_a_fetch_error(
    monkeypatch: pytest.MonkeyPatch, fake: Exception
) -> None:
    """The reason is the OS's, and nothing is left open."""
    connect_to(monkeypatch, fake)
    transport = peer()
    with pytest.raises(FetchError, match="no connection to peer.example:18444"):
        transport.send(MESSAGE, 5)
    assert not transport.is_open


def test_a_write_that_fails_closes_the_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A broken pipe is a fetch error, and the next send connects again."""
    broken = FakeSocket([], send_error=BrokenPipeError("gone"))
    working = FakeSocket([])
    sockets = iter([broken, working])
    monkeypatch.setattr(
        peer_transport, "create_connection", lambda *_a, **_k: next(sockets)
    )
    transport = peer()
    with pytest.raises(FetchError, match="gone"):
        transport.send(MESSAGE, 5)
    assert broken.closed == 1
    transport.send(MESSAGE, 5)
    assert working.written == WIRE


def test_a_send_that_outlasts_its_timeout_is_a_fetch_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The connect and the write share one deadline."""
    fake = FakeSocket([])
    connect_to(monkeypatch, fake)
    ticks = itertools.count()
    set_clock(monkeypatch, lambda: next(ticks) * 10.0)
    transport = peer()
    with pytest.raises(FetchError, match="timeout expired"):
        transport.send(MESSAGE, 5)
    assert fake.closed == 1
    assert not transport.is_open


# receiving


def test_a_message_is_read_whole_however_it_arrives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A message in pieces is read as the one it is, and the next follows."""
    pieces = [WIRE[i : i + 5] for i in range(0, len(WIRE), 5)]
    fake = FakeSocket([*pieces, WIRE])
    connect_to(monkeypatch, fake)
    transport = peer()
    transport.send(MESSAGE, 5)
    assert transport.receive(5) == MESSAGE
    assert transport.receive(5) == MESSAGE
    assert all(0 < timeout <= 5 for timeout in fake.timeouts)


def test_a_receive_without_a_connection_is_a_fetch_error() -> None:
    """Nothing is read before something is sent."""
    with pytest.raises(FetchError, match="not connected"):
        peer().receive(5)
    with pytest.raises(BTClibValueError, match="timeout"):
        peer().receive(-1)


def test_a_peer_that_goes_quiet_is_a_fetch_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The socket's timeout is the OS's, and the connection is closed."""
    fake = FakeSocket([WIRE[:10]], error=TimeoutError("timed out"))
    connect_to(monkeypatch, fake)
    transport = peer()
    transport.send(MESSAGE, 5)
    with pytest.raises(FetchError, match="no message from peer.example:18444"):
        transport.receive(5)
    assert not transport.is_open
    assert fake.closed == 1


def test_a_peer_that_hangs_up_is_a_fetch_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An end of stream inside a message is a connection closed."""
    connect_to(monkeypatch, FakeSocket([WIRE[:30]]))
    transport = peer()
    transport.send(MESSAGE, 5)
    with pytest.raises(FetchError, match="closed before a whole message"):
        transport.receive(5)
    assert not transport.is_open


def test_a_peer_that_trickles_is_a_fetch_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One deadline covers the whole message, not each read."""
    connect_to(monkeypatch, FakeSocket([WIRE[:10], WIRE[10:]]))
    transport = peer()
    transport.send(MESSAGE, 5)
    ticks = itertools.chain([0.0, 1.0], itertools.repeat(100.0))
    set_clock(monkeypatch, lambda: next(ticks))
    with pytest.raises(FetchError, match="timeout expired"):
        transport.receive(5)
    assert not transport.is_open


def test_a_message_announcing_too_much_is_refused_before_it_is_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The length field is the peer's to choose, and is bounded first."""
    length = (MAX_PROTOCOL_MESSAGE_LENGTH + 1).to_bytes(4, "little")
    header = MAGIC + b"block".ljust(12, b"\x00") + length + bytes(4)
    fake = FakeSocket([header])
    connect_to(monkeypatch, fake)
    transport = peer()
    transport.send(MESSAGE, 5)
    with pytest.raises(FetchError, match="invalid payload length: 4000001"):
        transport.receive(5)
    assert not transport.is_open
    assert fake.chunks == []


def test_a_message_with_a_wrong_checksum_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The codec's refusal is a fetch error, and the stream is dropped."""
    connect_to(monkeypatch, FakeSocket([WIRE[:-1] + b"\x01"]))
    transport = peer()
    transport.send(MESSAGE, 5)
    with pytest.raises(FetchError, match="invalid checksum"):
        transport.receive(5)
    assert not transport.is_open


# closing


def test_close_is_idempotent_and_the_context_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Leaving the context closes the connection, once."""
    fake = FakeSocket([])
    connect_to(monkeypatch, fake)
    with peer() as transport:
        transport.send(MESSAGE, 5)
        assert transport.is_open
    transport.close()
    assert fake.closed == 1
    assert not transport.is_open


def test_a_context_exit_passes_the_exception_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Closing does not swallow what the body raised."""
    connect_to(monkeypatch, FakeSocket([]))
    transport = peer()
    with pytest.raises(RuntimeError, match="body"), transport:
        raise RuntimeError("body")
    assert not transport.is_open
