# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `TcpPeerTransport` and `V2PeerTransport`, over a scripted socket.

`FakeSocket` stands where `socket.create_connection` returns: it hands
out the octets it was given, in the pieces it was given them in, and
records what is written. `V2Peer` is one that answers the v2 handshake
as a responder. No socket is opened.
`tests/integration/compact_filters_test.py` is where a real one is.
"""

from __future__ import annotations

import itertools
from collections.abc import Callable
from typing import Any

import pytest
from bitcoin_core_rpc import FetchError
from btclib.ellswift import ELL_SIZE
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.p2p import Ping
from btclib.p2p import message as message_module
from btclib.p2p.limits import MAX_PROTOCOL_MESSAGE_LENGTH
from btclib.p2p.message import Message
from ecc import ellswift
from typing_extensions import override

from btclib_wallet.fetch import peer_transport
from btclib_wallet.fetch import transport as fetch_transport
from btclib_wallet.fetch.peer_transport import TcpPeerTransport, V2PeerTransport

MAGIC = b"\xfa\xbf\xb5\xda"
MESSAGE = Ping(7).to_message(MAGIC)
WIRE = MESSAGE.serialize()


class FakeSocket:
    """A connection reading from a script and writing to a list."""

    def __init__(
        self,
        chunks: list[bytes],
        *,
        error: BaseException | None = None,
        send_error: BaseException | None = None,
        close_error: Exception | None = None,
    ) -> None:
        self.chunks = chunks
        self.error = error
        self.send_error = send_error
        self.close_error = close_error
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

    def send(self, data: bytes) -> int:
        """Write as `sendall` does, all of it at once."""
        self.sendall(data)
        return len(data)

    def close(self) -> None:
        """Count the closes, or fail after counting."""
        self.closed += 1
        if self.close_error is not None:
            raise self.close_error

    def fileno(self) -> int:
        """Return -1 once closed, as a socket does."""
        return -1 if self.closed else 3


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
        ("peer", 0, BTClibValueError, "invalid port: an int of 0 bits"),
        ("peer", 65536, BTClibValueError, "invalid port: an int of 17 bits"),
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


def test_a_timeout_is_never_longer_than_the_one_the_call_took(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two equal reads of the clock leave no more time than the call took.

    At this reading `(t + 5) - t` is a little over 5 in floating point,
    which two reads of a coarse clock can produce.
    """
    now = 8191.610680565681
    assert (now + 5) - now > 5
    fake = FakeSocket([WIRE])
    connect_to(monkeypatch, fake)
    set_clock(monkeypatch, lambda: now)
    transport = peer()
    transport.send(MESSAGE, 5)
    assert transport.receive(5) == MESSAGE
    assert fake.timeouts
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
    with pytest.raises(
        FetchError, match="invalid payload length: at most 4000000 bytes expected"
    ):
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


def test_a_socket_that_fails_to_close_is_a_fetch_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The connection is dropped all the same; a second close does nothing."""
    fake = FakeSocket([], close_error=OSError("bad descriptor"))
    connect_to(monkeypatch, fake)
    transport = peer()
    transport.send(MESSAGE, 5)
    with pytest.raises(FetchError, match="closing peer.example:18444: bad descriptor"):
        transport.close()
    assert not transport.is_open
    transport.close()
    assert fake.closed == 1


def test_a_failure_to_close_after_a_failed_write_reports_the_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The error raised is the one that broke the connection."""
    fake = FakeSocket(
        [], send_error=BrokenPipeError("gone"), close_error=OSError("bad descriptor")
    )
    connect_to(monkeypatch, fake)
    transport = peer()
    with pytest.raises(FetchError, match="no connection to peer.example:18444: gone"):
        transport.send(MESSAGE, 5)
    assert fake.closed == 1
    assert not transport.is_open


# the v2 transport, against a responder that answers what it reads

# a fixed responder key; not a key of anything
PEER_PRV_KEY = 2


def v2_peer(*, v1_fallback: bool = False) -> V2PeerTransport:
    """Return a v2 transport to a peer that does not exist.

    Skipped where `cryptography` is missing (README's *Installing*):
    `no_cryptography_test.py` asks what happens then.
    """
    pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    return V2PeerTransport("peer.example", 18444, v1_fallback=v1_fallback)


class V2Peer(FakeSocket):
    """A BIP324 responder, scripted on what the transport writes.

    Once the transport's key is in, its script is its key, `garbage`,
    its garbage terminator (or `terminator`), `decoys` decoy packets, the
    first authenticating the garbage (or `aad`), the version packet and
    `packets`. `sent` decrypts what the transport wrote after the
    handshake. `send_error` is raised by every write after the
    transport's version packet.
    """

    def __init__(
        self,
        *,
        garbage: bytes = b"",
        terminator: bytes | None = None,
        aad: bytes | None = None,
        decoys: int = 0,
        packets: Callable[[V2Peer], list[bytes]] = lambda _peer: [],
        error: BaseException | None = None,
        send_error: BaseException | None = None,
    ) -> None:
        super().__init__([], error=error)
        # skipped where `cryptography` is missing (README's *Installing*)
        pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
        from btclib.p2p.bip324 import Cipher  # noqa: PLC0415

        self.cipher_class = Cipher
        self.ell = ellswift.create(PEER_PRV_KEY)
        self.garbage = garbage
        self.terminator = terminator
        self.aad = garbage if aad is None else aad
        self.decoys = decoys
        self.packets = packets
        self.late_send_error = send_error
        self.writes = 0
        self.cipher: Cipher | None = None

    @override
    def sendall(self, data: bytes) -> None:
        """Record the octets, and answer the key once it is in."""
        # the key and garbage, then the terminator and the version packet
        if self.writes >= 2 and self.late_send_error is not None:
            raise self.late_send_error
        self.writes += 1
        super().sendall(data)
        if self.cipher is not None or len(self.written) < ELL_SIZE:
            return
        cipher = self.cipher = self.cipher_class(
            PEER_PRV_KEY,
            self.ell,
            bytes(self.written[:ELL_SIZE]),
            initiator=False,
            magic=MAGIC,
        )
        script = self.ell + self.garbage
        script += self.terminator or cipher.send_garbage_terminator
        aad = self.aad
        for _ in range(self.decoys):
            script += cipher.encrypt(b"\x12", aad, ignore=True)
            aad = b""
        script += cipher.encrypt(b"", aad)
        self.chunks.append(script + b"".join(self.packets(self)))

    def packet(self, command: str, payload: bytes) -> bytes:
        """Return a packet of one message, encrypted as the peer sends it."""
        from btclib.p2p.bip324 import contents_from_message  # noqa: PLC0415

        assert self.cipher is not None
        return self.cipher.encrypt(contents_from_message(command, payload))

    def sent(self) -> list[tuple[str, bytes]]:
        """Return the messages the transport wrote after its version packet."""
        from btclib.p2p.bip324 import (  # noqa: PLC0415
            EXPANSION,
            LENGTH_LEN,
            message_from_contents,
        )

        assert self.cipher is not None
        written = bytes(self.written[ELL_SIZE:])
        end = written.index(self.cipher.recv_garbage_terminator)
        aad, rest = written[:end], written[end + 16 :]
        contents = []
        while rest:
            size = EXPANSION + self.cipher.decrypt_length(rest[:LENGTH_LEN])
            packet, ignore = self.cipher.decrypt(rest[LENGTH_LEN:size], aad)
            assert not ignore
            contents.append(packet)
            # only the first packet, the version packet, authenticates it
            aad, rest = b"", rest[size:]
        assert contents[0] == b""
        return [message_from_contents(each) for each in contents[1:]]


def test_a_v2_transport_checks_its_arguments() -> None:
    """Host and port as `TcpPeerTransport`'s, and `v1_fallback` a bool."""
    with pytest.raises(BTClibValueError, match="empty host"):
        V2PeerTransport("", 18444)
    with pytest.raises(BTClibValueError, match="invalid port"):
        V2PeerTransport("peer", 0)
    with pytest.raises(BTClibTypeError, match="invalid v1_fallback type: str"):
        V2PeerTransport("peer", 18444, v1_fallback="no")  # type: ignore[arg-type]


def test_a_v2_construction_opens_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """The transport names its peer, is not connected and has no session."""
    calls = connect_to(monkeypatch, FakeSocket([]))
    transport = v2_peer()
    assert (transport.host, transport.port) == ("peer.example", 18444)
    assert not transport.is_open
    assert transport.session_id is None
    assert calls == []


def test_a_v2_message_and_timeout_are_checked_before_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A wrong argument is refused without a connection."""
    calls = connect_to(monkeypatch, V2Peer())
    with pytest.raises(BTClibTypeError, match="non-Message"):
        v2_peer().send(WIRE, 5)  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError, match="timeout"):
        v2_peer().send(MESSAGE, 0)
    with pytest.raises(BTClibValueError, match="timeout"):
        v2_peer().receive(-1)
    # a message built unchecked, with a payload no peer accepts
    oversized = Message(
        MAGIC, "tx", bytes(MAX_PROTOCOL_MESSAGE_LENGTH + 1), check_validity=False
    )
    with pytest.raises(BTClibValueError, match="invalid payload length"):
        v2_peer().send(oversized, 5)
    assert calls == []


def test_the_first_v2_send_completes_the_handshake(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Key, garbage, terminator and version packet, then the message.

    The peer sends the most garbage BIP324 allows, and decoys first.
    """
    fake = V2Peer(garbage=b"\x5a" * 4095, decoys=2)
    calls = connect_to(monkeypatch, fake)
    transport = v2_peer()
    transport.send(MESSAGE, 5)
    transport.send(MESSAGE, 5)
    assert fake.sent() == [(MESSAGE.command, MESSAGE.payload)] * 2
    assert len(calls) == 1
    assert transport.is_open
    assert fake.cipher is not None
    assert transport.session_id == fake.cipher.session_id


def test_a_v2_message_is_received_whole_and_decoys_are_dropped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Decoys, and a message type the codec does not know, are skipped."""

    def packets(peer: V2Peer) -> list[bytes]:
        assert peer.cipher is not None
        return [
            peer.cipher.encrypt(b"\x12\x34", ignore=True),
            # a short id beyond the table: Core drops the message
            peer.cipher.encrypt(b"\xff"),
            peer.packet(MESSAGE.command, MESSAGE.payload),
            peer.packet("feature", b"\x01"),
        ]

    fake = V2Peer(packets=packets)
    # the octets one at a time, however many are asked for
    monkeypatch.setattr(fake, "recv", lambda _size: FakeSocket.recv(fake, 1))
    connect_to(monkeypatch, fake)
    transport = v2_peer()
    transport.send(MESSAGE, 5)
    assert transport.receive(5) == MESSAGE
    assert transport.receive(5) == Message(MAGIC, "feature", b"\x01")
    assert all(0 < timeout <= 5 for timeout in fake.timeouts)


def test_a_v2_message_for_another_network_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The connection's network is its first message's, and stays open."""
    fake = V2Peer()
    connect_to(monkeypatch, fake)
    transport = v2_peer()
    transport.send(MESSAGE, 5)
    other = Ping(7).to_message(b"\xf9\xbe\xb4\xd9")
    with pytest.raises(BTClibValueError, match="another network"):
        transport.send(other, 5)
    assert transport.is_open
    assert fake.sent() == [(MESSAGE.command, MESSAGE.payload)]


@pytest.mark.parametrize(
    "fake, why",
    [
        (
            lambda: V2Peer(garbage=b"\x5a" * 4095, terminator=bytes(16)),
            "no garbage terminator",
        ),
        (
            lambda: V2Peer(garbage=b"\x5a" * 4096),
            "no garbage terminator",
        ),
        (lambda: V2Peer(garbage=b"\x5a", aad=b"\xa5"), "authentication failed"),
        (
            lambda: V2Peer(garbage=b"\x5a", aad=b"\xa5", decoys=1),
            "authentication failed",
        ),
    ],
    ids=["wrong terminator", "garbage too long", "garbage altered", "decoy altered"],
)
def test_a_failed_v2_handshake_is_a_fetch_error(
    monkeypatch: pytest.MonkeyPatch, fake: Callable[[], V2Peer], why: str
) -> None:
    """No terminator after the most garbage a peer may send is refused.

    So is garbage, or a decoy before the version packet, that the first
    packet does not authenticate.
    """
    pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    peer_socket = fake()
    connect_to(monkeypatch, peer_socket)
    transport = v2_peer()
    with pytest.raises(FetchError, match=why):
        transport.send(MESSAGE, 5)
    assert not transport.is_open
    assert transport.session_id is None
    assert peer_socket.closed == 1


def test_a_v2_peer_that_hangs_up_inside_its_key_is_a_fetch_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Part of a key is a v2 peer gone, not a v1 peer."""
    pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    fake = FakeSocket([ellswift.create(PEER_PRV_KEY)[:10]])
    connect_to(monkeypatch, fake)
    transport = v2_peer(v1_fallback=True)
    with pytest.raises(FetchError, match="closed before a whole message"):
        transport.send(MESSAGE, 5)
    assert not transport.is_open


@pytest.mark.parametrize(
    "error", [None, ConnectionResetError("reset")], ids=["closed", "reset"]
)
def test_a_v1_peer_is_refused_without_the_fallback(
    monkeypatch: pytest.MonkeyPatch, error: Exception | None
) -> None:
    """A hang-up before the peer's key is what a v1 peer does."""
    pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    fake = FakeSocket([], error=error)
    connect_to(monkeypatch, fake)
    transport = v2_peer()
    with pytest.raises(FetchError, match="hung up on the v2 handshake.*v1_fallback"):
        transport.send(MESSAGE, 5)
    assert not transport.is_open
    assert fake.closed == 1
    # the key and the garbage, which a v1 peer reads as a wrong header
    assert ELL_SIZE <= len(fake.written) <= ELL_SIZE + 4095


def test_a_v1_peer_is_spoken_to_over_v1_with_the_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A second connection, in plain text; closing it tries v2 again."""
    pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    refusing, plain, again = FakeSocket([]), FakeSocket([WIRE]), V2Peer()
    sockets = iter([refusing, plain, again])
    monkeypatch.setattr(
        peer_transport, "create_connection", lambda *_a, **_k: next(sockets)
    )
    transport = v2_peer(v1_fallback=True)
    transport.send(MESSAGE, 5)
    transport.send(MESSAGE, 5)
    assert plain.written == WIRE * 2
    assert transport.receive(5) == MESSAGE
    # open, over v1
    assert (transport.is_open, transport.session_id) == (True, None)
    transport.close()
    assert (refusing.closed, plain.closed) == (1, 1)
    assert not transport.is_open
    transport.send(MESSAGE, 5)
    assert again.sent() == [(MESSAGE.command, MESSAGE.payload)]


def test_a_v1_fallback_refuses_a_message_for_another_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The connection's network is its first message's over v1 too."""
    pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    refusing, plain = FakeSocket([]), FakeSocket([])
    sockets = iter([refusing, plain])
    monkeypatch.setattr(
        peer_transport, "create_connection", lambda *_a, **_k: next(sockets)
    )
    transport = v2_peer(v1_fallback=True)
    transport.send(MESSAGE, 5)
    other = Ping(7).to_message(b"\xf9\xbe\xb4\xd9")
    with pytest.raises(BTClibValueError, match="another network"):
        transport.send(other, 5)
    assert transport.is_open
    assert plain.written == WIRE


def test_an_interrupted_v2_handshake_leaves_nothing_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A `KeyboardInterrupt` inside the handshake closes its socket.

    The next send connects again, on the network of its own message.
    """
    pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    interrupted = FakeSocket([], error=KeyboardInterrupt())
    again = V2Peer()
    sockets = iter([interrupted, again])
    monkeypatch.setattr(
        peer_transport, "create_connection", lambda *_a, **_k: next(sockets)
    )
    transport = v2_peer()
    with pytest.raises(KeyboardInterrupt):
        transport.send(MESSAGE, 5)
    assert interrupted.closed == 1
    assert (transport.is_open, transport.session_id) == (False, None)
    transport.send(MESSAGE, 5)
    assert again.sent() == [(MESSAGE.command, MESSAGE.payload)]


def test_an_interrupted_v1_fallback_leaves_nothing_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An interrupt while the v1 connection opens keeps no v1 transport.

    The next send tries v2 again.
    """
    pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    again = V2Peer()
    outcomes: list[FakeSocket | BaseException] = [
        FakeSocket([]),
        KeyboardInterrupt(),
        again,
    ]

    def create_connection(*_args: object, **_kwargs: object) -> FakeSocket:
        outcome = outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(peer_transport, "create_connection", create_connection)
    transport = v2_peer(v1_fallback=True)
    with pytest.raises(KeyboardInterrupt):
        transport.send(MESSAGE, 5)
    assert not transport.is_open
    transport.send(MESSAGE, 5)
    assert again.sent() == [(MESSAGE.command, MESSAGE.payload)]
    assert transport.session_id is not None


def test_an_interrupted_v1_write_closes_the_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A message half written over the v1 fallback ends that connection."""
    pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    refusing, plain = FakeSocket([]), FakeSocket([])
    sockets = iter([refusing, plain])
    monkeypatch.setattr(
        peer_transport, "create_connection", lambda *_a, **_k: next(sockets)
    )
    transport = v2_peer(v1_fallback=True)
    transport.send(MESSAGE, 5)
    plain.send_error = KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):
        transport.send(MESSAGE, 5)
    assert not transport.is_open
    assert plain.closed == 1


@pytest.mark.parametrize("call", ["send", "receive"])
def test_an_interrupt_after_the_v2_handshake_closes_the_connection(
    monkeypatch: pytest.MonkeyPatch, call: str
) -> None:
    """A packet half written or half read leaves no connection open."""
    # the peer has nothing more to send, so a read is interrupted
    fake = V2Peer(error=KeyboardInterrupt())
    connect_to(monkeypatch, fake)
    transport = v2_peer()
    transport.send(MESSAGE, 5)
    if call == "send":
        fake.late_send_error = KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):
        getattr(transport, call)(*((MESSAGE, 5) if call == "send" else (5,)))
    assert (transport.is_open, transport.session_id) == (False, None)
    assert fake.closed == 1


def test_a_failed_v1_connection_closes_the_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The next send tries v2 again, as after any failure."""
    pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    refusing, plain, again = FakeSocket([]), FakeSocket([WIRE[:10]]), V2Peer()
    sockets = iter([refusing, plain, again])
    monkeypatch.setattr(
        peer_transport, "create_connection", lambda *_a, **_k: next(sockets)
    )
    transport = v2_peer(v1_fallback=True)
    transport.send(MESSAGE, 5)
    with pytest.raises(FetchError, match="closed before a whole message"):
        transport.receive(5)
    assert not transport.is_open
    assert plain.closed == 1
    transport.send(MESSAGE, 5)
    assert again.sent() == [(MESSAGE.command, MESSAGE.payload)]


def interrupted_when_kept(field: str, *, v1_fallback: bool = False) -> V2PeerTransport:
    """Return a v2 transport interrupted as it first keeps a connection.

    The `KeyboardInterrupt` comes as `field`, `_socket` or `_v1`, is set
    to the connection: after the call that opened it returned, before the
    transport holds it as open.
    """
    pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")

    class Interrupted(V2PeerTransport):
        @override
        def __setattr__(self, name: str, value: object) -> None:
            if name == field and value is not None:
                raise KeyboardInterrupt
            super().__setattr__(name, value)

    return Interrupted("peer.example", 18444, v1_fallback=v1_fallback)


def test_an_interrupt_as_the_v2_connection_is_kept_closes_its_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The socket is the transport's from the moment it is made."""
    fake = V2Peer()
    connect_to(monkeypatch, fake)
    transport = interrupted_when_kept("_socket")
    with pytest.raises(KeyboardInterrupt):
        transport.send(MESSAGE, 5)
    assert fake.closed == 1
    assert not transport.is_open


def test_an_interrupt_as_the_v1_fallback_is_kept_closes_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The v1 transport is the v2 one's from the moment it is made."""
    refusing, plain = FakeSocket([]), FakeSocket([])
    sockets = iter([refusing, plain])
    monkeypatch.setattr(
        peer_transport, "create_connection", lambda *_a, **_k: next(sockets)
    )
    transport = interrupted_when_kept("_v1", v1_fallback=True)
    with pytest.raises(KeyboardInterrupt):
        transport.send(MESSAGE, 5)
    assert plain.written == WIRE
    assert (refusing.closed, plain.closed) == (1, 1)
    assert not transport.is_open


def opened(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> tuple[TcpPeerTransport | V2PeerTransport, FakeSocket]:
    """Return a transport of `kind` after its first send, and its socket."""
    transport: TcpPeerTransport | V2PeerTransport
    if kind == "v1":
        fake = FakeSocket([])
        connect_to(monkeypatch, fake)
        transport = peer()
    elif kind == "v2":
        fake = V2Peer()
        connect_to(monkeypatch, fake)
        transport = v2_peer()
    else:
        fake = FakeSocket([])
        sockets = iter([FakeSocket([]), fake])
        monkeypatch.setattr(
            peer_transport, "create_connection", lambda *_a, **_k: next(sockets)
        )
        transport = v2_peer(v1_fallback=True)
    transport.send(MESSAGE, 5)
    return transport, fake


@pytest.mark.parametrize("kind", ["v1", "v2", "v1 fallback"])
def test_an_interrupted_close_leaves_the_socket_to_the_next_close(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    """A socket is let go of only once closed."""
    transport, fake = opened(monkeypatch, kind)
    close = fake.close
    interrupted: list[bool] = []

    def interrupted_close() -> None:
        if not interrupted:
            interrupted.append(True)
            raise KeyboardInterrupt
        close()

    monkeypatch.setattr(fake, "close", interrupted_close)
    with pytest.raises(KeyboardInterrupt):
        transport.close()
    assert fake.closed == 0
    transport.close()
    assert fake.closed == 1
    assert not transport.is_open


@pytest.mark.parametrize("kind", ["v1", "v2", "v1 fallback"])
def test_a_close_interrupted_once_the_socket_closed_leaves_it_not_open(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    """The socket still held is closed, and `is_open` says so."""
    transport, fake = opened(monkeypatch, kind)
    close = fake.close

    def closed_then_interrupted() -> None:
        close()
        raise KeyboardInterrupt

    monkeypatch.setattr(fake, "close", closed_then_interrupted)
    with pytest.raises(KeyboardInterrupt):
        transport.close()
    assert fake.closed == 1
    assert not transport.is_open


def test_a_send_after_a_close_interrupted_once_the_socket_closed_reconnects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The closed socket still held is not written to: as `is_open` says."""
    closed, again = FakeSocket([]), FakeSocket([])
    sockets = iter([closed, again])
    monkeypatch.setattr(
        peer_transport, "create_connection", lambda *_a, **_k: next(sockets)
    )
    transport = peer()
    transport.send(MESSAGE, 5)
    close = closed.close

    def closed_then_interrupted() -> None:
        close()
        raise KeyboardInterrupt

    monkeypatch.setattr(closed, "close", closed_then_interrupted)
    with pytest.raises(KeyboardInterrupt):
        transport.close()
    transport.send(MESSAGE, 5)
    assert closed.written == WIRE
    assert again.written == WIRE
    assert transport.is_open


def test_a_v1_fallback_that_closed_itself_is_not_used_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An interrupt kept the transport from closing it: v2 is tried again."""
    plain, again = FakeSocket([WIRE[:10]]), V2Peer()
    sockets = iter([FakeSocket([]), plain, again])
    monkeypatch.setattr(
        peer_transport, "create_connection", lambda *_a, **_k: next(sockets)
    )
    transport = v2_peer(v1_fallback=True)
    transport.send(MESSAGE, 5)
    discard = transport._discard
    interrupted: list[bool] = []

    def interrupted_discard() -> None:
        if not interrupted:
            interrupted.append(True)
            raise KeyboardInterrupt
        discard()

    # the v1 transport closes its socket on the short read, and the
    # interrupt comes as this transport is about to close itself
    monkeypatch.setattr(transport, "_discard", interrupted_discard)
    with pytest.raises(KeyboardInterrupt):
        transport.receive(5)
    assert plain.closed == 1
    assert not transport.is_open
    transport.send(MESSAGE, 5)
    assert again.sent() == [(MESSAGE.command, MESSAGE.payload)]
    assert transport.session_id is not None


def test_a_v1_fallback_that_fails_to_close_is_a_fetch_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The connection is dropped all the same, as over v2."""
    plain = FakeSocket([], close_error=OSError("bad descriptor"))
    sockets = iter([FakeSocket([]), plain])
    monkeypatch.setattr(
        peer_transport, "create_connection", lambda *_a, **_k: next(sockets)
    )
    transport = v2_peer(v1_fallback=True)
    transport.send(MESSAGE, 5)
    with pytest.raises(FetchError, match="closing peer.example:18444: bad descriptor"):
        transport.close()
    assert not transport.is_open
    transport.close()
    assert plain.closed == 1


class HangingUp(FakeSocket):
    """A peer that hangs up once `after` octets of ours are written.

    `sendall`, which cannot say how much it wrote, raises the hang-up.
    """

    def __init__(self, after: int, hang_up: ConnectionError) -> None:
        super().__init__([], send_error=hang_up)
        self.after = after
        self.hang_up = hang_up

    @override
    def send(self, data: bytes) -> int:
        """Write what fits before the hang-up, or raise it."""
        room = self.after - len(self.written)
        if room <= 0:
            raise self.hang_up
        self.written += data[:room]
        return min(room, len(data))


HANG_UPS = pytest.mark.parametrize(
    "hang_up",
    [ConnectionResetError("reset"), BrokenPipeError("broken pipe")],
    ids=["reset", "broken pipe"],
)


@HANG_UPS
def test_a_hang_up_while_the_key_is_written_falls_back_to_v1(
    monkeypatch: pytest.MonkeyPatch, hang_up: ConnectionError
) -> None:
    """As on a read: Core reconnects over v1 on either side's hang-up."""
    refusing, plain = HangingUp(24, hang_up), FakeSocket([])
    sockets = iter([refusing, plain])
    monkeypatch.setattr(
        peer_transport, "create_connection", lambda *_a, **_k: next(sockets)
    )
    transport = v2_peer(v1_fallback=True)
    transport.send(MESSAGE, 5)
    assert (len(refusing.written), refusing.closed) == (24, 1)
    assert plain.written == WIRE
    assert (transport.is_open, transport.session_id) == (True, None)


@HANG_UPS
def test_a_hang_up_while_the_key_is_written_names_the_fallback(
    monkeypatch: pytest.MonkeyPatch, hang_up: ConnectionError
) -> None:
    """Without the fallback it is refused as a hang-up on a read is."""
    fake = HangingUp(24, hang_up)
    calls = connect_to(monkeypatch, fake)
    transport = v2_peer()
    with pytest.raises(FetchError, match="as a v1 peer does, and v1_fallback is off"):
        transport.send(MESSAGE, 5)
    assert (len(calls), fake.closed) == (1, 1)
    assert not transport.is_open


def test_a_hang_up_before_a_v1_header_is_written_is_a_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Core reconnects over v1 only once a header's worth was sent."""
    fake = HangingUp(23, ConnectionResetError("reset"))
    calls = connect_to(monkeypatch, fake)
    transport = v2_peer(v1_fallback=True)
    with pytest.raises(FetchError, match="no connection to peer.example:18444: reset"):
        transport.send(MESSAGE, 5)
    assert (len(calls), fake.closed) == (1, 1)


def test_a_v2_connection_that_cannot_be_made_is_a_fetch_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reason is the OS's, and nothing is left open."""
    pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    connect_to(monkeypatch, OSError("unreachable"))
    transport = v2_peer()
    with pytest.raises(FetchError, match="no connection to peer.example:18444"):
        transport.send(MESSAGE, 5)
    assert not transport.is_open


def test_a_v2_write_that_fails_closes_the_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A broken pipe after the handshake is a fetch error too."""
    fake = V2Peer(send_error=BrokenPipeError("gone"))
    connect_to(monkeypatch, fake)
    transport = v2_peer()
    with pytest.raises(FetchError, match="no connection to peer.example:18444: gone"):
        transport.send(MESSAGE, 5)
    assert fake.closed == 1
    assert not transport.is_open


def test_a_v2_handshake_that_outlasts_its_timeout_is_a_fetch_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The connect, the handshake and the write share one deadline."""
    fake = V2Peer()
    connect_to(monkeypatch, fake)
    transport = v2_peer()
    ticks = itertools.count()
    set_clock(monkeypatch, lambda: next(ticks) * 10.0)
    with pytest.raises(FetchError, match="timeout expired"):
        transport.send(MESSAGE, 5)
    assert fake.closed == 1


def test_a_v2_receive_without_a_connection_is_a_fetch_error() -> None:
    """Nothing is read before something is sent."""
    with pytest.raises(FetchError, match="not connected"):
        v2_peer().receive(5)


def test_a_v2_peer_that_goes_quiet_is_a_fetch_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The socket's timeout is the OS's, and the connection is closed."""
    fake = V2Peer(error=TimeoutError("timed out"))
    connect_to(monkeypatch, fake)
    transport = v2_peer()
    transport.send(MESSAGE, 5)
    with pytest.raises(FetchError, match="no message from peer.example:18444"):
        transport.receive(5)
    assert not transport.is_open


def test_a_v2_packet_announcing_too_much_is_refused_before_it_is_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The length is the peer's to choose, and is bounded first."""
    fake = V2Peer(packets=lambda peer: [peer.packet("tx", bytes(20))])
    connect_to(monkeypatch, fake)
    transport = v2_peer()
    transport.send(MESSAGE, 5)
    monkeypatch.setattr(peer_transport, "_MAX_CONTENTS_LEN", 20)
    with pytest.raises(FetchError, match="packet too large: 21 bytes"):
        transport.receive(5)
    assert not transport.is_open
    assert len(fake.chunks[0]) == 21 + 17


@pytest.mark.parametrize(
    "tamper, why",
    [
        (lambda packet: packet[:-1] + bytes([packet[-1] ^ 1]), "authentication"),
        (lambda packet: packet, "invalid payload length"),
    ],
    ids=["tag", "payload too long"],
)
def test_a_v2_packet_refused_closes_the_connection(
    monkeypatch: pytest.MonkeyPatch,
    tamper: Callable[[bytes], bytes],
    why: str,
) -> None:
    """A tag that fails, and a message the codec refuses, end the stream."""
    fake = V2Peer(packets=lambda peer: [tamper(peer.packet("ping", bytes(8)))])
    connect_to(monkeypatch, fake)
    transport = v2_peer()
    transport.send(MESSAGE, 5)
    # a payload bound below a ping's, so that the codec refuses it
    if why != "authentication":
        monkeypatch.setattr(message_module, "MAX_PROTOCOL_MESSAGE_LENGTH", 4)
    with pytest.raises(FetchError, match=why):
        transport.receive(5)
    assert not transport.is_open


def test_v2_close_is_idempotent_and_the_context_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Leaving the context closes the connection, once; a close can fail."""
    fake = V2Peer()
    connect_to(monkeypatch, fake)
    with v2_peer() as transport:
        transport.send(MESSAGE, 5)
        assert transport.is_open
    transport.close()
    assert fake.closed == 1
    assert transport.session_id is None
    failing = V2Peer()
    failing.close_error = OSError("bad descriptor")
    connect_to(monkeypatch, failing)
    transport.send(MESSAGE, 5)
    with pytest.raises(FetchError, match="closing peer.example:18444: bad descriptor"):
        transport.close()
    assert not transport.is_open
