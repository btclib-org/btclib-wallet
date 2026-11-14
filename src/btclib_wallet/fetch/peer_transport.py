# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The seam a p2p fetcher talks to one peer through, and the sockets behind it.

`btclib.p2p` is the codec: it frames and parses a `Message` (its own
docstring says it opens no socket). `PeerTransport` is the seam where the
socket is. `TcpPeerTransport` and `V2PeerTransport` are the
implementations that open one. A test replaces the seam with an object
that answers from a script, as it replaces `LineTransport` for
`ElectrumFetcher`.

**A peer transport is a connection and not a call.** `LineTransport` is
one request and one answer on a connection of its own; a p2p peer sends
what it likes when it likes, and the handshake that opens a connection is
state both ends keep. So `PeerTransport` is `send`, `receive` and
`close`, and the connection is the object's.

**A failure closes the connection**: a read cut short leaves the stream
in the middle of a message. `PeerTransport` says what the caller sees.

**The network policy is `TlsLineTransport`'s**, except:

- the length a message or a v2 packet announces is bounded by
  `MAX_PROTOCOL_MESSAGE_LENGTH` before any of its payload is read;
- a timeout over each call, connect and v2 handshake included, rather
  than over an exchange: `send` and `receive` are separate calls;
- `TcpPeerTransport`'s stream is plain TCP, as the p2p v1 transport is.
  A peer is anonymous and its messages are checked by the fetcher
  against what it already holds, which is the reason this layer
  authenticates nothing.

**`V2PeerTransport` encrypts, and protects against a passive observer
only.** It speaks BIP324's v2 transport, whose handshake authenticates
neither end: an attacker on the path can complete one handshake with
each end and read everything. Each end then sees a different session id,
so a caller that compares `session_id` with the one the peer reports
(`getpeerinfo` on Bitcoin Core) detects it.

The cipher and the framing are `btclib.p2p.bip324`'s, which needs the
`cryptography` package: README's *Installing* says which installs lack
it and how to add it. Where it is missing, `V2PeerTransport` refuses on
construction, and the rest of this module works without it.

A peer that speaks v1 only hangs up on the v2 handshake. Bitcoin Core
then reconnects over v1; `V2PeerTransport` does so only where the caller
asks, with `v1_fallback=True`, since the second connection is plain
text, and otherwise raises.
"""

from __future__ import annotations

import secrets
from contextlib import suppress
from importlib import import_module
from socket import create_connection, socket
from time import monotonic
from typing import TYPE_CHECKING, Protocol, Self

from bitcoin_core_rpc import FetchError
from btclib.ellswift import ELL_SIZE
from btclib.exceptions import (
    BTClibRuntimeError,
    BTClibTypeError,
    BTClibValueError,
    IncompleteMessageError,
)
from btclib.p2p.limits import MAX_PROTOCOL_MESSAGE_LENGTH
from btclib.p2p.message import Message
from btclib.utils import assert_type, is_integer
from ecc import ellswift
from ecc.curves import secp256k1

from btclib_wallet._refusal import _message_text, _quoted
from btclib_wallet.fetch.transport import (
    _MAX_PORT,
    _READ_CHUNK,
    _time_left,
    _TransportError,
    valid_timeout,
)

if TYPE_CHECKING:
    from btclib.p2p.bip324 import Cipher

__all__ = [
    "PeerTransport",
    "TcpPeerTransport",
    "V2PeerTransport",
]

# the size of a message header, `btclib.p2p.message`'s own layout
_HEADER_SIZE = 24

# BIP324's bound on the garbage after a key, Core's
# `V2Transport::MAX_GARBAGE_LEN`
_MAX_GARBAGE_LEN = 4095
# Core's bound on a packet's contents: a long message type, its 12 bytes
# and the largest payload
_MAX_CONTENTS_LEN = 1 + 12 + MAX_PROTOCOL_MESSAGE_LENGTH

_NO_CRYPTOGRAPHY = (
    "the cryptography package is missing, as an install on Windows arm64"
    " leaves it, and the v2 transport needs it: install"
    " btclib-wallet[encryption]"
)


def _assert_bip324() -> None:
    """Refuse where `btclib.p2p.bip324` cannot be imported.

    It imports `cryptography`, which an install can lack (README's
    *Installing*), so it is imported only where a v2 transport is built.
    """
    # refused after `suppress`, as every refusal of this module is raised
    # after the `except` block that sees its cause, so that it chains
    # nothing: an OSError holds what the system says of the address
    with suppress(ImportError):
        import_module("btclib.p2p.bip324")
        return
    raise BTClibRuntimeError(_NO_CRYPTOGRAPHY)


def _assert_peer(host: str, port: int) -> None:
    """Refuse a host that is no name and a port that is no port."""
    if not isinstance(host, str):
        raise BTClibTypeError(f"non-string host: {_message_text(host)}")
    if not host:
        raise BTClibValueError("empty host")
    encoded = False
    # what `create_connection` encodes the host with, and a
    # `UnicodeError` rather than an `OSError` there. The refusal is
    # raised after `suppress`, so that it chains no codec error: one
    # holds the host
    with suppress(UnicodeError):
        encoded = bool(host.encode("idna"))
    if not encoded:
        raise BTClibValueError(f"invalid host: {_quoted(host)}")
    if not is_integer(port):
        raise BTClibTypeError(f"non-integer port: {_message_text(port)}")
    if not 0 < port <= _MAX_PORT:
        raise BTClibValueError(f"invalid port: {_message_text(port)}")


class PeerTransport(Protocol):
    """What a p2p fetcher needs of the connection to one peer.

    A transport that cannot answer raises `bitcoin_core_rpc`'s `FetchError`
    or a subclass of it, and is closed when it does: the next `send` opens
    a new connection. `close` is idempotent.
    """

    def send(self, message: Message, timeout: float) -> None:
        """Write one message, connecting first if there is no connection."""

    def receive(self, timeout: float) -> Message:
        """Return the next message the peer sends, waiting up to `timeout`."""

    def close(self) -> None:
        """Close the connection, if there is one."""


class TcpPeerTransport:
    """A `PeerTransport` over plain TCP to one peer.

    Constructed with the host and port it connects to, so the instance is
    the peer. Construction opens nothing, and nothing is opened until the
    first `send`. It works as a context manager that closes on exit.

    Everything that goes wrong below the message -- an unresolvable host, a
    refused connection, a timeout, a connection closed before a whole
    message, a message announcing more than a peer may send, a checksum that
    does not match, a socket that fails to close -- is a `FetchError`.
    """

    def __init__(self, host: str, port: int) -> None:
        _assert_peer(host, port)
        self._host = host
        self._port = port
        self._socket: socket | None = None

    @property
    def host(self) -> str:
        """Return the host this transport connects to."""
        return self._host

    @property
    def port(self) -> int:
        """Return the port this transport connects to."""
        return self._port

    @property
    def is_open(self) -> bool:
        """Return whether a connection is open."""
        # a close interrupted once the socket closed still holds it, closed
        return self._socket is not None and self._socket.fileno() != -1

    def __enter__(self) -> Self:
        """Return this transport."""
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Close the connection."""
        self.close()

    def close(self) -> None:
        """Close the connection, if there is one."""
        sock = self._socket
        if sock is not None:
            # let go of only once closed, or once its close failed: a
            # close interrupted before that leaves it to the next close
            closed = False
            with suppress(OSError):
                sock.close()
                closed = True
            self._socket = None
            if not closed:
                raise _TransportError(
                    f"closing {_quoted(self._host)}:{_quoted(self._port)}"
                )

    def _discard(self) -> None:
        """Close the connection after a failure, which stays the one raised."""
        with suppress(FetchError):
            self.close()

    def send(self, message: Message, timeout: float) -> None:
        """Write one message, connecting first if there is no connection."""
        if not isinstance(message, Message):
            raise BTClibTypeError(f"non-Message message: {_message_text(message)}")
        valid_timeout(timeout)
        deadline = monotonic() + timeout
        where = f"{_quoted(self._host)}:{_quoted(self._port)}"
        try:
            sock = self._socket
            # a close interrupted once the socket closed leaves it held
            if sock is None or sock.fileno() == -1:
                sock = self._socket = create_connection(
                    (self._host, self._port), timeout=timeout
                )
            sock.settimeout(_time_left(deadline, timeout, where))
            sock.sendall(message.serialize())
        except OSError:
            pass
        except _TransportError:
            self._discard()
            raise
        else:
            return
        self._discard()
        raise _TransportError(f"no connection to {where}")

    def receive(self, timeout: float) -> Message:
        """Return the next message the peer sends, waiting up to `timeout`."""
        valid_timeout(timeout)
        where = f"{_quoted(self._host)}:{_quoted(self._port)}"
        sock = self._socket
        if sock is None:
            raise _TransportError(f"{where}: not connected")
        deadline = monotonic() + timeout
        failure: str
        try:
            header = _read(sock, _HEADER_SIZE, deadline, timeout, where)
            missing = 0
            try:
                # refuses a length over the bound before any payload is read
                return Message.parse(header)
            except IncompleteMessageError as e:
                missing = e.missing
            rest = _read(sock, missing, deadline, timeout, where)
            return Message.parse(header + rest)
        except OSError:
            failure = f"no message from {where}"
        except ValueError:
            failure = f"{where}: a message that does not parse"
        except _TransportError:
            self._discard()
            raise
        self._discard()
        raise _TransportError(failure)


class V2PeerTransport:
    """A `PeerTransport` over BIP324's v2 transport to one peer.

    Constructed with the host and port it connects to, as
    `TcpPeerTransport` is, and opening nothing until the first `send`.
    That `send` connects on the network of its message's magic, over v2
    or the v1 fallback, and a later `send` of a message for another
    network is refused until `close`. It works as a context manager that
    closes on exit.

    The module docstring says what the encryption protects against.
    Construction raises `BTClibRuntimeError`, naming the `encryption`
    extra, where the `cryptography` package is missing.

    `v1_fallback` is whether a peer that hangs up on the handshake, as a
    v1 peer does, is connected to again over v1. Off by default: the
    second connection is plain text, and the hang-up is a `FetchError`.

    Everything that goes wrong below the message is a `FetchError`, as
    for `TcpPeerTransport`: a failed handshake, a packet whose tag does
    not match, a packet announcing more than a peer may send. A packet
    whose message type the codec refuses is dropped, as Core drops it.
    """

    def __init__(self, host: str, port: int, *, v1_fallback: bool = False) -> None:
        _assert_peer(host, port)
        assert_type(v1_fallback, bool, "v1_fallback")
        _assert_bip324()
        self._host = host
        self._port = port
        self._v1_fallback = v1_fallback
        self._socket: socket | None = None
        self._cipher: Cipher | None = None
        self._magic = b""
        # the connection over v1, where the fallback took over
        self._v1: TcpPeerTransport | None = None
        # a socket or a v1 transport not yet kept, or one being closed:
        # it is held here from the moment it is made until it is closed,
        # so that whatever interrupts its opening or its closing, a
        # `KeyboardInterrupt` included, leaves it to `close`
        self._pending: socket | TcpPeerTransport | None = None

    @property
    def host(self) -> str:
        """Return the host this transport connects to."""
        return self._host

    @property
    def port(self) -> int:
        """Return the port this transport connects to."""
        return self._port

    @property
    def is_open(self) -> bool:
        """Return whether a connection is open, over v2 or v1."""
        return self._socket is not None or (self._v1 is not None and self._v1.is_open)

    @property
    def session_id(self) -> bytes | None:
        """Return the v2 connection's session id, or None without one.

        None where no connection is open, or where it is over v1.
        """
        return None if self._cipher is None else self._cipher.session_id

    def __enter__(self) -> Self:
        """Return this transport."""
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Close the connection."""
        self.close()

    def close(self) -> None:
        """Close the connection, if there is one.

        The next `send` tries v2 again.
        """
        # at most one of the three is set; from here it is pending, no
        # longer open, and it is let go of only once closed
        self._pending, self._v1, self._socket, self._cipher, self._magic = (
            self._pending or self._v1 or self._socket,
            None,
            None,
            None,
            b"",
        )
        self._close_pending()

    def _close_pending(self) -> None:
        """Close what is pending, and only then let go of it."""
        pending = self._pending
        if pending is not None:
            closed = False
            try:
                pending.close()
                closed = True
            except OSError:
                pass
            except _TransportError:
                self._pending = None
                raise
            self._pending = None
            if not closed:
                raise _TransportError(
                    f"closing {_quoted(self._host)}:{_quoted(self._port)}"
                )

    def _discard(self) -> None:
        """Close the connection after a failure, which stays the one raised."""
        with suppress(FetchError):
            self.close()

    def send(self, message: Message, timeout: float) -> None:
        """Write one message, connecting first if there is no connection."""
        if not isinstance(message, Message):
            raise BTClibTypeError(f"non-Message message: {_message_text(message)}")
        valid_timeout(timeout)
        # one built with check_validity=False is asked again, before
        # anything is connected or encrypted
        message.assert_valid()
        self._assert_network(message)
        from btclib.p2p.bip324 import contents_from_message  # noqa: PLC0415

        deadline = monotonic() + timeout
        where = f"{_quoted(self._host)}:{_quoted(self._port)}"
        failure: str
        try:
            if self._v1 is not None:
                self._v1.send(message, timeout)
                return
            if self._socket is None:
                v1 = self._connect(message.magic, deadline, timeout, where)
                if v1 is not None:
                    self._open_v1(v1, message, _time_left(deadline, timeout, where))
                    return
            sock, cipher = self._connection()
            packet = cipher.encrypt(
                contents_from_message(message.command, message.payload)
            )
            sock.settimeout(_time_left(deadline, timeout, where))
            sock.sendall(packet)
        except OSError:
            failure = f"no connection to {where}"
        except ValueError as e:
            failure = f"{where}: {type(e).__name__}"
        except _TransportError:
            self._discard()
            raise
        except BaseException:
            # a `KeyboardInterrupt` can leave a packet half written
            self._discard()
            raise
        else:
            return
        self._discard()
        raise _TransportError(failure)

    def _assert_network(self, message: Message) -> None:
        """Refuse a message for another network than the connection's.

        A v1 connection that closed itself, on a failure that an interrupt
        kept from closing this transport, is closed first, so that the
        `send` calling this starts again over v2, as after `close`.
        """
        if self._v1 is not None and not self._v1.is_open:
            self._discard()
        if self._magic and message.magic != self._magic:
            raise BTClibValueError("message for another network than the connection")

    def _open_v1(self, v1: TcpPeerTransport, message: Message, timeout: float) -> None:
        """Send the first message over the v1 fallback, and keep it only then.

        Until then it is pending, so that anything raised, `KeyboardInterrupt`
        included, leaves it to `close`.
        """
        v1.send(message, timeout)
        self._v1, self._magic, self._pending = v1, message.magic, None

    def _connection(self) -> tuple[socket, Cipher]:
        """Return the socket and the cipher of the open v2 connection."""
        if self._socket is None or self._cipher is None:
            raise _TransportError(
                f"{_quoted(self._host)}:{_quoted(self._port)}: not connected"
            )
        return self._socket, self._cipher

    def _connect(
        self, magic: bytes, deadline: float, timeout: float, where: str
    ) -> TcpPeerTransport | None:
        """Connect and complete the handshake as its initiator.

        The connection is kept only once the handshake completes: until
        then the socket is pending, so that anything raised, `KeyboardInterrupt`
        included, leaves it to `close`. A peer that hangs up as a v1 peer
        does, before sending a byte, while we write or while we read, is
        refused, or answered with a v1 transport, not yet open, pending in
        its place, where the caller asked for one. A v2 connection is kept
        on the network of `magic`.
        """
        # what an interrupted call left pending, if anything
        with suppress(FetchError):
            self._close_pending()
        sock = self._pending = create_connection(
            (self._host, self._port), timeout=timeout
        )
        cipher = _handshake(sock, magic, deadline, timeout, where)
        if cipher is None:
            with suppress(FetchError):
                self._close_pending()
            if not self._v1_fallback:
                err_msg = f"{where} hung up on the v2 handshake, as a v1 peer"
                raise _TransportError(f"{err_msg} does, and v1_fallback is off")
            v1 = self._pending = TcpPeerTransport(self._host, self._port)
            return v1
        self._socket, self._cipher, self._magic, self._pending = (
            sock,
            cipher,
            magic,
            None,
        )
        return None

    def receive(self, timeout: float) -> Message:
        """Return the next message the peer sends, waiting up to `timeout`.

        Decoy packets, and packets whose message type the codec refuses,
        are dropped.
        """
        valid_timeout(timeout)
        from btclib.p2p.bip324 import message_from_contents  # noqa: PLC0415

        where = f"{_quoted(self._host)}:{_quoted(self._port)}"
        deadline = monotonic() + timeout
        failure: str
        try:
            if self._v1 is not None:
                return self._v1.receive(timeout)
            sock, cipher = self._connection()
            while True:
                contents, ignore = _packet(sock, cipher, b"", deadline, timeout, where)
                if ignore:
                    continue
                try:
                    command, payload = message_from_contents(contents)
                except BTClibValueError:
                    continue
                return Message(self._magic, command, payload)
        except OSError:
            failure = f"no message from {where}"
        except ValueError as e:
            failure = f"{where}: {type(e).__name__}"
        except _TransportError:
            self._discard()
            raise
        except BaseException:
            # a `KeyboardInterrupt` can leave a packet half read
            self._discard()
            raise
        self._discard()
        raise _TransportError(failure)


def _handshake(
    sock: socket, magic: bytes, deadline: float, timeout: float, where: str
) -> Cipher | None:
    """Return the cipher of a v2 handshake completed as its initiator.

    None where the peer hung up as a v1 peer does: before sending a byte,
    and after a v1 header's worth of ours, which is the rule of Core's
    `ShouldReconnectV1`. The hang-up is seen on a write or on a read.
    """
    from btclib.p2p.bip324 import (  # noqa: PLC0415
        GARBAGE_TERMINATOR_LEN,
        Cipher,
    )

    prv_key = 1 + secrets.randbelow(secp256k1.n - 1)
    ell_ours = ellswift.create(prv_key)
    garbage = secrets.token_bytes(secrets.randbelow(_MAX_GARBAGE_LEN + 1))
    if not _send_key(sock, ell_ours + garbage, deadline, timeout, where):
        return None
    sock.settimeout(_time_left(deadline, timeout, where))
    try:
        first = sock.recv(1)
    except ConnectionError:
        first = b""
    if not first:
        return None
    ell_theirs = first + _read(sock, ELL_SIZE - 1, deadline, timeout, where)
    cipher = Cipher(prv_key, ell_ours, ell_theirs, initiator=True, magic=magic)
    sock.settimeout(_time_left(deadline, timeout, where))
    # the garbage is authenticated by the version packet, whose
    # contents are reserved for extensions and empty
    sock.sendall(cipher.send_garbage_terminator + cipher.encrypt(b"", garbage))

    received = _read(sock, GARBAGE_TERMINATOR_LEN, deadline, timeout, where)
    while received[-GARBAGE_TERMINATOR_LEN:] != cipher.recv_garbage_terminator:
        if len(received) == _MAX_GARBAGE_LEN + GARBAGE_TERMINATOR_LEN:
            raise _TransportError(f"{where}: no garbage terminator")
        received += _read(sock, 1, deadline, timeout, where)
    # the peer's garbage is authenticated by its first packet, a decoy
    # or the version packet, whose contents are ignored
    aad = received[:-GARBAGE_TERMINATOR_LEN]
    ignore = True
    while ignore:
        _, ignore = _packet(sock, cipher, aad, deadline, timeout, where)
        aad = b""
    return cipher


def _send_key(
    sock: socket, data: bytes, deadline: float, timeout: float, where: str
) -> bool:
    """Write the key and the garbage; return False where the peer hung up.

    A hang-up is refused, as any failure, until a v1 header's worth is
    written: a v1 peer hangs up on a header it cannot read.
    """
    written = 0
    hung_up = False
    try:
        while written < len(data):
            sock.settimeout(_time_left(deadline, timeout, where))
            written += sock.send(data[written:])
    except ConnectionError:
        hung_up = True
    # refused after the `except` block, as every refusal of this module
    if hung_up and written < _HEADER_SIZE:
        raise _TransportError(f"no connection to {where}")
    return not hung_up


def _packet(
    sock: socket,
    cipher: Cipher,
    aad: bytes,
    deadline: float,
    timeout: float,
    where: str,
) -> tuple[bytes, bool]:
    """Return the next packet's contents, and whether it is a decoy.

    The length the packet announces is bounded before the rest is read.
    """
    from btclib.p2p.bip324 import EXPANSION, LENGTH_LEN  # noqa: PLC0415

    length = cipher.decrypt_length(_read(sock, LENGTH_LEN, deadline, timeout, where))
    if length > _MAX_CONTENTS_LEN:
        raise _TransportError(f"{where}: packet too large: {_quoted(length)} bytes")
    rest = _read(sock, EXPANSION - LENGTH_LEN + length, deadline, timeout, where)
    return cipher.decrypt(rest, aad)


def _read(
    sock: socket, size: int, deadline: float, timeout: float, where: str
) -> bytes:
    """Return exactly `size` octets, or raise before `deadline`."""
    buffer = bytearray()
    while len(buffer) < size:
        sock.settimeout(_time_left(deadline, timeout, where))
        if not (chunk := sock.recv(min(_READ_CHUNK, size - len(buffer)))):
            raise _TransportError(f"{where}: connection closed before a whole message")
        buffer.extend(chunk)
    return bytes(buffer)
