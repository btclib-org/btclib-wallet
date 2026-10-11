# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The seam a p2p fetcher talks to one peer through, and the socket behind it.

`btclib.p2p` is the codec: it frames and parses a `Message` (its own
docstring says it opens no socket). `PeerTransport` is the seam where the
socket is, and `TcpPeerTransport` is the implementation that opens one. A
test replaces the seam with an object that answers from a script, as it replaces
`LineTransport` for `ElectrumFetcher`.

**A peer transport is a connection and not a call.** `LineTransport` is
one request and one answer on a connection of its own; a p2p peer sends
what it likes when it likes, and the handshake that opens a connection is
state both ends keep. So `PeerTransport` is `send`, `receive` and
`close`, and the connection is the object's.

**The connection is opened by the first `send` and again after any
failure.** A failure closes it, because a read cut short leaves the
stream in the middle of a message, and the caller learns that from the
exception and greets the peer again. A transport raises
`bitcoin_core_rpc`'s `FetchError`, the vocabulary `LineTransport` states,
which `btclib_wallet.fetch.fetcher.client_errors` translates.

**The network policy**, the one `TlsLineTransport` keeps:

- the length a message announces is compared with
  `MAX_PROTOCOL_MESSAGE_LENGTH` before any of its payload is read;
- a timeout over each call, connect included, rather than per socket
  operation, so a peer sending one octet at a time cannot hold a call open;
- no proxy from the environment: `socket.create_connection` reads none;
- the stream is plain TCP, as the p2p v1 transport is. A peer is anonymous
  and its messages are checked by the fetcher against what it already
  holds, which is the reason this layer authenticates nothing.
"""

from __future__ import annotations

from socket import create_connection, socket
from time import monotonic
from typing import Protocol, Self

from bitcoin_core_rpc import FetchError
from btclib.exceptions import (
    BTClibTypeError,
    BTClibValueError,
    IncompleteMessageError,
)
from btclib.p2p.message import Message
from btclib.utils import is_integer

from btclib_wallet.fetch.transport import (
    _MAX_PORT,
    _READ_CHUNK,
    _time_left,
    valid_timeout,
)

__all__ = [
    "PeerTransport",
    "TcpPeerTransport",
]

# the size of a message header, `btclib.p2p.message`'s own layout
_HEADER_SIZE = 24


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
    message, a message announcing more than a peer may send, a checksum
    that does not match -- is a `FetchError`.
    """

    def __init__(self, host: str, port: int) -> None:
        if not isinstance(host, str):
            raise BTClibTypeError(f"non-string host: {host!r}")
        if not host:
            raise BTClibValueError("empty host")
        try:
            # what `create_connection` encodes the host with, and a
            # `UnicodeError` rather than an `OSError` there
            host.encode("idna")
        except UnicodeError as e:
            raise BTClibValueError(f"invalid host: {host!r}") from e
        if not is_integer(port):
            raise BTClibTypeError(f"non-integer port: {port!r}")
        if not 0 < port <= _MAX_PORT:
            raise BTClibValueError(f"invalid port: {port}")
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
        return self._socket is not None

    def __enter__(self) -> Self:
        """Return this transport."""
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Close the connection."""
        self.close()

    def close(self) -> None:
        """Close the connection, if there is one."""
        if self._socket is not None:
            sock, self._socket = self._socket, None
            sock.close()

    def send(self, message: Message, timeout: float) -> None:
        """Write one message, connecting first if there is no connection."""
        if not isinstance(message, Message):
            raise BTClibTypeError(f"non-Message message: {message!r}")
        valid_timeout(timeout)
        deadline = monotonic() + timeout
        where = f"{self._host}:{self._port}"
        try:
            sock = self._socket
            if sock is None:
                sock = self._socket = create_connection(
                    (self._host, self._port), timeout=timeout
                )
            sock.settimeout(_time_left(deadline, where))
            sock.sendall(message.serialize())
        except OSError as e:
            self.close()
            raise FetchError(f"no connection to {where}: {e}") from e
        except FetchError:
            self.close()
            raise

    def receive(self, timeout: float) -> Message:
        """Return the next message the peer sends, waiting up to `timeout`."""
        valid_timeout(timeout)
        where = f"{self._host}:{self._port}"
        sock = self._socket
        if sock is None:
            raise FetchError(f"{where}: not connected")
        deadline = monotonic() + timeout
        try:
            header = _read(sock, _HEADER_SIZE, deadline, where)
            try:
                # refuses a length over the bound before any payload is read
                return Message.parse(header)
            except IncompleteMessageError as e:
                rest = _read(sock, e.missing, deadline, where)
            return Message.parse(header + rest)
        except OSError as e:
            self.close()
            raise FetchError(f"no message from {where}: {e}") from e
        except ValueError as e:
            self.close()
            raise FetchError(f"{where}: {e}") from e
        except FetchError:
            self.close()
            raise


def _read(sock: socket, size: int, deadline: float, where: str) -> bytes:
    """Return exactly `size` octets, or raise before `deadline`."""
    buffer = bytearray()
    while len(buffer) < size:
        sock.settimeout(_time_left(deadline, where))
        chunk = sock.recv(min(_READ_CHUNK, size - len(buffer)))
        if not chunk:
            raise FetchError(f"{where}: connection closed before a whole message")
        buffer.extend(chunk)
    return bytes(buffer)
