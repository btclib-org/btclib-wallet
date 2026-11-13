# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `PersistentTlsLineTransport`, against TLS servers on loopback.

Each server listens on 127.0.0.1 and answers with a certificate of a test
authority made here, which the client's context trusts, so the handshake
and the host check run as they do against a server of one's own. Every
answer of the default handler carries the number of the connection it
came over, counted from 1, which is what tells a kept connection from a
new one.
"""

from __future__ import annotations

import ipaddress
import json
import select
import socket
import ssl
import threading
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from bitcoin_core_rpc import FetchError as RpcFetchError
from btclib.exceptions import BTClibTypeError, BTClibValueError
from typing_extensions import override

from btclib_wallet.electrum import (
    _reply_ids,
    encode_request,
    scripthash_get_balance_batch_request,
    scripthash_get_balance_batch_response,
)
from btclib_wallet.fetch import transport as transport_module
from btclib_wallet.fetch.electrum import ElectrumFetcher
from btclib_wallet.fetch.transport import PersistentTlsLineTransport
from tests import chained_text
from tests.fetch.electrum_history_test import MINE, _chain
from tests.fetch.history_test import OURS

# an install on Windows arm64 leaves `cryptography` out
x509 = pytest.importorskip("cryptography.x509")
ec = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ec")
hashes = pytest.importorskip("cryptography.hazmat.primitives.hashes")
serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")

HOST = "127.0.0.1"
# what a call that is answered waits for at most
TIMEOUT = 10.0
NOTIFICATION = b'{"method": "blockchain.headers.subscribe", "params": [{}]}'
# a notification as the elder JSON-RPC writes it, with a `null` id
NULL_ID_NOTIFICATION = (
    b'{"id": null, "method": "blockchain.headers.subscribe", "params": [{}]}'
)
# what a server line carries that no error may quote
MARKER = "marked-by-the-server"


def request(request_id: int) -> bytes:
    """Return a `server.ping` request line with this id."""
    return encode_request(request_id, "server.ping")


def answer(request_id: object, result: object) -> bytes:
    """Return the line answering `request_id` with `result`, no newline."""
    return json.dumps({"id": request_id, "result": result}).encode()


def answered_over(line: bytes) -> int:
    """Return the number of the connection a default answer came over."""
    result = json.loads(line)["result"]
    assert isinstance(result, int)
    return result


class Authority:
    """A certificate authority, and a server certificate it issued for HOST."""

    def __init__(self, directory: Path) -> None:
        now = datetime.now(UTC)
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test CA")])
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_usage = x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        )
        ca = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(ca_usage, critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        key = ec.generate_private_key(ec.SECP256R1())
        usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
        server_auth = x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH])
        address = x509.IPAddress(ipaddress.ip_address(HOST))
        cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, HOST)])
            )
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(usage, critical=True)
            .add_extension(server_auth, critical=False)
            .add_extension(x509.SubjectAlternativeName([address]), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        self.ca_pem = ca.public_bytes(serialization.Encoding.PEM).decode()
        self.cert_file = directory / "cert.pem"
        self.cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self.key_file = directory / "key.pem"
        self.key_file.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )


@pytest.fixture(scope="module")
def authority(tmp_path_factory: pytest.TempPathFactory) -> Authority:
    """Return the authority every server's certificate here chains to."""
    return Authority(tmp_path_factory.mktemp("authority"))


class Peer:
    """The server's end of one connection: request lines in, lines out."""

    def __init__(self, connection: ssl.SSLSocket, number: int) -> None:
        self.connection = connection
        self.number = number
        self._buffer = b""

    def read(self) -> bytes | None:
        """Return the next request line, or None once the client closed."""
        while b"\n" not in self._buffer:
            if chunk := self.connection.recv(4096):
                self._buffer += chunk
            else:
                return None
        line, _, self._buffer = self._buffer.partition(b"\n")
        return line + b"\n"

    def send(self, *lines: bytes) -> None:
        """Send `lines` in one write, each with its newline."""
        self.connection.sendall(b"".join(line + b"\n" for line in lines))


Handler = Callable[[Peer], None]


def numbered(peer: Peer) -> None:
    """Answer each request with the number of the connection it came over."""
    while (line := peer.read()) is not None:
        peer.send(answer(json.loads(line)["id"], peer.number))


class Server:
    """A TLS server on HOST, serving each connection with `handler`.

    `accepted` counts the connections it took. `ended` is set once the
    client has closed a connection the handler read to its end.
    """

    def __init__(self, authority: Authority, handler: Handler) -> None:
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(authority.cert_file, authority.key_file)
        self._handler = handler
        self._listener = socket.create_server((HOST, 0))
        # what lets `close` stop the accepting thread on every platform
        self._listener.settimeout(0.05)
        self.port: int = self._listener.getsockname()[1]
        self.accepted = 0
        self.ended = threading.Event()
        self._stop = threading.Event()
        self._sockets: list[ssl.SSLSocket] = []
        self._threads = [threading.Thread(target=self._accept)]
        self._threads[0].start()

    def _accept(self) -> None:
        while not self._stop.is_set():
            try:
                sock, _ = self._listener.accept()
            except TimeoutError:
                continue
            self.accepted += 1
            thread = threading.Thread(target=self._serve, args=(sock, self.accepted))
            self._threads.append(thread)
            thread.start()

    def _serve(self, sock: socket.socket, number: int) -> None:
        sock.settimeout(None)
        # a client refusing the handshake, or closing mid-line, ends it
        with (
            suppress(OSError),
            self._context.wrap_socket(sock, server_side=True) as tls,
        ):
            self._sockets.append(tls)
            self._handler(Peer(tls, number))
            self.ended.set()

    def close(self) -> None:
        """Stop accepting, end every connection, and wait for the threads."""
        self._stop.set()
        self._threads[0].join()
        self._listener.close()
        # the plain socket's shutdown wakes a handler blocked in a read,
        # and leaves the TLS state to the thread that owns it
        for tls in self._sockets:
            with suppress(OSError):
                socket.socket.shutdown(tls, socket.SHUT_RDWR)
        for thread in self._threads[1:]:
            thread.join(TIMEOUT)


@pytest.fixture
def serve(authority: Authority) -> Iterator[Callable[[Handler], Server]]:
    """Return what starts a server with a handler, closing each at teardown."""
    servers: list[Server] = []

    def start(handler: Handler) -> Server:
        server = Server(authority, handler)
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.close()


class Recording(ssl.SSLContext):
    """A client context that keeps each connection it wraps."""

    connections: list[ssl.SSLSocket]

    @override
    def wrap_socket(
        self, sock: socket.socket, *args: Any, **kwargs: Any
    ) -> ssl.SSLSocket:
        """Wrap `sock` as the base class does, and keep the result."""
        connection = super().wrap_socket(sock, *args, **kwargs)
        self.connections.append(connection)
        return connection


def trusting(authority: Authority) -> Recording:
    """Return a client context trusting `authority`, the host checked."""
    context = Recording(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=authority.ca_pem)
    context.connections = []
    return context


def client(
    server: Server, authority: Authority, max_line_size: int = 1 << 20
) -> PersistentTlsLineTransport:
    """Return a transport to `server`, trusting `authority`."""
    return PersistentTlsLineTransport(
        HOST, server.port, context=trusting(authority), max_line_size=max_line_size
    )


def last_connection(transport: PersistentTlsLineTransport) -> ssl.SSLSocket:
    """Return the last connection `transport` opened."""
    return cast("Recording", transport.context).connections[-1]


def wait_readable(transport: PersistentTlsLineTransport) -> None:
    """Wait until the last connection `transport` opened has data or an end."""
    readable, _, _ = select.select([last_connection(transport)], [], [], TIMEOUT)
    assert readable


def test_calls_share_one_connection(
    serve: Callable[[Handler], Server], authority: Authority
) -> None:
    """The connect and the handshake are paid once."""
    server = serve(numbered)
    with client(server, authority) as transport:
        # construction opens nothing
        assert server.accepted == 0
        assert [answered_over(transport(request(i), TIMEOUT)) for i in (1, 2, 3)] == [
            1,
            1,
            1,
        ]
        assert transport.is_open
    assert server.accepted == 1


def test_a_notification_before_the_answer_is_set_aside(
    serve: Callable[[Handler], Server], authority: Authority
) -> None:
    """What the server pushes is not the answer, and keeps the connection."""

    def notifying(peer: Peer) -> None:
        while (line := peer.read()) is not None:
            request_id = json.loads(line)["id"]
            peer.send(NOTIFICATION)
            peer.send(NOTIFICATION, answer(request_id, peer.number))

    server = serve(notifying)
    with client(server, authority) as transport:
        assert transport(request(1), TIMEOUT) == answer(1, 1)
        assert transport(request(2), TIMEOUT) == answer(2, 1)
    assert server.accepted == 1


def test_a_batch_is_answered_by_one_line(
    serve: Callable[[Handler], Server], authority: Authority
) -> None:
    """A batch's ids are what its answer is matched to, in any order."""

    def batching(peer: Peer) -> None:
        while (line := peer.read()) is not None:
            balances = [
                {"id": member["id"], "result": {"confirmed": i, "unconfirmed": 0}}
                for i, member in enumerate(reversed(json.loads(line)))
            ]
            peer.send(NOTIFICATION, json.dumps(balances).encode())

    server = serve(batching)
    batch = scripthash_get_balance_batch_request({7: "00" * 32, 8: "11" * 32})
    with client(server, authority) as transport:
        line = transport(batch, TIMEOUT)
    balances = scripthash_get_balance_batch_response(line, [7, 8])
    assert [balance.confirmed for balance in balances] == [1, 0]


@pytest.mark.parametrize("notification", [NOTIFICATION, NULL_ID_NOTIFICATION])
def test_a_notification_with_or_without_a_null_id_is_set_aside(
    notification: bytes,
    serve: Callable[[Handler], Server],
    authority: Authority,
) -> None:
    """A `null` id with a `method` is a notification, not an answer."""

    def notifying(peer: Peer) -> None:
        while (line := peer.read()) is not None:
            peer.send(notification, answer(json.loads(line)["id"], peer.number))

    server = serve(notifying)
    with client(server, authority) as transport:
        assert transport(request(1), TIMEOUT) == answer(1, 1)
        assert transport(request(2), TIMEOUT) == answer(2, 1)


def test_a_reused_id_opens_a_new_connection(
    serve: Callable[[Handler], Server], authority: Authority
) -> None:
    """A late copy of an answer is never read as the answer to a later call.

    Fetchers sharing a transport count their ids each from 1. Here the
    server, asked an id again on one connection, first sends its earlier
    answer again, past the check the call makes before it sends. Each
    answer names its connection and its place there. The ids a connection
    carried go with it, so the new one carries the other id again.
    """

    def repeating(peer: Peer) -> None:
        # the answers sent on this connection, by request id
        sent: dict[int, list[bytes]] = {}
        place = 0
        while (line := peer.read()) is not None:
            place += 1
            request_id = json.loads(line)["id"]
            copies = sent.setdefault(request_id, [])
            copies.append(answer(request_id, f"{peer.number}.{place}"))
            peer.send(*copies)

    server = serve(repeating)
    with client(server, authority) as transport:
        lines = [transport(request(i), TIMEOUT) for i in (1, 2, 1, 2)]
    assert lines == [
        answer(1, "1.1"),
        answer(2, "1.2"),
        answer(1, "2.1"),
        answer(2, "2.2"),
    ]
    assert server.accepted == 2


def test_a_connection_is_replaced_once_it_carried_its_ids(
    serve: Callable[[Handler], Server],
    authority: Authority,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ids kept of a connection are bounded, and kept until it goes."""
    monkeypatch.setattr(transport_module, "_MAX_IDS_PER_CONNECTION", 2)
    server = serve(numbered)
    with client(server, authority) as transport:
        lines = [transport(request(i), TIMEOUT) for i in (1, 2, 3, 4, 5)]
    assert lines == [
        answer(1, 1),
        answer(2, 1),
        answer(3, 2),
        answer(4, 2),
        answer(5, 3),
    ]
    assert server.accepted == 3


@pytest.mark.parametrize(
    "before", [(NOTIFICATION,), ()], ids=["buffered notification", "answer"]
)
def test_the_deadline_holds_over_each_line_read(
    before: tuple[bytes, ...],
    serve: Callable[[Handler], Server],
    authority: Authority,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An answer is not returned once the deadline has passed.

    The clock moves past the deadline as each line is read: the
    notification, with the answer already in the buffer, or the answer
    itself.
    """
    now = [1000.0]
    monkeypatch.setattr(transport_module, "monotonic", lambda: now[0])

    def slow_reply_ids(line: bytes) -> frozenset[int] | None:
        now[0] += TIMEOUT
        return _reply_ids(line)

    monkeypatch.setattr(transport_module, "_reply_ids", slow_reply_ids)

    def notifying(peer: Peer) -> None:
        while (line := peer.read()) is not None:
            peer.send(*before, answer(json.loads(line)["id"], peer.number))

    server = serve(notifying)
    with client(server, authority) as transport:
        with pytest.raises(RpcFetchError, match="timeout expired"):
            transport(request(1), TIMEOUT)
        assert not transport.is_open


def test_a_null_id_answers_the_request(
    serve: Callable[[Handler], Server], authority: Authority
) -> None:
    """A server that could not parse a request answers it with no id."""
    error = b'{"id": null, "error": {"code": -32700, "message": "parse error"}}'

    def unparsed(peer: Peer) -> None:
        while peer.read() is not None:
            peer.send(error)

    server = serve(unparsed)
    with client(server, authority) as transport:
        assert transport(request(1), TIMEOUT) == error


@pytest.mark.parametrize(
    "line, match",
    [
        (answer(2, "late"), "answering another request"),
        (answer([1], 1), "no JSON-RPC message"),
        (b'{"result": 1}', "no JSON-RPC message"),
        (b'{"id": null, "result": 1}', "no JSON-RPC message"),
        (b"[]", "no JSON-RPC message"),
        (b'{"id": 1, "method": "server.ping"}', "no JSON-RPC message"),
        (b"[" * 17 + b"]" * 17, "no JSON-RPC message"),
        (MARKER.encode(), "no JSON-RPC message"),
    ],
)
def test_a_line_answering_no_request_closes_the_connection(
    line: bytes,
    match: str,
    serve: Callable[[Handler], Server],
    authority: Authority,
) -> None:
    """Refused, and the next call opens a new connection."""

    def stale(peer: Peer) -> None:
        while (asked := peer.read()) is not None:
            if peer.number == 1:
                peer.send(line)
            peer.send(answer(json.loads(asked)["id"], peer.number))

    server = serve(stale)
    with client(server, authority) as transport:
        with pytest.raises(RpcFetchError, match=match):
            transport(request(1), TIMEOUT)
        assert not transport.is_open
        assert transport(request(3), TIMEOUT) == answer(3, 2)


def test_no_error_quotes_the_server(
    serve: Callable[[Handler], Server], authority: Authority
) -> None:
    """A line the server sends is described, never written out."""

    def quoting(peer: Peer) -> None:
        while peer.read() is not None:
            peer.send(json.dumps({"id": MARKER, "result": MARKER}).encode())

    server = serve(quoting)
    with client(server, authority) as transport, pytest.raises(RpcFetchError) as e:
        transport(request(1), TIMEOUT)
    assert MARKER not in chained_text(e.value)


def test_a_line_over_the_limit_closes_the_connection(
    serve: Callable[[Handler], Server], authority: Authority
) -> None:
    """The line is bounded on a kept connection too.

    What was read of the refused line goes with the connection, so the
    next call reads its answer whole.
    """

    def long(peer: Peer) -> None:
        while (line := peer.read()) is not None:
            result = "x" * 64 if peer.number == 1 else peer.number
            peer.send(answer(json.loads(line)["id"], result))

    server = serve(long)
    with client(server, authority, max_line_size=32) as transport:
        with pytest.raises(RpcFetchError, match="max_line_size of 32"):
            transport(request(1), TIMEOUT)
        assert not transport.is_open
        assert transport(request(2), TIMEOUT) == answer(2, 2)


def test_a_late_answer_is_never_read(
    serve: Callable[[Handler], Server], authority: Authority
) -> None:
    """A call that timed out leaves no answer for the next to read."""
    asked = threading.Event()
    release = threading.Event()

    def late(peer: Peer) -> None:
        while (line := peer.read()) is not None:
            if peer.number == 1:
                asked.set()
                release.wait(TIMEOUT)
            # the connection may be gone by now
            with suppress(OSError):
                peer.send(answer(json.loads(line)["id"], peer.number))

    server = serve(late)
    with client(server, authority) as transport:
        with pytest.raises(RpcFetchError, match="timed out|timeout expired"):
            transport(request(1), 0.5)
        assert asked.is_set()
        assert not transport.is_open
        release.set()
        assert transport(request(2), TIMEOUT) == answer(2, 2)


@pytest.mark.parametrize("poll", [True, False])
def test_a_connection_the_server_closed_is_replaced(
    poll: bool,
    serve: Callable[[Handler], Server],
    authority: Authority,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A server's idle close is found before the request is sent.

    With `select.poll`, and with `select.select`, which Windows has alone.
    """
    if not poll:
        monkeypatch.delattr(select, "poll", raising=False)

    def once(peer: Peer) -> None:
        line = peer.read()
        assert line is not None
        peer.send(answer(json.loads(line)["id"], peer.number))

    server = serve(once)
    with client(server, authority) as transport:
        assert transport(request(1), TIMEOUT) == answer(1, 1)
        wait_readable(transport)
        assert transport(request(2), TIMEOUT) == answer(2, 2)


def test_a_notification_between_calls_is_not_read(
    serve: Callable[[Handler], Server], authority: Authority
) -> None:
    """Data on the kept connection before a call sends is a new connection."""

    def pushing(peer: Peer) -> None:
        while (line := peer.read()) is not None:
            peer.send(answer(json.loads(line)["id"], peer.number))
            if peer.number == 1:
                peer.send(NOTIFICATION)

    server = serve(pushing)
    with client(server, authority) as transport:
        assert transport(request(1), TIMEOUT) == answer(1, 1)
        wait_readable(transport)
        assert transport(request(2), TIMEOUT) == answer(2, 2)


@pytest.mark.parametrize("held", ["buffer", "tls"])
def test_what_is_left_of_a_read_is_a_new_connection(
    held: str, serve: Callable[[Handler], Server], authority: Authority
) -> None:
    """A notification sent with the answer is read with it, or held by TLS.

    One write is one TLS record, which the read decrypts whole. Where the
    read asks for more than the answer, what follows it is in the
    transport's buffer; where it asks for the answer exactly, the rest is
    pending in the TLS layer, and the socket has nothing to read.
    """
    first = answer(1, 1)
    # the first read asks for one octet past the limit
    limit = len(first) if held == "tls" else 1 << 10

    def trailing(peer: Peer) -> None:
        while (line := peer.read()) is not None:
            peer.send(answer(json.loads(line)["id"], peer.number), NOTIFICATION)

    server = serve(trailing)
    with client(server, authority, max_line_size=limit) as transport:
        assert transport(request(1), TIMEOUT) == first
        connection = last_connection(transport)
        assert (connection.pending() > 0) is (held == "tls")
        readable, _, _ = select.select([connection], [], [], 0)
        assert not readable
        assert transport(request(2), TIMEOUT) == answer(2, 2)


def test_closing_ends_the_connection(
    serve: Callable[[Handler], Server], authority: Authority
) -> None:
    """The end of a `with` block closes it, and the server reads the end."""
    server = serve(numbered)
    with client(server, authority) as transport:
        transport(request(1), TIMEOUT)
    assert not transport.is_open
    assert server.ended.wait(TIMEOUT)
    transport.close()
    # a call after the close opens a new connection
    with transport:
        assert transport(request(2), TIMEOUT) == answer(2, 2)


class FailingClose(ssl.SSLSocket):
    """A connection whose close raises, once it has closed."""

    @override
    def close(self) -> None:
        """Close, then fail."""
        super().close()
        raise OSError(MARKER)


def test_a_close_that_fails_is_a_fetch_error(
    serve: Callable[[Handler], Server], authority: Authority
) -> None:
    """Raised by `close`, and set aside for the failure that closes it."""

    def second_stale(peer: Peer) -> None:
        while (line := peer.read()) is not None:
            request_id = json.loads(line)["id"]
            peer.send(answer(request_id if peer.number == 1 else 99, peer.number))

    server = serve(second_stale)
    transport = client(server, authority)
    transport.context.sslsocket_class = FailingClose
    assert transport(request(1), TIMEOUT) == answer(1, 1)
    with pytest.raises(RpcFetchError, match=f"closing {HOST}:{server.port}"):
        transport.close()
    assert not transport.is_open
    with pytest.raises(RpcFetchError, match="answering another request"):
        transport(request(2), TIMEOUT)
    assert not transport.is_open


def test_the_default_context_refuses_an_untrusted_server(
    serve: Callable[[Handler], Server],
) -> None:
    """TLS is verified by default: a test authority is no trusted one."""
    server = serve(numbered)
    with PersistentTlsLineTransport(HOST, server.port) as transport:
        with pytest.raises(RpcFetchError, match="CERTIFICATE_VERIFY_FAILED"):
            transport(request(1), TIMEOUT)
        assert not transport.is_open


def test_no_proxy_is_taken_from_the_environment(
    serve: Callable[[Handler], Server],
    authority: Authority,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A proxy named in the environment is not where the call goes."""
    for name in ("https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    server = serve(numbered)
    with client(server, authority) as transport:
        assert transport(request(1), TIMEOUT) == answer(1, 1)


def test_calls_from_several_threads_take_turns(
    serve: Callable[[Handler], Server], authority: Authority
) -> None:
    """Each call reads its own answer, over the one connection."""

    def echoing(peer: Peer) -> None:
        while (line := peer.read()) is not None:
            request_id = json.loads(line)["id"]
            peer.send(answer(request_id, request_id))

    server = serve(echoing)
    ids = range(1, 33)
    with client(server, authority) as transport, ThreadPoolExecutor(8) as pool:
        lines = list(pool.map(lambda i: transport(request(i), TIMEOUT), ids))
    assert lines == [answer(i, i) for i in ids]
    assert server.accepted == 1


def test_the_wait_for_the_connection_counts_against_the_deadline(
    serve: Callable[[Handler], Server], authority: Authority
) -> None:
    """A call queued behind a slow one fails at its own deadline."""
    asked = threading.Event()
    release = threading.Event()

    def slow(peer: Peer) -> None:
        while (line := peer.read()) is not None:
            asked.set()
            release.wait(TIMEOUT)
            peer.send(answer(json.loads(line)["id"], peer.number))

    server = serve(slow)
    with client(server, authority) as transport, ThreadPoolExecutor(1) as pool:
        first = pool.submit(transport, request(1), TIMEOUT)
        assert asked.wait(TIMEOUT)
        with pytest.raises(RpcFetchError, match="timeout expired"):
            transport(request(2), 0.2)
        # it did not wait for the slow call to end
        assert not first.done()
        release.set()
        assert first.result() == answer(1, 1)


def test_electrum_fetcher_reads_a_history_over_it(
    serve: Callable[[Handler], Server], authority: Authority
) -> None:
    """The same history as over the server in memory, on one connection.

    Each answer follows a notification, as on a connection that asked
    `blockchain.headers.subscribe`.
    """
    chain = _chain()

    def history(peer: Peer) -> None:
        while (line := peer.read()) is not None:
            peer.send(NOTIFICATION, chain(line, TIMEOUT))

    expected = ElectrumFetcher("regtest", transport=chain, verify_network=False)
    server = serve(history)
    with client(server, authority) as transport:
        fetcher = ElectrumFetcher("regtest", transport=transport, verify_network=False)
        assert fetcher.get_history([OURS, MINE]) == expected.get_history([OURS, MINE])
        assert fetcher.get_block_count() == expected.get_block_count()
    assert server.accepted == 1


@pytest.mark.parametrize(
    "request_, timeout, error, match",
    [
        ("{}\n", 1.0, BTClibTypeError, "non-bytes request"),
        (b'{"id": 1}', 1.0, BTClibValueError, "one newline-terminated line"),
        (b"ping\n", 1.0, BTClibValueError, "not a JSON-RPC line"),
        (NOTIFICATION + b"\n", 1.0, BTClibValueError, "no request id"),
        (
            b'{"id": null, "method": "server.ping"}\n',
            1.0,
            BTClibValueError,
            "no request id",
        ),
        (b"[]\n", 1.0, BTClibValueError, "no request id"),
        (
            b'{"id": "1", "method": "server.ping"}\n',
            1.0,
            BTClibValueError,
            "integer id",
        ),
        (b"[1]\n", 1.0, BTClibValueError, "not a JSON-RPC message"),
        (request(1), True, BTClibTypeError, "non-numeric timeout"),
        (request(1), 0, BTClibValueError, "not a positive number of seconds"),
    ],
)
def test_a_call_validates_its_arguments_before_connecting(
    request_: Any, timeout: Any, error: type[Exception], match: str
) -> None:
    """Refused before anything is opened."""
    transport = PersistentTlsLineTransport(HOST, 1)
    with pytest.raises(error, match=match):
        transport(request_, timeout)
    assert not transport.is_open
