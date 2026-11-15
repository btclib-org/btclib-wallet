# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for btclib_wallet.fetch.fetcher, the half no backend re-implements."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import TypeVar

import bitcoin_core_rpc as rpc
import pytest
from btclib.alias import Octets
from btclib.block.block_header import BlockHeader
from btclib.exceptions import (
    BTClibRuntimeError,
    BTClibTypeError,
    BTClibValueError,
)
from btclib.network import NETWORKS
from btclib.script import ScriptPubKey
from btclib.tx import OutPoint, Tx, TxOut
from typing_extensions import override

from btclib_wallet.exceptions import FetchError, HttpError, RpcError
from btclib_wallet.fetch import peer_transport as peer_transport_module
from btclib_wallet.fetch import transport as transport_module
from btclib_wallet.fetch.compact_filters import CompactFilterFetcher
from btclib_wallet.fetch.decorators import CachingFetcher, FallbackFetcher
from btclib_wallet.fetch.electrum import ElectrumFetcher
from btclib_wallet.fetch.esplora import EsploraFetcher
from btclib_wallet.fetch.fetcher import (
    Fetcher,
    NetworkVerifyingFetcher,
    block_header_from_raw,
    block_header_height,
    client_errors,
    fetch_errors,
    tx_for_network,
    tx_from_raw,
    tx_id_hex,
)
from btclib_wallet.fetch.history import start_height_for_time
from btclib_wallet.fetch.peer_transport import TcpPeerTransport, V2PeerTransport
from btclib_wallet.fetch.transport import (
    PersistentTlsLineTransport,
    TcpLineTransport,
    TlsLineTransport,
)
from tests.fetch import (
    REGTEST_GENESIS_HEADER_RAW,
    SIGNET_GENESIS_HEADER_RAW,
    TIP_HEADER_RAW,
    TIP_HEIGHT,
    TIP_ID,
    TX_ID,
    Recorded,
    StubFetcher,
    recorded_body,
)
from tests.fetch.bitcoin_core_rest_test import fetcher as rest_fetcher
from tests.fetch.bitcoin_core_test import fetcher as core_fetcher
from tests.fetch.compact_filters_test import build as compact_filters_fetcher
from tests.fetch.electrum_history_test import FIRST, FUNDING, MINE, SPEND, FakeServer
from tests.fetch.electrum_history_test import _chain as electrum_chain
from tests.fetch.electrum_history_test import _fetcher as electrum_history_fetcher
from tests.fetch.electrum_test import MERKLE_TX_ID
from tests.fetch.electrum_test import fetcher as electrum_fetcher
from tests.fetch.esplora_history_test import FakeEsplora
from tests.fetch.esplora_history_test import _explorer as esplora_explorer
from tests.fetch.esplora_history_test import _fetcher as esplora_history_fetcher
from tests.fetch.esplora_test import BASE
from tests.fetch.esplora_test import fetcher as esplora_fetcher
from tests.fetch.history_test import OURS, _tx
from tests.refused_value_test import HEX, SCALAR, SPELLINGS
from tests.secret_free import assert_secret_free

RAW = recorded_body("esplora_tx_hex.txt").decode().strip()
# the coinbase of the same block, which is a different transaction with
# the same provenance: what a backend answering the wrong question sends
OTHER_ID = "b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082"


@pytest.mark.parametrize(
    "error",
    [
        ValueError("not a number"),
        TypeError("nothing to index"),
        # what the stream readers under Tx.parse raise, which is neither
        BTClibRuntimeError("not enough binary data"),
    ],
)
def test_fetch_errors_names_the_source(error: Exception) -> None:
    """Wrap parse-time exceptions in a FetchError naming the call.

    A builtin's text can hold the answer it refused, and so can btclib's,
    so neither is relayed nor chained (issue #821): a builtin's type is
    named.
    """
    with (
        pytest.raises(FetchError, match="^'getblockcount': a malformed answer") as e,
        fetch_errors("getblockcount"),
    ):
        raise error
    if not isinstance(error, BTClibRuntimeError):
        assert str(e.value).endswith(f", as {type(error).__name__}")
    assert e.value.__cause__ is None
    assert e.value.__context__ is None


def test_fetch_errors_lets_a_fetch_error_through() -> None:
    """It is a RuntimeError, so a nested one is not re-wrapped.

    One the package built passes as it is, and one the caller's code built
    is refused by its class (issue #935).
    """
    err_msg = "^transaction: the answer is another transaction than the one asked$"
    with pytest.raises(FetchError, match=err_msg), fetch_errors("getblockcount"):
        tx_from_raw(RAW, OTHER_ID, "mainnet")
    err_msg = "^'getblockcount': no usable answer from the server: FetchError$"
    with pytest.raises(FetchError, match=err_msg), fetch_errors("getblockcount"):
        raise FetchError("the node is down")


def test_fetch_errors_is_transparent_when_nothing_is_raised() -> None:
    """Run the guarded body untouched when it raises nothing."""
    with fetch_errors("getblockcount"):
        value = 481824
    assert value == 481824


# what `client_errors` answers for any rpc error, the client's text not
# relayed
_AN_RPC_ERROR = r"^the server answered an rpc error \(rpc error code {}\)$"


def test_client_errors_raises_this_packages_rpc_error_with_the_code() -> None:
    """The client's `RpcError` leaves as this package's, its code kept.

    Built with the client's own class, so the translation is held to the
    attributes of the release installed.
    """
    error = rpc.RpcError("sendrawtransaction: the node answered an error", -26)
    with (
        pytest.raises(RpcError, match=_AN_RPC_ERROR.format(-26)) as exc,
        client_errors(),
    ):
        raise error
    assert exc.value.__cause__ is None
    assert exc.value.__context__ is None
    assert exc.value.code == -26
    assert exc.value.data is None
    assert not isinstance(exc.value, rpc.RpcError)


class _RpcErrorWithData(rpc.RpcError):
    """The client's `RpcError` as the releases that carry `data` build it."""

    def __init__(self, message: str, code: int, data: object) -> None:
        super().__init__(message, code)
        self.data = data


def test_client_errors_drops_the_data_a_client_release_carries() -> None:
    """`data` does not reach this package's `RpcError`, nor its text.

    Section 7 of the btclib-org standard, *A refusal carries no secret*:
    `data` is the node's, and can quote the request.
    """
    error = _RpcErrorWithData("getrawtransaction: not found", -5, {"tx": "key"})
    with (
        pytest.raises(RpcError, match=_AN_RPC_ERROR.format(-5)) as exc,
        client_errors(),
    ):
        raise error
    assert exc.value.__cause__ is None
    assert exc.value.__context__ is None
    assert exc.value.code == -5
    assert exc.value.data is None


def _peer_refusing(refusal: Exception) -> object:
    """Ask a `CompactFilterFetcher` whose peer transport raises `refusal`."""
    fetcher, peer = compact_filters_fetcher()

    def send(_message: object, _timeout: float) -> None:
        raise refusal

    setattr(peer, "send", send)  # noqa: B010
    return fetcher.get_block_count()


# what `client_errors` answers for a `FetchError` of no field
_NO_ANSWER = "no usable answer from the server: FetchError$"


@pytest.mark.parametrize(
    "call, err_msg",
    [
        (lambda e: core_fetcher(e).get_block_count(), f"^getblockcount: {_NO_ANSWER}"),
        (lambda e: rest_fetcher(e).get_block_count(), f"^{_NO_ANSWER}"),
        (lambda e: electrum_fetcher(e).get_block_count(), f"^{_NO_ANSWER}"),
        (lambda e: esplora_fetcher(e).get_block_count(), f"^{_NO_ANSWER}"),
        (_peer_refusing, f"^{_NO_ANSWER}"),
    ],
    ids=["rpc client", "rest client", "line transport", "http transport", "peer"],
)
def test_a_fetch_error_of_the_callers_own_is_refused_by_its_class(
    call: Callable[[Exception], object], err_msg: str
) -> None:
    """The census does not read the caller's code, so its text is dropped.

    Each client or transport is the caller's, and raises this package's
    `FetchError` (issue #935).
    """
    with pytest.raises(FetchError, match=err_msg) as e:
        call(FetchError(f"no answer for {HEX}"))
    assert e.value.__cause__ is None
    assert e.value.__context__ is None
    assert_secret_free(e.value, SPELLINGS)


@pytest.mark.parametrize(
    "call, err_msg, field, value",
    [
        (
            lambda: rest_fetcher(HttpError(HEX, 503)).get_block_count(),
            r"^the server answered HTTP 503$",
            "status",
            503,
        ),
        (
            lambda: core_fetcher(RpcError(HEX, -5, HEX)).get_block_count(),
            r"^getblockcount: the server answered an rpc error \(rpc error code -5\)$",
            "code",
            -5,
        ),
        (
            lambda: core_fetcher(RpcError(HEX, SCALAR)).get_block_count(),
            r"^getblockcount: the server answered an rpc error \(rpc error code 0\)$",
            "code",
            0,
        ),
    ],
    ids=["status", "code", "scalar code"],
)
def test_an_http_or_rpc_error_of_the_callers_own_keeps_its_field_alone(
    call: Callable[[], object], err_msg: str, field: str, value: int
) -> None:
    """Refused as `bitcoin_core_rpc`'s are: the field kept, the text dropped."""
    with pytest.raises(FetchError, match=err_msg) as e:
        call()
    assert getattr(e.value, field) == value
    assert getattr(e.value, "data", None) is None
    assert e.value.__cause__ is None
    assert e.value.__context__ is None
    assert_secret_free(e.value, SPELLINGS)


class _CallersFetcher(StubFetcher):
    """A `Fetcher` of the caller's own, raising `refusal` for each question.

    The tip height is answered where `tip` is True, so that the header
    asked after it is the question refused.
    """

    def __init__(self, refusal: Exception, *, tip: bool) -> None:
        super().__init__(Tx.parse(RAW))
        self.refusal = refusal
        self.tip = tip

    @override
    def get_tx(self, tx_id: Octets) -> Tx:
        """Raise the refusal."""
        raise self.refusal

    @override
    def get_block_count(self) -> int:
        """Answer the tip height, or raise the refusal."""
        if self.tip:
            return super().get_block_count()
        raise self.refusal

    @override
    def get_best_block_id(self) -> bytes:
        """Raise the refusal."""
        raise self.refusal

    @override
    def get_block_header(self, height: int) -> BlockHeader:
        """Raise the refusal."""
        raise self.refusal


# a time no block header is past, so that every height is asked for
_BORN = datetime(2100, 1, 1, tzinfo=UTC)


@pytest.mark.parametrize(
    "call, tip, err_msg",
    [
        (lambda f: CachingFetcher(f).get_tx(TX_ID), False, "get_tx"),
        (lambda f: CachingFetcher(f).get_block_header(1), False, "get_block_header"),
        (lambda f: CachingFetcher(f).get_block_count(), False, "get_block_count"),
        (lambda f: CachingFetcher(f).get_best_block_id(), False, "get_best_block_id"),
        (lambda f: f.get_tx_out(OutPoint(TX_ID, 0)), False, "get_tx"),
        (lambda f: start_height_for_time(f, _BORN), False, "get_block_count"),
        (lambda f: start_height_for_time(f, _BORN), True, "get_block_header"),
    ],
    ids=[
        "cached tx",
        "cached header",
        "cached tip height",
        "cached tip id",
        "tx out",
        "start height's tip",
        "start height's header",
    ],
)
def test_a_fetch_error_of_the_callers_own_fetcher_is_refused_by_its_class(
    call: Callable[[Fetcher], object], tip: bool, err_msg: str
) -> None:
    """A call of the package that asks the caller's `Fetcher` (issue #935).

    What it relays is refused by its class, as `client_errors` refuses a
    client's.
    """
    fetcher = _CallersFetcher(FetchError(f"no answer for {HEX}"), tip=tip)
    with pytest.raises(FetchError, match=f"^{err_msg}: {_NO_ANSWER}") as e:
        call(fetcher)
    assert e.value.__cause__ is None
    assert e.value.__context__ is None
    assert_secret_free(e.value, SPELLINGS)


def test_a_fallback_fetcher_names_the_class_of_the_callers_refusal() -> None:
    """It relays no backend's text already, and so none of the caller's."""
    fetcher = _CallersFetcher(FetchError(f"no answer for {HEX}"), tip=False)
    err_msg = "^get_tx: every backend failed -- _CallersFetcher: FetchError$"
    with pytest.raises(FetchError, match=err_msg) as e:
        FallbackFetcher([fetcher]).get_tx(TX_ID)
    assert e.value.__cause__ is None
    assert e.value.__context__ is None
    assert_secret_free(e.value, SPELLINGS)


def test_a_package_fetchers_refusal_passes_a_caching_fetcher_as_it_is() -> None:
    """Composed where the census reads it, the text is relayed (issue #935)."""
    with pytest.raises(FetchError, match="^transaction: a malformed answer$"):
        CachingFetcher(electrum_fetcher(5)).get_tx(TX_ID)


class _ProxyError(FetchError):
    """A `FetchError` of the caller's whose `__class__` answers `RpcError`."""

    __class__ = property(lambda _self: RpcError)


class _NoCodeError(RpcError):
    """An `RpcError` of the caller's whose `code` raises where it is read."""

    def __init__(self, message: str) -> None:
        FetchError.__init__(self, message)

    @property
    @override
    def code(self) -> int:  # type: ignore[override]
        """Raise, quoting the message."""
        raise AttributeError(self.args[0])


class _NoRpcCodeError(rpc.RpcError):
    """A `bitcoin_core_rpc.RpcError` whose `code` raises where it is read."""

    def __init__(self, message: str) -> None:
        rpc.FetchError.__init__(self, message)

    @property
    @override
    def code(self) -> int:  # type: ignore[override]
        """Raise, quoting the message."""
        raise AttributeError(self.args[0])


class _Nameless(type):
    """A metaclass whose classes raise where their name is read."""

    @property
    @override
    def __name__(cls) -> str:  # type: ignore[override]
        """Raise, as a class of the caller's can."""
        raise AttributeError(HEX)


class _UnnamedError(FetchError, metaclass=_Nameless):
    """A `FetchError` of the caller's whose class has no name to read."""


@pytest.mark.parametrize(
    "refusal, err_msg",
    [
        (_ProxyError, "_ProxyError"),
        (_NoCodeError, "_NoCodeError"),
        (_NoRpcCodeError, "_NoRpcCodeError"),
        (_UnnamedError, "an unnamed class"),
    ],
    ids=["class answered", "code that raises", "rpc code that raises", "no name"],
)
def test_a_refusal_is_classified_by_its_type_and_reads_nothing_that_raises(
    refusal: Callable[[str], Exception], err_msg: str
) -> None:
    """Its kind is its type's, and a read that raises chains nothing (#935).

    The class's name stands in for a field that could not be read.
    """
    with pytest.raises(FetchError) as e:
        rest_fetcher(refusal(f"no answer for {HEX}")).get_block_count()
    assert type(e.value) is FetchError
    assert str(e.value) == f"no usable answer from the server: {err_msg}"
    assert e.value.__cause__ is None
    assert e.value.__context__ is None
    assert_secret_free(e.value, SPELLINGS)


class _CallersEsplora(EsploraFetcher):
    """An `EsploraFetcher` of the caller's own, refusing the chain question."""

    @override
    def assert_network(self) -> None:
        """Raise a refusal holding the key."""
        raise FetchError(f"no chain for {HEX}")


_F = TypeVar("_F", bound=Fetcher)


def _overridden(fetcher: _F, method: str, refused: object = None) -> _F:
    """Return `fetcher` with `method` answered as a caller's subclass can.

    It raises a refusal holding the key where its first argument is
    `refused`, or at every call where `refused` is None, and otherwise
    answers as the method it replaces.
    """
    original = getattr(fetcher, method)

    def _answer(*args: object) -> object:
        if refused is None or args[0] == refused:
            raise FetchError(f"no answer for {HEX}")
        return original(*args)

    setattr(fetcher, method, _answer)
    return fetcher


def _listing_first() -> FakeServer:
    """Return the chain of `electrum_chain`, listing FIRST in OURS's history."""
    server = electrum_chain()
    listed = {"tx_hash": FIRST.id.hex(), "height": 4}
    server.edit = lambda method, _params, result: (
        [*result, listed] if method == "blockchain.scripthash.get_history" else result
    )
    return server


@pytest.mark.parametrize(
    "call, err_msg",
    [
        (
            lambda: _overridden(
                esplora_history_fetcher(esplora_explorer()), "get_tx"
            ).get_history([OURS, MINE]),
            "get_tx",
        ),
        (
            lambda: _overridden(
                esplora_history_fetcher(
                    FakeEsplora(
                        FakeServer([[FUNDING]], [_tx([OutPoint(SPEND.id, 0)], [MINE])])
                    )
                ),
                "get_tx",
            ).get_history([MINE]),
            "get_tx",
        ),
        (
            lambda: _overridden(
                electrum_history_fetcher(electrum_chain()), "get_tx"
            ).get_history([OURS, MINE]),
            "get_tx",
        ),
        (
            lambda: _overridden(electrum_fetcher(5), "get_block_header").verify_tx(
                MERKLE_TX_ID, TIP_HEIGHT
            ),
            "get_block_header",
        ),
        (
            lambda: _overridden(
                electrum_history_fetcher(electrum_chain()), "get_tx_merkle"
            ).verify_tx(FUNDING.id, 1),
            "get_tx_merkle",
        ),
        (
            lambda: _overridden(
                esplora_history_fetcher(esplora_explorer()), "text"
            ).get_block_header(1),
            "text",
        ),
        (
            lambda: _overridden(
                electrum_history_fetcher(electrum_chain()), "get_tx_merkle"
            ).get_history([OURS, MINE]),
            "get_tx_merkle",
        ),
        (
            lambda: _overridden(
                electrum_history_fetcher(electrum_chain()), "get_block_headers"
            ).get_history([MINE], 2),
            "get_block_headers",
        ),
        (
            # FIRST pays MINE alone, so whether it touches OURS is read off
            # the transaction its input spends, which no history lists
            lambda: _overridden(
                electrum_history_fetcher(_listing_first()), "get_tx", bytes(32)
            ).get_history([OURS]),
            "get_tx",
        ),
    ],
    ids=[
        "esplora confirmed",
        "esplora mempool",
        "electrum history",
        "electrum proof",
        "electrum proof merkle",
        "esplora header",
        "electrum merkle",
        "electrum headers",
        "spent output",
    ],
)
def test_a_method_of_the_callers_own_subclass_is_refused_by_its_class(
    call: Callable[[], object], err_msg: str
) -> None:
    """A package method asking a method a subclass overrides (issue #935)."""
    with pytest.raises(FetchError, match=f"^{err_msg}: {_NO_ANSWER}") as e:
        call()
    assert e.value.__cause__ is None
    assert e.value.__context__ is None
    assert_secret_free(e.value, SPELLINGS)


def test_the_chain_question_of_the_callers_own_subclass_is_refused() -> None:
    """`assert_network` is asked again at each question it refuses (#935)."""
    fetcher = _CallersEsplora(BASE, transport=Recorded((200, b"1")))
    for _ in range(2):
        err_msg = f"^assert_network: {_NO_ANSWER}"
        with pytest.raises(FetchError, match=err_msg) as e:
            fetcher.get_block_count()
        assert e.value.__cause__ is None
        assert e.value.__context__ is None
        assert_secret_free(e.value, SPELLINGS)


def _v2_peer_fetcher(host: str) -> object:
    """Ask a `CompactFilterFetcher` over a `V2PeerTransport`."""
    pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    transport = V2PeerTransport(host, 1)
    return CompactFilterFetcher("regtest", transport=transport).get_block_count()


def _line_fetcher(transport: Callable[[bytes, float], bytes]) -> object:
    """Ask an `ElectrumFetcher` over one of the line transports shipped."""
    return ElectrumFetcher(
        "mainnet", transport=transport, verify_network=False
    ).get_block_count()


@pytest.mark.parametrize(
    "call, err_msg",
    [
        (
            lambda host: _line_fetcher(TcpLineTransport(host, 1)),
            r"^no answer from a value of 65 characters:1: ConnectionRefusedError$",
        ),
        (
            lambda host: _line_fetcher(TlsLineTransport(host, 1)),
            r"^no answer from a value of 65 characters:1: ConnectionRefusedError$",
        ),
        (
            lambda host: _line_fetcher(PersistentTlsLineTransport(host, 1)),
            r"^no answer from a value of 65 characters:1: ConnectionRefusedError$",
        ),
        (
            lambda host: CompactFilterFetcher(
                "regtest", transport=TcpPeerTransport(host, 1)
            ).get_block_count(),
            r"^no connection to a value of 65 characters:1$",
        ),
        (_v2_peer_fetcher, r"^no connection to a value of 65 characters:1$"),
    ],
    ids=["tcp line", "tls line", "persistent tls", "tcp peer", "v2 peer"],
)
def test_a_shipped_transports_refusal_reaches_the_caller_as_it_is(
    call: Callable[[str], object], err_msg: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`client_errors` relays a `_TransportError` with its text (issue #935).

    The text is composed where the census reads it, and describes the host.
    """
    host = f"{HEX[:32]}.{HEX[32:]}"

    def open_connection(
        address: tuple[str, int], _deadline: float, _timeout: float, _where: str
    ) -> object:
        raise ConnectionRefusedError(f"cannot reach {address[0]}")

    monkeypatch.setattr(transport_module, "_open_connection", open_connection)
    monkeypatch.setattr(peer_transport_module, "_open_connection", open_connection)
    with pytest.raises(FetchError, match=err_msg) as e:
        call(host)
    assert e.value.__cause__ is None
    assert e.value.__context__ is None
    assert_secret_free(e.value, SPELLINGS)


def test_tx_id_hex_takes_whatever_octets_takes() -> None:
    """Accept hex, bytes, and whitespace-padded hex alike."""
    assert tx_id_hex(TX_ID) == TX_ID
    assert tx_id_hex(bytes.fromhex(TX_ID)) == TX_ID
    assert tx_id_hex(f"  {TX_ID}  ") == TX_ID


@pytest.mark.parametrize("tx_id", ["", "00", f"{TX_ID}00", "not hex at all"])
def test_tx_id_hex_refuses_what_is_not_an_id(tx_id: str) -> None:
    """A mistyped id is the caller's error, not the remote host's 404."""
    with pytest.raises(BTClibValueError):
        tx_id_hex(tx_id)


def test_tx_for_network_leaves_mainnet_alone() -> None:
    """Return the very same object for mainnet, not a relabelled copy."""
    tx = Tx.parse(RAW)
    assert tx_for_network(tx, "mainnet") is tx
    # and for every other spelling of it, the name being resolved and not
    # compared: " MainNet " used to fall through to the relabelling branch
    assert tx_for_network(tx, " MainNet ") is tx


def test_tx_for_network_refuses_a_network_no_table_has() -> None:
    """The label is written with check_validity=False, so nothing caught it.

    Every `ScriptPubKey`, `TxOut` and `Tx` built here is built unchecked
    -- deliberately, the relabelling touching nothing else -- so a
    network name that names nothing was baked into the transaction
    handed back, to surface as a `KeyError` from whatever went on to
    render an address, a long way from the call that caused it.
    """
    tx = Tx.parse(RAW)
    for unknown in ("mainet", "", "bitcoin"):
        with pytest.raises(BTClibValueError, match="unknown network: "):
            tx_for_network(tx, unknown)
    with pytest.raises(BTClibTypeError, match="not a network name: "):
        tx_for_network(tx, None)  # type: ignore[arg-type]


def test_tx_for_network_labels_the_outputs_and_touches_nothing_else() -> None:
    """The label is what an address is rendered from, and nothing else."""
    tx = Tx.parse(RAW)
    testnet = tx_for_network(tx, "testnet")

    assert [out.script_pub_key.network for out in testnet.vout] == ["testnet"] * 2
    assert [out.script_pub_key.network for out in tx.vout] == ["mainnet"] * 2
    # the serialization does not carry a network, so relabelling cannot
    # change it: same bytes, same id, same amounts, same scripts
    assert testnet.serialize(include_witness=True) == tx.serialize(include_witness=True)
    assert testnet.id == tx.id
    assert [out.value for out in testnet.vout] == [out.value for out in tx.vout]
    # and the two are not equal, ScriptPubKey comparing the network type
    assert testnet.vout[0].script_pub_key != tx.vout[0].script_pub_key


def test_the_label_is_what_an_address_is_rendered_from() -> None:
    """Which block 170 cannot show: both its outputs are p2pk.

    A p2pk script pays a public key and not a hash, so it has no address
    at all on either network -- `addresses` answers `[""]` for both, and
    a test written on it would pass whatever the label said. The same
    twenty bytes in a p2pkh script are a `1...` address on mainnet and an
    `m` or `n` one on testnet, and the label is the only thing that
    decides which.
    """
    tx = Tx.parse(RAW)
    p2pkh = ScriptPubKey("76a914" + "ab" * 20 + "88ac")
    tx.vout[0] = TxOut(tx.vout[0].value, p2pkh)

    assert tx.vout[0].script_pub_key.address.startswith("1")
    testnet = tx_for_network(tx, "testnet")
    assert testnet.vout[0].script_pub_key.address.startswith(("m", "n"))


def test_tx_from_raw_returns_the_transaction_asked_for() -> None:
    """Parse the raw serialization into the transaction with that id.

    However the caller holds it: the guard in front of the parse used to
    ask `isinstance(raw, (bytes, str))`, which is the packed form named
    by the types that were the packed form when the line was written, so
    a backend's answer kept in a buffer was refused as "not a
    serialization, but a bytearray" (issue btclib-org/btclib#1238).
    """
    octets = bytes.fromhex(RAW)
    for spelling in (RAW, octets, bytearray(octets), memoryview(octets)):
        tx = tx_from_raw(spelling, TX_ID, "mainnet")
        assert tx.id.hex() == TX_ID
        assert len(tx.vout) == 2


def test_tx_from_raw_catches_the_answer_to_another_question() -> None:
    """The one answer a backend cannot fake, checked where get_tx is served."""
    with pytest.raises(FetchError, match="^transaction: the answer is"):
        tx_from_raw(RAW, OTHER_ID, "mainnet")


def test_tx_from_raw_catches_it_on_either_side_of_the_id_requested() -> None:
    """A backend's id is refused whether it sorts above or below the ask.

    OTHER_ID above sorts below `TX_ID` (`b...` against `f...`), so that
    case alone leaves `hex() > tx_id` as good a check as `hex() != tx_id`.
    A requested id that sorts *above* the one `RAW` actually parses to is
    the other half, and it is what a byte-for-byte comparison must catch
    too -- a backend is not asked to sort correctly, only to answer for
    the id it was given.
    """
    above = "f" * 64
    with pytest.raises(FetchError, match="^transaction: the answer is"):
        tx_from_raw(RAW, above, "mainnet")


@pytest.mark.parametrize(
    "raw",
    [
        "not hex",
        # a transaction truncated in transit
        RAW[:100],
        "",
    ],
)
def test_tx_from_raw_reports_what_is_not_a_transaction(raw: str) -> None:
    """Wrap an unparsable body in a FetchError naming the transaction."""
    with pytest.raises(FetchError, match="^transaction:"):
        tx_from_raw(raw, TX_ID, "mainnet")


@pytest.mark.parametrize("height", [0, 1, TIP_HEIGHT])
def test_block_header_height_accepts_a_non_negative_int(height: int) -> None:
    """A height that is already a non-negative int passes through unchanged."""
    assert block_header_height(height) == height


def test_block_header_height_refuses_a_negative_height() -> None:
    """Refuse a negative height, before any backend is asked."""
    with pytest.raises(
        BTClibValueError, match="^invalid height: a negative int of 1 bits < 0$"
    ):
        block_header_height(-1)


@pytest.mark.parametrize("height", ["481824", 481824.0, None, True, False])
def test_block_header_height_refuses_a_non_integer_height(height: object) -> None:
    """Refuse anything that is not an int, a bool included."""
    with pytest.raises(BTClibTypeError, match="invalid height type"):
        block_header_height(height)  # type: ignore[arg-type]


def test_block_header_from_raw_returns_a_checked_header() -> None:
    """Parse the serialization and pass it through assert_valid_pow."""
    header = block_header_from_raw(TIP_HEADER_RAW, network="mainnet")
    assert header.hash.hex() == TIP_ID


@pytest.mark.parametrize(
    "raw",
    [
        "not hex",
        # a header truncated in transit
        TIP_HEADER_RAW[:100],
        "",
    ],
)
def test_block_header_from_raw_reports_what_is_not_a_header(raw: str) -> None:
    """Wrap an unparsable body in a FetchError naming a block header."""
    with pytest.raises(FetchError, match="^block header:"):
        block_header_from_raw(raw, network="mainnet")


def test_block_header_from_raw_checks_the_work_against_the_network_given() -> None:
    """Regtest's genesis is within regtest's limit and beyond mainnet's."""
    header = block_header_from_raw(REGTEST_GENESIS_HEADER_RAW, network="regtest")
    assert header.hash == NETWORKS["regtest"].genesis_block
    with pytest.raises(FetchError, match="^block header: a malformed answer"):
        block_header_from_raw(REGTEST_GENESIS_HEADER_RAW, network="mainnet")


def test_block_header_from_raw_holds_signet_to_signets_limit() -> None:
    """Signet's genesis is within signet's limit and beyond mainnet's."""
    header = block_header_from_raw(SIGNET_GENESIS_HEADER_RAW, network="signet")
    assert header.hash == NETWORKS["signet"].genesis_block
    with pytest.raises(FetchError, match="^block header: a malformed answer"):
        block_header_from_raw(SIGNET_GENESIS_HEADER_RAW, network="mainnet")


def test_block_header_from_raw_refuses_a_regtest_header_for_signet() -> None:
    """Signet's limit is not regtest's."""
    with pytest.raises(FetchError, match="^block header: a malformed answer"):
        block_header_from_raw(REGTEST_GENESIS_HEADER_RAW, network="signet")


def test_block_header_from_raw_holds_the_hash_to_the_target_its_bits_claim() -> None:
    """Within the network's limit is not enough: the bits' own target counts.

    Regtest's genesis with bits 0x1d00ffff and nonce 1: its hash is
    below regtest's limit, and above the target those bits name.
    """
    claimed = f"{REGTEST_GENESIS_HEADER_RAW[:-16]}ffff001d01000000"
    with pytest.raises(FetchError, match="^block header: a malformed answer"):
        block_header_from_raw(claimed, network="regtest")


def test_block_header_from_raw_resolves_the_network_name() -> None:
    """A name is resolved like any network name; an unknown one is refused."""
    header = block_header_from_raw(TIP_HEADER_RAW, network=" MainNet ")
    assert header.hash.hex() == TIP_ID
    with pytest.raises(BTClibValueError):
        block_header_from_raw(TIP_HEADER_RAW, network="foo")


def test_block_header_from_raw_refuses_a_header_with_no_proof_of_work() -> None:
    """A well-formed header answering no real proof of work is refused too.

    Zeroing the nonce leaves every other field, and so every other check,
    untouched -- what fails is `assert_valid_pow` alone, which is the one
    this exists to enforce.
    """
    forged = f"{TIP_HEADER_RAW[:-8]}00000000"
    with pytest.raises(FetchError, match="^block header: a malformed answer"):
        block_header_from_raw(forged, network="mainnet")


def test_the_interface_is_abstract() -> None:
    """No answers here: a Fetcher is one of the backends, or nothing."""
    with pytest.raises(TypeError, match="abstract"):
        Fetcher()  # type: ignore[abstract]


@pytest.mark.parametrize(
    "missing",
    ["get_tx", "get_block_count", "get_best_block_id", "get_block_header"],
)
def test_leaving_any_one_question_abstract_refuses_construction(
    missing: str,
) -> None:
    """Each question is `abstractmethod` on its own, not by inheriting one.

    `test_the_interface_is_abstract` covers `Fetcher` itself; a subclass
    that overrides every question but one is what a decorator removed
    from only one of them would let through.
    """
    methods = {
        "get_tx": lambda self, tx_id: Tx.parse(RAW),
        "get_block_count": lambda self: TIP_HEIGHT,
        "get_best_block_id": lambda self: bytes.fromhex(TIP_ID),
        "get_block_header": lambda self, height: BlockHeader.parse(TIP_HEADER_RAW),
    }
    del methods[missing]
    incomplete = type("Incomplete", (Fetcher,), methods)
    with pytest.raises(TypeError, match="abstract"):
        incomplete("mainnet")


def test_a_verifying_fetcher_without_assert_network_is_refused() -> None:
    """Every question answered and the chain question not declared.

    What a backend costs its caller when it is written without one is
    the check made never, on a class that compiles and passes its own
    tests, so `NetworkVerifyingFetcher` declares `assert_network`
    abstract and this is that refusal.
    """
    questions = {
        "get_tx": lambda self, tx_id: Tx.parse(RAW),
        "get_block_count": lambda self: TIP_HEIGHT,
        "get_best_block_id": lambda self: bytes.fromhex(TIP_ID),
        "get_block_header": lambda self, height: BlockHeader.parse(TIP_HEADER_RAW),
    }
    unasked = type("Unasked", (NetworkVerifyingFetcher,), questions)
    with pytest.raises(TypeError, match="abstract"):
        unasked("mainnet")

    asking = type(
        "Asking",
        (NetworkVerifyingFetcher,),
        {**questions, "assert_network": lambda self: None},
    )
    assert asking("mainnet").verify_network is True


def test_a_network_name_is_taken_as_the_rest_of_the_library_takes_one() -> None:
    """`Fetcher` normalizes the name it is given, and refuses before fetching.

    `__init__` puts the name through `network.validated_network_name`,
    so the spellings issue btclib-org/btclib#216 decided to keep reach a
    backend, and `Fetcher.network` is the name `network_from_name` answers to.
    """
    assert StubFetcher(Tx.parse(RAW), " TestNet4 ").network == "testnet4"
    with pytest.raises(BTClibValueError, match="unknown network: 'mainnnet'"):
        StubFetcher(Tx.parse(RAW), "mainnnet")
    # a name that is not a string is the type rule, which RELEASE_NOTES.md
    # tells a caller to act on
    with pytest.raises(BTClibTypeError, match="not a network name"):
        StubFetcher(Tx.parse(RAW), [])  # type: ignore[arg-type]


@pytest.mark.parametrize("network", ["mainnet", "testnet", "testnet4", "regtest"])
def test_the_network_is_the_one_it_was_given(network: str) -> None:
    """Expose the name the constructor resolved, for every name given."""
    assert StubFetcher(Tx.parse(RAW), network).network == network


def test_the_stub_answers_every_question() -> None:
    """A Fetcher answers every question it declares, so the stub must.

    A subclass leaving one abstract could not be instantiated at all, and
    the tests below would then be testing nothing -- which is what this
    says out loud rather than leaving to the lines never called.
    """
    fetcher = StubFetcher(Tx.parse(RAW))
    assert fetcher.get_tx(TX_ID).id.hex() == TX_ID
    assert fetcher.get_block_count() == TIP_HEIGHT
    assert fetcher.get_best_block_id().hex() == TIP_ID
    assert fetcher.get_block_header(TIP_HEIGHT).hash.hex() == TIP_ID


def test_get_tx_out_derives_the_output_from_the_transaction() -> None:
    """A backend that serves get_tx gets this one for free, from get_tx."""
    fetcher = StubFetcher(Tx.parse(RAW))
    out = fetcher.get_tx_out(OutPoint(TX_ID, 1))
    assert out.value == 40_00000000
    assert fetcher.asked == [TX_ID]
    assert out == Tx.parse(RAW).vout[1]


def test_get_tx_out_answers_for_an_output_already_spent() -> None:
    """Which `gettxout` would not, and is why it is not what is called.

    Both outputs of this transaction were spent years ago; a fee is the
    inputs less the outputs, so an answer restricted to the utxo set
    could never compute one.
    """
    fetcher = StubFetcher(Tx.parse(RAW))
    assert fetcher.get_tx_out(OutPoint(TX_ID, 0)).value == 10_00000000


def test_get_tx_out_refuses_a_vout_the_transaction_does_not_have() -> None:
    """Refuse an out-of-range vout with a FetchError describing it.

    2, one past the transaction's last output, is the boundary the check
    is written on; 1000 is not, and is what tells a `>=` refusal from one
    that only catches an exact match -- and, being outside the range
    CPython interns, from one that only catches identity.
    """
    fetcher = StubFetcher(Tx.parse(RAW))
    with pytest.raises(FetchError, match="out of range vout: an int of 2 bits "):
        fetcher.get_tx_out(OutPoint(TX_ID, 2))
    with pytest.raises(FetchError, match="out of range vout: an int of 10 bits "):
        fetcher.get_tx_out(OutPoint(TX_ID, 1000))
