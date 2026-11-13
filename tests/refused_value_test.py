# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A refusal describes the value it refuses, and does not print it.

Section 7 of the btclib-org standard, *A refusal carries no secret*: an
argument in the wrong place may be a key. Each test feeds a fixed random
key where another value belongs, and checks the refusal's chain with
`assert_secret_free`.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from hashlib import shake_256

import pytest
from base58_bech32.bech32 import BECH32_M_CONST, bech32_encode
from bitcoin_core_rpc import BitcoinCoreRpcClient
from btclib.b32 import power_of_2_base_conversion
from btclib.exceptions import BTClibRuntimeError, BTClibTypeError, BTClibValueError
from btclib.script import ScriptPubKey
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from ecc.curves import bytes_from_point, mult
from ecc.dsa import Sig as DsaSig
from typing_extensions import override

import btclib_wallet
from btclib_wallet import electrum, silent_payments
from btclib_wallet._refusal import _label
from btclib_wallet.bip21 import Bip21
from btclib_wallet.bip32 import BIP32KeyData
from btclib_wallet.bip85 import nsec_from_root_key
from btclib_wallet.bip322 import Sig
from btclib_wallet.bolt11 import Bolt11Invoice
from btclib_wallet.core_import import assert_imported, import_request
from btclib_wallet.descriptors import parse as parse_descriptor
from btclib_wallet.electrum import (
    block_header_request,
    block_headers_request,
    block_headers_response,
    decode_response,
    transaction_get_request,
)
from btclib_wallet.exceptions import FetchError, RpcError
from btclib_wallet.fetch import transport as transport_module
from btclib_wallet.fetch.bitcoin_core import BitcoinCoreFetcher
from btclib_wallet.fetch.compact_filters import CompactFilterFetcher
from btclib_wallet.fetch.electrum import ElectrumFetcher
from btclib_wallet.fetch.esplora import EsploraFetcher
from btclib_wallet.fetch.fetcher import block_header_height, tx_from_raw
from btclib_wallet.fetch.peer_transport import TcpPeerTransport, V2PeerTransport
from btclib_wallet.fetch.transport import (
    PersistentTlsLineTransport,
    TcpLineTransport,
    TlsLineTransport,
)
from btclib_wallet.psbt import Psbt
from btclib_wallet.psbt.psbt_utils import PSBT_V2
from btclib_wallet.tx_or_psbt import tx_or_psbt_from_any
from tests.core_import_test import account_pair
from tests.fetch import SEGWIT_TX_RAW
from tests.fetch.electrum_test import RpcErrorAnswer
from tests.fetch.electrum_test import fetcher as electrum_fetcher
from tests.secret_free import assert_secret_free

URL = "http://127.0.0.1:8332"
ADDRESS = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
# credentials of no node, named so that no `password=` argument holds a literal
RPC_USER = "rpcuser"
RPC_PASSWORD = "rpcpassword"  # noqa: S105  # pragma: allowlist secret
KEY = shake_256(b"btclib-wallet issues 745 and 749").digest(32)
SCALAR = int.from_bytes(KEY)
# each spelling of the key a refusal could print, the decimal included
SPELLINGS: list[str | bytes] = [KEY, KEY.hex(), str(SCALAR), f"{SCALAR:x}"]


@pytest.mark.parametrize(
    "call",
    [
        lambda: decode_response(b'{"id": 1, "result": 0}\n', SCALAR, "server.ping"),
        lambda: block_header_request(1, -SCALAR),
        lambda: block_headers_request(1, -SCALAR, 1),
        lambda: block_headers_request(1, 0, -SCALAR),
        lambda: transaction_get_request(1, str(SCALAR)),
        lambda: transaction_get_request(1, f"{SCALAR:#066x}"),
    ],
    ids=[
        "request id",
        "negative height",
        "negative start_height",
        "negative count",
        "tx_id of decimal digits",
        "tx_id of 0x-prefixed hex",
    ],
)
def test_electrum_describes_a_refused_int_or_tx_id(call: Callable[[], object]) -> None:
    """An int by its sign and bit length, a str by its length (issue #745)."""
    with pytest.raises(BTClibValueError) as e:
        call()
    assert_secret_free(e.value, SPELLINGS)


@pytest.mark.parametrize(
    "reader, err_msg",
    [
        (Psbt.b64decode, "^non-ascii character in base64 psbt at position 66$"),
        (Sig.b64decode, "^non-ascii character in base64 signature at position 66$"),
        (
            tx_or_psbt_from_any,
            "^neither hex nor base64: non-ascii character at position 66$",
        ),
    ],
    ids=["psbt", "bip322 signature", "tx or psbt"],
)
def test_base64_refuses_a_non_ascii_character_by_position(
    reader: Callable[[str], object], err_msg: str
) -> None:
    """The codec's error, which holds the whole text, is not chained.

    A key's hex is base64 alphabet, so the character outside ASCII after
    it is what is refused. Its position counts the whitespace the reader
    strips (issue #749).
    """
    with pytest.raises(BTClibValueError, match=err_msg) as e:
        reader(f"  {KEY.hex()}" + "\N{LATIN SMALL LETTER E WITH ACUTE}")
    assert_secret_free(e.value, SPELLINGS)


def _address(hrp: str) -> str:
    """Return a bech32m silent payment address of a v0 payload."""
    payload = bytes_from_point(mult(2)) + bytes_from_point(mult(3))
    data = [0, *power_of_2_base_conversion(payload, 8, 5)]
    return bech32_encode(hrp, data, m=BECH32_M_CONST).decode("ascii")


def test_silent_payments_quotes_a_refused_hrp_only_up_to_16_characters() -> None:
    """A longer hrp is described by its length (issue #749)."""
    hrp = KEY.hex()
    with pytest.raises(
        BTClibValueError, match="^invalid hrp: a value of 64 characters$"
    ) as e:
        silent_payments.keys_from_address(_address(hrp))
    assert_secret_free(e.value, SPELLINGS)
    with pytest.raises(BTClibValueError, match=f"^invalid hrp: '{hrp[:16]}'$"):
        silent_payments.keys_from_address(_address(hrp[:16]))
    with pytest.raises(
        BTClibValueError, match="^invalid hrp: a value of 17 characters$"
    ):
        silent_payments.keys_from_address(_address(hrp[:17]))


HEADERS = b'{"id": 1, "result": {}}\n'


@pytest.mark.parametrize(
    "call, err_msg",
    [
        (
            lambda: block_headers_response(HEADERS, 1, KEY.hex()),  # type: ignore[arg-type]
            "^block.headers: invalid count asked: a str of length 64$",
        ),
        (
            lambda: block_headers_response(HEADERS, 1, -SCALAR),
            "^block.headers: invalid count asked: a negative int of 256 bits$",
        ),
        (
            lambda: decode_response(KEY.hex(), 1, "server.ping"),  # type: ignore[arg-type]
            "^not a JSON-RPC line: a str of length 64$",
        ),
        (
            lambda: decode_response(KEY.hex().encode() + b"\xff", 1, "server.ping"),
            "^not a JSON-RPC line: a bytes of length 65, not UTF-8$",
        ),
        (
            lambda: decode_response(KEY.hex().encode(), 1, "server.ping"),
            "^not a JSON-RPC line: a bytes of length 64, not JSON$",
        ),
    ],
    ids=[
        "count of hex",
        "negative count",
        "line as a str",
        "line not UTF-8",
        "line not JSON",
    ],
)
def test_electrum_describes_a_refused_count_or_line(
    call: Callable[[], object], err_msg: str
) -> None:
    """The chain holds neither the codec's error nor the parser's (issue #790).

    Both hold the line.
    """
    with pytest.raises((BTClibTypeError, BTClibValueError), match=err_msg) as e:
        call()
    assert_secret_free(e.value, SPELLINGS)


@pytest.mark.parametrize(
    "call, err_msg",
    [
        (
            lambda: silent_payments.label_tweak(1, KEY.hex()),  # type: ignore[arg-type]
            "^non-integer label: str$",
        ),
        (
            lambda: silent_payments.label_tweak(1, SCALAR),
            "^label not in 0..2\\^32-1: an int of 256 bits$",
        ),
    ],
    ids=["label of hex", "label of a scalar"],
)
def test_silent_payments_describes_a_refused_label(
    call: Callable[[], object], err_msg: str
) -> None:
    """A type by its name, an int by its sign and bit length (issue #791)."""
    with pytest.raises((BTClibTypeError, BTClibValueError), match=err_msg) as e:
        call()
    assert_secret_free(e.value, SPELLINGS)


@pytest.mark.parametrize(
    "field, version, err_msg",
    [
        ("tx_modifiable", PSBT_V2, "^invalid tx modifiable: an int of 256 bits$"),
        (
            "fallback_lock_time",
            None,
            "^invalid fallback locktime: an int of 256 bits$",
        ),
    ],
)
def test_psbt_describes_an_int_field_wider_than_its_own(
    field: str, version: int | None, err_msg: str
) -> None:
    """Described, since no value refused fits its field (issue #792)."""
    tx_in = TxIn(OutPoint(b"\x01" * 32, 0), b"", 0xFFFFFFFF)
    tx_out = TxOut(1000, ScriptPubKey("0014" + "00" * 20))
    psbt = Psbt.from_tx(Tx(2, 0, [tx_in], [tx_out]))
    if version is not None:
        psbt.version = version
    setattr(psbt, field, SCALAR)
    with pytest.raises(BTClibValueError, match=err_msg) as e:
        psbt.assert_valid()
    assert_secret_free(e.value, SPELLINGS)


def test_block_header_height_describes_a_negative_height() -> None:
    """By its sign and bit length (issue #793)."""
    err_msg = "^invalid height: a negative int of 256 bits < 0$"
    with pytest.raises(BTClibValueError, match=err_msg) as e:
        block_header_height(-SCALAR)
    assert_secret_free(e.value, SPELLINGS)


def _answer(result: object) -> bytes:
    """Return the reply line answering request 1 with `result`."""
    return json.dumps({"id": 1, "result": result}).encode() + b"\n"


def _headers(**members: object) -> bytes:
    """Return a `blockchain.block.headers` answer of these members."""
    return _answer({"count": 1, "hex": "00" * 80, **members})


def _merkle(**members: object) -> bytes:
    """Return a `blockchain.transaction.get_merkle` answer of these members."""
    return _answer({"block_height": 1, "merkle": [], "pos": 0, **members})


HEX = KEY.hex()


@pytest.mark.parametrize(
    "call, err_msg",
    [
        (
            lambda: decode_response(str(SCALAR).encode(), 1, "server.ping"),
            "^not a JSON-RPC response object: an int of 256 bits$",
        ),
        (
            lambda: decode_response(json.dumps(HEX).encode(), 1, "server.ping"),
            "^not a JSON-RPC response object: a str of length 64$",
        ),
        (
            lambda: decode_response(
                json.dumps({"id": SCALAR}).encode(), 1, "server.ping"
            ),
            "^response id an int of 256 bits does not answer request an int of 1 bits$",
        ),
        (
            lambda: decode_response(
                json.dumps({"id": 1, "x": HEX}).encode(), 1, "server.ping"
            ),
            "^neither a result nor an error: a dict of length 2$",
        ),
        (
            lambda: electrum.scripthash_get_history_response(
                _answer([{"height": -SCALAR, "tx_hash": "00" * 32}]), 1
            ),
            "^scripthash.get_history: invalid height: a negative int of 256 bits < -1$",
        ),
        (
            lambda: electrum.transaction_get_response(_answer(SCALAR), 1),
            "^transaction.get: not a hex string: an int of 256 bits$",
        ),
        (
            lambda: electrum.headers_subscribe_response(_answer([HEX]), 1),
            "^headers.subscribe: not an object: a list of length 1$",
        ),
        (
            lambda: electrum.headers_subscribe_response(
                _answer({"height": HEX, "hex": ""}), 1
            ),
            "^headers.subscribe: invalid height: a str of length 64$",
        ),
        (
            lambda: electrum.headers_subscribe_response(
                _answer({"height": 1, "hex": SCALAR}), 1
            ),
            "^headers.subscribe: invalid hex: an int of 256 bits$",
        ),
        (
            lambda: electrum.block_header_response(_answer(SCALAR), 1),
            "^block.header: not a hex string: an int of 256 bits$",
        ),
        (
            lambda: block_headers_response(_answer([HEX]), 1, 1),
            "^block.headers: not an object: a list of length 1$",
        ),
        (
            lambda: block_headers_response(_headers(count=HEX), 1, 1),
            "^block.headers: invalid count: a str of length 64$",
        ),
        (
            lambda: block_headers_response(_headers(count=SCALAR), 1, 1),
            "^block.headers: invalid count: an int of 256 bits$",
        ),
        (
            lambda: block_headers_response(_headers(hex=SCALAR), 1, 1),
            "^block.headers: not a hex string: an int of 256 bits$",
        ),
        (
            lambda: block_headers_response(_headers(count=SCALAR), 1, SCALAR),
            "^block.headers: hex of 80 bytes, not 80 for each header counted$",
        ),
        (
            lambda: electrum.transaction_get_merkle_response(_answer([HEX]), 1),
            "^transaction.get_merkle: not an object: a list of length 1$",
        ),
        (
            lambda: electrum.transaction_get_merkle_response(
                _merkle(block_height=HEX), 1
            ),
            "^transaction.get_merkle: invalid block_height: a str of length 64$",
        ),
        (
            lambda: electrum.transaction_get_merkle_response(_merkle(merkle=HEX), 1),
            "^transaction.get_merkle: invalid merkle: a str of length 64$",
        ),
        (
            lambda: electrum.transaction_get_merkle_response(_merkle(pos=HEX), 1),
            "^transaction.get_merkle: invalid pos: a str of length 64$",
        ),
        (
            lambda: electrum.estimate_fee_response(_answer(HEX), 1),
            "^estimatefee: not a number: a str of length 64$",
        ),
        (
            lambda: electrum.estimate_fee_response(_answer(-SCALAR), 1),
            "^estimatefee: not a rate or -1: a negative int of 256 bits$",
        ),
        (
            lambda: electrum.encode_request(1, "m", [{HEX: object()}]),
            "^request not JSON: TypeError$",
        ),
        (
            lambda: electrum.encode_request(1, "m", [{HEX: float("nan")}]),
            "^request not JSON: ValueError$",
        ),
        (
            lambda: ElectrumFetcher(transport=KEY),  # type: ignore[arg-type]
            "^not a callable transport: a bytes of length 32$",
        ),
        (
            lambda: ElectrumFetcher(
                transport=TlsLineTransport("localhost", 1), verify_network=False
            ).get_block_headers(0, -SCALAR),
            "^invalid count: a negative int of 256 bits < 1$",
        ),
    ],
    ids=[
        "line of decimal digits",
        "line of a hex string",
        "response id",
        "reply with neither",
        "history height",
        "transaction",
        "tip not an object",
        "tip height",
        "tip hex",
        "header",
        "headers not an object",
        "headers count of hex",
        "headers count above the asked",
        "headers hex",
        "headers length",
        "merkle not an object",
        "merkle block_height",
        "merkle branch",
        "merkle pos",
        "fee not a number",
        "fee not a rate",
        "request params unwritable",
        "request params not finite",
        "fetcher transport",
        "fetcher count",
    ],
)
def test_electrum_describes_a_refused_reply_or_answered_field(
    call: Callable[[], object], err_msg: str
) -> None:
    """A line that is no reply, and each answered field refused (issue #795).

    A request json cannot write chains none of json's errors, whose notes
    quote the dict keys of the params.
    """
    with pytest.raises((BTClibTypeError, BTClibValueError), match=err_msg) as e:
        call()
    assert_secret_free(e.value, SPELLINGS)


def _bech32(hrp: str, data: bytes) -> str:
    """Return a bech32 string of `hrp` and the 5-bit words of `data`."""
    words = power_of_2_base_conversion(data, 8, 5)
    return bech32_encode(hrp, words, m=1, limit=None).decode("ascii")


@pytest.mark.parametrize(
    "call, err_msg",
    [
        (
            lambda: getattr(btclib_wallet, HEX),
            "^module 'btclib_wallet' has no attribute a value of 64 characters$",
        ),
        (lambda: Bip21.parse(HEX), "^not a bitcoin URI: a str of length 64$"),
        (
            lambda: Bip21.parse(f"bitcoin:{ADDRESS}?amount={HEX}"),
            "^invalid bip21 amount: a str of length 64$",
        ),
        (
            lambda: Bolt11Invoice.from_invoice(_bech32(HEX, b"")),
            "^not a lightning invoice prefix: a str of length 64$",
        ),
        (
            lambda: Bolt11Invoice.from_invoice(_bech32(f"ln{HEX}", b"")),
            "^unknown network prefix: a str of length 66$",
        ),
        (
            lambda: Bolt11Invoice.from_invoice(_bech32(f"lnbc{HEX}", b"")),
            "^invalid amount: a str of length 64$",
        ),
        (
            lambda: Bolt11Invoice.from_invoice(_bech32("lnbc", KEY)),
            "^invoice too short: a str of length 63$",
        ),
        (
            lambda: Bolt11Invoice(HEX, 0, [], DsaSig(1, 1, check_validity=False), 0),
            "^not a lightning network: a value of 64 characters$",
        ),
        (
            lambda: Bolt11Invoice.sign(
                1, HEX, 0, b"\x00" * 32, b"\x00" * 32, description="d"
            ),
            "^not a lightning network: a value of 64 characters$",
        ),
        (
            lambda: import_request(account_pair()[0], HEX),
            '^expected a number or "now" as timestamp: a str of length 64$',
        ),
        (
            lambda: parse_descriptor(f"wpkh(\N{LATIN SMALL LETTER E WITH ACUTE}{HEX})"),
            "^invalid descriptor character at position 5$",
        ),
    ],
    ids=[
        "attribute",
        "bip21 uri",
        "bip21 amount",
        "bolt11 prefix",
        "bolt11 network prefix",
        "bolt11 amount",
        "bolt11 invoice",
        "bolt11 network",
        "bolt11 network signed",
        "core import timestamp",
        "descriptor character",
    ],
)
def test_a_refused_argument_is_described(
    call: Callable[[], object], err_msg: str
) -> None:
    """A key passed in the wrong place is not in the refusal (issue #802)."""
    with pytest.raises((AttributeError, BTClibValueError), match=err_msg) as e:
        call()
    assert_secret_free(e.value, SPELLINGS)


class _EqualToAll(int):
    """An int equal to every value, so that it is in any range."""

    @override
    def __eq__(self, _other: object) -> bool:
        return True

    __hash__ = int.__hash__


def test_an_int_equal_to_all_is_in_any_range() -> None:
    """By its own comparison, which is why `assert_imported` reads int's."""
    assert _EqualToAll(SCALAR) in range(-(2**15), 2**15)


@pytest.mark.parametrize(
    "code",
    [SCALAR, -SCALAR, _EqualToAll(SCALAR), HEX],
    ids=["scalar", "negative scalar", "int equal to all", "hex"],
)
def test_core_import_quotes_no_code_outside_16_signed_bits(code: object) -> None:
    """JSON bounds no integer, so a code can hold a key (issue #836)."""
    answer = {"success": False, "error": {"code": code}}
    err_msg = "^import refused for request 0: error code None$"
    with pytest.raises(BTClibRuntimeError, match=err_msg) as e:
        assert_imported([{}], [answer])
    assert_secret_free(e.value, SPELLINGS)


@pytest.mark.parametrize(
    "value, shown",
    [
        ("mainnet", "mainnet"),
        (HEX, "a value of 64 characters"),
        (KEY, "a bytes of length 32"),
        (SCALAR, "a value of more than 16 digits"),
    ],
    ids=["label", "hex", "bytes", "scalar"],
)
def test_a_label_is_written_only_where_the_package_holds_it(
    value: object, shown: str
) -> None:
    """Any other value is shown as `_quoted` shows it (issue #821)."""
    labels = ("mainnet", "testnet")
    assert _label(value, labels) == shown
    assert_secret_free(BTClibValueError(_label(value, labels)), SPELLINGS)


@pytest.mark.parametrize(
    "call, err_msg",
    [
        (
            lambda: TlsLineTransport(KEY, 1),  # type: ignore[arg-type]
            "^non-string host: a bytes of length 32$",
        ),
        (lambda: TlsLineTransport(HEX, 1), "^invalid host: a value of 64 characters$"),
        (
            lambda: TlsLineTransport("h", HEX),  # type: ignore[arg-type]
            "^non-integer port: a str of length 64$",
        ),
        (lambda: TlsLineTransport("h", SCALAR), "^invalid port: an int of 256 bits$"),
        (
            lambda: TlsLineTransport("h", 1, context=KEY),  # type: ignore[arg-type]
            "^not an ssl.SSLContext: a bytes of length 32$",
        ),
        (
            lambda: TlsLineTransport("h", 1, max_line_size=HEX),  # type: ignore[arg-type]
            "^non-integer max_line_size: a str of length 64$",
        ),
        (
            lambda: TlsLineTransport("h", 1, max_line_size=-SCALAR),
            "^invalid max_line_size: a negative int of 256 bits$",
        ),
        (
            lambda: TlsLineTransport("h", 1)(HEX, 1.0),  # type: ignore[arg-type]
            "^non-bytes request: a str of length 64$",
        ),
        (
            lambda: TlsLineTransport("h", 1)(KEY, 1.0),
            "^not one newline-terminated line: a bytes of length 32$",
        ),
        (
            lambda: TcpLineTransport(KEY, 1),  # type: ignore[arg-type]
            "^non-string host: a bytes of length 32$",
        ),
        (lambda: TcpLineTransport(HEX, 1), "^invalid host: a value of 64 characters$"),
        (
            lambda: TcpLineTransport("h", HEX),  # type: ignore[arg-type]
            "^non-integer port: a str of length 64$",
        ),
        (lambda: TcpLineTransport("h", SCALAR), "^invalid port: an int of 256 bits$"),
        (
            lambda: TcpLineTransport("h", 1, max_line_size=HEX),  # type: ignore[arg-type]
            "^non-integer max_line_size: a str of length 64$",
        ),
        (
            lambda: TcpLineTransport("h", 1, max_line_size=-SCALAR),
            "^invalid max_line_size: a negative int of 256 bits$",
        ),
        (
            lambda: TcpLineTransport("h", 1)(HEX, 1.0),  # type: ignore[arg-type]
            "^non-bytes request: a str of length 64$",
        ),
        (
            lambda: TcpLineTransport("h", 1)(KEY, 1.0),
            "^not one newline-terminated line: a bytes of length 32$",
        ),
        (
            lambda: PersistentTlsLineTransport(KEY, 1),  # type: ignore[arg-type]
            "^non-string host: a bytes of length 32$",
        ),
        (
            lambda: PersistentTlsLineTransport(HEX, 1),
            "^invalid host: a value of 64 characters$",
        ),
        (
            lambda: PersistentTlsLineTransport("h", HEX),  # type: ignore[arg-type]
            "^non-integer port: a str of length 64$",
        ),
        (
            lambda: PersistentTlsLineTransport("h", SCALAR),
            "^invalid port: an int of 256 bits$",
        ),
        (
            lambda: PersistentTlsLineTransport("h", 1, context=KEY),  # type: ignore[arg-type]
            "^not an ssl.SSLContext: a bytes of length 32$",
        ),
        (
            lambda: PersistentTlsLineTransport("h", 1, max_line_size=HEX),  # type: ignore[arg-type]
            "^non-integer max_line_size: a str of length 64$",
        ),
        (
            lambda: PersistentTlsLineTransport("h", 1, max_line_size=-SCALAR),
            "^invalid max_line_size: a negative int of 256 bits$",
        ),
        (
            lambda: PersistentTlsLineTransport("h", 1)(HEX, 1.0),  # type: ignore[arg-type]
            "^non-bytes request: a str of length 64$",
        ),
        (
            lambda: PersistentTlsLineTransport("h", 1)(KEY, 1.0),
            "^not one newline-terminated line: a bytes of length 32$",
        ),
        (
            lambda: PersistentTlsLineTransport("h", 1)(f'"{HEX}"\n'.encode(), 1.0),
            "^not a JSON-RPC message: a str of length 64$",
        ),
        (
            lambda: PersistentTlsLineTransport("h", 1)(
                f'{{"id": "{HEX}"}}\n'.encode(), 1.0
            ),
            "^not an integer id: a str of length 64$",
        ),
        (
            lambda: TcpPeerTransport(KEY, 1),  # type: ignore[arg-type]
            "^non-string host: a bytes of length 32$",
        ),
        (lambda: TcpPeerTransport(HEX, 1), "^invalid host: a value of 64 characters$"),
        (
            lambda: TcpPeerTransport("h", HEX),  # type: ignore[arg-type]
            "^non-integer port: a str of length 64$",
        ),
        (lambda: TcpPeerTransport("h", SCALAR), "^invalid port: an int of 256 bits$"),
        (
            lambda: TcpPeerTransport("h", 1).send(KEY, 1.0),  # type: ignore[arg-type]
            "^non-Message message: a bytes of length 32$",
        ),
        (lambda: V2PeerTransport(HEX, 1), "^invalid host: a value of 64 characters$"),
        (
            lambda: V2PeerTransport("h", 1, v1_fallback=KEY),  # type: ignore[arg-type]
            "^invalid v1_fallback type: bytes$",
        ),
        (
            lambda: CompactFilterFetcher("regtest", transport=KEY),  # type: ignore[arg-type]
            "^not a peer transport: a bytes of length 32$",
        ),
        (
            lambda: EsploraFetcher(
                "https://esplora.example/api",
                transport=KEY,  # type: ignore[arg-type]
            ),
            "^not a callable transport: a bytes of length 32$",
        ),
        (
            lambda: BitcoinCoreFetcher(
                BitcoinCoreRpcClient(URL, user=RPC_USER, password=RPC_PASSWORD),
                estimate_mode=HEX,
            ),
            "^invalid estimate_mode: a value of 64 characters$",
        ),
    ],
    ids=[
        "tls host",
        "tls host name",
        "tls port type",
        "tls port",
        "tls context",
        "tls max_line_size type",
        "tls max_line_size",
        "tls request type",
        "tls request",
        "tcp host",
        "tcp host name",
        "tcp port type",
        "tcp port",
        "tcp max_line_size type",
        "tcp max_line_size",
        "tcp request type",
        "tcp request",
        "persistent host",
        "persistent host name",
        "persistent port type",
        "persistent port",
        "persistent context",
        "persistent max_line_size type",
        "persistent max_line_size",
        "persistent request type",
        "persistent request",
        "persistent request message",
        "persistent request id",
        "peer host",
        "peer host name",
        "peer port type",
        "peer port",
        "peer message",
        "v2 peer host name",
        "v2 peer v1_fallback",
        "compact filters transport",
        "esplora transport",
        "estimate_mode",
    ],
)
def test_a_refused_fetch_argument_is_described(
    call: Callable[[], object], err_msg: str
) -> None:
    """A key a transport or fetcher refuses is not in the text (issue #802).

    The host is refused after `suppress`: the idna codec's error holds it.
    """
    with pytest.raises((BTClibTypeError, BTClibValueError), match=err_msg) as e:
        call()
    assert_secret_free(e.value, SPELLINGS)


@pytest.mark.parametrize(
    "call, err_msg",
    [
        (
            lambda: electrum_fetcher(5).get_tx(KEY),
            "^transaction: a malformed answer$",
        ),
        (
            lambda: electrum_fetcher([]).get_tx_merkle(KEY, 1),
            ("^transaction merkle: a malformed answer$"),
        ),
        (
            lambda: electrum_fetcher(5).get_block_header(SCALAR),
            "^block header: a malformed answer$",
        ),
        (
            lambda: electrum_fetcher(5).get_block_headers(0, SCALAR),
            "^block headers: a malformed answer$",
        ),
        (
            lambda: tx_from_raw(5, HEX, "mainnet"),  # type: ignore[arg-type]
            "^transaction: not a serialization, but a int$",
        ),
        (
            lambda: tx_from_raw(SEGWIT_TX_RAW, HEX, "mainnet"),
            "^transaction: the answer is another transaction than the one asked$",
        ),
    ],
    ids=[
        "transaction",
        "transaction merkle",
        "block header",
        "block headers",
        "not a serialization",
        "another transaction",
    ],
)
def test_a_fetch_error_names_what_was_asked_without_its_value(
    call: Callable[[], object], err_msg: str
) -> None:
    """The label names the request, not the tx id or height (issue #805)."""
    with pytest.raises(FetchError, match=err_msg) as e:
        call()
    assert_secret_free(e.value, SPELLINGS)


@pytest.mark.parametrize(
    "call, code",
    [
        (
            lambda: electrum_fetcher(
                RpcErrorAnswer(f"{HEX} should be a transaction hash", 2, data=HEX)
            ).get_tx(KEY),
            2,
        ),
        (
            lambda: decode_response(
                json.dumps({"id": 1, "error": {"code": HEX, "data": HEX}}).encode(),
                1,
                "blockchain.transaction.get",
            ),
            0,
        ),
        (
            lambda: decode_response(
                json.dumps({"id": 1, "error": {"code": SCALAR}}).encode(),
                1,
                "blockchain.transaction.get",
            ),
            0,
        ),
        (
            lambda: decode_response(
                json.dumps({"id": None, "error": HEX}).encode(),
                1,
                "blockchain.transaction.get",
            ),
            0,
        ),
    ],
    ids=["message and data", "code and data", "scalar code", "bare error"],
)
def test_an_electrum_error_keeps_its_code_and_drops_its_text(
    call: Callable[[], object], code: int
) -> None:
    """A server's text can quote the request it refuses (issue #806)."""
    err_msg = "^blockchain.transaction.get: the server answered an error"
    err_msg += rf" \(rpc error code {code}\)$"
    with pytest.raises(RpcError, match=err_msg) as e:
        call()
    assert e.value.code == code
    assert e.value.data is None
    assert_secret_free(e.value, SPELLINGS)


def test_decode_response_refuses_a_method_the_protocol_does_not_name() -> None:
    """An `RpcError` names the method, so a key in its place is refused first.

    The refusal describes it (issue #806).
    """
    line = json.dumps({"id": 1, "error": {"code": 2, "message": "x"}}).encode()
    with pytest.raises(
        BTClibValueError, match="^unknown method: a str of length 64$"
    ) as e:
        decode_response(line, 1, HEX)
    assert_secret_free(e.value, SPELLINGS)


@pytest.mark.parametrize(
    "call, err_msg",
    [
        (
            lambda: Bip21.parse(f"bitcoin:{ADDRESS}?label={HEX}%ff"),
            "^invalid percent-encoding in label$",
        ),
        (
            lambda: BIP32KeyData(
                b"\x04\x88\xad\xe4", 1, b"\x01" * 4, SCALAR, b"\x00" * 32, b"\x00" + KEY
            ),
            "^invalid index: a value of more than 16 digits$",
        ),
        (
            lambda: nsec_from_root_key("", -SCALAR, 1),
            "^invalid nostr identity: a value of more than 16 digits$",
        ),
        (
            lambda: Bolt11Invoice(
                "mainnet", SCALAR, [], DsaSig(1, 1, check_validity=False), 0
            ),
            "^timestamp does not fit 35 bits: a value of more than 16 digits$",
        ),
    ],
    ids=["bip21 percent-escape", "bip32 index", "bip85 identity", "bolt11 timestamp"],
)
def test_a_refusal_of_each_kind_prints_no_key(
    call: Callable[[], object], err_msg: str
) -> None:
    """A key passed as an int or inside a str is in no refusal (issue #821).

    The percent-escape's `UnicodeDecodeError` holds the whole decoded
    value, so the refusal chains nothing.
    """
    with pytest.raises(BTClibValueError, match=err_msg) as e:
        call()
    assert_secret_free(e.value, SPELLINGS)


def test_a_host_that_passed_construction_is_described_where_it_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two labels of a key's hex are a hostname, quoted up to 16 characters.

    The connection is refused, and the refusal names the host as
    `_quoted` does (issue #821).
    """

    def create_connection(address: tuple[str, int], timeout: float) -> object:
        raise ConnectionRefusedError(address, timeout)

    monkeypatch.setattr(transport_module, "create_connection", create_connection)
    host = f"{HEX[:32]}.{HEX[32:]}"
    err_msg = "^no answer from a value of 65 characters:1: ConnectionRefusedError$"
    with pytest.raises(FetchError, match=err_msg) as e:
        TcpLineTransport(host, 1)(b"{}\n", 1.0)
    assert e.value.__cause__ is None
    assert_secret_free(e.value, SPELLINGS)
