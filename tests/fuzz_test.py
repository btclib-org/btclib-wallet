# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every parser, on input nobody wrote down.

The rest of the suite is fixed vectors: exactly what conformance needs,
and blind to the malformed bytes that never make it into a
specification's test section. This file is the converse. It does not
assert that a parser accepts the right things -- the vectors do that --
but that it *fails the way the library says it fails*, whatever it is
handed.

Issues btclib-org/btclib#133, btclib-org/btclib#135 and
btclib-org/btclib#138 were all one bug: a parser answering hostile input
with IndexError, or OverflowError, or a silent short read, where the
caller was catching BTClibValueError to reject it. btclib's own
`fuzz_test.py` drives btclib's parsers, and this one this package's.
"""

import contextlib
import functools
import importlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from btclib.bech32 import encode as bech32_encode
from btclib.exceptions import BTClibValueError
from hypothesis import example, given
from hypothesis import strategies as st

from btclib_wallet import bip38, bip322, descriptors, electrum, minikey, silent_payments
from btclib_wallet.bip21 import Bip21
from btclib_wallet.bip32.bip32 import BIP32KeyData
from btclib_wallet.bip32.der_path import indexes_from_der_path
from btclib_wallet.bip32.key_origin import BIP32KeyOrigin
from btclib_wallet.bolt11 import _SIGNATURE_WORDS, Bolt11Invoice
from btclib_wallet.descriptors import miniscript
from btclib_wallet.dlc import oracle
from btclib_wallet.psbt import psbt_utils
from btclib_wallet.psbt.psbt import Psbt
from btclib_wallet.psbt.psbt_in import PsbtIn
from btclib_wallet.psbt.psbt_out import PsbtOut
from btclib_wallet.tx_or_psbt import tx_or_psbt_from_any
from tests import aes_decrypt_block, aes_expand_key, module_names, public_classes_with
from tests.exception_family_test import RUNTIME_ERRORS, TYPE_ERRORS, VALUE_ERRORS

# What a parser is allowed to raise. Anything else -- an IndexError off a
# short slice, an OverflowError off an unchecked size, a KeyError, a
# UnicodeDecodeError -- leaves the contract btclib's exceptions module
# documents, and reaches a caller who wrote `except BTClibValueError` to
# reject bad input and has no reason to expect anything else. Each of the
# three with ecc's class of its kind beside it, which is what a
# parse that library performs refuses with (issue btclib-org/btclib#2282)
CONTRACT = (*VALUE_ERRORS, *TYPE_ERRORS, *RUNTIME_ERRORS)

# Bounded because these are parsers, not benchmarks: what a length field
# does with the bytes behind it is decided in the first few of them, and
# an input long enough to be interesting to a parser is one this
# strategy cannot stumble on anyway. The mutation test below is what
# reaches past the outermost check
MAX_INPUT = 512

BINARY_PARSERS: dict[str, Callable[[bytes], Any]] = {
    "Psbt.parse": Psbt.parse,
    "PsbtIn.parse": PsbtIn.parse,
    "PsbtOut.parse": PsbtOut.parse,
    "psbt_utils.deserialize_map": lambda data: psbt_utils.deserialize_map(data, "any"),
    "psbt_utils.parse_leaf_script": psbt_utils.parse_leaf_script,
    "psbt_utils.parse_taproot_tree": psbt_utils.parse_taproot_tree,
    "psbt_utils.parse_taproot_bip32": psbt_utils.parse_taproot_bip32,
    "BIP32KeyData.parse": BIP32KeyData.parse,
    "BIP32KeyOrigin.parse": BIP32KeyOrigin.parse,
    "OracleEvent.parse": oracle.OracleEvent.parse,
    "OracleAnnouncement.parse": oracle.OracleAnnouncement.parse,
    "OracleAttestation.parse": oracle.OracleAttestation.parse,
    # no bip322.Sig.parse: that class has none, its three payloads being
    # three unrelated serializations told apart by the prefix of the text
    # form alone, so the text entry point below is where it is read
}


@functools.wraps(bip38.decrypt)
def _bip38_decrypt(encrypted_key: str) -> Any:
    """Call `bip38.decrypt` with a fixed password and the test AES-256.

    `wraps` gives the wrapper `decrypt`'s name and module, which is what
    the inventory check below reads off an entry.
    """
    return bip38.decrypt(
        encrypted_key,
        "password",
        lambda key, block: aes_decrypt_block(block, aes_expand_key(key)),
    )


# The same contract, for what a user pastes rather than what a peer
# sends: a URI, an extended key, a descriptor.
#
# The base64 wrappers are here rather than above, and each is a parser of
# its own: `b64decode` decodes and then hands the bytes to `parse`, so
# what it adds is the decoding -- a str that is not ascii, padding that
# is not canonical, a length no multiple of four -- and that is a layer
# the binary entry point never sees
TEXT_PARSERS: dict[str, Callable[[str], Any]] = {
    "Bip21.parse": Bip21.parse,
    "BIP32KeyData.b58decode": BIP32KeyData.b58decode,
    "bip322.Sig.b64decode": bip322.Sig.b64decode,
    "Psbt.b64decode": Psbt.b64decode,
    "descriptors.checksum": descriptors.checksum,
    "descriptors.parse": descriptors.parse,
    "miniscript.parse": miniscript.parse,
    "Bolt11Invoice.from_invoice": Bolt11Invoice.from_invoice,
    "silent_payments.keys_from_address": silent_payments.keys_from_address,
    "bip38.decrypt": _bip38_decrypt,
    "minikey.prv_key_data_from_minikey": minikey.prv_key_data_from_minikey,
    "der_path.indexes_from_der_path": indexes_from_der_path,
    "tx_or_psbt.tx_or_psbt_from_any": tx_or_psbt_from_any,
}


# A class-level decoder is one of these: `parse` for octets, `b64decode`
# and `b58decode` for the two text encodings a class reads on its own, and
# `from_invoice` for BOLT11's bech32 text. `serialization_boundary_test.py`
# walks the first three only
_CLASS_DECODER_METHODS = ("parse", "b64decode", "b58decode", "from_invoice")

# And the module-function side: the names a bare function decodes
# under. A decoder named otherwise -- the `psbt_utils` entries above are
# such -- rests on the dicts, by hand, not on this walk
_MODULE_DECODER_NAMES = (
    "parse",
    "decode",
    "checksum",
    "decrypt",
    "keys_from_address",
    "prv_key_data_from_minikey",
    "indexes_from_der_path",
    "tx_or_psbt_from_any",
)


def _classes_driven_here() -> set[str]:
    """Every class the two dicts above drive, through which decoder.

    A bound classmethod carries in `__self__` the class it was read off
    rather than the one that defines the method, which is what the entry
    names: `GetCFilters` inherits `_FilterRangeRequest.parse`, and
    `__qualname__` answers with a private base the walk below never
    returns. The method name is part of the key, since a class offering
    two of them would otherwise collide.
    """
    driven = set()
    for entry_point in (*BINARY_PARSERS.values(), *TEXT_PARSERS.values()):
        cls = getattr(entry_point, "__self__", None)
        if isinstance(cls, type) and entry_point.__name__ in _CLASS_DECODER_METHODS:
            driven.add(f"{cls.__module__}.{cls.__qualname__}.{entry_point.__name__}")
    return driven


def _functions_driven_here() -> set[str]:
    """Every module function the two dicts above drive, module included."""
    return {
        f"{entry_point.__module__}.{entry_point.__name__}"
        for entry_point in (*BINARY_PARSERS.values(), *TEXT_PARSERS.values())
        if getattr(entry_point, "__self__", None) is None
    }


def test_every_class_that_decodes_is_driven_here() -> None:
    """The inventory is a promise only if omission is what fails.

    A class added to the package and given no line above is held to
    nothing here: the tests keep passing on the entry points they were
    given, and the new decoder answers hostile input however it likes.
    The walk is `tests/__init__.py`'s, `parse_contract_test.py` and
    `serialization_boundary_test.py` holding these same classes to their
    own contracts through it.
    """
    found = {
        f"{name}.{method}"
        for method in _CLASS_DECODER_METHODS
        for name in public_classes_with(method)
    }
    # a walk returning nothing is a defect in the walk and not in the
    # inventory, and the equality alone answers it with a mismatch of
    # every name: this is what says which of the two a red run is
    assert found
    assert found == _classes_driven_here()


def test_every_module_function_that_decodes_is_driven_here() -> None:
    """And the same promise where the entry point is a module function.

    The walk above finds classes, so a module-level decoder needs its
    own names, `_MODULE_DECODER_NAMES`.
    What is asserted is containment and not equality: the dicts already
    drive entry points named otherwise, and their coverage rests on the
    dicts above, by hand, not on this walk.
    """
    found = set()
    for module_name in module_names():
        module = importlib.import_module(module_name)
        for name in _MODULE_DECODER_NAMES:
            function = getattr(module, name, None)
            if not callable(function) or isinstance(function, type):
                continue
            if getattr(function, "__module__", "") != module_name:
                continue
            found.add(f"{module_name}.{name}")

    # the containment below is what an empty walk passes, the class walk
    # above having an equality to fail instead
    assert found
    assert found - _functions_driven_here() == set()


def _assert_contract(parse: Callable[[Any], Any], data: Any) -> None:
    """Call parse, and let anything outside the contract propagate.

    Rejecting the input is the expected answer to almost all of what
    these strategies generate, so there is nothing to assert about it.
    What the test is for is the third outcome, neither a value nor a
    refusal: hypothesis reports the exception, and the input it shrank
    to reach it.
    """
    with contextlib.suppress(*CONTRACT):
        parse(data)


@pytest.mark.parametrize(
    "parse", BINARY_PARSERS.values(), ids=list(BINARY_PARSERS.keys())
)
@given(data=st.binary(max_size=MAX_INPUT))
def test_binary_parser_honors_the_exception_contract(
    parse: Callable[[bytes], Any], data: bytes
) -> None:
    """Fuzz every binary parser: refusals stay within the contract."""
    _assert_contract(parse, data)


@pytest.mark.parametrize("parse", TEXT_PARSERS.values(), ids=list(TEXT_PARSERS.keys()))
@given(data=st.text(max_size=MAX_INPUT))
def test_text_parser_honors_the_exception_contract(
    parse: Callable[[str], Any], data: str
) -> None:
    """Fuzz every text parser: refusals stay within the contract."""
    _assert_contract(parse, data)


# A number of more than 4300 digits is past `MAX_INPUT` and past what
# `int()` takes, so the strategy above cannot stumble on it. Each text
# parser is handed one in every place a number is read.
_KEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"  # pragma: allowlist secret
_XPUB = (
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjq"  # pragma: allowlist secret
    "JoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"  # pragma: allowlist secret
)
_MINISCRIPT_TEXTS = (
    "older({n})",
    f"thresh({{n}},pk({_KEY}),s:pk({_KEY}))",
    f"multi({{n}},{_KEY})",
)
LONG_NUMBER_TEXTS = [(miniscript.parse, text) for text in _MINISCRIPT_TEXTS] + [
    (descriptors.parse, f"wsh(and_v(v:pk({_KEY}),{_MINISCRIPT_TEXTS[0]}))"),
    (descriptors.parse, f"wsh({_MINISCRIPT_TEXTS[1]})"),
    (descriptors.parse, f"wsh({_MINISCRIPT_TEXTS[2]})"),
    (descriptors.parse, f"wpkh({_XPUB}/{{n}})"),
]


def test_invoice_refuses_an_amount_over_4300_digits() -> None:
    """An amount `int()` cannot read leaves as the contract says."""
    for digits in ("9" * 5000, "0" * 5000 + "1"):
        words = [0] * (7 + _SIGNATURE_WORDS)
        invoice = bech32_encode("lnbc" + digits + "m", words, 1).decode()
        _assert_contract(Bolt11Invoice.from_invoice, invoice)


@pytest.mark.parametrize("parse, template", LONG_NUMBER_TEXTS)
def test_text_parser_refuses_a_number_over_4300_digits(
    parse: Callable[[str], Any], template: str
) -> None:
    """A number `int()` cannot read leaves as the contract says."""
    for digits in ("9" * 5000, "0" * 5000 + "1"):
        _assert_contract(parse, template.format(n=digits))


def _first_valid_psbt() -> bytes:
    """Return BIP174's first valid psbt, re-serialized to bytes."""
    filename = Path("psbt") / "_data" / "bip174_test_vectors.json"
    with (Path(__file__).parent / filename).open(encoding="ascii") as file_:
        vectors = json.load(file_)
    return Psbt.b64decode(vectors["valid psbts"][0]["encoded psbt"]).serialize()


PSBT_BIN = _first_valid_psbt()


def _mutations(sample: bytes) -> st.SearchStrategy[bytes]:
    """Return the near-misses of a valid serialization.

    Uniform random bytes are rejected by the first field of a parser and
    so exercise the outermost check and nothing beneath it. What reaches
    the code underneath is a serialization valid right up to the point
    where it is not: the truncation, the flipped length prefix, the
    trailing junk that must not be taken for a second record.
    """
    truncated = st.integers(min_value=0, max_value=len(sample)).map(
        lambda i: sample[:i]
    )
    flipped = st.builds(
        lambda i, byte: sample[:i] + bytes([byte]) + sample[i + 1 :],
        st.integers(min_value=0, max_value=len(sample) - 1),
        st.integers(min_value=0, max_value=0xFF),
    )
    extended = st.binary(max_size=32).map(lambda tail: sample + tail)
    return st.one_of(truncated, flipped, extended)


MUTATED_PARSERS: dict[str, tuple[Callable[[bytes], Any], bytes]] = {
    "Psbt.parse": (Psbt.parse, PSBT_BIN),
}


@pytest.mark.parametrize(
    "parse, sample",
    MUTATED_PARSERS.values(),
    ids=list(MUTATED_PARSERS.keys()),
)
@given(data=st.data())
def test_mutated_serialization_honors_the_exception_contract(
    parse: Callable[[bytes], Any], sample: bytes, data: st.DataObject
) -> None:
    """Fuzz near-miss serializations: refusals stay within the contract."""
    _assert_contract(parse, data.draw(_mutations(sample)))


# What a hostile Electrum server sends: one line of bytes, answering the
# request whose id the decoder is given. `decode_response` reads the line
# and each `*_response` function the `result` it returns, so a decoder
# is driven by the lines its own result shape accepts as well as by
# bytes that are no JSON at all. `block_headers_response` also takes the
# number of headers asked for; a balance batch takes the ids of every request
ELECTRUM_REQUEST_ID = 1
ELECTRUM_HEADERS_ASKED = 2
ELECTRUM_RESPONSES: dict[str, Callable[[bytes], Any]] = {
    name: functools.partial(
        getattr(electrum, name),
        **(
            {"request_ids": [ELECTRUM_REQUEST_ID]}
            if name == "scripthash_get_balance_batch_response"
            else {"request_id": ELECTRUM_REQUEST_ID}
        ),
        **(
            {"count": ELECTRUM_HEADERS_ASKED}
            if name == "block_headers_response"
            else {}
        ),
    )
    for name in electrum.__all__
    if name.endswith("_response")
}


def test_every_electrum_response_decoder_is_driven_here() -> None:
    """A decoder the module exports and the dict above lacks fails here.

    The module-function walk above reads the names `_MODULE_DECODER_NAMES`
    lists, which none of these has.
    """
    assert "decode_response" in ELECTRUM_RESPONSES
    assert len(ELECTRUM_RESPONSES) > 1
    assert {
        name
        for name in dir(electrum)
        if name.endswith("_response") and not name.startswith("_")
    } == set(ELECTRUM_RESPONSES)


# A line that is valid JSON of the right shape right up to the field a
# decoder reads: random bytes are refused by the JSON parser and reach
# nothing beneath it. The leaves are what the helpers ask of a field, an
# integer, a hex string, a list, a number, and what they refuse
_ELECTRUM_KEYS = st.sampled_from(
    [
        "id",
        "result",
        "error",
        "height",
        "hex",
        "block_height",
        "merkle",
        "pos",
        "count",
        "max",
    ]
)
_ELECTRUM_HEX = st.binary(max_size=80).map(bytes.hex) | st.just("00" * 32)
# whole headers, up to the number `ELECTRUM_HEADERS_ASKED` asks for
_ELECTRUM_HEADERS_HEX = st.integers(0, ELECTRUM_HEADERS_ASKED).flatmap(
    lambda n: st.binary(min_size=80 * n, max_size=80 * n).map(bytes.hex)
)
_ELECTRUM_JSON = st.recursive(
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(allow_nan=False)
    | st.text(max_size=8)
    | _ELECTRUM_HEX,
    lambda children: (
        st.lists(children, max_size=3)
        | st.dictionaries(_ELECTRUM_KEYS, children, max_size=4)
    ),
    max_leaves=12,
)
# a `result` shaped as each decoder reads it, each field either what it
# asks for or anything at all: the shape is what gets a line past the
# first checks, and a recursive strategy rarely draws it by chance
_ELECTRUM_RESULTS = (
    _ELECTRUM_JSON
    | st.fixed_dictionaries(
        {
            "height": st.integers() | _ELECTRUM_JSON,
            "hex": _ELECTRUM_HEX | _ELECTRUM_JSON,
        }
    )
    | st.fixed_dictionaries(
        {
            "block_height": st.integers() | _ELECTRUM_JSON,
            "merkle": st.lists(_ELECTRUM_HEX | _ELECTRUM_JSON, max_size=3)
            | _ELECTRUM_JSON,
            "pos": st.integers() | _ELECTRUM_JSON,
        }
    )
    | st.fixed_dictionaries(
        {
            "count": st.integers(-1, ELECTRUM_HEADERS_ASKED + 1) | _ELECTRUM_JSON,
            "hex": _ELECTRUM_HEADERS_HEX | _ELECTRUM_HEX | _ELECTRUM_JSON,
            "max": st.integers() | _ELECTRUM_JSON,
        }
    )
    | st.floats(allow_nan=False, allow_infinity=False)
)
_ELECTRUM_REPLIES = st.builds(
    lambda reply: json.dumps(reply).encode(),
    st.fixed_dictionaries(
        {"id": st.just(ELECTRUM_REQUEST_ID) | _ELECTRUM_JSON},
        optional={"result": _ELECTRUM_RESULTS, "error": _ELECTRUM_JSON},
    ),
)
# and a result nested around the bound `electrum._MAX_NESTING` sets, which
# a recursive strategy never reaches
_ELECTRUM_NESTED = st.integers(min_value=0, max_value=40).map(
    lambda depth: b'{"id":1,"result":' + b"[" * depth + b"]" * depth + b"}"
)
ELECTRUM_LINES = st.binary(max_size=MAX_INPUT) | _ELECTRUM_REPLIES | _ELECTRUM_NESTED


@pytest.mark.parametrize(
    "decode", ELECTRUM_RESPONSES.values(), ids=list(ELECTRUM_RESPONSES.keys())
)
@given(line=ELECTRUM_LINES)
def test_electrum_response_honors_the_exception_contract(
    decode: Callable[[bytes], Any], line: bytes
) -> None:
    """Fuzz every Electrum decoder: refusals stay within the contract."""
    _assert_contract(decode, line)


# What a stray-exception test cannot see: input the decoder must refuse
# and could return as a value, with no exception to catch. Each case
# asserts the refusal itself
_ELECTRUM_REFUSED = pytest.mark.parametrize(
    "decode", ELECTRUM_RESPONSES.values(), ids=list(ELECTRUM_RESPONSES.keys())
)


@_ELECTRUM_REFUSED
@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_electrum_response_refuses_a_constant_json_lacks(
    decode: Callable[[bytes], Any], constant: str
) -> None:
    """RFC 8259 has no `NaN` or `Infinity`, which `json` writes and reads."""
    line = json.dumps({"id": ELECTRUM_REQUEST_ID, "result": float(constant)})
    assert constant in line
    with pytest.raises(BTClibValueError, match="not a JSON-RPC line"):
        decode(line.encode())


@given(depth=st.integers(min_value=2, max_value=40) | st.just(2000))
@example(depth=16)
@example(depth=17)
def test_decode_response_refuses_nesting_past_the_bound(depth: int) -> None:
    """The reply object is level 1, and 16 levels are read."""
    line = b'{"id":1,"result":' + b"[" * (depth - 1) + b"]" * (depth - 1) + b"}"
    if depth > 16:
        with pytest.raises(BTClibValueError, match="nested beyond"):
            electrum.decode_response(line, ELECTRUM_REQUEST_ID)
    else:
        electrum.decode_response(line, ELECTRUM_REQUEST_ID)


@_ELECTRUM_REFUSED
@pytest.mark.parametrize("encoding", ["utf-16", "utf-32", "utf-16-le", "utf-8-sig"])
def test_electrum_response_refuses_a_line_that_is_not_plain_utf8(
    decode: Callable[[bytes], Any], encoding: str
) -> None:
    """`json.loads` guesses UTF-16 and UTF-32 from bytes; Electrum is UTF-8."""
    line = json.dumps({"id": ELECTRUM_REQUEST_ID, "result": "00" * 32})
    with pytest.raises(BTClibValueError, match="not a JSON-RPC line"):
        decode(line.encode(encoding))
