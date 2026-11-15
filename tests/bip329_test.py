# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib_wallet.bip329` module.

The oracle is the fragment of BIP329's Test Vectors section, vendored as
`tests/_data/bip329_test_vectors.jsonl` and pinned in
`tests/_data/README.md`; every other record here is composed, a key in it
derived at run time from a fixed seed.
"""

from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest
from btclib import b58
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.key import PubKeyData
from ecc.curves import bytes_from_point, mult, point_from_pub_key

from btclib_wallet import bip329
from btclib_wallet.bip32 import bip32
from btclib_wallet.descriptors import add_checksum
from tests.secret_free import assert_secret_free

_VECTORS = Path(__file__).parent / "_data" / "bip329_test_vectors.jsonl"

TXID = sha256(b"bip329 tx").hexdigest()
# a root of a fixed random seed, and its public key
XPRV = bip32.rootxprv_from_seed(sha256(b"bip329 seed").digest()[:16])
XPUB = bip32.xpub_from_xprv(XPRV)
PUB_KEY = bip32.BIP32KeyData.b58decode(XPUB).key.hex()
UNCOMPRESSED = bytes_from_point(point_from_pub_key(PUB_KEY), compressed=False).hex()
ADDRESS = "bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c"
# a base58 address, of the public key's hash
LEGACY = b58.p2pkh(PubKeyData(bytes.fromhex(PUB_KEY)))
WIF = b58.wif_from_prv_key(int.from_bytes(sha256(b"bip329 wif").digest()))
ORIGIN = "wpkh([d34db33f/84'/0'/0'])"
# falsy examples of wrong field types
_FALSY: tuple[object, ...] = (0, False, b"", [], {})
# the public key `bip329` gives the first key origin of an origin
GENERATOR = bytes_from_point(mult(1)).hex()


def _exact(message: str) -> str:
    """Return a pattern matching `message` whole."""
    return f"^{re.escape(message)}$"


def _line(record: dict[str, Any]) -> str:
    return json.dumps(record) + "\n"


def test_the_bip_s_fragment_is_read_as_json_reads_it() -> None:
    """Each record of the fragment is its JSON object, but spscan, skipped."""
    text = _VECTORS.read_text(encoding="utf-8")
    objects = [json.loads(line) for line in text.splitlines()]
    assert {o["type"] for o in objects} == set(bip329.TYPES)
    expected = [o for o in objects if o["type"] != "spscan"]
    assert bip329.parse(text) == expected
    assert bip329.parse(bip329.serialize(expected)) == expected


def test_serialize_writes_one_json_object_per_line() -> None:
    """The fields in BIP329's order, each line ending in a newline."""
    record = {"spendable": True, "label": "é", "ref": f"{TXID}:7", "type": "output"}
    text = bip329.serialize([record])
    assert text == (
        f'{{"type": "output", "ref": "{TXID}:7", "label": "\\u00e9",'
        ' "spendable": true}\n'
    )
    assert text.isascii()
    assert bip329.parse(text) == [record]
    assert bip329.serialize([]) == ""


def test_every_type_but_spscan_is_kept() -> None:
    """A record of each type round-trips, an extended public key included."""
    records: list[dict[str, Any]] = [
        {"type": "tx", "ref": TXID, "label": "a"},
        {"type": "addr", "ref": ADDRESS, "label": "b"},
        {"type": "pubkey", "ref": PUB_KEY, "label": "c"},
        {"type": "pubkey", "ref": PUB_KEY[2:], "label": "d"},
        {"type": "pubkey", "ref": UNCOMPRESSED, "label": "f"},
        {"type": "input", "ref": f"{TXID}:0", "origin": ORIGIN},
        {"type": "output", "ref": f"{TXID}:{2**32 - 1}", "spendable": False},
        {"type": "xpub", "ref": XPUB, "label": "e"},
    ]
    assert bip329.parse(bip329.serialize(records)) == records


def test_what_bip329_lets_a_reader_skip_is_skipped() -> None:
    """Unknown types, spscan, blank lines, extras, and a type and ref alone."""
    lines = [
        _line({"type": "silent", "ref": "anything", "label": "a"}),
        "\n",
        "   \n",
        _line({"type": "spscan", "ref": "spscan1q", "label": "a"}),
        _line({"type": "tx", "ref": TXID, "height": 1, "label": None}),
        _line({"type": "tx", "ref": TXID, "spendable": True}),
        _line({"type": "tx", "ref": TXID, "height": 1, "label": "a"}),
        _line(
            {"type": "addr", "ref": ADDRESS, "spendable": True, "label": "b"}
        ).replace("\n", "\r\n"),
    ]
    assert bip329.parse("".join(lines)) == [
        {"type": "tx", "ref": TXID, "label": "a"},
        {"type": "addr", "ref": ADDRESS, "label": "b"},
    ]


def test_a_type_of_another_case_is_unknown() -> None:
    """BIP329's types are lowercase, and `TX` is none of them, nor is `""`."""
    assert bip329.parse(_line({"type": "TX", "ref": TXID, "label": "a"})) == []
    assert bip329.parse(_line({"type": "", "ref": TXID, "label": "a"})) == []


@pytest.mark.parametrize(
    "line, message",
    [
        ("[1]", "line 1: not a JSON object: a list of length 1"),
        ('{"type": "tx"', "line 1: not JSON at line 1, column 14"),
        ('{"type": NaN}', "line 1: not JSON"),
        ('{"ref": 1e5000, "ref": 1}', "line 1: a name twice in one object"),
        ("[" * 65 + "]" * 65, "line 1: nested beyond 64"),
        ("{}", "line 1: type: missing"),
        ('{"type": 1}', "line 1: type: not a string: an int of 1 bits"),
        ('{"type": "tx"}', "line 1: ref: missing"),
        ('{"type": "tx", "ref": true}', "line 1: ref: not a string: a bool"),
        (
            json.dumps({"type": "tx", "ref": TXID, "label": 2}),
            "line 1: label: not a string: an int of 2 bits",
        ),
        (
            json.dumps({"type": "tx", "ref": TXID, "origin": []}),
            "line 1: origin: not a string: a list of length 0",
        ),
        (
            json.dumps({"type": "output", "ref": f"{TXID}:0", "spendable": "no"}),
            "line 1: spendable: not a boolean: a str of length 2",
        ),
    ],
)
def test_a_line_that_is_no_record_is_refused(line: str, message: str) -> None:
    """Each refusal names the line, and the field where there is one."""
    with pytest.raises(BTClibValueError, match=_exact(message)):
        bip329.parse(line)


def test_a_line_nested_64_levels_deep_is_read() -> None:
    """The bound is 64 levels, the record's own object included."""
    nested = "[" * 63 + "]" * 63
    line = f'{{"type": "tx", "ref": "{TXID}", "label": "a", "x": {nested}}}'
    assert bip329.parse(line) == [{"type": "tx", "ref": TXID, "label": "a"}]


def test_a_line_ends_at_a_newline_alone() -> None:
    """BIP329 separates lines by a newline, and not as `str.splitlines` does."""
    label = "a\x85b\u2028c\u2029d"
    line = json.dumps({"type": "tx", "ref": TXID, "label": label}, ensure_ascii=False)
    assert len(line.splitlines()) == 4
    assert bip329.parse(line) == [{"type": "tx", "ref": TXID, "label": label}]


def test_a_bracket_inside_a_string_does_not_nest() -> None:
    """The nesting is read outside strings, an escaped quote included."""
    label = "[" * 70 + '\\"'
    assert bip329.parse(f'{{"type": "tx", "ref": "{TXID}", "label": "{label}"}}') == [
        {"type": "tx", "ref": TXID, "label": "[" * 70 + '"'}
    ]


def test_the_refusal_names_the_line_it_is_on() -> None:
    """Line numbers count from 1, blank lines included."""
    text = _line({"type": "tx", "ref": TXID}) + "\n" + _line({"type": "tx"})
    with pytest.raises(BTClibValueError, match=_exact("line 3: ref: missing")):
        bip329.parse(text)


@pytest.mark.parametrize(
    "kind, ref, what",
    [
        ("tx", TXID[1:], "a transaction id"),
        ("tx", TXID + "\n", "a transaction id"),
        ("addr", ADDRESS[:-1], "an address"),
        ("pubkey", PUB_KEY[:-2], "a public key"),
        ("pubkey", "02" + "00" * 32, "a public key"),
        ("pubkey", "zz" * 33, "a public key"),
        ("input", TXID, "an outpoint"),
        ("input", f"{TXID}:01", "an outpoint"),
        ("output", f"{TXID}:{2**32}", "an outpoint"),
        ("output", f"{TXID}:-1", "an outpoint"),
        ("xpub", XPUB[:-1], "an extended key"),
        ("tx", f" {TXID}", "a transaction id"),
        ("pubkey", f"{PUB_KEY}\t", "a public key"),
        ("input", f"{TXID}:0\n", "an outpoint"),
        ("addr", f" {ADDRESS}", "an address"),
        ("addr", f"{ADDRESS}\r\n", "an address"),
        ("addr", f"\t{LEGACY}", "an address"),
        ("addr", LEGACY.lower(), "an address"),
        ("addr", ADDRESS[:10] + ADDRESS[10:].upper(), "an address"),
        ("xpub", f" {XPUB}", "an extended key"),
        ("xpub", f"{XPUB}\n", "an extended key"),
        ("xpub", f"\t{XPUB}\t", "an extended key"),
        ("tx", "", "a transaction id"),
    ],
)
def test_a_ref_that_is_not_what_its_type_names_is_refused(
    kind: str, ref: str, what: str
) -> None:
    """The ref is read as its type says."""
    with pytest.raises(BTClibValueError, match=_exact(f"line 1: ref: not {what}")):
        bip329.parse(_line({"type": kind, "ref": ref, "label": "a"}))
    message = f"labels[0].ref: not {what}"
    with pytest.raises(BTClibValueError, match=_exact(message)):
        bip329.serialize([{"type": kind, "ref": ref, "label": "a"}])


@pytest.mark.parametrize(
    "kind, ref",
    [
        ("tx", TXID.upper()),
        ("pubkey", PUB_KEY.upper()),
        ("input", f"{TXID.upper()}:0"),
        ("addr", ADDRESS.upper()),
    ],
)
def test_a_ref_is_kept_as_its_type_is_written(kind: str, ref: str) -> None:
    """Hex and a bech32 address in lowercase, as btclib writes them."""
    record = {"type": kind, "ref": ref, "label": "a"}
    kept = {"type": kind, "ref": ref.lower(), "label": "a"}
    assert bip329.parse(_line(record)) == [kept]
    assert bip329.serialize([record]) == _line(kept)
    assert any(character.isupper() for character in LEGACY)
    assert bip329.parse(_line({"type": "addr", "ref": LEGACY, "label": "a"})) == [
        {"type": "addr", "ref": LEGACY, "label": "a"}
    ]


@pytest.mark.parametrize(
    "origin",
    [
        ORIGIN,
        "pkh([d34db33f])",
        "sh(wpkh([d34db33f/49h/0h/0h]))",
        "tr([d34db33f/86'/0'/0'])",
        "wsh(sortedmulti(2,[d34db33f/48'/0'/0'/2'],[deadbeef/48'/0'/0'/2']))",
        "tr(musig([d34db33f/87'/0'/0'],[deadbeef/87'/0'/0']))",
        "wsh(or_d(pk([d34db33f/48'/0'/0'/2']),pk([deadbeef/48'/0'/0'/2'])))",
    ],
)
def test_an_origin_is_an_abbreviated_descriptor(origin: str) -> None:
    """Each key a key origin alone, as BIP329's own fragment writes one."""
    record = {"type": "tx", "ref": TXID, "origin": origin}
    assert bip329.parse(bip329.serialize([record])) == [record]


def _multi_a(keys: int) -> str:
    """Return a taproot origin of an internal key and a multi_a of `keys`."""
    origins = ",".join(f"[{position:08x}/1']" for position in range(keys))
    return f"tr([ffffffff/86'/0'/0'],multi_a(1,{origins}))"


def test_an_origin_is_bounded_and_its_keys_computed_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """1000 key origins at most, and a key for each position computed once."""
    computed: list[int] = []

    def counted(position: int) -> tuple[int, int]:
        computed.append(position)
        return mult(position)

    monkeypatch.setattr(bip329, "mult", counted)
    message = "line 1: origin: not an abbreviated descriptor"
    for origin in ("[deadbeef]" * 1001, _multi_a(1000)):
        with pytest.raises(BTClibValueError, match=_exact(message)):
            bip329.parse(_line({"type": "tx", "ref": TXID, "origin": origin}))
    assert not computed
    line = _line({"type": "tx", "ref": TXID, "origin": _multi_a(999)})
    assert len(bip329.parse(line * 3)) == 3
    # none at all where an earlier test computed them
    assert len(computed) == len(set(computed))
    assert set(computed) <= set(range(1, 1001))


@pytest.mark.parametrize(
    "origin",
    [
        f"wpkh({XPRV}/0/*)",
        f"wpkh([d34db33f/84'/0'/0']{XPRV})",
        f"wsh(multi(1,[d34db33f/48'/0'/0'/2'],{XPRV}))",
        f"wsh(multi(1,[d34db33f/48'/0'/0'/2'],{WIF}))",
        f"tr(musig([d34db33f/87'/0'/0'],{XPRV}))",
        f"wpkh({XPUB})",
        f"wpkh([d34db33f/84'/0'/0']{XPUB})",
        f"wsh(multi(1,[d34db33f/48'/0'/0'/2'],{PUB_KEY}))",
        f"sh(multi(1,[d34db33f],{GENERATOR}))",
        ORIGIN + add_checksum(f"wpkh([d34db33f/84'/0'/0']{GENERATOR})")[-9:],
        "[d34db33f]",
        "",
        "wpkh([d34db33f/84'/0'/0']/0/*)",
        add_checksum(ORIGIN),
        f" {ORIGIN}",
        f"{ORIGIN}\n",
        "wpkh([d34db33f/84' /0'/0'])",
        f"addr({ADDRESS})",
        "garbage",
        "wpkh()",
        "sp([d34db33f/352'/0'/0'])",
        "wpkh([d34db33f/84'/0'/0'],[deadbeef])",
    ],
)
def test_an_origin_holding_a_key_or_no_descriptor_is_refused(origin: str) -> None:
    """No key, no child path, no checksum, and a script btclib reads."""
    record = {"type": "tx", "ref": TXID, "origin": origin}
    message = "line 1: origin: not an abbreviated descriptor"
    with pytest.raises(BTClibValueError, match=_exact(message)) as e:
        bip329.parse(_line(record))
    assert e.value.__context__ is None
    assert_secret_free(e.value, [XPRV, WIF])
    message = "labels[0].origin: not an abbreviated descriptor"
    with pytest.raises(BTClibValueError, match=_exact(message)) as e:
        bip329.serialize([record])
    assert e.value.__context__ is None
    assert_secret_free(e.value, [XPRV, WIF])


def test_an_extended_private_key_is_refused_and_not_printed() -> None:
    """An xpub record requires a public extended key.

    Its refusal quotes none.
    """
    message = "line 1: ref: a private key, where BIP329 asks for a public one"
    with pytest.raises(BTClibValueError, match=_exact(message)) as e:
        bip329.parse(_line({"type": "xpub", "ref": XPRV}))
    assert_secret_free(e.value, [XPRV])


@pytest.mark.parametrize(
    "line",
    [
        f'{{"type": "xpub", "ref": "{XPRV}"',
        f'{{"type": "xpub", "ref": "{XPRV}", "ref": "{XPRV}"}}',
        f'{{"type": "output", "ref": "{TXID}:0", "spendable": "{XPRV}"}}',
        f'{{"type": "tx", "ref": "{XPRV}"}}',
        f'{{"type": "addr", "ref": "{XPRV}"}}',
        f'{{"type": "pubkey", "ref": "{XPRV}"}}',
        f'{{"type": "input", "ref": "{XPRV}"}}',
        f'{{"type": "tx", "ref": "{TXID}", "label": ["{XPRV}"]}}',
    ],
)
def test_a_refused_line_quotes_none_of_it(line: str) -> None:
    """A JSONDecodeError holds the line in `.doc`, and nothing chains it."""
    with pytest.raises(BTClibValueError) as e:
        bip329.parse(line)
    assert e.value.__context__ is None
    assert e.value.__cause__ is None
    assert_secret_free(e.value, [XPRV])


def test_parse_refuses_what_is_no_str() -> None:
    """The file's text, decoded by its caller."""
    with pytest.raises(BTClibTypeError, match=_exact("invalid labels type: bytes")):
        bip329.parse(b"{}")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "labels, error, message",
    [
        ("{}", BTClibTypeError, "invalid labels type: str"),
        ({}, BTClibTypeError, "invalid labels type: dict"),
        ([[]], BTClibTypeError, "labels[0]: not a mapping: list"),
        (
            [{"type": "tx", "ref": TXID, "height": 1}],
            BTClibValueError,
            "labels[0]: 'height', a BIP329 field this does not carry",
        ),
        (
            [{"type": "output", "ref": f"{TXID}:0", "fmv": {"USD": 1.0}}],
            BTClibValueError,
            "labels[0]: 'fmv', a BIP329 field this does not carry",
        ),
        (
            [{"type": "tx", "ref": TXID, "colour": "red"}],
            BTClibValueError,
            "labels[0]: no BIP329 field: 'colour'",
        ),
        (
            [{"type": "spscan", "ref": "spscan1q"}],
            BTClibValueError,
            "labels[0].type: spscan, a private key",
        ),
        (
            [{"type": "silent", "ref": "x"}],
            BTClibValueError,
            "labels[0].type: no BIP329 type: 'silent'",
        ),
        (
            [{"type": "", "ref": TXID, "label": "a"}],
            BTClibValueError,
            "labels[0].type: no BIP329 type: ''",
        ),
        (
            [{"type": "tx", "ref": TXID, "spendable": False}],
            BTClibValueError,
            "labels[0].spendable: on a record that is no output",
        ),
        (
            [
                {"type": "tx", "ref": TXID, "label": "a"},
                {"type": "tx", "ref": "00", "label": "a"},
            ],
            BTClibValueError,
            "labels[1].ref: not a transaction id",
        ),
        ([{"ref": TXID}], BTClibValueError, "labels[0].type: missing"),
        (
            [{"type": "tx", "ref": TXID}],
            BTClibValueError,
            "labels[0]: no label, origin or spendable",
        ),
        (
            [{"type": 1, "ref": TXID, "label": "a"}],
            BTClibTypeError,
            "labels[0].type: not a str: int",
        ),
        (
            [{"type": "tx", "ref": b"", "label": "a"}],
            BTClibTypeError,
            "labels[0].ref: not a str: bytes",
        ),
        (
            [{"type": "tx", "ref": TXID, "label": 2}],
            BTClibTypeError,
            "labels[0].label: not a str: int",
        ),
        (
            [{"type": "tx", "ref": TXID, "origin": ["o"]}],
            BTClibTypeError,
            "labels[0].origin: not a str: list",
        ),
        (
            [{"type": "output", "ref": f"{TXID}:0", "spendable": "no"}],
            BTClibTypeError,
            "labels[0].spendable: not a bool: str",
        ),
    ],
)
def test_serialize_refuses_what_bip329_does_not_define(
    labels: Any, error: type[Exception], message: str
) -> None:
    """The writer refuses what the reader refuses, and what it would skip."""
    with pytest.raises(error, match=_exact(message)):
        bip329.serialize(labels)


@pytest.mark.parametrize(
    "name, message",
    [
        # BIP329's Additional Fields, in its order
        *(
            (name, f"labels[0]: {name!r}, a BIP329 field this does not carry")
            for name in (
                "height",
                "time",
                "fee",
                "value",
                "rate",
                "keypath",
                "fmv",
                "heights",
            )
        ),
        ("colour", "labels[0]: no BIP329 field: 'colour'"),
    ],
)
def test_serialize_names_a_bip329_field_it_does_not_carry(
    name: str, message: str
) -> None:
    """A field BIP329 defines is told from a name it does not."""
    with pytest.raises(BTClibValueError, match=_exact(message)):
        bip329.serialize([{"type": "tx", "ref": TXID, "label": "a", name: 1}])


@pytest.mark.parametrize(
    "name, expected, value",
    [
        (name, expected, value)
        for name, expected in (
            ("type", "not a str"),
            ("ref", "not a str"),
            ("label", "not a str"),
            ("origin", "not a str"),
            ("spendable", "not a bool"),
        )
        for value in _FALSY
        # False is a spendable's own value
        if name != "spendable" or value is not False
    ],
)
def test_serialize_refuses_a_falsy_value_of_another_type(
    name: str, expected: str, value: object
) -> None:
    """A falsy value of another type is refused, as a truthy one is."""
    record = {"type": "output", "ref": f"{TXID}:0", "label": "a", name: value}
    message = f"labels[0].{name}: {expected}: {type(value).__name__}"
    with pytest.raises(BTClibTypeError, match=_exact(message)):
        bip329.serialize([record])


def test_an_empty_label_is_a_label_and_false_is_a_spendable() -> None:
    """An empty label is a label, and an omitted one changes nothing."""
    empty = {"type": "tx", "ref": TXID, "label": ""}
    unspendable = {"type": "output", "ref": f"{TXID}:0", "spendable": False}
    text = bip329.serialize([empty, unspendable])
    assert text == _line(empty) + _line(unspendable)
    assert bip329.parse(text) == [empty, unspendable]
    assert bip329.parse(_line({"type": "tx", "ref": TXID})) == []
    message = "labels[0]: no label, origin or spendable"
    with pytest.raises(BTClibValueError, match=_exact(message)):
        bip329.serialize([{"type": "tx", "ref": TXID, "label": None}])


def test_an_output_record_holds_every_field_bip329_defines() -> None:
    """`label`, `origin` and `spendable` together, read and written."""
    record = {
        "type": "output",
        "ref": f"{TXID}:1",
        "label": "a",
        "origin": ORIGIN,
        "spendable": True,
    }
    assert bip329.serialize([record]) == _line(record)
    assert bip329.parse(_line(record)) == [record]


def test_serialize_leaves_out_a_field_that_is_none() -> None:
    """None is no value of any field, as null is read as absent."""
    origin = "wpkh([d34db33f/84'/0'/0'])"
    record = {"type": "tx", "ref": TXID, "label": None, "origin": origin}
    expected = _line({"type": "tx", "ref": TXID, "origin": origin})
    assert bip329.serialize([record]) == expected
