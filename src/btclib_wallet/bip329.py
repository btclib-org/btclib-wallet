# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BIP329 labels: a wallet's labels as JSON Lines, read and written.

`bip-0329.mediawiki`, bitcoin/bips@5253e9a294cd, a Draft.

A label record is a JSON object with a `type` and a `ref`, and optionally
a `label`, an `origin` and, for an output, `spendable`. `parse` reads a
BIP329 file, one record per line, and `serialize` writes one. A record is
a `dict` holding those fields alone, in that order, which is also what
`bip139` carries in an account's `labels`. The fields BIP329 lists as
additional, such as `height`, `fee`, `rate` and `fmv`, are not kept, and
a restore loses them. A wallet reads `height` and `fee` back from the
chain; `rate` and `fmv` are prices at the time of a transaction, which no
chain holds.

What a read verifies, each refusal naming the line and the field and
quoting none of the record:

- the line is a JSON object, nested at most 64 levels deep, with no name
  twice and no `NaN` or `Infinity`, which RFC 8259 lacks;
- `type` is there and is a string, and so is `ref` in a record of a type
  this keeps; each other field is of its JSON type;
- the `ref` is what its `type` names: a transaction id, an address btclib
  decodes, a public key on the curve, an input or an output as
  ``<txid>:<index>``, or an extended public key. An extended private key
  is refused: BIP329's `xpub` is an extended public key. A `ref` with
  whitespace around it, or in another spelling a decoder reads and
  another wallet's label would not match, is refused; hex, and a bech32
  address in uppercase, are kept in lowercase;
- the `origin` is what BIP329 says it is, an abbreviated BIP380
  descriptor: each key a key origin alone, as in
  ``wpkh([d34db33f/84'/0'/0'])``, with no key, no child path and no
  checksum. An origin that holds a key is refused, and so is one that
  btclib's descriptors do not read, a script type they lack among them,
  which BIP329 may allow, and one of more than 1000 key origins.

One line refused refuses the whole file: `parse` returns every record or
none.

A record of a type BIP329 does not define is skipped, as BIP329 says. So
is an ``spscan`` record, whose `ref` holds the private scan key of a
silent payments wallet, which this package does not hold. `spendable` on
a record that is no output is dropped, BIP329 giving it to outputs alone.
A field whose value is ``null`` is read as absent. A record left with a
`type` and a `ref` alone is skipped: BIP329 says a wallet leaves a label
it is not given as it is, so such a record changes nothing.

`serialize` refuses what `parse` would refuse, and also a field it does
not carry, whether BIP329 defines it, as it does its additional fields,
or not, an ``spscan`` record, a type BIP329 does not define,
`spendable` on a record that is no output, and a record of a `type` and a
`ref` alone, which carries nothing. A field of the wrong Python type is a
`BTClibTypeError`. It writes each record as `parse` keeps it, and ASCII,
which is UTF-8, so a label of any text survives the file.

An extended private key is refused in a `ref` and in an `origin`, and
an `origin` holds no key of any kind. A `ref` of 32 bytes of hex, a
transaction id or an x-only public key, may be any 32 bytes, and is not
told from a private key. A `label` is the caller's text, written and read
as it is, whatever it holds. The file names the wallet's transactions,
addresses and coins.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from functools import cache
from typing import Any, NoReturn, TypeGuard

from bip32_descriptors.bip32.bip32 import BIP32KeyData
from bip32_descriptors.descriptors.descriptors import add_checksum
from bip32_descriptors.descriptors.descriptors import parse as _parse_descriptor
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.network import NETWORKS, networks_from_xkeyversion
from btclib.script.script_pub_key import ScriptPubKey
from ecc.curves import bytes_from_point, mult, point_from_pub_key

from btclib_wallet._refusal import _label, _message_text, _position, _quoted

__all__ = ["TYPES", "parse", "serialize"]

# BIP329's record types, in its order
TYPES = ("tx", "addr", "pubkey", "input", "output", "xpub", "spscan")

# the type whose `ref` holds a private key, which this package does not hold
_SKIPPED = "spscan"

# BIP329's fields, in the order a record is written
_FIELDS = ("type", "ref", "label", "origin", "spendable")
# the fields BIP329 lists as additional, which this does not carry
_ADDITIONAL = ("height", "time", "fee", "value", "rate", "keypath", "fmv", "heights")
# the Python type `serialize` takes for each
_WRITTEN_TYPES = {
    "type": str,
    "ref": str,
    "label": str,
    "origin": str,
    "spendable": bool,
}

_TXID = re.compile(r"[0-9a-fA-F]{64}")
_OUTPOINT = re.compile(r"[0-9a-fA-F]{64}:(?:0|[1-9][0-9]{0,9})")
_HEX = re.compile(r"[0-9a-fA-F]*")
# a bracket, which in a descriptor is a key origin, whatever it holds
_BRACKETS = re.compile(r"\[[^\[\]]*\]")
# the most key origins an origin holds: a taproot internal key beside one
# multi_a() of 999 keys, the most BIP387 gives it and btclib's descriptors
# read
_MAX_KEY_ORIGINS = 1000

# deep enough for every object BIP329 and BIP139 define, and for an
# application's own `proprietary` object beside them. `electrum`'s
# `_MAX_NESTING` says why `json.loads` is not handed a deeper text
_MAX_NESTING = 64

# a string, whatever it holds. `_too_deep` appends two quotes, so that a
# string left open still closes
_STRING = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"', re.DOTALL)
_NOT_BRACKET = re.compile(r"[^\[\]{}]+")


def _too_deep(text: str) -> bool:
    """Return True if `text` nests brackets deeper than `_MAX_NESTING`.

    A bracket inside a string does not count. The scan stops at the first
    excess.
    """
    depth = 0
    for bracket in _NOT_BRACKET.sub("", _STRING.sub("", f'{text}""')):
        if bracket in "[{":
            depth += 1
            if depth > _MAX_NESTING:
                return True
        else:
            depth -= 1
    return False


def _refuse_constant(name: str) -> NoReturn:
    """Refuse `NaN`, `Infinity` and `-Infinity`, which RFC 8259 lacks."""
    raise BTClibValueError(f"not JSON: {_quoted(name)}")


def _loads(text: str, where: str) -> Any:
    """Return the JSON value of `text`, or refuse it naming `where`.

    Refused: a nesting deeper than `_MAX_NESTING`, checked before
    `json.loads` runs; a name twice in one object, which two readers may
    read as two different values; `NaN` and the infinities; and what is
    no JSON. Every refusal is raised after the `except` block, so that it
    chains nothing: a `JSONDecodeError` holds the whole input in `.doc`.
    It names where the parser stopped, by line and column.
    """
    if _too_deep(text):
        raise BTClibValueError(f"{where}: nested beyond {_MAX_NESTING}")
    repeated: list[int] = []

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        found = dict(items)
        if len(found) < len(items):
            repeated.append(len(items))
        return found

    problem = "not JSON"
    try:
        value = json.loads(
            text, parse_constant=_refuse_constant, object_pairs_hook=pairs
        )
    except json.JSONDecodeError as error:
        problem = f"not JSON at line {_position(error.lineno)}"
        problem += f", column {_position(error.colno)}"
    # a BTClibValueError of `_refuse_constant`, an int past the digit limit
    # of `int`, and a nesting the scan above cannot see, inside a string
    # that `json` reads in another way
    except (ValueError, RecursionError):
        pass
    else:
        if not repeated:
            return value
        problem = "a name twice in one object"
    raise BTClibValueError(f"{where}: {problem}")


def _is_sequence(value: object) -> TypeGuard[Sequence[Any]]:
    """Answer whether a value is a sequence of items, a str or bytes not one."""
    return isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    )


def _string(value: object, at: str) -> str:
    """Return a JSON string, or refuse what is none naming `at`."""
    if not isinstance(value, str):
        raise BTClibValueError(f"{at}: not a string: {_message_text(value)}")
    return value


def _point(ref: str) -> str | None:
    """Return hex text of a public key on the curve in lowercase, or None.

    In SEC form, 33 or 65 bytes, or x-only in 32 bytes, which is the
    even-y point BIP340 says those bytes mean.
    """
    if not _HEX.fullmatch(ref) or len(ref) not in {64, 66, 130}:
        return None
    sec = bytes.fromhex(ref if len(ref) > 64 else f"02{ref}")
    with suppress(ValueError):
        point_from_pub_key(sec)
        return ref.lower()
    return None


def _outpoint(ref: str) -> str | None:
    """Return an outpoint, ``<txid>:<index>``, in lowercase, or None.

    The index is below 2**32, as a transaction's are numbered.
    """
    if _OUTPOINT.fullmatch(ref) and int(ref[65:]) < 2**32:
        return ref.lower()
    return None


def _txid(ref: str) -> str | None:
    """Return a transaction id in lowercase hex, or None."""
    return ref.lower() if _TXID.fullmatch(ref) else None


def _extended_key(ref: str) -> str | None:
    """Return an extended key of either kind, or None.

    It has to be spelled as it is encoded: `b58decode` also reads one with
    whitespace around it, which another wallet's label would not match.
    """
    with suppress(ValueError):
        if BIP32KeyData.b58decode(ref).b58encode() == ref:
            return ref
    return None


def _address(ref: str) -> str | None:
    """Return an address btclib decodes, of any network, as btclib spells it.

    A bech32 address in uppercase, which BIP173 allows, is returned in
    lowercase. Any other spelling is None: `from_address` also reads one
    with whitespace around it, which another wallet's label would not
    match.
    """
    with suppress(ValueError):
        address = ScriptPubKey.from_address(ref).address
        if address in {ref, ref.lower()}:
            return address
    return None


def _is_address_of(address: str, network: str) -> bool:
    """Answer whether an address as btclib spells it is so on `network`.

    Testnet, testnet4 and signet share their prefixes, and regtest shares
    the base58 ones, so an address is one of each network that spells it
    the same way.
    """
    script = ScriptPubKey.from_address(address).script
    return ScriptPubKey(script, network).address == address


# what each type's `ref` is, as this keeps it, and what a refusal calls it
_REFS: dict[str, tuple[Callable[[str], str | None], str]] = {
    "tx": (_txid, "a transaction id"),
    "addr": (_address, "an address"),
    "pubkey": (_point, "a public key"),
    "input": (_outpoint, "an outpoint"),
    "output": (_outpoint, "an outpoint"),
    "xpub": (_extended_key, "an extended key"),
}


def _ref(kind: str, ref: str, at: str, network: str | None) -> str:
    """Return a `ref` as this keeps it, or refuse one its `type` does not name.

    `network`, where there is one, is the network an address has to be
    spelled for and an extended key to be of; None takes either of any
    network.
    """
    spell, what = _REFS[kind]
    kept = spell(ref)
    if kept is None:
        raise BTClibValueError(f"{at}: not {what}")
    if kind == "xpub":
        xkey = BIP32KeyData.b58decode(kept)
        if xkey.is_private:
            err_msg = f"{at}: a private key, where BIP329 asks for a public one"
            raise BTClibValueError(err_msg)
        if network is not None and network not in networks_from_xkeyversion(
            xkey.version
        ):
            err_msg = f"{at}: not an extended key of {_label(network, NETWORKS)}"
            raise BTClibValueError(err_msg)
    if kind == "addr" and network is not None and not _is_address_of(kept, network):
        raise BTClibValueError(f"{at}: not an address of {_label(network, NETWORKS)}")
    return kept


@cache
def _stand_in(position: int) -> str:
    """Return the public key `_is_origin` gives a key origin, in SEC hex.

    The point `position` times the generator: distinct for each position,
    as a miniscript refuses a key twice, and computed once for each, as
    `position` is at most `_MAX_KEY_ORIGINS`.
    """
    return bytes_from_point(mult(position)).hex()


def _is_origin(text: str) -> bool:
    """Answer whether text is an abbreviated descriptor, as BIP329's `origin`.

    A BIP380 descriptor whose every key is a key origin alone, with no key
    after it, no child path and no checksum: ``wpkh([d34db33f/84'/0'/0'])``.
    Each bracket is given a public key after it, `_stand_in` of k for the
    k-th, and the text then has to parse as a descriptor whose every key, a
    ``musig()``'s participants included, has an origin: a key the text held
    has none, or sits after a bracket where a key was given, which does not
    parse. More than `_MAX_KEY_ORIGINS` brackets are refused before any key
    is computed.
    """
    if "#" in text or text.count("[") > _MAX_KEY_ORIGINS:
        return False
    given = 0

    def fill(match: re.Match[str]) -> str:
        nonlocal given
        given += 1
        return match.group(0) + _stand_in(given)

    keys = []
    # an ecc refusal as well as a descriptor's, and a nesting too deep
    with suppress(ValueError, RecursionError):
        filled = add_checksum(_BRACKETS.sub(fill, text))
        keys = list(_parse_descriptor(filled).key_expressions)
    if not keys:
        return False
    while keys:
        key = keys.pop()
        if key.participants:
            keys.extend(key.participants)
        elif key.origin is None:
            return False
    return True


def _fields(
    value: Mapping[str, Any], kind: str, where: str, sep: str, network: str | None
) -> dict[str, Any]:
    """Return the fields of a record of a type this keeps, or refuse them."""
    ref = value.get("ref")
    if ref is None:
        raise BTClibValueError(f"{where}{sep}ref: missing")
    at = f"{where}{sep}ref"
    record: dict[str, Any] = {
        "type": kind,
        "ref": _ref(kind, _string(ref, at), at, network),
    }
    if (label := value.get("label")) is not None:
        record["label"] = _string(label, f"{where}{sep}label")
    if (origin := value.get("origin")) is not None:
        at = f"{where}{sep}origin"
        if not _is_origin(_string(origin, at)):
            raise BTClibValueError(f"{at}: not an abbreviated descriptor")
        record["origin"] = origin
    spendable = value.get("spendable")
    if spendable is not None and kind == "output":
        if not isinstance(spendable, bool):
            err_msg = f"{where}{sep}spendable: not a boolean:"
            err_msg += f" {_message_text(spendable)}"
            raise BTClibValueError(err_msg)
        record["spendable"] = spendable
    return record


def _record(
    value: object, where: str, sep: str, network: str | None
) -> dict[str, Any] | None:
    """Return a label record as `parse` keeps it, None for one it skips.

    `where` names the record and `sep` joins a field's name to it in a
    refusal: ``line 3: ref`` in a BIP329 file, and
    ``accounts[0].labels[2].ref`` in a BIP139 export.
    """
    if not isinstance(value, dict):
        raise BTClibValueError(f"{where}: not a JSON object: {_message_text(value)}")
    kind = value.get("type")
    if kind is None:
        raise BTClibValueError(f"{where}{sep}type: missing")
    _string(kind, f"{where}{sep}type")
    known = next((name for name in TYPES if name == kind), None)
    if known is None or known == _SKIPPED:
        return None
    record = _fields(value, known, where, sep, network)
    # a type and a ref alone change nothing a wallet holds
    return record if len(record) > 2 else None


def _assert_written_types(record: Mapping[str, Any], where: str) -> None:
    """Refuse a field `serialize` is handed in a Python type not its own."""
    for field, kind_of in _WRITTEN_TYPES.items():
        if field in record and not isinstance(record[field], kind_of):
            err_msg = f"{where}.{field}: not a {kind_of.__name__}:"
            err_msg += f" {type(record[field]).__name__}"
            raise BTClibTypeError(err_msg)


def _written(value: object, where: str, network: str | None) -> dict[str, Any]:
    """Return the record `serialize` writes of a mapping, or refuse it.

    The checks `serialize` adds to `parse`'s, which its module docstring
    lists, and then `parse`'s own: what is returned is what `parse` keeps.
    """
    if not isinstance(value, Mapping):
        raise BTClibTypeError(f"{where}: not a mapping: {type(value).__name__}")
    for name in value:
        if name in _ADDITIONAL:
            err_msg = f"{where}: {_quoted(name)}, a BIP329 field this does not carry"
            raise BTClibValueError(err_msg)
        if name not in _FIELDS:
            raise BTClibValueError(f"{where}: no BIP329 field: {_quoted(name)}")
    record = {name: value[name] for name in _FIELDS if value.get(name) is not None}
    _assert_written_types(record, where)
    kind = record.get("type")
    if kind is None:
        raise BTClibValueError(f"{where}.type: missing")
    if kind == _SKIPPED:
        raise BTClibValueError(f"{where}.type: {_SKIPPED}, a private key")
    if kind not in TYPES:
        raise BTClibValueError(f"{where}.type: no BIP329 type: {_quoted(kind)}")
    if "spendable" in record and kind != "output":
        raise BTClibValueError(f"{where}.spendable: on a record that is no output")
    if "ref" in record and len(record) == 2:
        raise BTClibValueError(f"{where}: no label, origin or spendable")
    return _fields(record, kind, where, ".", network)


def parse(labels: str) -> list[dict[str, Any]]:
    r"""Return the label records of a BIP329 file, in the file's order.

    `labels` is the text of the file, one JSON object per line, lines
    separated by ``\n``; a line holding only whitespace is skipped. What
    is read, refused and skipped is the module docstring's.
    """
    if not isinstance(labels, str):
        raise BTClibTypeError(f"invalid labels type: {type(labels).__name__}")
    records = []
    for number, line in enumerate(labels.split("\n"), start=1):
        if not line.strip():
            continue
        where = f"line {_position(number)}"
        record = _record(_loads(line, where), where, ": ", None)
        if record is not None:
            records.append(record)
    return records


def serialize(labels: Sequence[Mapping[str, Any]]) -> str:
    """Return the BIP329 file of label records, one line each.

    Each record is a mapping of BIP329's fields, as `parse` returns one;
    a field whose value is None is left out. What is refused is the
    module docstring's, the refusal naming a record by its index. The
    text ends with a newline, and is empty for no record.
    """
    if not _is_sequence(labels):
        raise BTClibTypeError(f"invalid labels type: {type(labels).__name__}")
    lines = []
    for index, value in enumerate(labels):
        where = f"labels[{_position(index)}]"
        lines.append(json.dumps(_written(value, where, None)) + "\n")
    return "".join(lines)
