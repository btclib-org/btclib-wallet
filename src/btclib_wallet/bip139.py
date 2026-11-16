# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BIP139 wallet exports: a wallet's policy in one JSON file, read and written.

`bip-0139.md` and `bip-0139/field-registry.md`, bitcoin/bips@100ba872c808.
BIP139 is a Draft with no test vectors. A file this module writes as
`VERSION` is read by it for good: a later Draft that changes what that
version means is a second version, read beside it.

What a backup of a policy needs, and what this module reads and writes
of BIP139, is a `network` and, for each account, its descriptor, the
names of the keys it holds, its birth height and its labels. An account
is a `dict` of these fields, BIP139's own names, each optional but the
first:

- `descriptor`: the account descriptor, for a `bip380` account a BIP380
  output descriptor, which may be BIP389's ``<0;1>`` multipath one. This
  module requires its checksum: `serialize` adds the checksum to a text
  without one, and takes a `Descriptor` too, written as its text;
- `change_descriptor`: the explicit change-side descriptor, paired with
  `descriptor`, for a wallet that keeps its receive and change
  descriptors apart, as Bitcoin Core does. This module reads one beside a
  `descriptor` with a single path alone;
- `birth_block`: the account's creation time as a block height, where an
  importer may start scanning instead of at genesis. An exporter may
  estimate it, at or before the true height, never after;
- `receive_index` and `change_index`: the maximum generated index of the
  receive and of the change addresses;
- `keys`: maps a BIP32 fingerprint in hex, which `parse` returns in
  lowercase, to how this account uses the key: a `dict` of an `alias`,
  the user's name for the key, and a `role` in the wallet's operations,
  one of `ROLES`, either optional. The key object's own `key`, the
  fingerprint again, is written by `serialize` and checked by `parse`,
  which does not return it;
- `labels`: label records following BIP329, as `bip329` reads and writes
  them.

`serialize` writes these, and `parse` returns the network and the
accounts in the same shape, so that one reads back what the other wrote.
The network is btclib's name for it, which BIP139 spells `bitcoin` for
mainnet and `testnet3` for testnet. An account's `type` is BIP380's,
`bip380`, which is the one this module reads.

What a read verifies, each refusal naming the field by its position, such
as ``accounts[1].keys``, and quoting at most a short value, as
`_refusal._quoted` does:

- the file is one JSON object, as `bip329` reads JSON;
- `version` is `VERSION`;
- `network` is one BIP139 names and btclib holds, so not `mutinynet`;
- `accounts` holds at least one account, and each account's `type` is
  `bip380`: one of another type is refused, not skipped, since a restore
  that left an account out would show less money than the wallet holds;
- each descriptor parses on that network, its checksum required, and
  holds no private key, neither an extended one nor a WIF;
- a multipath `descriptor` has no `change_descriptor`, which has a single
  path;
- `birth_block` is an integer from 0 to 2**63 - 1, and each index one
  from 0 to 2**31 - 1, the highest unhardened index of BIP32;
- each fingerprint of `keys` is one the account's descriptors name, by a
  key origin or by a key that has none, and its `key` field is that
  fingerprint; an `alias` and a `role` are strings;
- each label is a BIP329 record, as `bip329` reads one, an address label
  spelled for the network and an extended public key label of it;
- on mainnet, no account holds `bip39_mnemonic`, which BIP139 forbids
  there: the file is refused, naming the field and not its words.

One field refused refuses the whole file, one label among them: `parse`
returns every account or none.

What BIP139 says to discard, this discards: a field it names that this
module does not read, such as `signers`, `transactions` and
`proprietary`, a field of its own an application adds, a `role` it does
not name, and `bip39_mnemonic` on a test network. A field whose value is
``null`` is read as absent.

`serialize` refuses what `parse` would refuse, so that what it writes
reads back. It also refuses a field it does not carry, whether BIP139's
field registry defines it or not, a `role` that is not one of `ROLES`,
and a `Descriptor` of another network. A field of
the wrong Python type is a `BTClibTypeError`. It writes each label as
`bip329` keeps it, and ASCII, which is UTF-8, indented for a person to
read.

No descriptor either returns or writes holds a private key, neither an
extended one nor a WIF, and a label holds none where `bip329` says it
does not. A key's `alias` and a label's `label` are the caller's text,
written and read as they are, whatever they hold. The file holds every
descriptor of the wallet, so whoever reads it can derive every address,
and from the chain read the wallet's balance and history.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any, TypeGuard

from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash160
from btclib.network import NETWORKS, validated_network_name

from btclib_wallet._refusal import _exact_int, _label, _message_text, _position, _quoted
from btclib_wallet.bip32.bip32 import fingerprint
from btclib_wallet.bip329 import (
    _is_sequence,
    _loads,
    _record,
    _string,
    _written,
)
from btclib_wallet.descriptors.descriptors import (
    Descriptor,
    add_checksum,
    multipath_descriptors,
)
from btclib_wallet.descriptors.descriptors import (
    parse as _parse_descriptor,
)

__all__ = ["ROLES", "VERSION", "parse", "serialize"]

VERSION = "BIP139-1"

# the key roles of BIP139's field registry, in its order
ROLES = ("main", "recovery", "inheritance", "cosigning")

# btclib's name of each network, and BIP139's
_NETWORKS = {
    "mainnet": "bitcoin",
    "testnet": "testnet3",
    "testnet4": "testnet4",
    "signet": "signet",
    "regtest": "regtest",
}
# the network BIP139 names and btclib does not
_MUTINYNET = "mutinynet"

_TYPE = "bip380"
# each integer field, and the power of 2 it stays below: an index is
# BIP32's unhardened one
_BITS = {"birth_block": 63, "receive_index": 31, "change_index": 31}
# every account field this reads and writes
_FIELDS = (
    "descriptor",
    "change_descriptor",
    "birth_block",
    "receive_index",
    "change_index",
    "keys",
    "labels",
)
_KEY_FIELDS = ("alias", "role")
# the account and key fields of BIP139's field registry, in its order:
# `serialize` writes `type` and `key` itself, and takes none of the others
# beyond `_FIELDS` and `_KEY_FIELDS`
_REGISTRY_ACCOUNT_FIELDS = (
    "type",
    "descriptor",
    "name",
    "description",
    "status",
    "hidden",
    "change_descriptor",
    "receive_index",
    "change_index",
    "range_start",
    "range_end",
    "change_range_start",
    "change_range_end",
    "gap_limit",
    "birth_block",
    "last_height",
    "bip352_labels",
    "keys",
    "labels",
    "transactions",
    "coins",
    "psbts",
    "bip39_mnemonic",
    "proprietary",
)
_REGISTRY_KEY_FIELDS = ("key", "alias", "role", "key_type", "proof_of_registration")
_MNEMONIC = "bip39_mnemonic"

_FINGERPRINT = re.compile(r"[0-9a-fA-F]{8}")

# what a descriptor's refusal says that a refusal here repeats after the
# field's position; any other is "not a descriptor"
_REASONS = frozenset(
    (
        "invalid descriptor checksum",
        *(
            f"not a {name} key: {what}"
            for name in NETWORKS
            for what in ("WIF prefix", "version")
        ),
    )
)


def _reason(error: ValueError) -> str:
    """Return what a descriptor's refusal says, if one of `_REASONS`."""
    text = str(error)
    # a generator would turn a StopIteration raised by a caller's comparison
    # into a RuntimeError
    for reason in _REASONS:  # sourcery skip: use-next
        if reason == text:
            return reason
    return "not a descriptor"


def _holds_private_key(descriptor: str, network: str) -> bool:
    """Answer whether a descriptor text holds a WIF or an extended private key.

    `descriptors.parse` neuters an extended private key into the mapping
    it is handed, and keeps a WIF's public key and its version byte.
    """
    prv_keys: dict[str, str] = {}
    keys = list(_parse_descriptor(descriptor, network, prv_keys).key_expressions)
    while keys:
        key = keys.pop()
        if key.wif_prefix:
            return True
        keys.extend(key.participants)
    return bool(prv_keys)


def _fingerprints(descriptor: str, network: str) -> set[str]:
    """Return the fingerprints a descriptor names, in lowercase hex.

    A key's origin names its master; a key with no origin is named by its
    own fingerprint, the HASH160 of its public key, as BIP32 defines it. A
    ``musig()``, which BIP390 gives no origin, is named by its
    participants.
    """
    found = set()
    keys = list(_parse_descriptor(descriptor, network).key_expressions)
    while keys:
        key = keys.pop()
        keys.extend(key.participants)
        if key.origin is not None:
            found.add(key.origin.master_fingerprint.hex())
        elif key.xkey:
            found.add(fingerprint(key.xkey).hex())
        elif key.pub_key is not None:
            found.add(hash160(key.pub_key)[:4].hex())
    return found


def _descriptor(value: object, at: str, network: str) -> list[str]:
    """Return the single paths of a descriptor field, or refuse it."""
    if not isinstance(value, str):
        raise BTClibValueError(f"{at}: not a string: {_message_text(value)}")
    if "#" not in value:
        raise BTClibValueError(f"{at}: no checksum")
    # raised after the block: a refusal of the descriptor's own, or of
    # ecc's, is not this package's to chain
    reason = None
    singles: list[str] = []
    try:
        singles = multipath_descriptors(value, network)
    except ValueError as error:
        reason = _reason(error)
    if reason is not None:
        raise BTClibValueError(f"{at}: {reason}")
    if any(_holds_private_key(single, network) for single in singles):
        raise BTClibValueError(f"{at}: a private key")
    return singles


def _is_integer(value: object) -> TypeGuard[int]:
    """Answer whether a value is an int, a bool not one.

    A bool is no integer, as `btclib.utils.is_integer` says. The type
    decides, for the reason `_refusal._quoted` gives.
    """
    kind = type(value)
    return issubclass(kind, int) and kind is not bool and isinstance(value, int)


def _integer(value: object, at: str, bits: int) -> int:
    """Return an integer from 0 to 2**bits - 1, or refuse it.

    2**63 - 1 is the largest SQLite INTEGER, which a `Ledger` writes a
    height into, and 2**31 - 1 the highest unhardened BIP32 index. The
    value is kept as the exact int `_exact_int` reads.
    """
    if not _is_integer(value):
        raise BTClibValueError(f"{at}: not an integer: {_message_text(value)}")
    number = _exact_int(value)
    if number < 0:
        raise BTClibValueError(f"{at}: negative")
    if number >= 2**bits:
        raise BTClibValueError(f"{at}: not below 2**{bits}")
    return number


def _key_names(entry: object, where: str, fingerprint_hex: str) -> dict[str, str]:
    """Return the alias and the role of a key object, or refuse it."""
    if not isinstance(entry, dict):
        raise BTClibValueError(f"{where}: not a JSON object: {_message_text(entry)}")
    key = entry.get("key")
    if key is None:
        raise BTClibValueError(f"{where}.key: missing")
    if not isinstance(key, str) or key.lower() != fingerprint_hex:
        raise BTClibValueError(f"{where}.key: not the fingerprint of the entry")
    names = {
        field: _string(entry[field], f"{where}.{field}")
        for field in _KEY_FIELDS
        if entry.get(field) is not None
    }
    # a role BIP139 does not name is not read, as it says of an enum
    if names.get("role") not in ROLES:
        names.pop("role", None)
    return names


def _keys(value: object, at: str, named: set[str]) -> dict[str, dict[str, str]]:
    """Return the key names of an account, or refuse them.

    An entry is named by its position in the object, and never by its
    name: a fingerprint is what it should be, and may be anything.
    """
    if not isinstance(value, dict):
        raise BTClibValueError(f"{at}: not a JSON object: {_message_text(value)}")
    keys: dict[str, dict[str, str]] = {}
    for position, (name, entry) in enumerate(value.items()):
        where = f"{at} entry {_position(position)}"
        if not isinstance(name, str) or not _FINGERPRINT.fullmatch(name):
            raise BTClibValueError(f"{where}: not a fingerprint")
        fingerprint_hex = name.lower()
        if fingerprint_hex not in named:
            raise BTClibValueError(f"{where}: a key the descriptor does not name")
        if fingerprint_hex in keys:
            raise BTClibValueError(f"{where}: a fingerprint named twice")
        keys[fingerprint_hex] = _key_names(entry, where, fingerprint_hex)
    return keys


def _labels(value: object, at: str, network: str) -> list[dict[str, Any]]:
    """Return the BIP329 records of an account, or refuse them."""
    if not isinstance(value, list):
        raise BTClibValueError(f"{at}: not a JSON array: {_message_text(value)}")
    records = []
    for index, item in enumerate(value):
        record = _record(item, f"{at}[{_position(index)}]", ".", network)
        if record is not None:
            records.append(record)
    return records


def _assert_bip380(value: dict[str, Any], at: str, network: str) -> None:
    """Refuse an account of another type, and a mainnet one with a mnemonic."""
    if network == "mainnet" and value.get(_MNEMONIC) is not None:
        raise BTClibValueError(f"{at}.{_MNEMONIC}: a mnemonic in a mainnet export")
    kind = value.get("type")
    if kind is None:
        raise BTClibValueError(f"{at}.type: missing")
    if kind != _TYPE:
        raise BTClibValueError(f"{at}.type: {_quoted(kind)}, not {_TYPE}")


def _descriptors(
    value: dict[str, Any], at: str, network: str
) -> tuple[dict[str, str], list[str]]:
    """Return the descriptor fields of an account, and their single paths."""
    descriptor = value.get("descriptor")
    if descriptor is None:
        raise BTClibValueError(f"{at}.descriptor: missing")
    singles = _descriptor(descriptor, f"{at}.descriptor", network)
    fields = {"descriptor": descriptor}
    if (change := value.get("change_descriptor")) is not None:
        if len(singles) > 1:
            err_msg = f"{at}.change_descriptor: beside a multipath descriptor"
            raise BTClibValueError(err_msg)
        change_singles = _descriptor(change, f"{at}.change_descriptor", network)
        if len(change_singles) > 1:
            raise BTClibValueError(f"{at}.change_descriptor: a multipath descriptor")
        singles += change_singles
        fields["change_descriptor"] = change
    return fields, singles


def _account(value: object, at: str, network: str) -> dict[str, Any]:
    """Return an account as `parse` returns it, or refuse it."""
    if not isinstance(value, dict):
        raise BTClibValueError(f"{at}: not a JSON object: {_message_text(value)}")
    _assert_bip380(value, at, network)
    fields, singles = _descriptors(value, at, network)
    account: dict[str, Any] = dict(fields) | {
        name: _integer(value[name], f"{at}.{name}", bits)
        for name, bits in _BITS.items()
        if value.get(name) is not None
    }
    if (keys := value.get("keys")) is not None:
        named = set().union(*(_fingerprints(single, network) for single in singles))
        account["keys"] = _keys(keys, f"{at}.keys", named)
    if (labels := value.get("labels")) is not None:
        account["labels"] = _labels(labels, f"{at}.labels", network)
    return account


def _network(value: object) -> str:
    """Return btclib's name of the network BIP139 names, or refuse it."""
    if value is None:
        raise BTClibValueError("network: missing")
    if value == _MUTINYNET:
        raise BTClibValueError(f"network: {_MUTINYNET}, which btclib does not hold")
    for name, bip139_name in _NETWORKS.items():
        if bip139_name == value:
            return name
    raise BTClibValueError(f"network: {_quoted(value)}, which BIP139 does not name")


def _accounts(value: object, network: str) -> list[dict[str, Any]]:
    """Return the accounts of an export, at least one, or refuse them."""
    if value is None:
        raise BTClibValueError("accounts: missing")
    if not isinstance(value, list):
        raise BTClibValueError(f"accounts: not a JSON array: {_message_text(value)}")
    if not value:
        raise BTClibValueError("accounts: no account")
    return [
        _account(account, f"accounts[{_position(index)}]", network)
        for index, account in enumerate(value)
    ]


def parse(export: str) -> dict[str, Any]:
    """Return the network and the accounts of a BIP139 export.

    `export` is the text of the file. The answer maps `network` to
    btclib's name of the network and `accounts` to a list of accounts, as
    the module docstring says, which also says what is refused and what is
    discarded.
    """
    if not isinstance(export, str):
        raise BTClibTypeError(f"invalid export type: {type(export).__name__}")
    document = _loads(export, "export")
    if not isinstance(document, dict):
        err_msg = f"export: not a JSON object: {_message_text(document)}"
        raise BTClibValueError(err_msg)
    version = document.get("version")
    if version is None:
        raise BTClibValueError("version: missing")
    if version != VERSION:
        raise BTClibValueError(f"version: {_quoted(version)}, not {VERSION}")
    network = _network(document.get("network"))
    return {
        "network": network,
        "accounts": _accounts(document.get("accounts"), network),
    }


def _written_descriptor(value: object, at: str, network: str) -> str:
    """Return the text `serialize` writes of a descriptor, its checksum added.

    A `Descriptor` is its text, public by construction, and has to be of
    `network`. Text is read as `parse` reads it, once checksummed.
    """
    if isinstance(value, Descriptor):
        if value.network != network:
            err_msg = f"{at}: a descriptor of {_label(value.network, NETWORKS)}"
            raise BTClibValueError(err_msg)
        return add_checksum(str(value))
    if not isinstance(value, str):
        raise BTClibTypeError(f"{at}: not a descriptor: {type(value).__name__}")
    if "#" in value:
        return value
    # raised after the block, as `_descriptor` says
    reason = None
    try:
        return add_checksum(value)
    except ValueError as error:
        reason = _reason(error)
    raise BTClibValueError(f"{at}: {reason}")


def _written_names(names: object, where: str) -> dict[str, str]:
    """Return the alias and the role `serialize` writes, or refuse them."""
    if not isinstance(names, Mapping):
        raise BTClibTypeError(f"{where}: not a mapping: {type(names).__name__}")
    for given in names:
        if given in _KEY_FIELDS:
            continue
        # the registry's own name, written whole: `_quoted` describes a
        # name past 16 characters by its length alone
        if known := next((f for f in _REGISTRY_KEY_FIELDS if f == given), None):
            err_msg = f"{where}: {known!r}, a BIP139 key field this does not carry"
            raise BTClibValueError(err_msg)
        raise BTClibValueError(f"{where}: no BIP139 key field: {_quoted(given)}")
    for field in _KEY_FIELDS:
        text = names.get(field)
        if text is not None and not isinstance(text, str):
            err_msg = f"{where}.{field}: not a str: {type(text).__name__}"
            raise BTClibTypeError(err_msg)
    role = names.get("role")
    if role is not None and role not in ROLES:
        raise BTClibValueError(f"{where}.role: not one of ROLES")
    return {
        field: names[field] for field in _KEY_FIELDS if names.get(field) is not None
    }


def _written_keys(value: object, at: str) -> dict[str, dict[str, str]]:
    """Return the `keys` object `serialize` writes, or refuse the names."""
    if not isinstance(value, Mapping):
        raise BTClibTypeError(f"{at}: not a mapping: {type(value).__name__}")
    keys: dict[str, dict[str, str]] = {}
    for position, (name, names) in enumerate(value.items()):
        where = f"{at} entry {_position(position)}"
        if not isinstance(name, str):
            raise BTClibTypeError(f"{where}: not a str: {type(name).__name__}")
        written = _written_names(names, where)
        fingerprint_hex = name.lower()
        if fingerprint_hex in keys:
            raise BTClibValueError(f"{where}: a fingerprint named twice")
        keys[fingerprint_hex] = {"key": fingerprint_hex} | written
    return keys


def _written_labels(value: object, at: str, network: str) -> list[dict[str, Any]]:
    """Return the BIP329 records `serialize` writes, or refuse them."""
    if not _is_sequence(value):
        raise BTClibTypeError(f"{at}: not a sequence: {type(value).__name__}")
    return [
        _written(label, f"{at}[{_position(index)}]", network)
        for index, label in enumerate(value)
    ]


def _written_account(value: object, at: str, network: str) -> dict[str, Any]:
    """Return the account object `serialize` writes, or refuse the account."""
    if not isinstance(value, Mapping):
        raise BTClibTypeError(f"{at}: not a mapping: {type(value).__name__}")
    for given in value:
        if given in _FIELDS:
            continue
        # the registry's own name, written whole, as `_written_names` says
        if known := next((f for f in _REGISTRY_ACCOUNT_FIELDS if f == given), None):
            err_msg = f"{at}: {known!r}, a BIP139 account field this does not carry"
            raise BTClibValueError(err_msg)
        raise BTClibValueError(f"{at}: no BIP139 account field: {_quoted(given)}")
    account: dict[str, Any] = {"type": _TYPE} | {
        field: _written_descriptor(value[field], f"{at}.{field}", network)
        for field in ("descriptor", "change_descriptor")
        if value.get(field) is not None
    }
    for field in _BITS:
        given = value.get(field)
        if given is not None and not _is_integer(given):
            err_msg = f"{at}.{field}: not an int: {type(given).__name__}"
            raise BTClibTypeError(err_msg)
    account |= {
        field: _integer(value[field], f"{at}.{field}", bits)
        for field, bits in _BITS.items()
        if value.get(field) is not None
    }
    if (keys := value.get("keys")) is not None:
        account["keys"] = _written_keys(keys, f"{at}.keys")
    if (labels := value.get("labels")) is not None:
        account["labels"] = _written_labels(labels, f"{at}.labels", network)
    return account


def serialize(accounts: Sequence[Mapping[str, Any]], network: str = "mainnet") -> str:
    """Return the BIP139 export of a wallet's accounts on a network.

    Each account is a mapping of the fields the module docstring lists, a
    field whose value is None left out; what `parse` returns is such a
    list. `network` is btclib's name of the network, as `descriptors.parse`
    takes it. What is refused is the module docstring's, the refusal
    naming an account by its index. The text ends with a newline.
    """
    if not _is_sequence(accounts):
        raise BTClibTypeError(f"invalid accounts type: {type(accounts).__name__}")
    name = validated_network_name(network)
    written = [
        _written_account(account, f"accounts[{_position(index)}]", name)
        for index, account in enumerate(accounts)
    ]
    # read as `parse` reads it, so that what is written is read back
    _accounts(written, name)
    document = {"version": VERSION, "network": _NETWORKS[name], "accounts": written}
    return json.dumps(document, indent=2) + "\n"
