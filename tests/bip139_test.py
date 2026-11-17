# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib_wallet.bip139` module.

BIP139 publishes no test vector, so the documents here are built from its
text, `bip-0139.md` and `bip-0139/field-registry.md` at
bitcoin/bips@100ba872c808: each field and value is one the registry
names. The keys are derived at run time from fixed seeds.
"""

from __future__ import annotations

import json
import re
from hashlib import sha256
from typing import Any

import pytest
from bip32_descriptors.bip32 import bip32
from bip32_descriptors.descriptors import add_checksum, parse
from bip39_slip39.bip39 import mnemonic_from_entropy
from btclib import b58
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash160
from btclib.network import NETWORKS
from btclib.script.script_pub_key import ScriptPubKey
from typing_extensions import override

from btclib_wallet import bip139
from tests.secret_free import assert_secret_free

PATH = "48h/0h/0h/2h"
TEST_PATH = "48h/1h/0h/2h"


def _root(word: bytes, network: str = "mainnet") -> str:
    """Return the root of a fixed random seed."""
    seed = sha256(word).digest()[:16]
    return bip32.rootxprv_from_seed(seed, NETWORKS[network].bip32_prv)


def _fingerprint(root: str) -> str:
    return bip32.fingerprint(root).hex()


def _key(root: str, path: str) -> str:
    """Return the key expression of an account key, origin included."""
    xpub = bip32.xpub_from_xprv(bip32.derive(root, f"m/{path}"))
    return f"[{_fingerprint(root)}/{path}]{xpub}"


OWNER = _root(b"owner")
HEIR = _root(b"heir")
OWNER_FP = _fingerprint(OWNER)
HEIR_FP = _fingerprint(HEIR)
# the policy of ISS btclib-org/btclib-wallet#927: the owner's key, or the
# heir's after a year of blocks
POLICY = add_checksum(
    f"wsh(or_d(pk({_key(OWNER, PATH)}/<0;1>/*),"
    f"and_v(v:pkh({_key(HEIR, PATH)}/<0;1>/*),older(52560))))"
)
RECEIVE = add_checksum(f"wpkh({_key(OWNER, PATH)}/0/*)")
CHANGE = add_checksum(f"wpkh({_key(OWNER, PATH)}/1/*)")
TEST_OWNER = _root(b"owner", "testnet")
TEST_RECEIVE = add_checksum(f"wpkh({_key(TEST_OWNER, TEST_PATH)}/0/*)")
ADDRESS = "bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c"
# the same script, spelled for testnet
TESTNET_ADDRESS = ScriptPubKey(
    ScriptPubKey.from_address(ADDRESS).script, "testnet"
).address
TXID = sha256(b"bip139 tx").hexdigest()
MNEMONIC = mnemonic_from_entropy(sha256(b"bip139 mnemonic").digest()[:16])

ACCOUNT: dict[str, Any] = {
    "descriptor": POLICY,
    "birth_block": 870000,
    "receive_index": 4,
    "change_index": 2,
    "keys": {
        OWNER_FP: {"alias": "Alice", "role": "main"},
        HEIR_FP: {"alias": "Bob", "role": "inheritance"},
    },
    "labels": [
        {"type": "addr", "ref": ADDRESS, "label": "savings"},
        {"type": "output", "ref": f"{TXID}:0", "spendable": False},
    ],
}


def _exact(message: str) -> str:
    """Return a pattern matching `message` whole."""
    return f"^{re.escape(message)}$"


def _document(*accounts: object, network: str = "bitcoin") -> str:
    """Return an export of the accounts, BIP139's fields as given."""
    return json.dumps(
        {"version": "BIP139-1", "network": network, "accounts": list(accounts)}
    )


def _json_account(**fields: Any) -> dict[str, Any]:
    """Return the JSON object of a bip380 account of `RECEIVE`, and `fields`."""
    return {"type": "bip380", "descriptor": RECEIVE} | fields


def test_an_export_reads_back_what_was_written() -> None:
    """`parse` answers the network and the accounts `serialize` was given."""
    core_style = {"descriptor": RECEIVE, "change_descriptor": CHANGE}
    text = bip139.serialize([ACCOUNT, core_style])
    assert bip139.parse(text) == {
        "network": "mainnet",
        "accounts": [ACCOUNT, core_style],
    }
    assert bip139.serialize(**bip139.parse(text)) == text


@pytest.mark.parametrize("role", ["main", "recovery", "inheritance", "cosigning"])
def test_every_role_of_bip139_s_registry_reads_back(role: str) -> None:
    """The four Key Roles of the field registry, in its order."""
    account = {"descriptor": RECEIVE, "keys": {OWNER_FP: {"role": role}}}
    assert bip139.parse(bip139.serialize([account]))["accounts"] == [account]


@pytest.mark.parametrize("name", ["birth_block", "receive_index", "change_index"])
def test_a_height_or_an_index_of_zero_reads_back(name: str) -> None:
    """Zero is the first height and the first index, not a negative one."""
    account = {"descriptor": RECEIVE, name: 0}
    assert bip139.parse(bip139.serialize([account]))["accounts"] == [account]


def test_an_empty_value_is_kept_and_not_read_as_absent() -> None:
    """An empty label, alias, `keys` and `labels`, read and written as given."""
    accounts: list[dict[str, Any]] = [
        {
            "descriptor": RECEIVE,
            "keys": {OWNER_FP: {"alias": ""}},
            "labels": [{"type": "tx", "ref": TXID, "label": ""}],
        },
        {"descriptor": RECEIVE, "keys": {}, "labels": []},
    ]
    text = bip139.serialize(accounts)
    written = json.loads(text)["accounts"]
    assert written[0]["keys"] == {OWNER_FP: {"key": OWNER_FP, "alias": ""}}
    assert written[0]["labels"] == accounts[0]["labels"]
    assert (written[1]["keys"], written[1]["labels"]) == ({}, [])
    assert bip139.parse(text)["accounts"] == accounts


@pytest.mark.parametrize(
    "fields, parsed, written",
    [
        (
            {"change_descriptor": ""},
            "accounts[0].change_descriptor: no checksum",
            "accounts[0].change_descriptor: not a descriptor",
        ),
        (
            {"bip39_mnemonic": ""},
            "accounts[0].bip39_mnemonic: a mnemonic in a mainnet export",
            None,
        ),
    ],
)
def test_an_empty_value_is_refused_where_it_is_no_value(
    fields: dict[str, Any], parsed: str, written: str | None
) -> None:
    """An empty change descriptor, and an empty mnemonic on mainnet."""
    with pytest.raises(BTClibValueError, match=_exact(parsed)):
        bip139.parse(_document(_json_account(**fields)))
    if written is not None:
        with pytest.raises(BTClibValueError, match=_exact(written)):
            bip139.serialize([{"descriptor": RECEIVE, **fields}])


def test_an_output_label_holds_every_field_bip329_defines() -> None:
    """`label`, `origin` and `spendable` together, read and written."""
    label = {
        "type": "output",
        "ref": f"{TXID}:1",
        "label": "a",
        "origin": "wpkh([d34db33f/84'/0'/0'])",
        "spendable": True,
    }
    text = bip139.serialize([{"descriptor": RECEIVE, "labels": [label]}])
    assert json.loads(text)["accounts"][0]["labels"] == [label]
    assert bip139.parse(text)["accounts"][0]["labels"] == [label]


def test_serialize_writes_bip139_s_fields() -> None:
    """The version, BIP139's network name, and each account's `type`."""
    document = json.loads(bip139.serialize([ACCOUNT]))
    assert document["version"] == bip139.VERSION == "BIP139-1"
    assert document["network"] == "bitcoin"
    (account,) = document["accounts"]
    assert account["type"] == "bip380"
    assert account["keys"][HEIR_FP] == {
        "key": HEIR_FP,
        "alias": "Bob",
        "role": "inheritance",
    }


@pytest.mark.parametrize(
    "network, name",
    [
        ("mainnet", "bitcoin"),
        ("testnet", "testnet3"),
        ("testnet4", "testnet4"),
        ("signet", "signet"),
        ("regtest", "regtest"),
    ],
)
def test_each_network_btclib_holds_has_its_bip139_name(network: str, name: str) -> None:
    """BIP139 spells mainnet `bitcoin` and testnet `testnet3`."""
    root = _root(b"owner", network)
    account = {"descriptor": add_checksum(f"wpkh({_key(root, TEST_PATH)}/0/*)")}
    text = bip139.serialize([account], network)
    assert json.loads(text)["network"] == name
    assert bip139.parse(text) == {"network": network, "accounts": [account]}


def test_every_network_btclib_holds_is_in_the_table() -> None:
    """A network btclib adds is one this module has to name."""
    assert set(bip139._NETWORKS) == set(NETWORKS)


def test_serialize_takes_btclib_s_spelling_of_a_network() -> None:
    """Its case and the whitespace around it, as `validated_network_name`."""
    assert json.loads(bip139.serialize([ACCOUNT], " MainNet "))["network"] == "bitcoin"


def test_what_bip139_says_to_discard_is_discarded() -> None:
    """Every field of the registry this module does not read is dropped."""
    document = {
        "version": "BIP139-1",
        "network": "testnet3",
        "name": "Family",
        "note": "for the heirs",
        "date": 1731628800,
        "exporter": "Sparrow 2.2.0",
        "transactions": {TXID: {"fee": 141, "blockheight": 3}},
        "psbts": {TXID: "cHNidP8B"},
        "signers": [{"fingerprints": [OWNER_FP], "key_storage": "cold"}],
        "proprietary": {"app": [[[{"deep": True}]]]},
        "accounts": [
            {
                "type": "bip380",
                "descriptor": TEST_RECEIVE,
                "name": "savings",
                "description": "the first",
                "status": "active",
                "hidden": False,
                "change_descriptor": None,
                "range_start": 0,
                "gap_limit": 20,
                "last_height": 90,
                "bip352_labels": [0, 1],
                "keys": {
                    OWNER_FP: {
                        "key": OWNER_FP,
                        "role": "a role of a later registry",
                        "key_type": "internal",
                        "proof_of_registration": [["d", "00"]],
                    }
                },
                "transactions": [TXID],
                "coins": [{"outpoint": f"{TXID}:0", "frozen": True}],
                "psbts": [TXID],
                "bip39_mnemonic": MNEMONIC,
                "proprietary": None,
            }
        ],
    }
    assert bip139.parse(json.dumps(document)) == {
        "network": "testnet",
        "accounts": [{"descriptor": TEST_RECEIVE, "keys": {OWNER_FP: {}}}],
    }


def test_a_multipath_descriptor_and_a_core_pair_are_both_read() -> None:
    """BIP389's ``<0;1>``, or a single-path `descriptor` and its change."""
    text = _document(
        _json_account(descriptor=POLICY), _json_account(change_descriptor=CHANGE)
    )
    accounts = bip139.parse(text)["accounts"]
    assert accounts == [
        {"descriptor": POLICY},
        {"descriptor": RECEIVE, "change_descriptor": CHANGE},
    ]


@pytest.mark.parametrize(
    "document, message",
    [
        ("[]", "export: not a JSON object: a list of length 0"),
        ("{", "export: not JSON at line 1, column 2"),
        ('{\n"version": Infinity}', "export: not JSON"),
        ('{"version": 1, "version": 1}', "export: a name twice in one object"),
        ("{}", "version: missing"),
        ('{"version": "BIP139-2"}', "version: 'BIP139-2', not BIP139-1"),
        ('{"version": ""}', "version: '', not BIP139-1"),
        ('{"version": "BIP139-1"}', "network: missing"),
        (
            '{"version": "BIP139-1", "network": ""}',
            "network: '', which BIP139 does not name",
        ),
        (
            '{"version": "BIP139-1", "network": "mutinynet"}',
            "network: mutinynet, which btclib does not hold",
        ),
        (
            '{"version": "BIP139-1", "network": "mainnet"}',
            "network: 'mainnet', which BIP139 does not name",
        ),
        ('{"version": "BIP139-1", "network": "bitcoin"}', "accounts: missing"),
        (
            '{"version": "BIP139-1", "network": "bitcoin", "accounts": {}}',
            "accounts: not a JSON array: a dict of length 0",
        ),
        (
            '{"version": "BIP139-1", "network": "bitcoin", "accounts": []}',
            "accounts: no account",
        ),
        (_document([]), "accounts[0]: not a JSON object: a list of length 0"),
        (_document({}), "accounts[0].type: missing"),
        (_document({"type": "bip388"}), "accounts[0].type: 'bip388', not bip380"),
        (_document({"type": 380}), "accounts[0].type: an int of 9 bits, not bip380"),
        (_document({"type": "bip380"}), "accounts[0].descriptor: missing"),
        (_document({"type": ""}), "accounts[0].type: '', not bip380"),
        (
            _document({"type": "bip380", "descriptor": ""}),
            "accounts[0].descriptor: no checksum",
        ),
    ],
)
def test_an_export_that_is_not_one_is_refused(document: str, message: str) -> None:
    """Each refusal names the field by its position."""
    with pytest.raises(BTClibValueError, match=_exact(message)):
        bip139.parse(document)


def test_an_account_is_named_by_its_index() -> None:
    """The second account's field is `accounts[1]`'s."""
    text = _document(_json_account(), _json_account(birth_block=-1))
    message = "accounts[1].birth_block: negative"
    with pytest.raises(BTClibValueError, match=_exact(message)):
        bip139.parse(text)


@pytest.mark.parametrize(
    "descriptor, message",
    [
        (1, "not a string: an int of 1 bits"),
        (RECEIVE.partition("#")[0], "no checksum"),
        (
            RECEIVE[:-1] + ("q" if RECEIVE[-1] != "q" else "p"),
            "invalid descriptor checksum",
        ),
        (TEST_RECEIVE, "not a mainnet key: version"),
        # the package names the second key's position, which is not repeated
        (
            add_checksum(
                f"wsh(multi(1,{b58.wif_from_prv_key(1)},"
                f"{b58.wif_from_prv_key(1, network='testnet')}))"
            ),
            "not a mainnet key: WIF prefix",
        ),
        (f" {RECEIVE}", "invalid descriptor checksum"),
        (f"{RECEIVE}\n", "invalid descriptor checksum"),
        (add_checksum(f" {RECEIVE.partition('#')[0]}"), "not a descriptor"),
        (add_checksum("wpkh(nokey)"), "not a descriptor"),
        (add_checksum("wpkh(xpub)/0/*"), "not a descriptor"),
    ],
)
def test_a_descriptor_that_does_not_parse_is_refused(
    descriptor: object, message: str
) -> None:
    """With its checksum, on the export's network."""
    text = _document(_json_account(descriptor=descriptor))
    with pytest.raises(
        BTClibValueError, match=_exact(f"accounts[0].descriptor: {message}")
    ):
        bip139.parse(text)


def test_the_change_descriptor_is_read_as_the_descriptor_is() -> None:
    """Its own position, and the same checks."""
    text = _document(_json_account(change_descriptor=TEST_RECEIVE))
    message = "accounts[0].change_descriptor: not a mainnet key: version"
    with pytest.raises(BTClibValueError, match=_exact(message)):
        bip139.parse(text)


@pytest.mark.parametrize(
    "fields, message",
    [
        (
            {"descriptor": POLICY, "change_descriptor": CHANGE},
            "accounts[0].change_descriptor: beside a multipath descriptor",
        ),
        (
            {"change_descriptor": POLICY},
            "accounts[0].change_descriptor: a multipath descriptor",
        ),
    ],
)
def test_a_change_descriptor_has_one_path_beside_one_path(
    fields: dict[str, Any], message: str
) -> None:
    """A multipath descriptor holds its change already."""
    with pytest.raises(BTClibValueError, match=_exact(message)):
        bip139.parse(_document(_json_account(**fields)))


def _wif() -> str:
    return b58.wif_from_prv_key(int.from_bytes(sha256(b"bip139 wif").digest()))


def _pub_key(root: str) -> str:
    """Return the public key of a root, in SEC hex."""
    return bip32.BIP32KeyData.b58decode(bip32.xpub_from_xprv(root)).key.hex()


@pytest.mark.parametrize(
    "private",
    [
        lambda: f"wpkh({bip32.derive(OWNER, f'm/{PATH}')}/0/*)",
        lambda: f"wsh(or_d(pk({_key(HEIR, PATH)}/0/*),pk({_wif()})))",
        lambda: f"tr(musig({OWNER},{bip32.xpub_from_xprv(HEIR)})/0/*)",
        lambda: f"tr(musig({_wif()},{_pub_key(HEIR)}))",
    ],
)
def test_a_descriptor_holding_a_private_key_is_refused(private: Any) -> None:
    """An xprv or a WIF, a ``musig()`` participant included, never quoted."""
    descriptor = add_checksum(private())
    text = _document(_json_account(descriptor=descriptor))
    with pytest.raises(
        BTClibValueError, match=_exact("accounts[0].descriptor: a private key")
    ) as e:
        bip139.parse(text)
    assert_secret_free(e.value, [OWNER, bip32.derive(OWNER, f"m/{PATH}"), _wif()])
    with pytest.raises(
        BTClibValueError, match=_exact("accounts[0].descriptor: a private key")
    ) as e:
        bip139.serialize([{"descriptor": descriptor}])
    assert_secret_free(e.value, [OWNER, bip32.derive(OWNER, f"m/{PATH}"), _wif()])


def test_a_private_key_is_refused_on_a_test_network_too() -> None:
    """BIP139 allows one there, and this module does not."""
    xprv = bip32.derive(TEST_OWNER, f"m/{TEST_PATH}")
    descriptor = add_checksum(f"wpkh({xprv}/0/*)")
    message = "accounts[0].descriptor: a private key"
    text = _document(_json_account(descriptor=descriptor), network="testnet3")
    with pytest.raises(BTClibValueError, match=_exact(message)) as e:
        bip139.parse(text)
    assert_secret_free(e.value, [TEST_OWNER, xprv])
    with pytest.raises(BTClibValueError, match=_exact(message)) as e:
        bip139.serialize([{"descriptor": descriptor}], "testnet")
    assert_secret_free(e.value, [TEST_OWNER, xprv])


@pytest.mark.parametrize(
    "name, bits",
    [("birth_block", 63), ("receive_index", 31), ("change_index", 31)],
)
@pytest.mark.parametrize(
    "value, problem",
    [
        (True, "not an integer: a bool"),
        (1.0, "not an integer: a float"),
        ("1", "not an integer: a str of length 1"),
        (-1, "negative"),
        (None, "not below 2**{bits}"),
    ],
)
def test_a_height_or_an_index_is_an_integer_below_its_bound(
    name: str, bits: int, value: object, problem: str
) -> None:
    """A height below 2**63, an index below 2**31, BIP32's unhardened one."""
    given = 2**bits if value is None else value
    message = f"accounts[0].{name}: {problem.format(bits=bits)}"
    with pytest.raises(BTClibValueError, match=_exact(message)):
        bip139.parse(_document(_json_account(**{name: given})))
    top = 2**bits - 1
    assert bip139.parse(_document(_json_account(**{name: top})))["accounts"] == [
        {"descriptor": RECEIVE, name: top}
    ]


@pytest.mark.parametrize(
    "keys, message",
    [
        ([], "accounts[0].keys: not a JSON object: a list of length 0"),
        ({"d34db33": {}}, "accounts[0].keys entry 0: not a fingerprint"),
        ({f" {OWNER_FP}": {}}, "accounts[0].keys entry 0: not a fingerprint"),
        ({f"{OWNER_FP}\n": {}}, "accounts[0].keys entry 0: not a fingerprint"),
        (
            {OWNER_FP: {"key": f"{OWNER_FP} "}},
            "accounts[0].keys entry 0.key: not the fingerprint of the entry",
        ),
        (
            {"deadbeef": {}},
            "accounts[0].keys entry 0: a key the descriptor does not name",
        ),
        (
            {OWNER_FP: {"key": OWNER_FP}, OWNER_FP.upper(): {"key": OWNER_FP}},
            "accounts[0].keys entry 1: a fingerprint named twice",
        ),
        (
            {OWNER_FP: "Alice"},
            "accounts[0].keys entry 0: not a JSON object: a str of length 5",
        ),
        ({OWNER_FP: {}}, "accounts[0].keys entry 0.key: missing"),
        (
            {OWNER_FP: {"key": ""}},
            "accounts[0].keys entry 0.key: not the fingerprint of the entry",
        ),
        (
            {OWNER_FP: {"key": HEIR_FP}},
            "accounts[0].keys entry 0.key: not the fingerprint of the entry",
        ),
        (
            {OWNER_FP: {"key": 1}},
            "accounts[0].keys entry 0.key: not the fingerprint of the entry",
        ),
        (
            {OWNER_FP: {"key": OWNER_FP, "alias": 1}},
            "accounts[0].keys entry 0.alias: not a string: an int of 1 bits",
        ),
        (
            {OWNER_FP: {"key": OWNER_FP, "role": ["main"]}},
            "accounts[0].keys entry 0.role: not a string: a list of length 1",
        ),
    ],
)
def test_keys_name_keys_the_descriptor_holds(keys: object, message: str) -> None:
    """An entry is named by its position, never by its fingerprint."""
    with pytest.raises(BTClibValueError, match=_exact(message)):
        bip139.parse(_document(_json_account(keys=keys)))


def test_an_empty_role_is_refused_on_write_and_dropped_on_read() -> None:
    """An empty role: `serialize` refuses it, `parse` drops it."""
    message = "accounts[0].keys entry 0.role: not one of ROLES"
    with pytest.raises(BTClibValueError, match=_exact(message)):
        bip139.serialize([{"descriptor": RECEIVE, "keys": {OWNER_FP: {"role": ""}}}])
    keys = {OWNER_FP: {"key": OWNER_FP, "alias": "a", "role": ""}}
    account = bip139.parse(_document(_json_account(keys=keys)))["accounts"][0]
    assert account["keys"] == {OWNER_FP: {"alias": "a"}}


def test_a_fingerprint_is_read_in_either_case_and_kept_in_lowercase() -> None:
    """BIP139 says hexadecimal, and names no case."""
    upper = OWNER_FP.upper()
    assert upper != OWNER_FP
    keys = {upper: {"key": upper, "alias": "", "role": "recovery"}}
    account = bip139.parse(_document(_json_account(keys=keys)))["accounts"][0]
    assert account["keys"] == {OWNER_FP: {"alias": "", "role": "recovery"}}


def test_a_key_origin_with_no_path_names_its_fingerprint() -> None:
    """``[deadbeef]`` names deadbeef, whatever key follows it."""
    xpub = bip32.xpub_from_xprv(bip32.derive(HEIR, f"m/{PATH}"))
    assert bip32.fingerprint(xpub).hex() != "deadbeef"
    descriptor = add_checksum(f"wpkh([deadbeef]{xpub}/0/*)")
    account = {"descriptor": descriptor, "keys": {"deadbeef": {"alias": "a"}}}
    assert bip139.parse(bip139.serialize([account]))["accounts"] == [account]


def test_a_key_with_no_origin_is_named_by_its_own_fingerprint() -> None:
    """An extended key by BIP32's fingerprint, a fixed key by its HASH160."""
    xpub = bip32.xpub_from_xprv(HEIR)
    pub_key = bip32.BIP32KeyData.b58decode(bip32.xpub_from_xprv(OWNER)).key
    pub_key_fp = hash160(pub_key)[:4].hex()
    descriptor = add_checksum(f"wsh(or_d(pk({xpub}/0/*),pk({pub_key.hex()})))")
    keys = {HEIR_FP: {"key": HEIR_FP}, pub_key_fp: {"key": pub_key_fp}}
    text = _document(_json_account(descriptor=descriptor, keys=keys))
    assert bip139.parse(text)["accounts"][0]["keys"] == {HEIR_FP: {}, pub_key_fp: {}}


def test_a_musig_is_named_by_its_participants() -> None:
    """BIP390's aggregate, which has no origin, holds the participants' keys."""
    owner = _key(OWNER, PATH)
    heir = _key(HEIR, PATH)
    descriptor = add_checksum(f"tr(musig({owner},{heir})/0/*)")
    keys = {OWNER_FP: {"key": OWNER_FP}, HEIR_FP: {"key": HEIR_FP}}
    text = _document(_json_account(descriptor=descriptor, keys=keys))
    assert bip139.parse(text)["accounts"][0]["keys"] == {OWNER_FP: {}, HEIR_FP: {}}
    assert {key.origin for key in parse(descriptor).key_expressions} == {None}


def test_the_change_descriptor_names_keys_too() -> None:
    """A key of the change alone is one the account holds."""
    change = add_checksum(f"wpkh({_key(HEIR, PATH)}/1/*)")
    keys = {HEIR_FP: {"key": HEIR_FP}}
    text = _document(_json_account(change_descriptor=change, keys=keys))
    assert bip139.parse(text)["accounts"][0]["keys"] == {HEIR_FP: {}}


@pytest.mark.parametrize(
    "labels, message",
    [
        ({}, "accounts[0].labels: not a JSON array: a dict of length 0"),
        (
            [{"type": "tx", "ref": TXID}, "x"],
            "accounts[0].labels[1]: not a JSON object: a str of length 1",
        ),
        ([{"type": "tx"}], "accounts[0].labels[0].ref: missing"),
        (
            [{"type": "addr", "ref": TESTNET_ADDRESS, "label": "a"}],
            "accounts[0].labels[0].ref: not an address of mainnet",
        ),
        (
            [{"type": "xpub", "ref": bip32.xpub_from_xprv(TEST_OWNER), "label": "a"}],
            "accounts[0].labels[0].ref: not an extended key of mainnet",
        ),
    ],
)
def test_labels_are_bip329_records_of_the_network(labels: object, message: str) -> None:
    """As `bip329` reads them, an address and an extended key of the network."""
    with pytest.raises(BTClibValueError, match=_exact(message)):
        bip139.parse(_document(_json_account(labels=labels)))


def test_a_label_origin_holding_a_key_is_refused_and_not_printed() -> None:
    """BIP329's `origin` holds key origins alone, read and written."""
    origin = f"wpkh({OWNER}/0/*)"
    labels = [{"type": "tx", "ref": TXID, "origin": origin}]
    message = "accounts[0].labels[0].origin: not an abbreviated descriptor"
    with pytest.raises(BTClibValueError, match=_exact(message)) as e:
        bip139.parse(_document(_json_account(labels=labels)))
    assert_secret_free(e.value, [OWNER])
    with pytest.raises(BTClibValueError, match=_exact(message)) as e:
        bip139.serialize([{"descriptor": RECEIVE, "labels": labels}])
    assert_secret_free(e.value, [OWNER])


def test_serialize_writes_a_label_as_bip329_keeps_it() -> None:
    """Hex in lowercase, as `bip329` keeps a ref."""
    labels = [{"type": "tx", "ref": TXID.upper(), "label": "a"}]
    document = json.loads(bip139.serialize([{"descriptor": RECEIVE, "labels": labels}]))
    assert document["accounts"][0]["labels"] == [
        {"type": "tx", "ref": TXID, "label": "a"}
    ]


def test_a_label_bip329_skips_is_skipped() -> None:
    """An spscan record, its scan key private, and a type and a ref alone."""
    labels = [
        {"type": "spscan", "ref": "spscan1q", "label": "a"},
        {"type": "tx", "ref": TXID},
        {"type": "tx", "ref": TXID, "label": "a"},
    ]
    account = bip139.parse(_document(_json_account(labels=labels)))["accounts"][0]
    assert account["labels"] == [{"type": "tx", "ref": TXID, "label": "a"}]


def test_a_mainnet_mnemonic_is_refused_naming_the_field_and_not_its_words() -> None:
    """BIP139 forbids `bip39_mnemonic` on mainnet."""
    text = _document(_json_account(bip39_mnemonic=MNEMONIC))
    message = "accounts[0].bip39_mnemonic: a mnemonic in a mainnet export"
    with pytest.raises(BTClibValueError, match=_exact(message)) as e:
        bip139.parse(text)
    assert_secret_free(e.value, [MNEMONIC, *MNEMONIC.split()])


@pytest.mark.parametrize(
    "document",
    [
        f'{{"version": "BIP139-1", "bip39_mnemonic": "{MNEMONIC}"',
        f'{{"version": "BIP139-1", "x": "{MNEMONIC}", "x": 1}}',
        f'{{"version": "{MNEMONIC}"}}',
        f'{{"version": "BIP139-1", "network": "{MNEMONIC}"}}',
        _document({"type": MNEMONIC}),
        _document(_json_account(descriptor=f"{MNEMONIC}#")),
        _document(_json_account(keys={MNEMONIC: {}})),
        _document(_json_account(keys={OWNER_FP: {"key": MNEMONIC}})),
    ],
)
def test_a_refused_export_quotes_none_of_it(document: str) -> None:
    """A JSONDecodeError holds the text in `.doc`, and nothing chains it."""
    with pytest.raises(BTClibValueError) as e:
        bip139.parse(document)
    assert e.value.__context__ is None
    assert e.value.__cause__ is None
    assert_secret_free(e.value, [MNEMONIC, *MNEMONIC.split()])


def test_parse_refuses_what_is_no_str() -> None:
    """The file's text, decoded by its caller."""
    with pytest.raises(BTClibTypeError, match=_exact("invalid export type: bytes")):
        bip139.parse(b"{}")  # type: ignore[arg-type]


def test_serialize_takes_a_descriptor_and_writes_its_checksummed_text() -> None:
    """A `Descriptor` is public by construction; text gets its checksum."""
    unchecked = RECEIVE.partition("#")[0]
    text = bip139.serialize([{"descriptor": parse(RECEIVE)}, {"descriptor": unchecked}])
    accounts = bip139.parse(text)["accounts"]
    assert accounts == [{"descriptor": RECEIVE}, {"descriptor": RECEIVE}]


@pytest.mark.parametrize(
    "accounts, error, message",
    [
        ("x", BTClibTypeError, "invalid accounts type: str"),
        ({}, BTClibTypeError, "invalid accounts type: dict"),
        ([], BTClibValueError, "accounts: no account"),
        ([[]], BTClibTypeError, "accounts[0]: not a mapping: list"),
        (
            [{"type": "bip380"}],
            BTClibValueError,
            "accounts[0]: 'type', a BIP139 account field this does not carry",
        ),
        (
            [{"descriptor": RECEIVE, "gap_limit": 20}],
            BTClibValueError,
            "accounts[0]: 'gap_limit', a BIP139 account field this does not carry",
        ),
        (
            [{"descriptor": RECEIVE, "colour": "red"}],
            BTClibValueError,
            "accounts[0]: no BIP139 account field: 'colour'",
        ),
        ([{}], BTClibValueError, "accounts[0].descriptor: missing"),
        (
            [{"descriptor": parse(TEST_RECEIVE, "testnet")}],
            BTClibValueError,
            "accounts[0].descriptor: a descriptor of testnet",
        ),
        (
            [{"descriptor": b"wpkh()"}],
            BTClibTypeError,
            "accounts[0].descriptor: not a descriptor: bytes",
        ),
        (
            [{"descriptor": "wpkh(é)"}],
            BTClibValueError,
            "accounts[0].descriptor: not a descriptor",
        ),
        (
            [{"descriptor": RECEIVE, "keys": []}],
            BTClibTypeError,
            "accounts[0].keys: not a mapping: list",
        ),
        (
            [{"descriptor": RECEIVE, "keys": {1: {}}}],
            BTClibTypeError,
            "accounts[0].keys entry 0: not a str: int",
        ),
        (
            [{"descriptor": RECEIVE, "keys": {OWNER_FP: "Alice"}}],
            BTClibTypeError,
            "accounts[0].keys entry 0: not a mapping: str",
        ),
        (
            [{"descriptor": RECEIVE, "keys": {OWNER_FP: {"key": OWNER_FP}}}],
            BTClibValueError,
            "accounts[0].keys entry 0: 'key', a BIP139 key field this does not carry",
        ),
        (
            [{"descriptor": RECEIVE, "keys": {OWNER_FP: {"key_type": "internal"}}}],
            BTClibValueError,
            (
                "accounts[0].keys entry 0: 'key_type', a BIP139 key field this"
                " does not carry"
            ),
        ),
        (
            [{"descriptor": RECEIVE, "keys": {OWNER_FP: {"colour": "red"}}}],
            BTClibValueError,
            "accounts[0].keys entry 0: no BIP139 key field: 'colour'",
        ),
        (
            [{"descriptor": RECEIVE, "keys": {OWNER_FP: {"role": "heir"}}}],
            BTClibValueError,
            "accounts[0].keys entry 0.role: not one of ROLES",
        ),
        (
            [
                {
                    "descriptor": RECEIVE,
                    "keys": {OWNER_FP: {"alias": "A"}, OWNER_FP.upper(): {}},
                }
            ],
            BTClibValueError,
            "accounts[0].keys entry 1: a fingerprint named twice",
        ),
        (
            [{"descriptor": RECEIVE, "keys": {HEIR_FP: {}}}],
            BTClibValueError,
            "accounts[0].keys entry 0: a key the descriptor does not name",
        ),
        (
            [{"descriptor": RECEIVE, "keys": {f"{OWNER_FP} ": {}}}],
            BTClibValueError,
            "accounts[0].keys entry 0: not a fingerprint",
        ),
        (
            [{"descriptor": f"{RECEIVE} "}],
            BTClibValueError,
            "accounts[0].descriptor: invalid descriptor checksum",
        ),
        (
            [{"descriptor": RECEIVE, "labels": "x"}],
            BTClibTypeError,
            "accounts[0].labels: not a sequence: str",
        ),
        (
            [{"descriptor": RECEIVE, "labels": [{"type": "spscan", "ref": "s"}]}],
            BTClibValueError,
            "accounts[0].labels[0].type: spscan, a private key",
        ),
        (
            [{"descriptor": RECEIVE, "birth_block": False}],
            BTClibTypeError,
            "accounts[0].birth_block: not an int: bool",
        ),
        (
            [{"descriptor": RECEIVE, "change_index": "1"}],
            BTClibTypeError,
            "accounts[0].change_index: not an int: str",
        ),
        (
            [{"descriptor": RECEIVE, "receive_index": 2**31}],
            BTClibValueError,
            "accounts[0].receive_index: not below 2**31",
        ),
        (
            [{"descriptor": RECEIVE, "keys": {OWNER_FP: {"alias": 1}}}],
            BTClibTypeError,
            "accounts[0].keys entry 0.alias: not a str: int",
        ),
        (
            [{"descriptor": RECEIVE, "keys": {OWNER_FP: {"role": ["main"]}}}],
            BTClibTypeError,
            "accounts[0].keys entry 0.role: not a str: list",
        ),
        (
            [
                {
                    "descriptor": RECEIVE,
                    "labels": [{"type": "tx", "ref": TXID, "label": 2}],
                }
            ],
            BTClibTypeError,
            "accounts[0].labels[0].label: not a str: int",
        ),
    ],
)
def test_serialize_refuses_what_parse_would_and_what_bip139_does_not_name(
    accounts: Any, error: type[Exception], message: str
) -> None:
    """The writer's refusals, each at the account's index."""
    with pytest.raises(error, match=_exact(message)):
        bip139.serialize(accounts)


@pytest.mark.parametrize(
    "name, message",
    [
        # the Account Fields of BIP139's field registry, in its order, but
        # the ones `serialize` takes
        *(
            (
                name,
                f"accounts[0]: {name!r}, a BIP139 account field this does not carry",
            )
            for name in (
                "type",
                "name",
                "description",
                "status",
                "hidden",
                "range_start",
                "range_end",
                "change_range_start",
                "change_range_end",
                "gap_limit",
                "last_height",
                "bip352_labels",
                "transactions",
                "coins",
                "psbts",
                "bip39_mnemonic",
                "proprietary",
            )
        ),
        ("colour", "accounts[0]: no BIP139 account field: 'colour'"),
    ],
)
def test_serialize_names_a_bip139_account_field_it_does_not_carry(
    name: str, message: str
) -> None:
    """A field the registry defines is told from a name it does not."""
    with pytest.raises(BTClibValueError, match=_exact(message)):
        bip139.serialize([{"descriptor": RECEIVE, name: 1}])


@pytest.mark.parametrize(
    "name, message",
    [
        # the Key Fields of BIP139's field registry, in its order, but the
        # ones `serialize` takes
        *(
            (
                name,
                (
                    f"accounts[0].keys entry 0: {name!r}, a BIP139 key field this"
                    " does not carry"
                ),
            )
            for name in ("key", "key_type", "proof_of_registration")
        ),
        ("colour", "accounts[0].keys entry 0: no BIP139 key field: 'colour'"),
    ],
)
def test_serialize_names_a_bip139_key_field_it_does_not_carry(
    name: str, message: str
) -> None:
    """A field the registry defines is told from a name it does not."""
    with pytest.raises(BTClibValueError, match=_exact(message)):
        bip139.serialize([{"descriptor": RECEIVE, "keys": {OWNER_FP: {name: 1}}}])


@pytest.mark.parametrize("value", [0, False, b"", [], {}], ids=repr)
@pytest.mark.parametrize(
    "fields, at, expected",
    [
        (lambda v: {"descriptor": v}, "accounts[0].descriptor", "not a descriptor"),
        (
            lambda v: {"descriptor": RECEIVE, "change_descriptor": v},
            "accounts[0].change_descriptor",
            "not a descriptor",
        ),
        (
            lambda v: {"descriptor": RECEIVE, "keys": {OWNER_FP: {"alias": v}}},
            "accounts[0].keys entry 0.alias",
            "not a str",
        ),
        (
            lambda v: {"descriptor": RECEIVE, "keys": {OWNER_FP: {"role": v}}},
            "accounts[0].keys entry 0.role",
            "not a str",
        ),
        (
            lambda v: {
                "descriptor": RECEIVE,
                "labels": [{"type": "tx", "ref": TXID, "label": v}],
            },
            "accounts[0].labels[0].label",
            "not a str",
        ),
    ],
)
def test_serialize_refuses_a_falsy_value_of_another_type(
    value: object, fields: Any, at: str, expected: str
) -> None:
    """A falsy value of another type is refused, as a truthy one is."""
    message = f"{at}: {expected}: {type(value).__name__}"
    with pytest.raises(BTClibTypeError, match=_exact(message)):
        bip139.serialize([fields(value)])


@pytest.mark.parametrize("value", ["", b"", [], {}, 0.0], ids=repr)
@pytest.mark.parametrize("name", ["birth_block", "receive_index", "change_index"])
def test_serialize_refuses_a_falsy_height_or_index_of_another_type(
    name: str, value: object
) -> None:
    """Not an int, however empty, as `False` already is."""
    message = f"accounts[0].{name}: not an int: {type(value).__name__}"
    with pytest.raises(BTClibTypeError, match=_exact(message)):
        bip139.serialize([{"descriptor": RECEIVE, name: value}])


def test_serialize_refuses_a_network_btclib_does_not_name() -> None:
    """`validated_network_name`'s refusal, BIP139's name included."""
    with pytest.raises(BTClibValueError, match="^unknown network: 'bitcoin'"):
        bip139.serialize([{"descriptor": RECEIVE}], "bitcoin")


def test_serialize_leaves_out_a_field_that_is_none() -> None:
    """None is no value of any field, as null is read as absent."""
    account = {"descriptor": RECEIVE, "change_descriptor": None, "keys": None}
    assert bip139.parse(bip139.serialize([account]))["accounts"] == [
        {"descriptor": RECEIVE}
    ]


def test_a_value_claiming_to_be_an_int_is_not_one() -> None:
    """Its type decides, not the `__class__` it reports."""

    class Height:
        """An object no int, whose `__class__`, which isinstance reads, is."""

        __class__: Any = property(lambda _self: int)

    assert isinstance(Height(), int)
    message = "accounts[0].birth_block: not an int: Height"
    with pytest.raises(BTClibTypeError, match=_exact(message)):
        bip139.serialize([{"descriptor": RECEIVE, "birth_block": Height()}])


def test_an_int_subclass_is_bounded_by_its_value() -> None:
    """A subclass's own comparison does not let a negative height through."""

    class Height(int):
        @override
        def __lt__(self, other: int) -> bool:
            return False

    # the subclass's own __lt__ is what is asserted: `>=` would call int's
    assert not Height(-1) < 0  # sourcery skip: de-morgan
    with pytest.raises(
        BTClibValueError, match=_exact("accounts[0].birth_block: negative")
    ):
        bip139.serialize([{"descriptor": RECEIVE, "birth_block": Height(-1)}])
    text = bip139.serialize([{"descriptor": RECEIVE, "birth_block": Height(5)}])
    assert json.loads(text)["accounts"][0]["birth_block"] == 5
