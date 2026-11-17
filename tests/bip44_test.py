# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib_wallet.bip44` module.

`account_descriptors` is read against the same vectors as
`address_from_der_path`: it answers with the receive and change
descriptors of an account and reads the purpose off the same table, so
the addresses it describes have to be the addresses the other derives.

The discovery is read against `_Chain`, a `HistoryReader` in memory, so
that no test reaches the network.
"""

from __future__ import annotations

import dataclasses
import json
import platform
from collections.abc import Callable, Iterable, Iterator, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Any, NoReturn, cast, get_args

import pytest
from bip32_descriptors.bip32 import bip32, fingerprint
from bip32_descriptors.descriptors import (
    Descriptor,
    WpkhDescriptor,
    add_checksum,
    checksum,
    parse,
    wallet_policy,
    wallet_policy_address,
    wallet_policy_descriptor,
)
from btclib import b32, b58
from btclib.alias import Octets
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.key import PubKeyData
from btclib.network import NETWORKS
from btclib.script import ScriptPubKey
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from ecc.exceptions import EccValueError
from typing_extensions import override

from btclib_wallet.bip44 import (
    _ADDRESS_FROM_SCRIPT_TYPE,
    SCRIPT_TYPE_FROM_PURPOSE,
    BIP44ScriptType,
    _window_end,
    account_descriptors,
    address_from_der_path,
    discover_account,
    discover_accounts,
)
from btclib_wallet.exceptions import FetchError
from btclib_wallet.fetch.history import (
    BlockRef,
    HistoryTx,
    ScriptHistory,
    history_scripts,
)
from btclib_wallet.mnemonic.bip39 import mxprv_from_mnemonic
from tests import replace_unchecked
from tests.refused_value_test import HEX, SPELLINGS
from tests.secret_free import assert_secret_free

# the "abandon abandon ... about" seed of BIP39, which BIP84 and BIP86
# publish as a root key: the same key, spelled with two versions
_XPRV_ROOT = "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"
_ZPRV_ROOT = "zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5"
# BIP49's own root, the same seed on testnet
_UPRV_ROOT = "uprv8tXDerPXZ1QsVNjUJWTurs9kA1KGfKUAts74GCkcXtU8GwnH33GDRbNJpEqTvipfCyycARtQJhmdfWf8oKt41X9LL1zeD2pLsWmxEk3VAwd"

# (master key, account xpub, path, address), every field published.
#
# BIP44 has no address vector of its own -- it leans on BIP32's, which
# stop at the extended keys -- so the two mainnet rows for purposes 44
# and 49 are SLIP132's, which walks m/44h/0h/0h and m/49h/0h/0h from this
# very seed. Purpose 49 on testnet is BIP49's own vector, and the three
# rows each of purposes 84 and 86 are BIP84's and BIP86's.
#
# The account xpub of a row is the key the wallet exports, and the two
# entry points must agree: SLIP132 writes the purpose into the version
# byte, so the 49 mainnet row starts from a master xprv and an account
# ypub, which derive keys of different versions and the same address.
#
# https://github.com/satoshilabs/slips/blob/master/slip-0132.md
# https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki
# https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
# https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
_VECTORS = [
    (
        _XPRV_ROOT,
        "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj",
        "m/44h/0h/0h/0/0",
        "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
    ),
    (
        _XPRV_ROOT,
        "ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP",
        "m/49h/0h/0h/0/0",
        "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
    ),
    (
        _UPRV_ROOT,
        "upub5EFU65HtV5TeiSHmZZm7FUffBGy8UKeqp7vw43jYbvZPpoVsgU93oac7Wk3u6moKegAEWtGNF8DehrnHtv21XXEMYRUocHqguyjknFHYfgY",
        "m/49h/1h/0h/0/0",
        "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2",
    ),
    (
        _ZPRV_ROOT,
        "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
        "m/84h/0h/0h/0/0",
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
    ),
    (
        _ZPRV_ROOT,
        "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
        "m/84h/0h/0h/0/1",
        "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
    ),
    (
        _ZPRV_ROOT,
        "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
        "m/84h/0h/0h/1/0",
        "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
    ),
    (
        _XPRV_ROOT,
        "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ",
        "m/86h/0h/0h/0/0",
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
    ),
    (
        _XPRV_ROOT,
        "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ",
        "m/86h/0h/0h/0/1",
        "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh",
    ),
    (
        _XPRV_ROOT,
        "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ",
        "m/86h/0h/0h/1/0",
        "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7",
    ),
]


@pytest.mark.parametrize("mxkey, xpub, der_path, address", _VECTORS)
def test_bip44_vectors(mxkey: str, xpub: str, der_path: str, address: str) -> None:
    """Reproduce SLIP132, BIP49, BIP84 and BIP86 addresses, any level."""
    # from the master key, walking the whole path
    assert address_from_der_path(mxkey, der_path) == address
    # from the account xpub, walking the two public levels left
    assert address_from_der_path(xpub, der_path) == address
    # and from the address key itself, with nothing left to walk
    xkey = bip32.derive(mxkey, der_path)
    assert address_from_der_path(xkey, der_path) == address
    # a BIP32KeyData is a BIP32Key too
    assert (
        address_from_der_path(bip32.BIP32KeyData.b58decode(xkey), der_path) == address
    )


@pytest.mark.parametrize("mxkey, xpub, der_path, address", _VECTORS)
def test_the_account_descriptors_reach_the_same_addresses(
    mxkey: str, xpub: str, der_path: str, address: str
) -> None:
    """`account_descriptors` and `address_from_der_path` are one mapping.

    The purpose says which encoding a path means and both read it from the
    same table, so the pair a wallet exports has to describe the addresses
    this module answers for the same path: the change chain of the pair at
    an index is the `/1/index` address, and the receive chain the `/0/`
    one. The vectors above are published addresses, so this is the
    descriptor half of them.

    The account level is where the two split: `address_from_der_path`
    walks all five levels, while a descriptor names the first three in its
    key origin and derives the last two -- which is why the descriptors
    are built from the account path alone.
    """
    account, chain, index = der_path.rsplit("/", 2)
    pair = account_descriptors(mxkey, account)
    assert pair[int(chain)].address(int(index)) == address

    # and from the account xpub, which cannot say which master key it came
    # from, so the fingerprint the origin needs is handed in
    master_fingerprint = fingerprint(mxkey)
    from_account = account_descriptors(xpub, account, master_fingerprint)
    assert str(from_account[int(chain)]) == str(pair[int(chain)])


def test_purpose_mapping() -> None:
    """The mapping is the one BIP44, BIP49, BIP84 and BIP86 define."""
    assert SCRIPT_TYPE_FROM_PURPOSE == {
        44: "p2pkh",
        49: "p2wpkh-p2sh",
        84: "p2wpkh",
        86: "p2tr",
    }


def test_unknown_purpose() -> None:
    """Refuse purpose 48 bare, and let the script type override win."""
    # 48 is BIP48, multi-signature: a real purpose, and one whose script
    # type an account key does not determine
    err_msg = "unknown BIP44 purpose: an int of 6 bits not in "
    with pytest.raises(BTClibValueError, match=err_msg):
        address_from_der_path(_XPRV_ROOT, "m/48h/0h/0h/0/0")

    # the override says what the mapping cannot, and the composition it
    # names is the one it performs
    der_path = "m/48h/0h/0h/0/0"
    address = address_from_der_path(_XPRV_ROOT, der_path, "p2wpkh")
    # `b32.p2wpkh` takes a public key and no extended key (issue
    # btclib-org/btclib#1188)
    derived = bip32.pub_keyinfo_from_xkey(bip32.derive(_XPRV_ROOT, der_path))
    assert address == b32.p2wpkh(PubKeyData(*derived))

    # it overrides a known purpose too, and the p2wpkh of BIP84's path is
    # BIP84's address whichever way it is asked for
    assert (
        address_from_der_path(_ZPRV_ROOT, "m/84h/0h/0h/0/0", "p2wpkh")
        == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    )


def test_unknown_script_type() -> None:
    """Refuse p2wsh, and verify the alias and the table agree."""
    # the alias and the table say the same four encodings, which is what
    # lets one of them type the other
    assert get_args(BIP44ScriptType) == tuple(_ADDRESS_FROM_SCRIPT_TYPE)
    assert set(SCRIPT_TYPE_FROM_PURPOSE.values()) == set(get_args(BIP44ScriptType))

    # p2wsh is an encoding btclib has; it is not one a single derived key
    # determines, so it is not in the table. mypy rejects the call, the
    # Literal being the static half of this check; the runtime half is for
    # the caller who does not run mypy
    with pytest.raises(
        BTClibValueError,
        match=r"unknown script type: 'p2wsh' not in \(p2pkh, p2tr, p2wpkh, p2wpkh-p2sh\)",
    ):
        address_from_der_path(_XPRV_ROOT, "m/84h/0h/0h/0/0", "p2wsh")  # type: ignore[arg-type]


def test_coin_type() -> None:
    """Refuse a coin type off the key's network, and Litecoin's."""
    # a mainnet key with the testnet coin type, and the other way round
    err_msg = "coin type 1 is 'test', the extended key is 'main'"
    with pytest.raises(BTClibValueError, match=err_msg):
        address_from_der_path(_XPRV_ROOT, "m/44h/1h/0h/0/0")
    err_msg = "coin type 0 is 'main', the extended key is 'test'"
    with pytest.raises(BTClibValueError, match=err_msg):
        address_from_der_path(_UPRV_ROOT, "m/49h/0h/0h/0/0")

    # 2 is Litecoin: another chain, and no bitcoin address to give it
    with pytest.raises(
        BTClibValueError, match="unregistered BIP44 coin type: an int of 2 bits not in"
    ):
        address_from_der_path(_XPRV_ROOT, "m/44h/2h/0h/0/0")


@pytest.mark.parametrize(
    "der_path, err_msg",
    [
        ("m/84h/0h/0h/0", "invalid BIP44 path: 4 levels instead of 5"),
        ("m/84h/0h/0h/0/0/0", "invalid BIP44 path: 6 levels instead of 5"),
        ("m/84/0h/0h/0/0", "purpose, coin type and account must be hardened"),
        ("m/84h/0/0h/0/0", "purpose, coin type and account must be hardened"),
        ("m/84h/0h/0/0/0", "purpose, coin type and account must be hardened"),
        ("m/84h/0h/0h/0h/0", "change and address index must not be hardened"),
        ("m/84h/0h/0h/0/0h", "change and address index must not be hardened"),
    ],
)
def test_invalid_path(der_path: str, err_msg: str) -> None:
    """Refuse a BIP44 path of wrong depth or wrong hardening."""
    with pytest.raises(BTClibValueError, match=err_msg):
        address_from_der_path(_ZPRV_ROOT, der_path)


def test_key_depth() -> None:
    """Refuse a key whose depth or index disagrees with the path."""
    der_path = "m/84h/0h/0h/0/0"

    # the account xpub of another account: the depth says which index of
    # the path the key must be, and it is not that one
    xpub = bip32.xpub_from_xprv(bip32.derive(_ZPRV_ROOT, "m/84h/0h/1h"))
    err_msg = "key index an int of 32 bits at depth an int of 2 bits is not the path's 2147483648"
    with pytest.raises(BTClibValueError, match=err_msg):
        address_from_der_path(xpub, der_path)

    # a key deeper than the path itself has no tail left to walk, and the
    # bound is the path's own length: an account path is three levels
    xkey = bip32.derive(_ZPRV_ROOT, "m/84h/0h/0h/0/0/0")
    err_msg = "invalid key depth: an int of 3 bits is past the 5 levels of the path"
    with pytest.raises(BTClibValueError, match=err_msg):
        address_from_der_path(xkey, der_path)


def test_root_xpub() -> None:
    """A root xpub cannot walk a BIP44 path, and bip32 says so."""
    xpub = bip32.xpub_from_xprv(_ZPRV_ROOT)
    err_msg = "invalid hardened derivation from public key"
    with pytest.raises(BTClibValueError, match=err_msg):
        address_from_der_path(xpub, "m/84h/0h/0h/0/0")


# A Trezor's own replies, recorded by bitcoin-s: the account xpubs of one
# mnemonic and addresses of each. tests/_data/README.md pins the file. Its
# first line is a comment, so it is not JSON as it stands.
_TREZOR_MNEMONIC = (
    "stage boring net gather radar radio arrest eye ask risk girl country"
)
_TREZOR_PURPOSE = {"legacy": 44, "p2sh-segwit": 49, "segwit": 84}
_TREZOR_FILE = Path(__file__).parent / "_data" / "trezor-addresses.json"
_TREZOR_ACCOUNTS = json.loads(
    _TREZOR_FILE.read_text(encoding="ascii").split("\n", 1)[1]
)


def _without_version(xkey: str) -> tuple[Any, ...]:
    """Return the fields of an extended key but its version."""
    return dataclasses.astuple(bip32.BIP32KeyData.b58decode(xkey))[1:]


@pytest.mark.parametrize(
    "account",
    [pytest.param(a, id=f"{a['pathType']}-{a['account']}") for a in _TREZOR_ACCOUNTS],
)
def test_trezor_addresses(account: dict[str, Any]) -> None:
    """Reproduce a Trezor's addresses from the account xpub and the mnemonic.

    The file spells the keys of purposes 49 and 84 as SLIP132's ypub and
    zpub. The key derived here is an xpub, so the two are compared but for
    the version bytes.
    """
    purpose = _TREZOR_PURPOSE[account["pathType"]]
    root = mxprv_from_mnemonic(_TREZOR_MNEMONIC, "")
    account_path = f"m/{purpose}h/0h/{account['account']}h"
    derived = bip32.xpub_from_xprv(bip32.derive(root, account_path))
    assert account["xpub"][:4] == {44: "xpub", 49: "ypub", 84: "zpub"}[purpose]
    assert _without_version(derived) == _without_version(account["xpub"])

    assert len(account["addresses"]) == 6
    for entry in account["addresses"]:
        path = entry["path"].replace("'", "h")
        chain = {"External": 0, "Change": 1}[entry["chain"]]
        assert path == f"{account_path}/{chain}/{entry['addressIndex']}"
        assert address_from_der_path(account["xpub"], path) == entry["address"]
        assert address_from_der_path(root, path) == entry["address"]


def test_the_account_descriptor_pair() -> None:
    """One account, two chains, and one difference between them.

    BIP44 puts receiving addresses under `/0` and change under `/1`, and a
    wallet is both: what the pair says about the account -- the key origin,
    the account xpub, the wildcard, the script type the purpose means -- is
    the same on both sides, and the chain step is not. The addresses those
    descriptors describe are checked against `address_from_der_path` by
    `test_the_account_descriptors_reach_the_same_addresses`, on the
    published vectors.
    """
    receive, change = account_descriptors(_XPRV_ROOT, "m/84h/0h/0h")
    account_xpub = bip32.xpub_from_xprv(bip32.derive(_XPRV_ROOT, "m/84h/0h/0h"))
    master_fingerprint = fingerprint(_XPRV_ROOT).hex()

    for descriptor, chain in ((receive, 0), (change, 1)):
        assert isinstance(descriptor, WpkhDescriptor)
        assert descriptor.is_ranged
        assert descriptor.network == "mainnet"
        (key,) = descriptor.key_expressions
        assert key.xkey == account_xpub
        assert key.der_path == (chain,)
        assert key.wildcard == 0
        assert key.origin is not None
        assert key.origin.description == f"{master_fingerprint}/84h/0h/0h"
        assert str(descriptor) == (
            f"wpkh([{master_fingerprint}/84h/0h/0h]{account_xpub}/{chain}/*)"
        )

    assert receive.address(7) != change.address(7)
    # and each is a descriptor like any other: it writes itself back and
    # parses again to the same scripts
    for descriptor in (receive, change):
        assert parse(str(descriptor)).script_pub_keys(3) == descriptor.script_pub_keys(
            3
        )


def test_the_account_descriptors_of_each_purpose() -> None:
    """The purpose selects the fragment, as it selects the encoding.

    Four purposes, four shapes, and the table is checked against the
    purpose mapping: a fifth script type would be a purpose this cannot
    build, which is a refusal rather than a guess.
    """
    for purpose, expected in (
        (44, "pkh("),
        (49, "sh(wpkh("),
        (84, "wpkh("),
        (86, "tr("),
    ):
        receive, change = account_descriptors(_XPRV_ROOT, f"m/{purpose}h/0h/0h")
        assert str(receive).startswith(expected)
        assert str(change).startswith(expected)
    assert set(SCRIPT_TYPE_FROM_PURPOSE.values()) == set(get_args(BIP44ScriptType))

    # a purpose the mapping does not name is refused, and script_type is
    # the override -- BIP48 multisig, whose script type an account key does
    # not determine
    with pytest.raises(
        BTClibValueError, match="unknown BIP44 purpose: an int of 6 bits"
    ):
        account_descriptors(_XPRV_ROOT, "m/48h/0h/0h")
    overridden = account_descriptors(_XPRV_ROOT, "m/48h/0h/0h", None, "p2wpkh")[0]
    assert str(overridden).startswith("wpkh(")
    with pytest.raises(
        BTClibValueError,
        match=r"unknown script type: 'p2wsh' not in \(p2pkh, p2tr, p2wpkh, p2wpkh-p2sh\)",
    ):
        account_descriptors(_XPRV_ROOT, "m/48h/0h/0h", None, "p2wsh")  # type: ignore[arg-type]


def test_an_account_descriptor_needs_a_fingerprint_it_cannot_compute() -> None:
    """The origin names the *master* key, and only the master key says so.

    A key at depth three carries its own fingerprint and its parent's, and
    neither is the master's, so an account xpub has to be told. Where the
    key is the master one it is computed instead — and a value handed in
    beside it has to agree, neither being more likely to be right.
    """
    account_xpub = bip32.xpub_from_xprv(bip32.derive(_XPRV_ROOT, "m/84h/0h/0h"))
    with pytest.raises(BTClibValueError, match="no master fingerprint"):
        account_descriptors(account_xpub, "m/84h/0h/0h")

    master_fingerprint = fingerprint(_XPRV_ROOT)
    told = account_descriptors(account_xpub, "m/84h/0h/0h", master_fingerprint)
    computed = account_descriptors(_XPRV_ROOT, "m/84h/0h/0h")
    assert str(told[0]) == str(computed[0])
    # the same key with the fingerprint named too, which is what it is
    assert str(
        account_descriptors(_XPRV_ROOT, "m/84h/0h/0h", master_fingerprint)[0]
    ) == (str(computed[0]))
    with pytest.raises(BTClibValueError, match="is not the key's own"):
        account_descriptors(_XPRV_ROOT, "m/84h/0h/0h", "deadbeef")


def test_account_descriptors_validates_an_already_built_key_too() -> None:
    """The rule of btclib-org/btclib#684: an object is validated as a string is.

    A string went through `BIP32KeyData.b58decode`, which validates by
    default; an already-built `BIP32KeyData` was trusted as it stood.
    """
    good = bip32.BIP32KeyData.b58decode(_XPRV_ROOT)
    receive, _ = account_descriptors(good, "m/84h/0h/0h")
    assert str(receive) == str(account_descriptors(_XPRV_ROOT, "m/84h/0h/0h")[0])

    bad = replace_unchecked(bip32.BIP32KeyData.b58decode(_XPRV_ROOT), index=-1)
    err_msg = "invalid index: a negative int of 1 bits"
    with pytest.raises(BTClibValueError, match=err_msg):
        bad.assert_valid()
    with pytest.raises(BTClibValueError, match=err_msg):
        account_descriptors(bad, "m/84h/0h/0h")


def test_an_account_descriptor_holds_a_bip32_version() -> None:
    """A SLIP132 zpub says what the descriptor function already says.

    Same key, one spelling of it: the version bytes come back BIP32's, so
    the descriptor is one every implementation reads -- Bitcoin Core
    decodes those versions and no others -- and the script type is stated
    once, by `wpkh()`.
    """
    receive = account_descriptors(_ZPRV_ROOT, "m/84h/0h/0h")[0]
    (key,) = receive.key_expressions
    assert key.xkey.startswith("xpub")
    # the same account key, spelled with BIP32's own private version and
    # then neutered: 0488ade4 is xprv and 0488b21e the xpub it becomes
    assert key.xkey == bip32.xpub_from_xprv(
        bip32.derive(_ZPRV_ROOT, "m/84h/0h/0h", b"\x04\x88\xad\xe4")
    )
    # and the scripts are the ones the SLIP132 spelling describes
    assert receive.address(0) == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"


def test_an_account_path_is_three_hardened_levels() -> None:
    """What an account xpub stands for, and what the coin type has to say.

    The two levels below an account are the unhardened ones, so an account
    path is exactly as much as a wallet exports -- a fourth level is
    already a chain, and an unhardened account level would leave the level
    above it the last that needed a private key.
    """
    for der_path, err_msg in (
        ("m/84h/0h", "2 levels instead of 3"),
        ("m/84h/0h/0h/0", "4 levels instead of 3"),
        ("m/84h/0h/0", "must be hardened"),
        ("m/84/0h/0h", "must be hardened"),
    ):
        with pytest.raises(BTClibValueError, match=err_msg):
            account_descriptors(_XPRV_ROOT, der_path)

    # the coin type is a claim about the chain and the key is the chain
    with pytest.raises(
        BTClibValueError,
        match="coin type 1 is 'test', the extended key is 'main'",
    ):
        account_descriptors(_XPRV_ROOT, "m/84h/1h/0h")
    with pytest.raises(
        BTClibValueError, match="unregistered BIP44 coin type: an int of 2 bits"
    ):
        account_descriptors(_XPRV_ROOT, "m/84h/2h/0h")

    # a key below the account level has walked past the path
    deeper = bip32.derive(_XPRV_ROOT, "m/84h/0h/0h/0")
    with pytest.raises(BTClibValueError, match="past the 3 levels of the path"):
        account_descriptors(deeper, "m/84h/0h/0h")
    # and one at the account level has to be *that* account
    other = bip32.xpub_from_xprv(bip32.derive(_XPRV_ROOT, "m/84h/0h/1h"))
    with pytest.raises(
        BTClibValueError,
        match="key index an int of 32 bits at depth an int of 2 bits is not the path's 2147483648",
    ):
        account_descriptors(other, "m/84h/0h/0h", "deadbeef")


def test_wallet_policy_of_a_receive_change_pair_agrees_with_both() -> None:
    """`account_descriptors`' own pair produces BIP388's own `/**` shorthand.

    That pair -- a BIP44 account's receive and change descriptors,
    `.../0/*` and `.../1/*` -- is the shape most callers actually hold,
    and the one shape `wallet_policy(descriptor)` alone refuses
    (`test_wallet_policy_refuses_what_cannot_become_one` in
    bip32-descriptors' `tests/descriptors/descriptors_test.py` measures
    that).
    Given both, the policy answers the very scripts the two descriptors
    it was built from answer, at every index and on both branches.
    """
    xpub = "xpub6C7Mz3RXdDAhrx7ECcAg29du1qTQeFHwk1WEUz3JHCNUhZQNeGAdkUb19AZZheLWLqWL71ZEL5G93Uxpj7BXE5TxU3P9mnEaj8itk5V5n7Z"
    recv, chg = account_descriptors(xpub, "84h/0h/0h", master_fingerprint="6738736c")
    template, key_info = wallet_policy(recv, chg)
    assert template == "wpkh(@0/**)"
    for index in (0, 1, 9):
        for multipath_index, expected in ((0, recv), (1, chg)):
            resolved = wallet_policy_descriptor(template, key_info, multipath_index)
            assert resolved.script_pub_key(index) == expected.script_pub_key(index)
            address = wallet_policy_address(template, key_info, index, multipath_index)
            assert address == expected.address(index)


class _Chain:
    """A `HistoryReader` over one block of transactions, recording its reads.

    A transaction is listed where one of its outputs pays to a script asked
    for, or one of its inputs spends such an output, as the contract says.
    """

    def __init__(self) -> None:
        self.txs: list[Tx] = []
        self.reads: list[frozenset[bytes]] = []
        # called with the scripts of each read before it is answered, so
        # that a test can move the chain between two reads
        self.on_read: Callable[[frozenset[bytes]], None] | None = None
        self._payments = 0

    def pay(self, script_pub_key: ScriptPubKey) -> Tx:
        """Return a payment to the script from outside, put in the block."""
        self._payments += 1
        foreign = OutPoint(b"\xff" * 28 + self._payments.to_bytes(4, "big"), 0)
        tx = Tx(vin=[TxIn(foreign)], vout=[TxOut(10_000, script_pub_key)])
        self.txs.append(tx)
        return tx

    def spend(self, tx: Tx, script_pub_key: ScriptPubKey) -> Tx:
        """Return a spend of the first output of `tx` to the script."""
        spend = Tx(vin=[TxIn(OutPoint(tx.id, 0))], vout=[TxOut(9_000, script_pub_key)])
        self.txs.append(spend)
        return spend

    def _paid(self, tx_in: TxIn) -> bytes:
        return next(
            (
                tx.vout[tx_in.prev_out.vout].script_pub_key.script
                for tx in self.txs
                if tx.id == tx_in.prev_out.tx_id
            ),
            b"",
        )

    def get_history(
        self, scripts: Iterable[Octets | ScriptPubKey], start_height: int = 0
    ) -> ScriptHistory:
        """Answer as `HistoryReader` says, from the one block."""
        wanted = history_scripts(scripts)
        if self.on_read is not None:
            self.on_read(wanted)
        self.reads.append(wanted)
        block = BlockRef(1, b"\x01" * 32)
        txs = tuple(
            HistoryTx(tx, block)
            for tx in self.txs
            if any(tx_out.script_pub_key.script in wanted for tx_out in tx.vout)
            or any(self._paid(tx_in) in wanted for tx_in in tx.vin)
        )
        return ScriptHistory(BlockRef(min(start_height, 1), bytes(32)), block, txs)


def _account_xpub(account_path: str) -> str:
    """Return the account xpub of `_XPRV_ROOT` at the path."""
    return bip32.xpub_from_xprv(bip32.derive(_XPRV_ROOT, account_path))


_FINGERPRINT = fingerprint(_XPRV_ROOT)
# somebody else's script, which a spend from the account pays
_FOREIGN = ScriptPubKey(b"\x51")
# the account keys of purpose 84, the WIF of a key below them, and a test
# network root: the private keys a text handed to discovery may hold
_XPRV_84 = bip32.derive(_XPRV_ROOT, "m/84h/0h/0h")
_XPUB_84 = bip32.xpub_from_xprv(_XPRV_84)
_WIF_KEY = bip32.BIP32KeyData.b58decode(bip32.derive(_XPRV_84, "m/0/0")).key[1:]
_WIF = b58.wif_from_prv_key(_WIF_KEY)
_TPRV = bip32.rootxprv_from_seed(b"\x02" * 32, NETWORKS["testnet"].bip32_prv)
# the receive branch of that account, as text
_TEXT_84 = f"wpkh([{_FINGERPRINT.hex()}/84h/0h/0h]{_XPUB_84}/0/*)"


class _Text(str):
    """A str subclass, which a branch's text may be."""

    __slots__ = ()


def test_discover_account_reads_each_branch_to_its_gap_limit() -> None:
    """A branch is read until `gap_limit` indexes in a row have no history.

    Index 20 of the receive branch is 19 unused indexes past index 0, so a
    gap limit of 20 finds it; index 41 is 20 unused indexes past index 20,
    so it takes a gap limit of 21. The change branch is read too.
    """
    receive, change = account_descriptors(_XPRV_ROOT, "m/84h/0h/0h")
    chain = _Chain()
    for index in (0, 20, 41):
        chain.pay(receive.script_pub_key(index))
    change_payment = chain.pay(change.script_pub_key(3))

    use = discover_account((receive, change), chain)
    assert use is not None
    assert use.descriptors == (receive, change)
    assert use.used == ((0, 20), (3,))
    assert [entry.tx for entry in use.history.txs] == [*chain.txs[:2], change_payment]
    # the windows of the receive branch: 0 to 19, 20, then 21 to 40, and
    # the read of the four used scripts after the scan
    window_sizes = [len(read) for read in chain.reads]
    assert window_sizes[:3] == [20, 1, 20]
    assert window_sizes[-1] == 3

    wider = discover_account([receive, change], chain, gap_limit=21)
    assert wider is not None
    assert wider.used == ((0, 20, 41), (3,))


def test_discover_account_counts_a_payment_and_not_a_spend() -> None:
    """A position is used where a transaction pays it: a spend lists beside it.

    A spend from index 2 to a foreign script is in the history, and it adds
    no position: index 2 is used by the payment it spends.
    """
    receive, change = account_descriptors(_XPRV_ROOT, "m/86h/0h/0h")
    chain = _Chain()
    payment = chain.pay(receive.script_pub_key(2))
    spend = chain.spend(payment, _FOREIGN)
    use = discover_account([receive, change], chain, gap_limit=5)
    assert use is not None
    assert use.used == ((2,), ())
    assert [entry.tx for entry in use.history.txs] == [payment, spend]


def test_used_is_what_the_history_holds() -> None:
    """The chain moves between the scan and the last read: `used` follows it.

    The windows find indexes 1 and 4 paid. Where the payment to 4 leaves
    the chain before the last read, as a reorganization takes it out,
    `used` holds index 1 alone, as `history` does. Where both leave, the
    account is unused.
    """
    receive, change = account_descriptors(_XPRV_ROOT, "m/84h/0h/0h")
    paid = [receive.script_pub_key(index) for index in (1, 4)]
    last_read = frozenset(script.script for script in paid)

    chain = _Chain()
    kept, dropped = (chain.pay(script) for script in paid)

    def drop(wanted: frozenset[bytes]) -> None:
        if wanted == last_read:
            chain.txs.remove(dropped)

    chain.on_read = drop
    use = discover_account([receive, change], chain, gap_limit=4)
    assert use is not None
    assert use.used == ((1,), ())
    assert [entry.tx for entry in use.history.txs] == [kept]

    emptied = _Chain()
    for script in paid:
        emptied.pay(script)

    def drop_all(wanted: frozenset[bytes]) -> None:
        if wanted == last_read:
            emptied.txs.clear()

    emptied.on_read = drop_all
    assert discover_account([receive, change], emptied, gap_limit=4) is None


def test_the_scan_ends_at_the_last_index_of_a_branch() -> None:
    """A window never reaches past index 2**31 - 1, the last a branch has.

    Read through the helper: a scan reaching the top through the public
    functions would derive two billion scripts first.
    """
    assert _window_end([], 20) == 20
    assert _window_end([0, 5], 20) == 26
    assert _window_end([2**31 - 10], 20) == 2**31
    assert _window_end([2**31 - 1], 1) == 2**31
    assert _window_end([], 2**31) == 2**31


def test_an_unused_account_is_none() -> None:
    """With no position used there is nothing to read after the scan."""
    receive, change = account_descriptors(_XPRV_ROOT, "m/84h/0h/0h")
    chain = _Chain()
    chain.pay(_FOREIGN)
    assert discover_account([receive, change], chain, gap_limit=3) is None
    assert [len(read) for read in chain.reads] == [3, 3]


@pytest.mark.parametrize(
    "descriptors, error, match",
    [
        (None, BTClibTypeError, "invalid descriptors type: 'NoneType'"),
        ({0: "wpkh()"}, BTClibTypeError, "invalid descriptors type: 'dict'"),
        # an iterator of a type both CPython and PyPy name alike
        (map(str, ["wpkh()"]), BTClibTypeError, "invalid descriptors type: 'map'"),
        # a text, and its bytes, where the sequence of them belongs, empty
        # or not: a str is no sequence of branches, whatever its length
        (_TEXT_84, BTClibTypeError, "^invalid descriptors type: 'str'$"),
        (_TEXT_84.encode(), BTClibTypeError, "^invalid descriptors type: 'bytes'$"),
        ("", BTClibTypeError, "^invalid descriptors type: 'str'$"),
        (b"", BTClibTypeError, "^invalid descriptors type: 'bytes'$"),
        (
            [84, _TEXT_84],
            BTClibTypeError,
            "^descriptor 0: not a Descriptor or a str: 'int'$",
        ),
        (
            [_TEXT_84, 84],
            BTClibTypeError,
            "^descriptor 1: not a Descriptor or a str: 'int'$",
        ),
        ([], BTClibValueError, "no descriptor to discover"),
        ((), BTClibValueError, "no descriptor to discover"),
        # exactly a tuple or a list: a subclass or another sequence is refused
        (range(1), BTClibTypeError, "^invalid descriptors type: 'range'$"),
        (bytearray(b"w"), BTClibTypeError, "^invalid descriptors type: 'bytearray'$"),
        (
            type("_Branches", (list,), {})([_TEXT_84]),
            BTClibTypeError,
            "^invalid descriptors type: '_Branches'$",
        ),
        (
            [parse(f"wpkh({_XPUB_84}/0/7)"), _TEXT_84],
            BTClibValueError,
            "^descriptor 0: not a ranged descriptor$",
        ),
        (
            [_TEXT_84, parse(f"wpkh({_XPUB_84}/0/7)")],
            BTClibValueError,
            "^descriptor 1: not a ranged descriptor$",
        ),
        (
            [f"wpkh({_XPUB_84}/0/7)", _TEXT_84],
            BTClibValueError,
            "^descriptor 0: not a ranged descriptor$",
        ),
        (
            [_TEXT_84, f"wpkh({_XPUB_84}/0/7)"],
            BTClibValueError,
            "^descriptor 1: not a ranged descriptor$",
        ),
    ],
)
def test_discover_account_refuses_what_is_no_branch(
    descriptors: Any, error: type[Exception], match: str
) -> None:
    """The branches are ranged descriptors or their text, at least one."""
    with pytest.raises(error, match=match):
        discover_account(descriptors, _Chain())


@pytest.mark.parametrize(
    "der_path", ["m/44h/0h/0h", "m/49h/0h/0h", "m/84h/0h/0h", "m/86h/0h/0h"]
)
def test_discover_account_reads_a_text_as_the_descriptor_it_parses_to(
    der_path: str,
) -> None:
    """A text, with or without its checksum, and a `Descriptor` read alike.

    The same answer and the same reads, whichever form each branch takes.
    """
    receive, change = account_descriptors(_XPRV_ROOT, der_path)
    chain = _Chain()
    chain.pay(receive.script_pub_key(0))
    chain.pay(change.script_pub_key(3))
    expected = discover_account([receive, change], chain, gap_limit=4)
    assert expected is not None
    assert expected.used == ((0,), (3,))
    reads = list(chain.reads)
    forms: list[Sequence[Descriptor | str]] = [
        [str(receive), str(change)],
        (add_checksum(str(receive)), add_checksum(str(change))),
        [receive, str(change)],
    ]
    for branches in forms:
        chain.reads.clear()
        assert discover_account(branches, chain, gap_limit=4) == expected
        assert chain.reads == reads


def test_discover_account_parses_a_text_under_network() -> None:
    """A text is read under `network`; a `Descriptor` carries its own.

    The test networks share one extended-key version, so a tpub is
    testnet's or regtest's as `network` says, and a key of the other
    network type is refused.
    """
    receive, change = account_descriptors(_TPRV, "m/84h/1h/0h")
    chain = _Chain()
    chain.pay(receive.script_pub_key(1))
    expected = discover_account([receive, change], chain, gap_limit=2)
    assert expected is not None
    texts = [str(receive), str(change)]
    assert discover_account(texts, chain, gap_limit=2, network="testnet") == expected
    regtest = discover_account(texts, chain, gap_limit=2, network="regtest")
    assert regtest is not None
    assert regtest.used == expected.used
    assert [branch.network for branch in regtest.descriptors] == ["regtest"] * 2
    with pytest.raises(
        BTClibValueError, match="^descriptor 0: key 0: not a mainnet key: version$"
    ):
        discover_account(texts, chain, gap_limit=2)

    pair = account_descriptors(_XPRV_ROOT, "m/84h/0h/0h")
    assert discover_account(pair, _Chain(), gap_limit=2, network="testnet") is None
    with pytest.raises(
        BTClibValueError, match="^descriptor 1: key 0: not a testnet key: version$"
    ):
        discover_account([pair[0], str(pair[1])], _Chain(), network="testnet")


@pytest.mark.parametrize("network", list(NETWORKS))
def test_discover_account_reads_a_text_under_each_network(network: str) -> None:
    """A text read under `network` is the `Descriptor` parsed under it.

    The same answer and the same reads, and each branch of that network,
    on every network btclib names.
    """
    root, path = (
        (_XPRV_ROOT, "m/84h/0h/0h") if network == "mainnet" else (_TPRV, "m/84h/1h/0h")
    )
    texts = [str(branch) for branch in account_descriptors(root, path)]
    objects = [parse(text, network) for text in texts]
    chain = _Chain()
    chain.pay(objects[0].script_pub_key(1))
    expected = discover_account(objects, chain, gap_limit=2)
    assert expected is not None
    reads = list(chain.reads)
    chain.reads.clear()
    use = discover_account(texts, chain, gap_limit=2, network=network)
    assert use == expected
    assert chain.reads == reads
    assert [branch.network for branch in use.descriptors] == [network] * 2


# each private key the texts below hold, and the bytes of each
_SECRETS = [
    secret
    for key in (_XPRV_84, _XPRV_ROOT, _TPRV)
    for secret in (key, bip32.BIP32KeyData.b58decode(key).key[1:])
] + [_WIF, _WIF_KEY]
# an xprv a character off, which no checksum accepts
_DAMAGED = _XPRV_84[:40] + ("a" if _XPRV_84[40] != "a" else "b") + _XPRV_84[41:]
# a compressed key whose x is past the field's prime, so that no point has it
_NO_POINT = "02" + "ff" * 32
_PRIVATE = "a private key: pass the public descriptor"
_RECEIVE_84 = parse(_TEXT_84)
# each branch refused, by name, and the end of its refusal, after the
# position: most hold a private key, and those `parse` refuses are each
# of a class or a chain of its own
_REFUSED: list[tuple[str, str | bytes, str]] = [
    ("xprv", f"wpkh({_XPRV_84}/0/*)", _PRIVATE),
    ("hardened-xprv", f"wpkh({_XPRV_ROOT}/84h/0h/0h/0/*)", _PRIVATE),
    ("unranged-xprv", f"wpkh({_XPRV_84}/0/7)", _PRIVATE),
    ("xprv-in-a-leaf", f"tr({_XPUB_84}/0/*,pk({_XPRV_84}/1/*))", _PRIVATE),
    ("wif", add_checksum(f"wsh(multi(1,{_WIF},{_XPUB_84}/0/*))"), _PRIVATE),
    (
        "wif-in-a-musig-leaf",
        f"tr({_XPUB_84}/0/*,pk(musig({_WIF},{_XPUB_84}/0)))",
        _PRIVATE,
    ),
    (
        "wif-in-a-musig-internal-key",
        f"tr(musig({_WIF},{_XPUB_84}/0),pk({_XPUB_84}/1/*))",
        _PRIVATE,
    ),
    ("checksum", f"wpkh({_XPRV_84}/0/*)#aaaaaaaa", "invalid descriptor checksum"),
    (
        "damaged-xprv",
        f"wpkh({_DAMAGED}/0/*)",
        "key 0: derivation path after a key that cannot derive",
    ),
    (
        "multipath",
        f"wpkh({_XPRV_84}/<0;1>/*)",
        "multipath key expression: use multipath_descriptors first",
    ),
    ("tprv", f"wpkh({_TPRV}/0/*)", "key 0: not a mainnet key: version"),
    (
        "non-ascii",
        f"wpkh({_XPRV_84}/0/*\N{LATIN SMALL LETTER E WITH ACUTE})",
        "invalid descriptor character at position [0-9]+",
    ),
    (
        "unbalanced",
        f"wpkh({_XPRV_84}/0/*",
        r"'wpkh\(\.\.\.' is not a valid descriptor function",
    ),
    ("two-keys", f"wpkh({_WIF},{_XPRV_84})", "key 0: invalid key expression"),
    ("no-key", "wpkh()", "key 0: No key provided"),
    # `parse` chains a `_CoreFallbackError` to this refusal
    (
        "chained-by-parse",
        f"wsh(and_v(v:pk({_XPRV_84}/0/*),older(0)))",
        "A function is needed within P2WSH",
    ),
    # an `EccValueError`, no `BTClibValueError`
    (
        "no-point",
        f"wsh(multi(1,{_XPRV_84}/0/*,{_NO_POINT}))",
        "key 1: not a public key",
    ),
    # `parse` chains a `Base58Bech32ValueError` to this refusal
    (
        "address-checksum",
        "addr(bc1qcr8te4kr609gcawutmrza06j4xv80jy8z306fyu)",
        "invalid checksum",
    ),
    ("bytes", _XPRV_84.encode(), "not a Descriptor or a str: 'bytes'"),
]


def _parse_refusal(text: object) -> Exception | None:
    """Return `parse`'s refusal of a text, or None where it reads one."""
    if not isinstance(text, str):
        return None
    try:
        parse(text)
    except (BTClibValueError, EccValueError) as err:
        return err
    return None


@pytest.mark.parametrize(
    "descriptors, position, match",
    [
        pytest.param(descriptors, i, f"^descriptor {i}: {end}$", id=f"{name}-{i}")
        for name, text, end in _REFUSED
        for i, descriptors in enumerate(([text, _RECEIVE_84], [_RECEIVE_84, text]))
    ],
)
def test_discover_account_refuses_a_private_key_without_quoting_it(
    descriptors: list[Any], position: int, match: str
) -> None:
    """A branch is refused by its position, and no refusal quotes a key.

    `parse` would read an xprv or a WIF as its public key, and none is
    taken. A text `parse` refuses is refused as a new refusal of its
    class, its text after the position, with nothing of `parse`'s refusal
    chained. Nothing is read.
    """
    chain = _Chain()
    with pytest.raises(
        (BTClibTypeError, BTClibValueError, EccValueError), match=match
    ) as e:
        discover_account(descriptors, chain)
    assert not chain.reads
    assert e.value.__cause__ is None
    assert e.value.__context__ is None
    assert_secret_free(e.value, _SECRETS)
    refused = _parse_refusal(descriptors[position])
    if refused is None:
        kind = (
            BTClibValueError
            if isinstance(descriptors[position], str)
            else BTClibTypeError
        )
        assert type(e.value) is kind
    else:
        assert type(e.value) is type(refused)
        assert str(e.value) == f"descriptor {position}: {refused}"


@pytest.mark.parametrize(
    "descriptors, match",
    [
        (f"wpkh({_XPRV_84}/0/*)", "^invalid descriptors type: 'str'$"),
        (_Text(f"wpkh({_XPRV_84}/0/*)"), "^invalid descriptors type: '_Text'$"),
        (f"wpkh({_XPRV_84}/0/*)".encode(), "^invalid descriptors type: 'bytes'$"),
        (
            bytearray(f"wpkh({_XPRV_84}/0/*)".encode()),
            "^invalid descriptors type: 'bytearray'$",
        ),
    ],
)
def test_discover_account_refuses_a_bare_private_text_without_quoting_it(
    descriptors: Any, match: str
) -> None:
    """A text holding a key, where the sequence of branches belongs."""
    chain = _Chain()
    with pytest.raises(BTClibTypeError, match=match) as e:
        discover_account(descriptors, chain)
    assert not chain.reads
    assert e.value.__cause__ is None
    assert e.value.__context__ is None
    assert_secret_free(e.value, _SECRETS)


def _raise_a_key(*_args: object, **_kwargs: object) -> NoReturn:
    """Raise with a key, as a method of a caller's class may."""
    raise RuntimeError(_XPRV_84)  # pragma: no cover -- never runs


class _NameRaises(type):
    """A metaclass whose `__name__` raises with a key."""

    @override
    def __getattribute__(cls, name: str) -> Any:  # pragma: no cover -- never runs
        if name == "__name__":
            raise RuntimeError(_XPRV_84)
        return super().__getattribute__(name)


class _NameIsAKey(type):
    """A metaclass whose `__name__` answers a key."""

    @override
    def __getattribute__(cls, name: str) -> Any:  # pragma: no cover -- never runs
        return _XPRV_84 if name == "__name__" else super().__getattribute__(name)


# what a metaclass is asked for, about the class, by a check that asks
_TYPE_ATTRIBUTES = frozenset(
    (
        "__bases__",
        "__class__",
        "__dict__",
        "__module__",
        "__mro__",
        "__name__",
        "__qualname__",
        "__subclasses__",
    )
)


class _TypeAttributesRaise(type):
    """A metaclass whose class attributes, `__mro__` first, raise with a key."""

    @override
    def __getattribute__(cls, name: str) -> Any:  # pragma: no cover -- never runs
        if name in _TYPE_ATTRIBUTES:
            raise RuntimeError(_XPRV_84)
        return super().__getattribute__(name)


class _ClaimsDescriptorOrder(type):
    """A metaclass whose `__mro__` claims `Descriptor`."""

    @override
    def __getattribute__(cls, name: str) -> Any:  # pragma: no cover -- never runs
        if name == "__mro__":
            return (cls, Descriptor, object)
        return super().__getattribute__(name)


class _HashRaises(type):
    """A metaclass whose `__hash__` raises with a key."""

    @override
    def __hash__(cls) -> int:
        raise RuntimeError(_XPRV_84)  # pragma: no cover -- never runs


class _EqualsAll(type):
    """A metaclass equal to every type, hashed as `type` hashes a class."""

    __hash__ = type.__hash__

    @override
    def __eq__(cls, other: object) -> bool:
        return True  # pragma: no cover -- never runs


class _ForgesDescriptor(_EqualsAll):
    """A metaclass equal to every type, hashed as a `Descriptor` class is.

    An abstract class's check finds a class it has met by its hash, then
    compares: this one would be taken for `WpkhDescriptor`.
    """

    @override
    def __hash__(cls) -> int:
        return hash(type(_RECEIVE_84))  # pragma: no cover -- never runs


class _EqualsAllNameRaises(_EqualsAll, _NameRaises):
    """A metaclass equal to every type, whose `__name__` raises."""


class _EqualsAllNameIsAKey(_EqualsAll, _NameIsAKey):
    """A metaclass equal to every type, whose `__name__` answers a key."""


class _ClassLie:
    """An object whose `__class__` raises with a key."""

    __class__ = property(_raise_a_key)


def _claim_str(_self: object) -> type:
    """Answer str, as the `__class__` of an object claiming to be one."""
    return str  # pragma: no cover -- never runs


class _ClaimsStr:
    """An object whose `__class__` claims str."""

    __class__ = property(_claim_str)


class _Twice(list[str]):
    """A list that shows one branch when walked first, and another after."""

    walks = 0

    @override
    def __iter__(self) -> Iterator[str]:  # pragma: no cover -- never runs
        type(self).walks += 1
        return iter([_TEXT_84 if type(self).walks == 1 else _PRIVATE_TEXT])

    @override
    def __len__(self) -> int:
        return 0  # pragma: no cover -- never runs


class _Shown(str):
    """A text holding a key, whose `partition` shows a public one."""

    __slots__ = ()

    @override
    def partition(self, sep: str, /) -> tuple[str, str, str]:
        return _TEXT_84.partition(sep)  # pragma: no cover -- never runs


# the change branch of that account, as text
_CHANGE_84 = _TEXT_84.replace("/0/*", "/1/*")


class _Switched(str):
    """A text whose `partition` shows another one past its checksum."""

    __slots__ = ()

    @override
    def partition(self, sep: str, /) -> tuple[str, str, str]:
        return _CHANGE_84, "#", checksum(_TEXT_84)  # pragma: no cover -- never runs


class _Branch(StrEnum):
    """A branch's text as a `StrEnum` member."""

    RECEIVE = _TEXT_84


class _Network(StrEnum):
    """A network's name as a `StrEnum` member."""

    MAINNET = "mainnet"


_PRIVATE_TEXT = f"wpkh({_XPRV_84}/0/*)"
# a class named by a key, as `_quoted` describes a name past its length
_KEY_NAMED = f"a value of {len(_XPRV_84)} characters"


def _refusal(call: Callable[[], object]) -> BaseException:
    """Return what `call` raised, failing where it returns.

    The test asserts on what is returned, so that a refusal of the wrong
    kind fails an assertion: left to propagate, pytest's report would
    read the caller's class, whose `__name__` may raise in turn.
    """
    try:
        call()
    except BaseException as err:  # noqa: BLE001
        return err
    pytest.fail("no refusal")  # pragma: no cover -- every call here refuses


# where a value is handed: as the branches, as branch 0 or 1, as network
_PLACES = ["bare", "item-0", "item-1", "network"]


def _assert_refused(build: Callable[[], Any], place: str, shown: str) -> None:
    """Assert what `build` returns is refused where `place` says, by its type.

    The refusal names the type as `shown`, holds no key anywhere, chains
    nothing where no exception is being handled, and comes before the
    chain is read. The value is built here, and is no argument: pytest's
    report of a failure would show it, and read its type's name.
    """
    value = build()
    chain = _Chain()
    item = "not a Descriptor or a str:"
    calls: dict[str, tuple[Callable[[], object], str]] = {
        "bare": (
            lambda: discover_account(value, chain),
            f"invalid descriptors type: {shown}",
        ),
        "item-0": (
            lambda: discover_account([value, _RECEIVE_84], chain),
            f"descriptor 0: {item} {shown}",
        ),
        "item-1": (
            lambda: discover_account((_RECEIVE_84, value), chain),
            f"descriptor 1: {item} {shown}",
        ),
        "network": (
            lambda: discover_account([_RECEIVE_84], chain, network=value),
            f"invalid network type: {shown}",
        ),
    }
    call, expected = calls[place]
    refusal = _refusal(call)
    assert type(refusal) is BTClibTypeError
    assert str(refusal) == expected
    assert not chain.reads
    assert refusal.__cause__ is None
    assert refusal.__context__ is None
    assert_secret_free(refusal, _SECRETS)


def _hostile(method: str) -> Callable[[], object]:
    """Return what builds a text whose `method` raises with a key."""
    return lambda: type("_Hostile", (str,), {method: _raise_a_key})(_PRIVATE_TEXT)


_HOSTILE_METHODS = [
    "__add__",
    "__contains__",
    "__eq__",
    "__format__",
    "__getitem__",
    "__hash__",
    "__iter__",
    "__len__",
    "__radd__",
    "__repr__",
    "__str__",
    "encode",
    "isascii",
    "partition",
    "split",
    "startswith",
    "strip",
]

_SHAPES = [
    *[pytest.param(_hostile(m), "'_Hostile'", id=m) for m in _HOSTILE_METHODS],
    pytest.param(lambda: _Text(_TEXT_84), "'_Text'", id="plain-subclass"),
    pytest.param(lambda: _Shown(_PRIVATE_TEXT), "'_Shown'", id="shows-public"),
    pytest.param(
        lambda: _Switched(add_checksum(_TEXT_84)), "'_Switched'", id="switches"
    ),
    pytest.param(lambda: _Branch.RECEIVE, "'_Branch'", id="str-enum-text"),
    pytest.param(lambda: _Network.MAINNET, "'_Network'", id="str-enum-network"),
    pytest.param(
        lambda: type(_XPRV_84, (str,), {})(_PRIVATE_TEXT), _KEY_NAMED, id="key-named"
    ),
    pytest.param(type(_XPRV_84, (), {}), _KEY_NAMED, id="key-named-object"),
    pytest.param(
        lambda: _NameRaises("_Named", (str,), {})(_PRIVATE_TEXT),
        "'_Named'",
        id="name-raises",
    ),
    pytest.param(
        lambda: _NameIsAKey("_Named", (str,), {})(_PRIVATE_TEXT),
        "'_Named'",
        id="name-is-a-key",
    ),
    pytest.param(
        lambda: _TypeAttributesRaise("_Asked", (str,), {})(_PRIVATE_TEXT),
        "'_Asked'",
        id="type-attributes-raise",
    ),
    pytest.param(
        _TypeAttributesRaise("_Asked", (), {}),
        "'_Asked'",
        id="type-attributes-raise-object",
    ),
    pytest.param(
        lambda: _ClaimsDescriptorOrder("_Claims", (str,), {})(_PRIVATE_TEXT),
        "'_Claims'",
        id="claims-descriptor-order",
    ),
    pytest.param(
        lambda: _HashRaises("_Hashed", (str,), {})(_PRIVATE_TEXT),
        "'_Hashed'",
        id="hash-raises",
    ),
    pytest.param(
        lambda: _EqualsAllNameRaises("_Equal", (str,), {})(_PRIVATE_TEXT),
        "'_Equal'",
        id="equals-all-name-raises",
    ),
    pytest.param(
        lambda: _EqualsAllNameIsAKey("_Equal", (str,), {})(_PRIVATE_TEXT),
        "'_Equal'",
        id="equals-all-name-is-a-key",
    ),
    pytest.param(
        _EqualsAllNameRaises("_Equal", (), {}), "'_Equal'", id="equals-all-object"
    ),
    pytest.param(
        lambda: _ForgesDescriptor("_Forged", (str,), {})(_PRIVATE_TEXT),
        "'_Forged'",
        id="forges-a-descriptor",
    ),
    pytest.param(
        lambda: type("_ClassRaises", (str,), {"__class__": property(_raise_a_key)})(
            _PRIVATE_TEXT
        ),
        "'_ClassRaises'",
        id="class-raises",
    ),
    pytest.param(_ClassLie, "'_ClassLie'", id="class-raises-object"),
    pytest.param(_ClaimsStr, "'_ClaimsStr'", id="claims-str"),
    pytest.param(lambda: _Twice([_TEXT_84]), "'_Twice'", id="walks-twice"),
    pytest.param(
        lambda: _NameRaises("_Named", (list,), {})([_PRIVATE_TEXT]),
        "'_Named'",
        id="list-name-raises",
    ),
    pytest.param(
        lambda: _HashRaises("_Hashed", (tuple,), {})((_PRIVATE_TEXT,)),
        "'_Hashed'",
        id="tuple-hash-raises",
    ),
]


@pytest.mark.parametrize("place", _PLACES)
@pytest.mark.parametrize("build, shown", _SHAPES)
def test_discover_account_refuses_a_value_of_another_type(
    build: Callable[[], Any], shown: str, place: str
) -> None:
    """A value that is not exactly a str, a tuple or a list is refused.

    Where the branches belong, as a branch and as the network: a str
    subclass, a `StrEnum` member, a list or tuple subclass and an object
    claiming str through `__class__` alike. No method of the value or of
    its metaclass runs: each above raises with a key, or answers one, or
    shows another text, and none of these reaches the refusal.
    """
    _assert_refused(build, place, shown)


class _ForgesWpkh(type):
    """A metaclass hashed as `WpkhDescriptor`, whose `==` raises once armed."""

    armed = False

    @override
    def __hash__(cls) -> int:
        return hash(type(_RECEIVE_84))

    @override
    def __eq__(cls, other: object) -> bool:  # pragma: no cover -- on a hash clash
        if _ForgesWpkh.armed:
            raise RuntimeError(_XPRV_84)
        return cls is other


def test_discover_account_runs_no_eq_of_a_class_descriptor_has_met() -> None:
    """A class `Descriptor` has met, its hash forged, is never compared.

    An abstract class's check looks a type up among those it has met by
    hash and then `==`: once `Descriptor` has refused a class whose
    metaclass hashes it as `WpkhDescriptor`, checking a value `parse`
    built would run that metaclass's `__eq__`. A branch is told by its
    type's order instead, a text and a `Descriptor` alike.
    """
    foreign = _ForgesWpkh("_Foreign", (), {})
    # what `Descriptor` has met is the interpreter's: a class it took, kept
    # by an earlier test, would be found before the one it refused
    descriptor = cast("Any", Descriptor)
    descriptor._abc_caches_clear()
    try:
        # `Descriptor` meets the class, and keeps it among those it refused
        assert not issubclass(foreign, Descriptor)
        _ForgesWpkh.armed = True
        for branch in (_TEXT_84, _RECEIVE_84):
            chain = _Chain()
            chain.pay(_RECEIVE_84.script_pub_key(0))
            use = discover_account([branch], chain, gap_limit=1)
            assert use is not None
            assert use.used == ((0,),)
    finally:
        _ForgesWpkh.armed = False
        descriptor._abc_caches_clear()


@pytest.mark.parametrize(
    "text", ["wpkh()", f"wsh(and_v(v:pk({_XPUB_84}/0/*),older(0)))"]
)
def test_discover_account_keeps_the_exception_its_caller_handles(text: str) -> None:
    """The exception a caller handles stays the context of a refusal.

    Python chains that exception, as to any raised there, and it is the
    caller's own object: what the refusal leaves out is `parse`'s refusal,
    which `parse` itself chains to some.
    """
    handled = RuntimeError("the caller's own")
    try:
        raise handled
    except RuntimeError:
        refusal = _refusal(lambda: discover_account([text], _Chain()))
    assert type(refusal) is BTClibValueError
    assert str(refusal).startswith("descriptor 0: ")
    assert refusal.__cause__ is None
    assert refusal.__context__ is handled
    assert handled.__context__ is None


def test_discover_account_takes_the_str_of_a_str_enum() -> None:
    """A `StrEnum` member's `str()` is the exact str a branch or network is."""
    chain = _Chain()
    chain.pay(_RECEIVE_84.script_pub_key(0))
    expected = discover_account([_RECEIVE_84], chain, gap_limit=1)
    assert expected is not None
    use = discover_account(
        [str(_Branch.RECEIVE)], chain, gap_limit=1, network=str(_Network.MAINNET)
    )
    assert use == expected


# the classes `_LateMro` leaves str out of the order of, by id
_LEFT_OUT: set[int] = set()


class _LateMro(type):
    """A metaclass that leaves str out of a class's order once told to.

    Told only after the class has made its instances: on PyPy a class
    without str in its order takes no argument.
    """

    @override
    def mro(cls) -> list[type]:
        return [cls, object] if id(cls) in _LEFT_OUT else type.mro(cls)

    @property
    @override
    def __name__(cls) -> str:  # type: ignore[override]
        raise RuntimeError(_XPRV_84)


class _LeftOutText(str, metaclass=_LateMro):
    """A str whose methods raise, str left out of its order below."""

    __slots__ = ()
    __str__ = __repr__ = __len__ = __format__ = __iter__ = _raise_a_key
    __add__ = __radd__ = __getitem__ = _raise_a_key


# a name a class is given, and a text
_LEFT_OUT_NAME = _LeftOutText("_Renamed")
_LEFT_OUT_PRIVATE = _LeftOutText(_PRIVATE_TEXT)
# assigning the bases asks `mro` again: str leaves _LeftOutText's order
_LEFT_OUT.add(id(_LeftOutText))
_LeftOutText.__bases__ = (str,)

_PYPY = platform.python_implementation() == "PyPy"


def _renamed(name: str) -> type:
    """Return a class whose `__name__` is assigned `name`."""
    renamed = type("_Original", (), {})
    renamed.__name__ = name
    return renamed


@pytest.mark.parametrize("place", _PLACES)
@pytest.mark.parametrize(
    "build, shown",
    [
        pytest.param(_renamed(_LEFT_OUT_NAME), "'_Renamed'", id="named"),
        pytest.param(lambda: _LEFT_OUT_PRIVATE, "'_LeftOutText'", id="text"),
    ],
)
def test_discover_account_names_a_type_left_out_of_str(
    build: Callable[[], Any], shown: str, place: str
) -> None:
    """A class named by a str whose class left str out of its order.

    The refusal names it all the same: neither the metaclass's `__name__`
    nor a method of the name runs. A text whose class left str out is
    refused as any other type.
    """
    _assert_refused(build, place, shown)


@pytest.mark.skipif(_PYPY, reason="PyPy keeps a str copied from a class's name")
def test_a_name_left_out_of_str_is_one_str_add_refuses() -> None:
    """The control of the test above, where CPython keeps the name.

    Once str has left its class's order, `isinstance` denies the name and
    the text are str, and `str.__add__` refuses them: `"".join` is what
    copies the name.
    """
    stored = vars(type)["__name__"].__get__(_renamed(_LEFT_OUT_NAME), type)
    assert type(stored) is _LeftOutText
    # objects to mypy, which would take a `_LeftOutText` for a str
    values: tuple[object, ...] = (stored, _LEFT_OUT_PRIVATE)
    for value in values:
        assert not isinstance(value, str)
        with pytest.raises(TypeError, match="^descriptor '__add__' requires"):
            str.__add__(cast("str", value), "")
    with pytest.raises(RuntimeError):
        _ = type(stored).__name__
    copied = "".join((stored,))  # noqa: FLY002
    assert type(copied) is str
    assert copied == "_Renamed"


class _NominalStr(type):
    """A metaclass whose classes claim str's order without its storage."""

    @override
    def mro(cls) -> list[type]:
        return [cls, str, object]


def _nominal_str() -> object | None:
    """Return a value of a class claiming str's order, named by a key.

    None where the interpreter refuses to build the class, as CPython
    does: PyPy builds it.
    """
    try:
        nominal = cast("type[object]", _NominalStr("_Nominal", (), {}))
    except TypeError:
        return None
    nominal.__name__ = _XPRV_84  # pragma: no cover -- PyPy builds the class
    return object.__new__(nominal)  # pragma: no cover -- PyPy builds the class


@pytest.mark.parametrize("place", _PLACES)
def test_discover_account_refuses_a_class_claiming_str_s_order(place: str) -> None:
    """A value whose class claims str's order is refused by its type.

    Its type is not str, whatever `isinstance` answers for it on PyPy.
    """
    if _nominal_str() is None:
        assert not _PYPY
        return
    _assert_refused(_nominal_str, place, _KEY_NAMED)  # pragma: no cover -- PyPy


@pytest.mark.parametrize("tail", ["/*h", "/0h/*"])
def test_discover_account_refuses_a_branch_as_its_scan_refuses_it(tail: str) -> None:
    """A branch that fails while it is scanned names no position.

    A hardened step after an xpub parses, and the scan refuses it once
    the branch before it has been read, text and `Descriptor` alike.
    """
    text = f"wpkh({_XPUB_84}{tail})"
    for branch in (text, parse(text)):
        chain = _Chain()
        with pytest.raises(
            BTClibValueError, match="^invalid hardened derivation from public key$"
        ):
            discover_account([_RECEIVE_84, branch], chain, gap_limit=2)
        assert chain.reads


def test_discover_account_refuses_a_reader_and_a_limit() -> None:
    """A reader with no `get_history`, a gap limit that is no count, no network.

    The network is checked where every branch is a `Descriptor` too.
    """
    pair = account_descriptors(_XPRV_ROOT, "m/84h/0h/0h")
    with pytest.raises(BTClibValueError, match="^unknown network: 'nonet'"):
        discover_account(pair, _Chain(), network="nonet")
    with pytest.raises(BTClibTypeError, match="^invalid network type: 'float'$"):
        discover_account(pair, _Chain(), network=1.5)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="^invalid network type: 'NoneType'$"):
        discover_account(pair, _Chain(), network=None)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="not a HistoryReader: object"):
        discover_account(pair, object())  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid gap_limit type: bool"):
        discover_account(pair, _Chain(), gap_limit=True)
    with pytest.raises(
        BTClibValueError, match="invalid gap_limit: an int of 0 bits is below 1"
    ):
        discover_account(pair, _Chain(), gap_limit=0)
    with pytest.raises(BTClibValueError, match="is above the 2147483648 indexes"):
        discover_account(pair, _Chain(), gap_limit=2**31 + 1)


def test_discover_accounts_finds_an_account_past_an_unused_one() -> None:
    """Account 1 used under one purpose, account 0 empty under it.

    BIP44 stops at the first unused account, which is `account_gap`'s
    default: under purpose 86 it reads account 0 alone and misses account
    1. An `account_gap` of 2 finds it. Under purpose 84 account 0 is used,
    so account 1 is read, and account 2 too where the gap is 2.
    """
    xpubs = {
        84: [_account_xpub(f"m/84h/0h/{account}h") for account in range(3)],
        86: [
            _account_xpub("m/86h/0h/0h"),
            _account_xpub("m/86h/0h/1h"),
            _account_xpub("m/86h/0h/2h"),
            _account_xpub("m/86h/0h/3h"),
        ],
    }
    chain = _Chain()
    receive_84, _ = account_descriptors(_XPRV_ROOT, "m/84h/0h/0h")
    chain.pay(receive_84.script_pub_key(0))
    _, change_86 = account_descriptors(_XPRV_ROOT, "m/86h/0h/1h")
    chain.pay(change_86.script_pub_key(4))

    found = discover_accounts(xpubs, chain, _FINGERPRINT, gap_limit=5)
    assert list(found.accounts) == [(84, 0)]
    assert found.accounts[84, 0].used == ((0,), ())
    assert found.cut_short == ()

    found = discover_accounts(xpubs, chain, _FINGERPRINT, account_gap=2, gap_limit=5)
    assert list(found.accounts) == [(84, 0), (86, 1)]
    assert found.accounts[86, 1].used == ((), (4,))
    assert found.accounts[86, 1].descriptors == account_descriptors(
        xpubs[86][1], "m/86h/0h/1h", _FINGERPRINT
    )


def test_discover_accounts_cuts_short_a_purpose_whose_xpubs_end_first() -> None:
    """A purpose whose every xpub is used keeps its accounts, and is cut short.

    Purpose 84 is that purpose. An account after its xpubs may be used,
    so the answer says so, and purpose 86 is read after it. Under 86
    account 0 is used and account 1 is not: that ends the default gap of
    1, and not a gap of 2.
    """
    xpubs = {
        84: [_account_xpub(f"m/84h/0h/{account}h") for account in range(2)],
        86: [_account_xpub(f"m/86h/0h/{account}h") for account in range(2)],
    }
    chain = _Chain()
    for der_path in ("m/84h/0h/0h", "m/84h/0h/1h", "m/86h/0h/0h"):
        receive, _ = account_descriptors(_XPRV_ROOT, der_path)
        chain.pay(receive.script_pub_key(0))

    found = discover_accounts(xpubs, chain, _FINGERPRINT, gap_limit=2)
    assert list(found.accounts) == [(84, 0), (84, 1), (86, 0)]
    assert all(use.used == ((0,), ()) for use in found.accounts.values())
    assert found.cut_short == (84,)

    found = discover_accounts(xpubs, chain, _FINGERPRINT, account_gap=2, gap_limit=2)
    assert list(found.accounts) == [(84, 0), (84, 1), (86, 0)]
    assert found.cut_short == (84, 86)


def test_discover_accounts_reads_a_test_network_key_under_coin_type_1() -> None:
    """The coin type is the one the key's network registers."""
    tprv = bip32.rootxprv_from_seed(b"\x02" * 32, NETWORKS["testnet"].bip32_prv)
    tpubs = [
        bip32.xpub_from_xprv(bip32.derive(tprv, f"m/84h/1h/{account}h"))
        for account in range(2)
    ]
    chain = _Chain()
    receive, _ = account_descriptors(tprv, "m/84h/1h/0h")
    chain.pay(receive.script_pub_key(1))
    found = discover_accounts({84: tpubs}, chain, fingerprint(tprv), gap_limit=2)
    assert list(found.accounts) == [(84, 0)]
    assert found.accounts[84, 0].descriptors[0] == receive


@pytest.mark.parametrize(
    "account_xpubs, error, match",
    [
        ([], BTClibTypeError, "invalid account_xpubs type: list"),
        ({}, BTClibValueError, "no purpose to discover"),
        ({"84": ["x"]}, BTClibTypeError, "invalid purpose type: str"),
        (
            {84: _account_xpub("m/84h/0h/0h")},
            BTClibTypeError,
            "purpose 84: invalid xpubs type: str",
        ),
        ({84: []}, BTClibValueError, "purpose 84: no account xpub"),
        (
            {
                84: [
                    _account_xpub("m/84h/0h/0h"),
                    bip32.derive(_XPRV_ROOT, "m/84h/0h/1h"),
                ]
            },
            BTClibValueError,
            "purpose 84, account 1: an extended private key: pass its xpub",
        ),
        (
            {84: [_account_xpub("m/84h/0h/1h")]},
            BTClibValueError,
            "key index an int of 32 bits at depth an int of 2 bits is not the path's 2147483648",
        ),
        (
            {84: [bip32.xpub_from_xprv(_XPRV_ROOT)]},
            BTClibValueError,
            "invalid hardened derivation from public key",
        ),
        (
            {48: [_account_xpub("m/48h/0h/0h")]},
            BTClibValueError,
            "purpose: an int of 6 bits",
        ),
    ],
)
def test_discover_accounts_checks_every_argument_before_reading(
    account_xpubs: Any, error: type[Exception], match: str
) -> None:
    """A refusal comes before the reader is asked anything."""
    chain = _Chain()
    with pytest.raises(error, match=match):
        discover_accounts(account_xpubs, chain, _FINGERPRINT)
    assert not chain.reads


def test_discover_accounts_refuses_a_reader_and_the_limits() -> None:
    """The reader and both limits are checked as `discover_account` checks."""
    xpubs = {84: [_account_xpub("m/84h/0h/0h")]}
    chain = _Chain()
    with pytest.raises(BTClibTypeError, match="not a HistoryReader: NoneType"):
        discover_accounts(xpubs, None, _FINGERPRINT)  # type: ignore[arg-type]
    with pytest.raises(
        BTClibValueError, match="invalid account_gap: an int of 0 bits is below 1"
    ):
        discover_accounts(xpubs, chain, _FINGERPRINT, account_gap=0)
    with pytest.raises(BTClibTypeError, match="invalid gap_limit type: float"):
        discover_accounts(xpubs, chain, _FINGERPRINT, gap_limit=1.5)  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError, match="is above the 2147483648 indexes"):
        discover_accounts(xpubs, chain, _FINGERPRINT, gap_limit=2**31 + 1)
    with pytest.raises(BTClibValueError, match="instead of 4"):
        discover_accounts(xpubs, chain, "00")
    assert not chain.reads


def test_a_fetch_error_of_the_callers_reader_is_refused_by_its_class() -> None:
    """The reader is the caller's code, so its text is not relayed (issue #935).

    The first read, of a window, and the last, of every position found,
    are refused in turn.
    """
    pair = account_descriptors(_XPRV_ROOT, "m/84h/0h/0h")
    chain = _Chain()
    chain.pay(pair[0].script_pub_key(0))
    assert discover_account(pair, chain, gap_limit=2) is not None
    for refused in (0, len(chain.reads) - 1):
        chain.reads.clear()

        def refuse(_scripts: frozenset[bytes], refused: int = refused) -> None:
            if len(chain.reads) == refused:
                raise FetchError(f"no history for {HEX}")

        chain.on_read = refuse
        err_msg = "^get_history: no usable answer from the server: FetchError$"
        with pytest.raises(FetchError, match=err_msg) as e:
            discover_account(pair, chain, gap_limit=2)
        assert e.value.__cause__ is None
        assert e.value.__context__ is None
        assert_secret_free(e.value, SPELLINGS)


def test_an_account_use_is_a_value() -> None:
    """Two scans of one chain answer equal values."""
    pair = account_descriptors(_XPRV_ROOT, "m/84h/0h/0h")
    chain = _Chain()
    chain.pay(pair[1].script_pub_key(0))
    first = discover_account(pair, chain, gap_limit=2)
    assert first is not None
    assert first == discover_account(pair, chain, gap_limit=2)
    assert isinstance(first.descriptors[0], Descriptor)
