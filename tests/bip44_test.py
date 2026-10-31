# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib_wallet.bip44` module.

`account_descriptors` is read against the same vectors as
`address_from_der_path`: it answers with the receive and change
descriptors of an account and reads the purpose off the same table, so
the addresses it describes have to be the addresses the other derives.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any, get_args

import pytest
from btclib import b32
from btclib.exceptions import BTClibValueError
from btclib.key import PubKeyData

from btclib_wallet.bip32 import bip32, fingerprint
from btclib_wallet.bip44 import (
    _ADDRESS_FROM_SCRIPT_TYPE,
    SCRIPT_TYPE_FROM_PURPOSE,
    BIP44ScriptType,
    account_descriptors,
    address_from_der_path,
)
from btclib_wallet.descriptors import (
    WpkhDescriptor,
    parse,
    wallet_policy,
    wallet_policy_address,
    wallet_policy_descriptor,
)
from btclib_wallet.mnemonic.bip39 import mxprv_from_mnemonic
from tests import replace_unchecked

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
    err_msg = "unknown BIP44 purpose: 48 not in "
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
    with pytest.raises(BTClibValueError, match="unknown script type: p2wsh not in "):
        address_from_der_path(_XPRV_ROOT, "m/84h/0h/0h/0/0", "p2wsh")  # type: ignore[arg-type]


def test_coin_type() -> None:
    """Refuse a coin type off the key's network, and Litecoin's."""
    # a mainnet key with the testnet coin type, and the other way round
    err_msg = "coin type 1 is test, the extended key is main"
    with pytest.raises(BTClibValueError, match=err_msg):
        address_from_der_path(_XPRV_ROOT, "m/44h/1h/0h/0/0")
    err_msg = "coin type 0 is main, the extended key is test"
    with pytest.raises(BTClibValueError, match=err_msg):
        address_from_der_path(_UPRV_ROOT, "m/49h/0h/0h/0/0")

    # 2 is Litecoin: another chain, and no bitcoin address to give it
    with pytest.raises(
        BTClibValueError, match="unregistered BIP44 coin type: 2 not in"
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
    err_msg = "key index 1h at depth 3 is not the path's 0h"
    with pytest.raises(BTClibValueError, match=err_msg):
        address_from_der_path(xpub, der_path)

    # a key deeper than the path itself has no tail left to walk, and the
    # bound is the path's own length: an account path is three levels
    xkey = bip32.derive(_ZPRV_ROOT, "m/84h/0h/0h/0/0/0")
    err_msg = "invalid key depth: 6 is past the 5 levels of the path"
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
    with pytest.raises(BTClibValueError, match="unknown BIP44 purpose: 48"):
        account_descriptors(_XPRV_ROOT, "m/48h/0h/0h")
    overridden = account_descriptors(_XPRV_ROOT, "m/48h/0h/0h", None, "p2wpkh")[0]
    assert str(overridden).startswith("wpkh(")
    with pytest.raises(BTClibValueError, match="unknown script type: p2wsh"):
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
    err_msg = "invalid index: -1"
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
    with pytest.raises(BTClibValueError, match="coin type 1 is test"):
        account_descriptors(_XPRV_ROOT, "m/84h/1h/0h")
    with pytest.raises(BTClibValueError, match="unregistered BIP44 coin type: 2"):
        account_descriptors(_XPRV_ROOT, "m/84h/2h/0h")

    # a key below the account level has walked past the path
    deeper = bip32.derive(_XPRV_ROOT, "m/84h/0h/0h/0")
    with pytest.raises(BTClibValueError, match="past the 3 levels of the path"):
        account_descriptors(deeper, "m/84h/0h/0h")
    # and one at the account level has to be *that* account
    other = bip32.xpub_from_xprv(bip32.derive(_XPRV_ROOT, "m/84h/0h/1h"))
    with pytest.raises(BTClibValueError, match="is not the path's 0h"):
        account_descriptors(other, "m/84h/0h/0h", "deadbeef")


def test_wallet_policy_of_a_receive_change_pair_agrees_with_both() -> None:
    """`account_descriptors`' own pair produces BIP388's own `/**` shorthand.

    That pair -- a BIP44 account's receive and change descriptors,
    `.../0/*` and `.../1/*` -- is the shape most callers actually hold,
    and the one shape `wallet_policy(descriptor)` alone refuses
    (`test_wallet_policy_refuses_what_cannot_become_one` in
    `tests/descriptors/descriptors_test.py` measures that).
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
