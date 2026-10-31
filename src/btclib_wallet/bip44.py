# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BIP44: the address of a path and the descriptors of an account.

https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki

The composition every wallet performs and no single call here did:
`bip32.derive` walks the path, `b58` and `b32` encode the address, and
the purpose level -- BIP43's, the first of the five -- says which of the
four encodings the path means. Nothing in this module derives or encodes
anything itself; what it adds is the mapping that makes a path
unambiguous, and the two checks that keep it honest.

The module sits above `script`, and taproot is the reason: a p2tr
address encodes the *tweaked* output key of BIP341, which
`script.taproot.output_pubkey` computes, and `bip32` is below `script`
and may not import it. `slip132` sits beside it at the top level for a
narrower version of the same shape: it needs `b58` and `b32`, which
import `bip32`, so it cannot live inside the package whose keys it
derives addresses from either.

`account_descriptors` applies the same mapping to an account: its
receive and change descriptors, built from an account xpub and the master
fingerprint of the key it came from.

What imports this module is what the mapping and the checks are for:
`wallet` takes the encoders and the purpose lookup rather than keeping a
second copy of either. This module imports `descriptors` for the
fragments of the account pair; ARCHITECTURE.md says why the edge runs
that way.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from btclib import b32, b58
from btclib.alias import NetworkType, Octets
from btclib.exceptions import BTClibValueError
from btclib.key import PubKeyData
from btclib.network import (
    NETWORKS,
    network_from_xkeyversion,
    network_type_from_xkeyversion,
)
from btclib.script.taproot import output_pubkey
from btclib.utils import bytes_from_octets

from btclib_wallet.bip32.bip32 import (
    BIP32Key,
    BIP32KeyData,
    derive_,
    fingerprint,
    key_data_from_bip32_key,
    pub_keyinfo_from_xkey,
    xpub_from_xprv,
)
from btclib_wallet.bip32.der_path import (
    HARDENED_OFFSET,
    DerPath,
    indexes_from_der_path,
    str_from_index_int,
)
from btclib_wallet.bip32.key_origin import BIP32KeyOrigin
from btclib_wallet.descriptors.descriptors import (
    Descriptor,
    PkhDescriptor,
    ShDescriptor,
    TrDescriptor,
    WpkhDescriptor,
)
from btclib_wallet.descriptors.key_expression import KeyExpression

__all__ = [
    "SCRIPT_TYPE_FROM_PURPOSE",
    "BIP44ScriptType",
    "account_descriptors",
    "address_from_der_path",
]

# The four address encodings a purpose level can name: 44 is p2pkh, 49
# p2wpkh-p2sh, 84 p2wpkh and 86 p2tr. It types both sides of this module
# -- the mapping read out of its _data/bip44_purposes.json and the
# script_type argument that overrides it -- so the two cannot drift apart
# in silence.
#
# Qualified BIP44, and not named ScriptType, because it is not btclib's
# notion of one: script.type_and_payload answers p2pk, p2ms, nulldata,
# p2sh and p2wsh besides these, b58.address_from_h160 takes p2pkh or
# p2sh, and p2wpkh-p2sh belongs to neither list -- it is a nesting of one
# script in another, not an output script type. The field is called
# script_type because that is what electrum's bip39_wallet_formats.json,
# the source of the mapping, calls it; the name is kept and qualified
# rather than corrected, so that the data and the code read the same.
#
# A Literal for the reasons btclib.alias.NetworkType is one, and with the
# same limit: it is a mypy fact and not a runtime one, so the json is
# still checked where it is used
BIP44ScriptType = Literal["p2pkh", "p2wpkh-p2sh", "p2wpkh", "p2tr"]

# purpose, coin type, account, change, address index: BIP44 fixes the
# meaning of each level, so a path of any other length is not one
_LEVELS = 5
# the first three of them, which are the hardened ones and as much of the
# path as an account xpub stands for: what a wallet exports, and what a
# descriptor's key origin names
_ACCOUNT_LEVELS = 3

# the mapping is data and lives with the network data, not in this file:
# it is the canonical row of the wallet-format table electrum ships as
# bip39_wallet_formats.json (sourced from walletsrecovery.org) and uses
# to scan a seed for the derivations wallets actually use. What a
# recovery helper wants next -- per-wallet rows, with the xpub version
# each writes -- is more of this file and no more of this module, and
# that list tracks the wallet ecosystem rather than the library
_PURPOSES_FILE = Path(__file__).parent / "_data" / "bip44_purposes.json"
with _PURPOSES_FILE.open(encoding="ascii") as _purposes:
    # json object keys are strings; a purpose is an int, as it is in a
    # derivation path. The values are annotated and not validated here:
    # BIP44ScriptType is a mypy fact and json.load answers Any, so what
    # refuses a script type the file should not have named is the same
    # table lookup that refuses one a caller passes
    SCRIPT_TYPE_FROM_PURPOSE: dict[int, BIP44ScriptType] = {
        int(purpose): script_type
        for purpose, script_type in json.load(_purposes).items()
    }

# BIP44's registered coin types, and the only two it registers: 0 is
# Bitcoin and 1 is "Bitcoin Testnet", which SLIP44 widens to the test
# chain of every coin. That is why what they are checked against is the
# network *type* of the extended key and not its name: btclib's test
# networks share one set of version bytes, so an xkey cannot say which of
# them it is, and coin type 1 does not distinguish them either
_NETWORK_TYPE_FROM_COIN_TYPE: dict[int, NetworkType] = {0: "main", 1: "test"}


def _p2tr(key: PubKeyData) -> str:
    """Return the p2tr address of a key, tweaked as BIP86 prescribes.

    BIP86 is BIP44 for taproot and the tweak is the whole of it: the
    output key commits to the internal key and to no script path, so what
    the address encodes is not the derived key but `output_pubkey` of it
    with an empty merkle root. The other three encoders take the derived
    key as it comes, which is why this one is a function here and
    `b32.p2tr` -- which expects the output key already tweaked -- is not
    in the table below.
    """
    return b32.p2tr(output_pubkey(key)[0], key.network)


# a key and the network in, the address out: four encodings that already
# exist, named by the script type the purpose resolves to. Keyed by
# BIP44ScriptType, so the alias and this table are checked against each
# other -- a fifth encoding is a key mypy does not know.
#
# The key carries the network, so each of the four takes one argument and
# not two: a `PubKeyData` is the SEC octets and the network they are read
# on, which is what an address is built from (issue btclib-org/btclib#1188)
_ADDRESS_FROM_SCRIPT_TYPE: dict[BIP44ScriptType, Callable[[PubKeyData], str]] = {
    "p2pkh": b58.p2pkh,
    "p2wpkh-p2sh": b58.p2wpkh_p2sh,
    "p2wpkh": b32.p2wpkh,
    "p2tr": _p2tr,
}


def _assert_valid_path(indexes: list[int]) -> None:
    """Raise unless the indexes are the five levels BIP44 defines.

    The hardening is checked and not merely documented because the
    purpose is read off the first index: `m/84/0h/0h/0/0` derives a key
    no BIP84 wallet has, and reading 84 out of it would answer that key
    with a p2wpkh address as if it were the right one.
    """
    if len(indexes) != _LEVELS:
        err_msg = f"invalid BIP44 path: {len(indexes)} levels instead of {_LEVELS}"
        raise BTClibValueError(err_msg)

    if any(index < HARDENED_OFFSET for index in indexes[:_ACCOUNT_LEVELS]):
        err_msg = "invalid BIP44 path: purpose, coin type and account must be hardened"
        raise BTClibValueError(err_msg)

    if any(index >= HARDENED_OFFSET for index in indexes[_ACCOUNT_LEVELS:]):
        err_msg = "invalid BIP44 path: change and address index must not be hardened"
        raise BTClibValueError(err_msg)


def _assert_valid_account_path(indexes: list[int]) -> None:
    """Raise unless the indexes are the three hardened levels of an account.

    m/purpose'/coin_type'/account', which is what a wallet exports and what
    a descriptor names in its key origin: the two levels below it are the
    unhardened ones public derivation can walk, so an account path is
    exactly as much as an xpub is useful for.

    The hardening is checked for the reason the five-level check gives, and
    one more: the whole point of stopping here is that nothing below needs
    a private key, and an unhardened account level would make the level
    above it -- not this path -- the last one that did.
    """
    if len(indexes) != _ACCOUNT_LEVELS:
        err_msg = f"invalid BIP44 account path: {len(indexes)} levels"
        err_msg += f" instead of {_ACCOUNT_LEVELS}"
        raise BTClibValueError(err_msg)

    if any(index < HARDENED_OFFSET for index in indexes):
        err_msg = "invalid BIP44 account path: purpose, coin type and account"
        err_msg += " must be hardened"
        raise BTClibValueError(err_msg)


def _script_type_from_purpose(purpose: int) -> BIP44ScriptType:
    """Return the script type of a purpose, refusing the ones unknown.

    Refusing is the answer because the alternative is to guess: a purpose
    the mapping does not name says the path was written for a scheme this
    module has never been told about, and answering it with p2pkh --
    BIP44's own encoding, the tempting default -- would be an address the
    wallet that wrote the path does not watch. The caller who knows what
    the scheme is says so with the script_type argument, which is the
    override, and gets no guess either way.
    """
    script_type = SCRIPT_TYPE_FROM_PURPOSE.get(purpose)
    if script_type is None:
        known = ", ".join(str(known) for known in sorted(SCRIPT_TYPE_FROM_PURPOSE))
        err_msg = f"unknown BIP44 purpose: {purpose} not in ({known});"
        err_msg += " pass script_type to say what it means"
        raise BTClibValueError(err_msg)
    return script_type


def _assert_valid_coin_type(coin_type: int, xkey: BIP32KeyData) -> None:
    """Raise unless the coin type agrees with the key's own network.

    The address is minted on the network of the key, never on the one the
    path claims: the version bytes are what an xprv, a tpub or a zprv
    *is*, while the coin type is a claim about where the key was meant to
    live. When the two disagree, one of them is a mistake and nothing
    here can tell which, so neither is silently preferred -- taking the
    key's network alone would answer `m/44h/1h/0h/0/0` under a mainnet
    xprv with a real-money address, from a path that says testnet.

    An unregistered coin type is refused for the same reason and not as
    an extra rule: coin type 2 is Litecoin, and the address this module
    would hand back is a bitcoin one, computed from a key the path says
    belongs to another chain.

    There is no override, where an unknown purpose has one, because an
    override here would mean "encode another chain's key as a bitcoin
    address" -- the very mistake this level of the path exists to
    prevent. A caller who wants exactly that is one b58 or b32 call away.
    """
    network_type = _NETWORK_TYPE_FROM_COIN_TYPE.get(coin_type)
    if network_type is None:
        registered = ", ".join(str(coin) for coin in _NETWORK_TYPE_FROM_COIN_TYPE)
        err_msg = f"unregistered BIP44 coin type: {coin_type} not in ({registered})"
        raise BTClibValueError(err_msg)

    key_network_type = network_type_from_xkeyversion(xkey.version)
    if network_type != key_network_type:
        err_msg = f"coin type {coin_type} is {network_type},"
        err_msg += f" the extended key is {key_network_type}"
        raise BTClibValueError(err_msg)


def _indexes_left_to_derive(xkey: BIP32KeyData, indexes: list[int]) -> list[int]:
    """Return the tail of the path the key has not walked yet.

    The path is always the whole of it, from the master key down, because
    that is where the purpose is; the key may be anywhere along it. An
    account xpub is the case that matters -- it is what a wallet exports,
    and the two levels left below it are the unhardened ones public
    derivation can walk -- and its depth says which levels are already
    behind it.

    What the key can be checked against is its own index, which is the
    path element at its depth. That catches the account xpub paired with
    the path of another account; it cannot catch a key from another
    purpose or another coin, nothing in an extended key recording where
    it came from, so the caller's word is taken for the levels above.

    The bound is the path's own length rather than BIP44's five, because
    an account path is three of them: a key deeper than the path it is
    handed has walked past its end, whichever of the two paths it is.
    """
    if xkey.depth > len(indexes):
        err_msg = f"invalid key depth: {xkey.depth} is past the {len(indexes)}"
        err_msg += " levels of the path"
        raise BTClibValueError(err_msg)

    if xkey.depth and xkey.index != indexes[xkey.depth - 1]:
        err_msg = f"key index {str_from_index_int(xkey.index)} at depth {xkey.depth}"
        err_msg += f" is not the path's {str_from_index_int(indexes[xkey.depth - 1])}"
        raise BTClibValueError(err_msg)

    return indexes[xkey.depth :]


def address_from_der_path(
    xkey: BIP32Key, der_path: DerPath, script_type: BIP44ScriptType | None = None
) -> str:
    """Return the address of a BIP44 derivation path.

    der_path is the whole five-level path,
    m/purpose'/coin_type'/account'/change/address_index, in any spelling
    `bip32.derive` accepts; xkey is the extended key it starts from,
    which may be the master key or any key already partway down it -- an
    account xpub, typically, the depth saying how much of the path is
    behind it.

    The purpose selects the encoding: 44 is p2pkh, 49 p2wpkh-p2sh, 84
    p2wpkh, 86 p2tr. A purpose outside that mapping raises, unless
    script_type names one of those four encodings, which then overrides
    the mapping for known purposes too.

    The network is the extended key's own; the coin type has to agree
    with it, 0 for mainnet and 1 for any test network, or the path and
    the key are describing different chains and neither wins.
    """
    xkey = key_data_from_bip32_key(xkey)

    indexes = indexes_from_der_path(der_path)
    _assert_valid_path(indexes)

    if script_type is None:
        script_type = _script_type_from_purpose(indexes[0] - HARDENED_OFFSET)
    # the lookup and not an isinstance: the table is the list of encodings
    # this module has, so missing from it and unknown are one thing. The
    # check survives BIP44ScriptType typing the argument because a Literal
    # is a mypy fact and not a runtime one -- it is what refuses a fifth
    # script type from the json above, and from a caller who runs no type
    # checker
    address_funct = _ADDRESS_FROM_SCRIPT_TYPE.get(script_type)
    if address_funct is None:
        known = ", ".join(sorted(_ADDRESS_FROM_SCRIPT_TYPE))
        err_msg = f"unknown script type: {script_type} not in ({known})"
        raise BTClibValueError(err_msg)

    _assert_valid_coin_type(indexes[1] - HARDENED_OFFSET, xkey)

    # `derive_` and not `derive`, so that the derived key stays decoded: an
    # extended key is not what an address builder takes (issue
    # btclib-org/btclib#1188), so what the encoder is handed is its public
    # key, and `derive` would serialize this one here for
    # `pub_keyinfo_from_xkey` to decode straight back
    key = derive_(xkey, _indexes_left_to_derive(xkey, indexes))
    network = network_from_xkeyversion(xkey.version)
    # check_validity=False: `pub_keyinfo_from_xkey` answers the SEC
    # octets of an extended key it has parsed, and `network` is the name
    # that key's own version bytes resolve to
    return address_funct(
        PubKeyData(*pub_keyinfo_from_xkey(key, network), check_validity=False)
    )


# BIP44's fourth level, the two chains every wallet keeps: 0 receives and
# 1 is change, which is the only difference between the pair below
_RECEIVE_CHAIN = 0
_CHANGE_CHAIN = 1

# what a standard account descriptor is, per script type: the fragment
# built around one ranged key expression. Keyed by BIP44ScriptType, as
# `_ADDRESS_FROM_SCRIPT_TYPE` is, so the alias and the two tables are
# checked against each other -- a fifth script type is a key mypy does not
# know.
#
# Lambdas because `network` is keyword-only on `Descriptor`, so a fragment
# class cannot be the value directly, and because ``sh(wpkh())`` is two
# fragments where the others are one
_DESCRIPTOR_FROM_SCRIPT_TYPE: dict[
    BIP44ScriptType, Callable[[KeyExpression, str], Descriptor]
] = {
    "p2pkh": lambda key, network: PkhDescriptor(key, network=network),
    "p2wpkh-p2sh": lambda key, network: ShDescriptor(
        WpkhDescriptor(key, network=network), network=network
    ),
    "p2wpkh": lambda key, network: WpkhDescriptor(key, network=network),
    "p2tr": lambda key, network: TrDescriptor(key, network=network),
}


def _account_xpub(xkey: BIP32KeyData, indexes: list[int]) -> str:
    """Return the account xpub, derived from the key if it is above it.

    Neutered whatever was handed in, as `descriptors.parse` neuters what
    it reads: a descriptor holds no key that signs, and nothing below an
    account level hardens, so the xpub computes every script the pair
    describes.

    The version bytes are BIP32's, whichever the key arrived in. A SLIP132
    ypub or zpub says which script type its keys are for, which is what the
    descriptor function says: the two spellings would then be one claim
    made twice, and a descriptor holding a zpub is one no other
    implementation reads -- Bitcoin Core decodes the BIP32 versions and
    nothing else. Same key, same scripts, one spelling of it.
    """
    network = NETWORKS[network_from_xkeyversion(xkey.version)]
    version = network.bip32_prv if xkey.is_private else network.bip32_pub
    # `derive_`, which answers the key: `derive` would serialize to base58
    # for `xpub_from_xprv` to decode straight back
    derived = derive_(xkey, _indexes_left_to_derive(xkey, indexes), version)
    return xpub_from_xprv(derived) if xkey.is_private else derived.b58encode()


def _account_fingerprint(
    xkey: BIP32KeyData, master_fingerprint: Octets | None
) -> bytes:
    """Return the master fingerprint of the key origin, checking what it can.

    Computed from the key only when the key *is* the master one, at depth
    zero: the fingerprint of a key at any other depth is that key's, not
    its master's, and a key origin naming it would send a signer looking
    for a master key nobody has. So a key already below the root has to be
    told, and where the caller says it too the two must agree -- one of
    them would otherwise be silently preferred, and neither is more likely
    to be right.
    """
    own = fingerprint(xkey.b58encode()) if xkey.depth == 0 else None
    if master_fingerprint is None:
        if own is None:
            err_msg = "no master fingerprint: a key below the root cannot say"
            err_msg += " which master key it came from"
            raise BTClibValueError(err_msg)
        return own
    given = bytes_from_octets(master_fingerprint, 4)
    if own is not None and own != given:
        err_msg = f"master fingerprint {given.hex()} is not the key's own"
        err_msg += f" {own.hex()}"
        raise BTClibValueError(err_msg)
    return given


def account_descriptors(
    xkey: BIP32Key,
    der_path: DerPath,
    master_fingerprint: Octets | None = None,
    script_type: BIP44ScriptType | None = None,
) -> tuple[Descriptor, Descriptor]:
    """Return the receive and change descriptors of a BIP44 account.

    der_path is the three-level account path,
    m/purpose'/coin_type'/account', in any spelling `bip32.derive`
    accepts; xkey is the extended key it starts from, which may be the
    master key or any key already partway down it -- the account xpub
    itself, typically, which is what a wallet exports and what a hardware
    signer answers with.

    The purpose selects the encoding, as it does for a BIP44 address: 44
    is ``pkh()``, 49 ``sh(wpkh())``, 84 ``wpkh()``, 86 ``tr()``. A purpose
    outside `SCRIPT_TYPE_FROM_PURPOSE` raises unless script_type names
    one of those four, which then overrides the mapping for known
    purposes too. The network is the extended key's own, and the coin
    type has to agree with it.

    Both chains come back because a wallet is both: BIP44 puts receiving
    addresses under `/0` and change under `/1`, and a wallet that imported
    one and not the other cannot recognize its own change -- which is a
    lost output rather than a missing feature. They differ in that step
    and in nothing else, the key origin and the wildcard being the same.

    The master fingerprint is what the key origin needs and what an
    extended key below the root cannot supply, so it is a parameter; where
    xkey is the master key it is computed, and a value handed in beside it
    has to match.

    `descriptors.add_checksum(str(descriptor))` is the text Bitcoin Core
    takes. The BIP389 spelling of the pair -- one descriptor with a
    ``<0;1>`` step -- is text and not a parsed descriptor:
    `descriptors.multipath_descriptors` expands one and `descriptors.parse`
    refuses one, so what this returns is the two.
    """
    xkey = key_data_from_bip32_key(xkey)

    indexes = indexes_from_der_path(der_path)
    _assert_valid_account_path(indexes)
    if script_type is None:
        script_type = _script_type_from_purpose(indexes[0] - HARDENED_OFFSET)
    # the lookup and not an isinstance, for `address_from_der_path`'s reason
    build = _DESCRIPTOR_FROM_SCRIPT_TYPE.get(script_type)
    if build is None:
        known = ", ".join(sorted(_DESCRIPTOR_FROM_SCRIPT_TYPE))
        raise BTClibValueError(f"unknown script type: {script_type} not in ({known})")
    _assert_valid_coin_type(indexes[1] - HARDENED_OFFSET, xkey)

    # the xpub first, and the fingerprint after it: a key that does not fit
    # the path is about the two arguments the caller passed together, where
    # a missing fingerprint is about a third
    account_xpub = _account_xpub(xkey, indexes)
    origin = BIP32KeyOrigin(_account_fingerprint(xkey, master_fingerprint), indexes)
    network = network_from_xkeyversion(xkey.version)

    def chain(index: int) -> Descriptor:
        key = KeyExpression(
            origin=origin, xkey=account_xpub, der_path=(index,), wildcard=0
        )
        return build(key, network)

    return chain(_RECEIVE_CHAIN), chain(_CHANGE_CHAIN)
