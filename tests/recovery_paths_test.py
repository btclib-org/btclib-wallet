# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `recovery_descriptors`: its vectors, its spends, its refusals.

The vectors are the custody descriptors of
`tests/wallet/custody_wallet_test.py`, deployed on mainnet, and the
policies issue btclib-org/btclib-wallet#928 names: Liana's
SimpleInheritance and MultisigSecurity, and libnunchuk's expanding and
decaying multisig. What the issue says of those templates is their only
source here, so what they pin is the policy, not the other wallet's
descriptor. The keys are read off the custody descriptors, or derived at
run time where a test signs, so this file spells no key of its own.

The ``tr()`` vectors have no deployment behind them: Bitcoin Core gave
their checksums and addresses from the text the function writes, and
`_CORE_VECTORS` says how.
"""

from __future__ import annotations

import hashlib
import operator
import platform
import re
from collections.abc import Callable
from dataclasses import replace
from enum import IntEnum
from typing import Any

import pytest
from bip32_descriptors.bip32 import BIP32KeyData
from bip32_descriptors.bip32.bip32 import (
    derive,
    fingerprint,
    rootxprv_from_seed,
    xpub_from_xprv,
)
from bip32_descriptors.descriptors import (
    Descriptor,
    TrDescriptor,
    WshDescriptor,
    add_checksum,
    miniscript,
    parse,
)
from bip32_descriptors.descriptors.miniscript import SpendContext
from btclib.alias import Octets
from btclib.b58 import wif_from_prv_key
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.key import PrvKeyData
from btclib.network import NETWORKS
from btclib.script import sig_hash
from btclib.script.engine import verify_transaction
from btclib.script.taproot import leaf_hash, output_prvkey_from_merkle_root
from btclib.script.witness import Witness
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx
from btclib.tx.tx_in import TxIn
from btclib.tx.tx_out import TxOut
from ecc import dsa, ssa
from typing_extensions import override

from btclib_wallet.psbt import Psbt, finalize, miniscript_solver
from btclib_wallet.psbt.psbt import taproot_sig_hash
from btclib_wallet.psbt.psbt_updater import update_psbt_input
from btclib_wallet.recovery_paths import recovery_descriptors
from tests.secret_free import assert_secret_free
from tests.wallet.custody_wallet_test import (
    _RANGED,
    _RANGED_QUORUMS,
    _TRANSIT_PRIMARY_BLOCKS,
    _VAULT_RECOVERY_BLOCKS,
)

_BLOCKS = {"vault": _VAULT_RECOVERY_BLOCKS, "transit": _TRANSIT_PRIMARY_BLOCKS}


def _account_keys(text: str) -> list[str]:
    """Return the account keys of a descriptor, in the order it names them."""
    return [
        str(replace(key, der_path=(), wildcard=None))
        for key in parse(text).key_expressions
    ]


# every account key of the custody descriptors, each once
_KEYS = list(
    dict.fromkeys(
        key
        for wallets in _RANGED.values()
        for branches in wallets.values()
        for key in _account_keys(branches[0][0])
    )
)
A, B, C, D, E, F = _KEYS[:6]


def _other_chain_code(key: str) -> str:
    """Return the key's public key under another chain code, with no origin."""
    d = BIP32KeyData.b58decode(key.split("]")[1])
    chain_code = bytes(byte ^ 0xFF for byte in d.chain_code)
    other = BIP32KeyData(
        d.version, d.depth, d.parent_fingerprint, d.index, chain_code, d.key
    )
    return other.b58encode()


def _other_public_key(key: str, other: str) -> str:
    """Return `other`'s public key under `key`'s chain code, with no origin."""
    d = BIP32KeyData.b58decode(key.split("]")[1])
    public = BIP32KeyData.b58decode(other.split("]")[1]).key
    data = BIP32KeyData(
        d.version, d.depth, d.parent_fingerprint, d.index, d.chain_code, public
    )
    return data.b58encode()


# the public key of A under another chain code: another account key
_A_OTHER_CHAIN_CODE = _other_chain_code(A)
# B's public key under A's chain code: another account key too
_A_OTHER_PUBLIC_KEY = _other_public_key(A, B)
# A with its origin's hardened steps written ' rather than h
_A_APOSTROPHE = "]".join((A.split("]")[0].replace("h", "'"), A.split("]")[1]))


@pytest.mark.parametrize(
    "deployment,wallet",
    [(deployment, wallet) for deployment in _RANGED for wallet in ("vault", "transit")],
)
def test_the_custody_descriptors_are_its_vectors(deployment: str, wallet: str) -> None:
    """Both deployments, both wallets, both chains, byte for byte.

    The quorums are read off the receive descriptor with the thresholds
    the custody test records, and the call has to write back both
    descriptors, checksum included, and the addresses the deployment
    uses.
    """
    keys = _account_keys(_RANGED[deployment][wallet][0][0])
    quorums = []
    for threshold, count in _RANGED_QUORUMS[wallet]:
        quorums.append((threshold, keys[:count]))
        keys = keys[count:]
    *primary, (threshold, recovery) = quorums
    descriptors = recovery_descriptors(
        primary, [(threshold, recovery, _BLOCKS[wallet])]
    )
    for chain, descriptor in enumerate(descriptors):
        text, addresses = _RANGED[deployment][wallet][chain]
        assert add_checksum(str(descriptor)) == text
        assert [descriptor.address(i) for i in range(len(addresses))] == addresses


def _keys(chain: int, *pairs: tuple[str, int]) -> str:
    """Return the keys of a fragment, each at its branch pair and chain."""
    return ",".join(f"{key}/{pair + chain}/*" for key, pair in pairs)


# (primary, recovery, the receive and change descriptors as a function of
# the chain). The pair of a key is 0 the first time the call names it, 2
# the second, 4 the third
_POLICIES: dict[
    str,
    tuple[
        list[tuple[int, list[str]]],
        list[tuple[int, list[str], int]],
        Callable[[int], str],
    ],
] = {
    # Liana's SimpleInheritance: one primary key, and one inheritance key
    # after a timelock
    "simple inheritance": (
        [(1, [A])],
        [(1, [B], 52560)],
        lambda c: (
            f"wsh(or_i(pk({_keys(c, (A, 0))}),"
            f"and_v(v:pk({_keys(c, (B, 0))}),older(52560))))"
        ),
    ),
    # Liana's MultisigSecurity: 2-of-2 now, 2-of-3 after a timelock
    "multisig security": (
        [(2, [A, B])],
        [(2, [A, B, C], 4320)],
        lambda c: (
            f"wsh(or_i(multi(2,{_keys(c, (A, 0), (B, 0))}),"
            f"and_v(v:multi(2,{_keys(c, (A, 2), (B, 2), (C, 0))}),older(4320))))"
        ),
    ),
    # libnunchuk's expanding multisig: n grows after the timelock
    "expanding": (
        [(2, [A, B, C])],
        [(2, [A, B, C, D], 4320)],
        lambda c: (
            f"wsh(or_i(multi(2,{_keys(c, (A, 0), (B, 0), (C, 0))}),"
            f"and_v(v:multi(2,{_keys(c, (A, 2), (B, 2), (C, 2), (D, 0))}),"
            "older(4320))))"
        ),
    ),
    # libnunchuk's decaying multisig: m shrinks after the timelock
    "decaying": (
        [(2, [A, B, C])],
        [(1, [A, B, C], 4320)],
        lambda c: (
            f"wsh(or_i(multi(2,{_keys(c, (A, 0), (B, 0), (C, 0))}),"
            f"and_v(v:multi(1,{_keys(c, (A, 2), (B, 2), (C, 2))}),older(4320))))"
        ),
    ),
    # a decay in two steps, which nests the recovery paths to the right
    "decaying twice": (
        [(3, [A, B, C])],
        [(2, [A, B, C], 144), (1, [A, B, C], 4320)],
        lambda c: (
            f"wsh(or_i(multi(3,{_keys(c, (A, 0), (B, 0), (C, 0))}),"
            f"or_i(and_v(v:multi(2,{_keys(c, (A, 2), (B, 2), (C, 2))}),older(144)),"
            f"and_v(v:multi(1,{_keys(c, (A, 4), (B, 4), (C, 4))}),older(4320)))))"
        ),
    ),
    # two primary quorums and three recovery paths, one-key quorums among
    # them, a key reused inside the primary path
    "two primaries, three paths": (
        [(1, [A]), (2, [A, B])],
        [(1, [C], 144), (2, [D, E], 4320), (1, [F], 52560)],
        lambda c: (
            f"wsh(andor(pk({_keys(c, (A, 0))}),multi(2,{_keys(c, (A, 2), (B, 0))}),"
            f"or_i(and_v(v:pk({_keys(c, (C, 0))}),older(144)),"
            f"or_i(and_v(v:multi(2,{_keys(c, (D, 0), (E, 0))}),older(4320)),"
            f"and_v(v:pk({_keys(c, (F, 0))}),older(52560))))))"
        ),
    ),
    # two paths that open at the same block: after a year, two of three
    # lawyers or the heir alone
    "equal locks": (
        [(1, [A])],
        [(2, [B, C, D], 52560), (1, [E], 52560)],
        lambda c: (
            f"wsh(or_i(pk({_keys(c, (A, 0))}),"
            f"or_i(and_v(v:multi(2,{_keys(c, (B, 0), (C, 0), (D, 0))}),older(52560)),"
            f"and_v(v:pk({_keys(c, (E, 0))}),older(52560)))))"
        ),
    ),
    # one public key under two chain codes is two account keys: each
    # takes its own first pair, and they derive other script keys
    "one public key, two chain codes": (
        [(1, [A])],
        [(1, [_A_OTHER_CHAIN_CODE], 144)],
        lambda c: (
            f"wsh(or_i(pk({_keys(c, (A, 0))}),"
            f"and_v(v:pk({_keys(c, (_A_OTHER_CHAIN_CODE, 0))}),older(144))))"
        ),
    ),
    # the same two account keys in one quorum: a key is its public key
    # and its chain code, and each pair differs in one of the two
    "one public key, two chain codes, in one quorum": (
        [(2, [A, _A_OTHER_CHAIN_CODE])],
        [(1, [B], 144)],
        lambda c: (
            f"wsh(or_i(multi(2,{_keys(c, (A, 0), (_A_OTHER_CHAIN_CODE, 0))}),"
            f"and_v(v:pk({_keys(c, (B, 0))}),older(144))))"
        ),
    ),
    "one chain code, two public keys, in one quorum": (
        [(2, [A, _A_OTHER_PUBLIC_KEY])],
        [(1, [C], 144)],
        lambda c: (
            f"wsh(or_i(multi(2,{_keys(c, (A, 0), (_A_OTHER_PUBLIC_KEY, 0))}),"
            f"and_v(v:pk({_keys(c, (C, 0))}),older(144))))"
        ),
    ),
    # the bounds of the blocks, both taken
    "blocks at 1 and at 65535": (
        [(1, [A])],
        [(1, [B], 1), (1, [C], 65535)],
        lambda c: (
            f"wsh(or_i(pk({_keys(c, (A, 0))}),"
            f"or_i(and_v(v:pk({_keys(c, (B, 0))}),older(1)),"
            f"and_v(v:pk({_keys(c, (C, 0))}),older(65535)))))"
        ),
    ),
    # one recovery path given twice: the second copy takes the next pair
    "two identical paths": (
        [(1, [A])],
        [(1, [B], 144), (1, [B], 144)],
        lambda c: (
            f"wsh(or_i(pk({_keys(c, (A, 0))}),"
            f"or_i(and_v(v:pk({_keys(c, (B, 0))}),older(144)),"
            f"and_v(v:pk({_keys(c, (B, 2))}),older(144)))))"
        ),
    ),
    # one origin spelled with h and with ', which is one origin: each
    # occurrence is written back as it was given
    "an origin in both spellings": (
        [(1, [A])],
        [(1, [_A_APOSTROPHE], 144)],
        lambda c: (
            f"wsh(or_i(pk({_keys(c, (A, 0))}),"
            f"and_v(v:pk({_keys(c, (_A_APOSTROPHE, 2))}),older(144))))"
        ),
    ),
    # the most keys multi() takes, each needed, now and after the timelock
    "20 of 20": (
        [(20, _KEYS[:20])],
        [(20, _KEYS[:20], 144)],
        lambda c: (
            f"wsh(or_i(multi(20,{_keys(c, *[(k, 0) for k in _KEYS[:20]])}),"
            f"and_v(v:multi(20,{_keys(c, *[(k, 2) for k in _KEYS[:20]])}),"
            "older(144))))"
        ),
    ),
    # two primary quorums of 20 of 20, which spend together
    "two primaries of 20 of 20": (
        [(20, _KEYS[:20]), (20, _KEYS[:20])],
        [(20, _KEYS[:20], 144)],
        lambda c: (
            f"wsh(andor(multi(20,{_keys(c, *[(k, 0) for k in _KEYS[:20]])}),"
            f"multi(20,{_keys(c, *[(k, 2) for k in _KEYS[:20]])}),"
            f"and_v(v:multi(20,{_keys(c, *[(k, 4) for k in _KEYS[:20]])}),"
            "older(144))))"
        ),
    ),
    # one key in five quorums, which takes five branch pairs
    "one key, five quorums": (
        [(1, [A])],
        [(1, [A], 144), (1, [A], 288), (1, [A], 432), (1, [A], 576)],
        lambda c: (
            f"wsh(or_i(pk({_keys(c, (A, 0))}),"
            f"or_i(and_v(v:pk({_keys(c, (A, 2))}),older(144)),"
            f"or_i(and_v(v:pk({_keys(c, (A, 4))}),older(288)),"
            f"or_i(and_v(v:pk({_keys(c, (A, 6))}),older(432)),"
            f"and_v(v:pk({_keys(c, (A, 8))}),older(576)))))))"
        ),
    ),
}


@pytest.mark.parametrize("policy", _POLICIES)
def test_each_policy_is_one_call(policy: str) -> None:
    """Each policy is one call, and the call writes the shape it is owed."""
    primary, recovery, expected = _POLICIES[policy]
    descriptors = recovery_descriptors(primary, recovery)
    assert tuple(str(descriptor) for descriptor in descriptors) == (
        expected(0),
        expected(1),
    )


def test_two_chain_codes_derive_two_script_keys() -> None:
    """The public key of A under another chain code signs with other keys."""
    descriptors = recovery_descriptors([(1, [A])], [(1, [_A_OTHER_CHAIN_CODE], 144)])
    for descriptor in descriptors:
        first, second = descriptor.key_expressions
        assert first.sec(0) != second.sec(0)
        assert first.sec(2**31 - 1) != second.sec(2**31 - 1)


@pytest.mark.parametrize("network", ["testnet", "regtest", "signet", "testnet4"])
def test_each_network_takes_its_own_keys(network: str) -> None:
    """Both chains on each network but mainnet, to the last unhardened index.

    The keys are derived here with the network's version bytes.
    """
    net = NETWORKS[network]
    roots = [rootxprv_from_seed(bytes([i]) * 16, net.bip32_prv) for i in (1, 2)]
    keys = [xpub_from_xprv(derive(root, "m/48h/1h/0h/2h")) for root in roots]
    descriptors = recovery_descriptors([(1, [keys[0]])], [(1, [keys[1]], 144)], network)
    for chain, descriptor in enumerate(descriptors):
        assert str(descriptor) == (
            f"wsh(or_i(pk({keys[0]}/{chain}/*),"
            f"and_v(v:pk({keys[1]}/{chain}/*),older(144))))"
        )
        for index in (0, 2**31 - 1):
            assert descriptor.address(index).startswith(f"{net.hrp}1q")


# the two values `script_type` takes
_SCRIPT_TYPES: list[Any] = ["p2wsh", "p2tr"]


@pytest.mark.parametrize("script_type", _SCRIPT_TYPES)
def test_a_network_is_read_whatever_its_case_and_spaces(script_type: Any) -> None:
    """A network in capitals and between spaces is the network.

    As `validated_network_name` reads it: " MAINNET " is mainnet.
    """
    respelled = recovery_descriptors(_P, _R, " MAINNET ", script_type=script_type)
    assert respelled == recovery_descriptors(_P, _R, script_type=script_type)


@pytest.mark.parametrize("script_type", _SCRIPT_TYPES)
def test_a_sequence_of_any_kind_is_taken(script_type: Any) -> None:
    """Tuples are what the annotation says, and lists answer the same."""
    as_tuples = recovery_descriptors(
        ((1, (A,)),), ((1, (B,), 52560),), script_type=script_type
    )
    as_lists = recovery_descriptors(
        [[1, [A]]],  # type: ignore[list-item]
        [[1, [B], 52560]],  # type: ignore[list-item]
        script_type=script_type,
    )
    assert as_tuples == as_lists


_ACCOUNT = "m/48h/0h/0h/2h"
# twenty signers' master keys, derived here and published nowhere
_ROOTS = [rootxprv_from_seed(bytes([i]) * 16) for i in range(1, 21)]
_SIGNER_KEYS = [
    f"[{fingerprint(root).hex()}/48h/0h/0h/2h]{xpub_from_xprv(derive(root, _ACCOUNT))}"
    for root in _ROOTS
]


def _spend(
    descriptor: Descriptor, signers: list[tuple[int, int]], sequence: int
) -> Psbt:
    """Return the finalized psbt spending index 3 of the descriptor.

    `signers` are (signer, branch) pairs: the key of that signer at that
    branch signs. The input carries the witness script and the signatures,
    and the solver chooses the path they open at that sequence.
    """
    assert isinstance(descriptor, WshDescriptor)
    index = 3
    script = descriptor.inner.redeem_script(index)
    prevout = TxOut(50_000, descriptor.script_pub_key(index))
    tx = Tx(
        version=2,
        vin=[TxIn(OutPoint(b"\x05" * 32, 0), sequence=sequence)],
        vout=[TxOut(49_000, prevout.script_pub_key)],
    )
    psbt = Psbt.from_tx(tx)
    psbt.inputs[0].witness_utxo = prevout
    psbt.inputs[0].witness_script = script
    msg_hash = sig_hash.segwit_v0(script, tx, 0, sig_hash.ALL, prevout.value)
    signatures = {}
    for signer, branch in signers:
        xprv = derive(_ROOTS[signer], f"{_ACCOUNT}/{branch}/{index}")
        prv_key = BIP32KeyData.b58decode(xprv).key[1:]
        signature = dsa.sign_(msg_hash, prv_key).serialize() + b"\x01"
        signatures[PrvKeyData(int.from_bytes(prv_key)).pub.sec] = signature
    psbt.inputs[0].partial_sigs = signatures
    final = finalize(psbt, solver=miniscript_solver)
    spending = final.tx
    spending.vin[0].script_witness = final.inputs[0].final_script_witness
    # the engine is what says the spend is one the network takes
    verify_transaction([prevout], spending)
    return final


# the sequence of an input with no relative lock
_NO_LOCK = 0xFFFFFFFD

# (primary, recovery, and each path: the blocks it waits, none for the
# primary path, and the (signer, branch pair) that sign it). The decay
# names every key on every path, so each path takes its own branch pair
_SPENDS = {
    "decaying twice": (
        [(3, [0, 1, 2])],
        [(2, [0, 1, 2], 144), (1, [0, 1, 2], 4320)],
        [
            (None, [(0, 0), (1, 0), (2, 0)]),
            (144, [(0, 2), (2, 2)]),
            (4320, [(1, 4)]),
        ],
    ),
    "two primaries": (
        [(1, [0]), (1, [1])],
        [(1, [2], 144)],
        [(None, [(0, 0), (1, 0)]), (144, [(2, 0)])],
    ),
    # the owner now; two of three lawyers, or the heir alone, after the
    # same timelock
    "equal locks": (
        [(1, [0])],
        [(2, [1, 2, 3], 144), (1, [4], 144)],
        [(None, [(0, 0)]), (144, [(1, 0), (3, 0)]), (144, [(4, 0)])],
    ),
    "20 of 20": (
        [(20, list(range(20)))],
        [(20, list(range(20)), 144)],
        [
            (None, [(s, 0) for s in range(20)]),
            (144, [(s, 2) for s in range(20)]),
        ],
    ),
    "two primaries of 20 of 20": (
        [(20, list(range(20))), (20, list(range(20)))],
        [(20, list(range(20)), 144)],
        [
            (None, [(s, 0) for s in range(20)] + [(s, 2) for s in range(20)]),
            (144, [(s, 4) for s in range(20)]),
        ],
    ),
    "one key, five quorums": (
        [(1, [0])],
        [(1, [0], 144), (1, [0], 288), (1, [0], 432), (1, [0], 576)],
        [
            (None, [(0, 0)]),
            (144, [(0, 2)]),
            (288, [(0, 4)]),
            (432, [(0, 6)]),
            (576, [(0, 8)]),
        ],
    ),
}

_SPEND_CASES = [
    pytest.param(policy, path, chain, id=f"{policy}-path {path}-chain {chain}")
    for policy, (_, _, paths) in _SPENDS.items()
    for path in range(len(paths))
    for chain in (0, 1)
]

_NO_SATISFACTION = "no satisfaction with the signatures, preimages and lock times given"


@pytest.mark.parametrize("policy,path,chain", _SPEND_CASES)
def test_each_path_spends_once_its_timelock_has_passed(
    policy: str, path: int, chain: int
) -> None:
    """Sign along one path, and spend: at its timelock, and not before it.

    The solver finalizes the psbt and the script engine runs the spend,
    so what is shown is that the descriptors returned spend along every
    path they describe, from either chain, with the keys of the branch
    pair the docstring gives.
    """
    primary, recovery, paths = _SPENDS[policy]
    descriptors = recovery_descriptors(
        [(t, [_SIGNER_KEYS[s] for s in signers]) for t, signers in primary],
        [(t, [_SIGNER_KEYS[s] for s in signers], b) for t, signers, b in recovery],
    )
    blocks, signers = paths[path]
    on_chain = [(signer, pair + chain) for signer, pair in signers]
    if blocks is None:
        _spend(descriptors[chain], on_chain, _NO_LOCK)
        return
    with pytest.raises(BTClibValueError, match=f"^{re.escape(_NO_SATISFACTION)}$"):
        _spend(descriptors[chain], on_chain, blocks - 1)
    _spend(descriptors[chain], on_chain, blocks)


def test_older_beyond_16_bits_is_met_at_once() -> None:
    """The ground of the 65535 bound: ``older(65536)`` waits for nothing.

    BIP68 reads the low 16 bits of the sequence, so the satisfier finds
    65536 blocks met by a sequence of 0, where 65535 is not.
    """
    key = PrvKeyData(1).pub.sec.hex()
    signature = "30" + "00" * 70
    at_once = SpendContext(sequence=0, version=2)
    node = miniscript.parse(f"and_v(v:pk({key}),older(65536))")
    assert node.satisfy({key: signature}, at_once)
    node = miniscript.parse(f"and_v(v:pk({key}),older(65535))")
    with pytest.raises(BTClibValueError, match=f"^{re.escape(_NO_SATISFACTION)}$"):
        node.satisfy({key: signature}, at_once)


_XPRV = derive(_ROOTS[0], _ACCOUNT)
_TPUB = xpub_from_xprv(
    derive(rootxprv_from_seed(bytes(16), NETWORKS["testnet"].bip32_prv), "m/1h")
)
_PUB_KEY = PrvKeyData(1).pub.sec.hex()
# the private key of _XPRV, a fixed random value as `assert_secret_free`
# asks, and its WIF
_PRV_KEY = BIP32KeyData.b58decode(_XPRV).key[1:]
_WIF = wif_from_prv_key(_PRV_KEY, "mainnet")
# A and the same xpub under another origin: another fingerprint and
# another path, another fingerprint alone, another path alone
_A_FINGERPRINT, _A_PATH = A[1:].split("]")[0].split("/", 1)
_A_XPUB = A.split("]")[1]
_OTHER_ORIGIN = f"[00000000/1h]{_A_XPUB}"
_OTHER_FINGERPRINT = f"[00000000/{_A_PATH}]{_A_XPUB}"
_OTHER_PATH = f"[{_A_FINGERPRINT}/1h]{_A_XPUB}"


def _respellings(key: str) -> dict[str, str]:
    """Return the key in xpubs that differ from its own outside the key.

    Each differs in one field, its depth, its parent's fingerprint or its
    child index, and keeps the public key, the chain code and the origin.
    """
    origin, xpub = key.split("]")
    d = BIP32KeyData.b58decode(xpub)
    fields = {
        "depth": (d.depth + 1, d.parent_fingerprint, d.index),
        "parent fingerprint": (d.depth, bytes([1, 2, 3, 4]), d.index),
        "child index": (d.depth, d.parent_fingerprint, d.index + 1),
    }
    return {
        name: f"{origin}]"
        + BIP32KeyData(d.version, depth, parent, index, d.chain_code, d.key).b58encode()
        for name, (depth, parent, index) in fields.items()
    }


_RESPELLED = _respellings(A)


class _Named(IntEnum):
    """An IntEnum, refused where an int belongs."""

    TWO = 2


_CLAIMS_STR: Any = property(lambda _self: str)
_CLAIMS_LIST: Any = property(lambda _self: list)


class _ClaimsStr:
    """No str, whose `__class__` says str."""

    __class__ = _CLAIMS_STR


class _ClaimsList:
    """No sequence, whose `__class__` says list."""

    __class__ = _CLAIMS_LIST


def _raises(*_args: object, **_kwargs: object) -> Any:
    """Raise with the WIF, so that a call of it shows in the refusal."""
    raise RuntimeError(_WIF)


# the methods a hostile value answers with `_raises`: all a refusal or a
# check could ask of an int, a str, a tuple or a list
_METHODS = [
    "__bool__",
    "__contains__",
    "__eq__",
    "__format__",
    "__ge__",
    "__getitem__",
    "__gt__",
    "__hash__",
    "__index__",
    "__int__",
    "__iter__",
    "__le__",
    "__len__",
    "__lt__",
    "__ne__",
    "__repr__",
    "__reversed__",
    "__str__",
    "count",
    "index",
    "lower",
    "strip",
]


class _NamedWif(type):
    """A metaclass whose `__name__` is the WIF, as a caller's could be.

    It answers rather than raises: pytest names a value's class by this
    `__name__` when it reports a failure, and a raise there stops pytest.
    """

    @property
    @override
    def __name__(cls) -> str:  # type: ignore[override]
        return _WIF


def _hostile(base: type) -> type:
    """Return a subclass of `base` whose every method raises with the WIF.

    Its `__class__` raises too, and its metaclass's `__name__` is the WIF.
    """
    body: dict[str, object] = dict.fromkeys(_METHODS, _raises)
    body["__class__"] = property(_raises)
    return _NamedWif(f"_Hostile{base.__name__.title()}", (base,), body)


# a subclass of each type a position takes, and an IntEnum
_SUBCLASSES: dict[str, Callable[[], object]] = {
    "int": lambda: _hostile(int)(2),
    "str": lambda: _hostile(str)(A),
    "tuple": lambda: _hostile(tuple)((1, [A])),
    "list": lambda: _hostile(list)([(1, [A])]),
    "IntEnum": lambda: _Named.TWO,
}
# the name each is refused with
_SUBCLASS_NAMES = {
    "int": "_HostileInt",
    "str": "_HostileStr",
    "tuple": "_HostileTuple",
    "list": "_HostileList",
    "IntEnum": "_Named",
}


_P = [(1, [A])]
_R = [(1, [B], 144)]

# (primary, recovery, network, the class refused, its message)
_REFUSED: dict[str, tuple[object, object, object, type[Exception], str]] = {
    "network": (_P, _R, "nonet", BTClibValueError, "unknown network: 'nonet'"),
    "primary type": (A, _R, "mainnet", BTClibTypeError, "invalid primary type: 'str'"),
    "recovery type": (
        _P,
        1,
        "mainnet",
        BTClibTypeError,
        "invalid recovery type: 'int'",
    ),
    "no primary": (
        [],
        _R,
        "mainnet",
        BTClibValueError,
        "invalid primary: 0 quorums, not one or two",
    ),
    "three primaries": (
        [(1, [A]), (1, [C]), (1, [D])],
        _R,
        "mainnet",
        BTClibValueError,
        "invalid primary: 3 quorums, not one or two",
    ),
    "no recovery": (_P, [], "mainnet", BTClibValueError, "invalid recovery: no path"),
    "quorum type": (
        [1],
        _R,
        "mainnet",
        BTClibTypeError,
        "invalid primary quorum 0 type: 'int'",
    ),
    "quorum arity": (
        [(1, [A], 144)],
        _R,
        "mainnet",
        BTClibValueError,
        "invalid primary quorum 0: 3 items, not 2",
    ),
    "path arity": (
        _P,
        [(1, [B])],
        "mainnet",
        BTClibValueError,
        "invalid recovery path 0: 2 items, not 3",
    ),
    "threshold type": (
        [(True, [A])],
        _R,
        "mainnet",
        BTClibTypeError,
        "invalid threshold of primary quorum 0 type: 'bool'",
    ),
    "keys type": (
        [(1, A)],
        _R,
        "mainnet",
        BTClibTypeError,
        "invalid keys of primary quorum 0 type: 'str'",
    ),
    "no keys": (
        [(1, [])],
        _R,
        "mainnet",
        BTClibValueError,
        "invalid primary quorum 0: no keys",
    ),
    "threshold zero": (
        [(0, [A, C])],
        _R,
        "mainnet",
        BTClibValueError,
        "invalid threshold of primary quorum 0: an int of 0 bits, not 1 to 2",
    ),
    "threshold above the keys": (
        _P,
        [(3, [B, C], 144)],
        "mainnet",
        BTClibValueError,
        "invalid threshold of recovery path 0: an int of 2 bits, not 1 to 2",
    ),
    "key type": (
        [(1, [b"key"])],
        _R,
        "mainnet",
        BTClibTypeError,
        "invalid key 0 of primary quorum 0 type: 'bytes'",
    ),
    "no KEY expression": (
        [(1, [f"{A})"])],
        _R,
        "mainnet",
        BTClibValueError,
        "invalid key 0 of primary quorum 0: not a KEY expression of the network",
    ),
    "another network": (
        [(1, [_TPUB])],
        _R,
        "mainnet",
        BTClibValueError,
        "invalid key 0 of primary quorum 0: not a KEY expression of the network",
    ),
    "private key": (
        [(1, [_XPRV])],
        _R,
        "mainnet",
        BTClibValueError,
        "invalid key 0 of primary quorum 0: a private key, where an xpub belongs",
    ),
    "a WIF": (
        [(1, [_WIF])],
        _R,
        "mainnet",
        BTClibValueError,
        "invalid key 0 of primary quorum 0: a private key, where an xpub belongs",
    ),
    "no extended key": (
        [(1, [_PUB_KEY])],
        _R,
        "mainnet",
        BTClibValueError,
        "invalid key 0 of primary quorum 0: no extended key",
    ),
    "a step": (
        [(1, [f"{A}/0"])],
        _R,
        "mainnet",
        BTClibValueError,
        "invalid key 0 of primary quorum 0: a derivation step after the account key",
    ),
    "a multipath step": (
        [(1, [f"{A}/<0;1>/*"])],
        _R,
        "mainnet",
        BTClibValueError,
        "invalid key 0 of primary quorum 0: a derivation step after the account key",
    ),
    "a wildcard": (
        _P,
        [(1, [f"{B}/*"], 144)],
        "mainnet",
        BTClibValueError,
        "invalid key 0 of recovery path 0: a derivation step after the account key",
    ),
    "a key twice in a quorum": (
        [(1, [A, C, A])],
        _R,
        "mainnet",
        BTClibValueError,
        "invalid primary quorum 0: key 2 repeats a key",
    ),
    "a key under two origins": (
        _P,
        [(1, [_OTHER_ORIGIN], 144)],
        "mainnet",
        BTClibValueError,
        "invalid key 0 of recovery path 0: its xpub has another origin before it",
    ),
    "a key under another fingerprint alone": (
        _P,
        [(1, [_OTHER_FINGERPRINT], 144)],
        "mainnet",
        BTClibValueError,
        "invalid key 0 of recovery path 0: its xpub has another origin before it",
    ),
    "a key under another path alone": (
        _P,
        [(1, [_OTHER_PATH], 144)],
        "mainnet",
        BTClibValueError,
        "invalid key 0 of recovery path 0: its xpub has another origin before it",
    ),
    "blocks type": (
        _P,
        [(1, [B], True)],
        "mainnet",
        BTClibTypeError,
        "invalid blocks of recovery path 0 type: 'bool'",
    ),
    "no blocks": (
        _P,
        [(1, [B], 0)],
        "mainnet",
        BTClibValueError,
        "invalid blocks of recovery path 0: an int of 0 bits, not 1 to 65535",
    ),
    "beyond 16 bits": (
        _P,
        [(1, [B], 65536)],
        "mainnet",
        BTClibValueError,
        "invalid blocks of recovery path 0: an int of 17 bits, not 1 to 65535",
    ),
    "blocks decreasing": (
        _P,
        [(1, [B], 144), (1, [C], 143)],
        "mainnet",
        BTClibValueError,
        "invalid blocks of recovery path 1: below the path before it",
    ),
    "primary whose __class__ says list": (
        _ClaimsList(),
        _R,
        "mainnet",
        BTClibTypeError,
        "invalid primary type: '_ClaimsList'",
    ),
    "key whose __class__ says str": (
        [(1, [_ClaimsStr()])],
        _R,
        "mainnet",
        BTClibTypeError,
        "invalid key 0 of primary quorum 0 type: '_ClaimsStr'",
    ),
    "network type": (_P, _R, 1, BTClibTypeError, "invalid network type: 'int'"),
    "network whose __class__ says str": (
        _P,
        _R,
        _ClaimsStr(),
        BTClibTypeError,
        "invalid network type: '_ClaimsStr'",
    ),
    # what parse refuses of the whole descriptor, with no position:
    # multi() takes 20 keys at most
    "parse's own rules": (
        [(1, _KEYS[:21])],
        [(1, [_KEYS[21]], 144)],
        "mainnet",
        BTClibValueError,
        "A function is needed within P2WSH",
    ),
    # six paths of 20 keys each are beyond the 3600 bytes of a P2WSH script
    "a script too large": (
        _P,
        [(1, _KEYS[:20], 144 + i) for i in range(6)],
        "mainnet",
        BTClibValueError,
        "A function is needed within P2WSH",
    ),
    # 45 one-key paths fit in the script, and a spend along the last one
    # takes more opcodes than P2WSH allows
    "beyond the resource limits": (
        _P,
        [(1, [A], 144 + i) for i in range(45)],
        "mainnet",
        BTClibValueError,
        "a sub-expression is not sane: satisfying it may exceed the resource limits",
    ),
}
# the same key in another xpub: refused in one quorum as a repeat, and in
# another quorum as a second spelling, each with its position
for _field, _xpub in _RESPELLED.items():
    _REFUSED[f"another {_field}, in the quorum"] = (
        [(2, [A, _xpub])],
        _R,
        "mainnet",
        BTClibValueError,
        "invalid primary quorum 0: key 1 repeats a key",
    )
    _REFUSED[f"another {_field}, in another quorum"] = (
        _P,
        [(1, [_xpub], 144)],
        "mainnet",
        BTClibValueError,
        "invalid key 0 of recovery path 0: its key is named before in another xpub",
    )


# the refusals of `parse` that only ``wsh()`` makes
_WSH_ONLY = {"parse's own rules", "a script too large", "beyond the resource limits"}


@pytest.mark.parametrize(
    "case,script_type",
    [
        (case, script_type)
        for case in _REFUSED
        for script_type in _SCRIPT_TYPES
        if script_type == "p2wsh" or case not in _WSH_ONLY
    ],
)
def test_what_it_refuses(case: str, script_type: Any) -> None:
    """Each refusal, of its class and with its whole message."""
    primary, recovery, network, refused, message = _REFUSED[case]
    pattern = f"^{re.escape(message)}"
    # btclib's message goes on to list the networks
    if case != "network":
        pattern += "$"
    with pytest.raises(refused, match=pattern):
        recovery_descriptors(primary, recovery, network, script_type=script_type)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "case, reason",
    [
        ("parse's own rules", "invalid number of keys in multi: an int of 5 bits"),
        (
            "a script too large",
            "miniscript too large for P2WSH: at least 4159 bytes of script",
        ),
    ],
)
def test_parse_chains_its_reason_under_bitcoin_cores_text(
    case: str, reason: str
) -> None:
    """A ``wsh()`` is refused in Bitcoin Core's words, `parse`'s the cause."""
    primary, recovery, network, refused, message = _REFUSED[case]
    with pytest.raises(refused, match=f"^{re.escape(message)}$") as raised:
        recovery_descriptors(primary, recovery, network, script_type="p2wsh")  # type: ignore[arg-type]
    assert str(raised.value.__cause__) == reason


def _deep_xpubs() -> dict[int, str]:
    """Return xpubs at depths 253, 254 and 255, derived here."""
    xprv = _ROOTS[0]
    found = {}
    for depth in range(1, 256):
        xprv = derive(xprv, "m/0")
        if depth >= 253:
            found[depth] = xpub_from_xprv(xprv)
    return found


_DEEP = _deep_xpubs()

# where a key may stand: the first key of the one primary quorum, a later
# key of a quorum, the second of two primaries, a recovery path's key
_POSITIONS: dict[str, tuple[str, Callable[[object], tuple[object, object]]]] = {
    "primary": (
        "key 0 of primary quorum 0",
        lambda key: ([(1, [key])], _R),
    ),
    "a later key": (
        "key 1 of primary quorum 0",
        lambda key: ([(1, [A, key])], _R),
    ),
    "second primary": (
        "key 0 of primary quorum 1",
        lambda key: ([(1, [A]), (1, [key])], _R),
    ),
    "recovery": (
        "key 0 of recovery path 0",
        lambda key: (_P, [(1, [key], 144)]),
    ),
    "second recovery path": (
        "key 1 of recovery path 1",
        lambda key: (_P, [(1, [B], 144), (1, [C, key], 288)]),
    ),
}


@pytest.mark.parametrize("script_type", _SCRIPT_TYPES)
@pytest.mark.parametrize("position", ["primary", "recovery"])
def test_a_key_has_room_for_the_branch_and_the_index(
    position: str, script_type: Any
) -> None:
    """Depth 253 derives addresses; 254 and 255 are refused, not returned.

    BIP32's depth is one byte, so a key at 254 or 255 parses, and both
    descriptors built on it fail at their first address.
    """
    where, call = _POSITIONS[position]
    primary, recovery = call(_DEEP[253])
    descriptors = recovery_descriptors(primary, recovery, script_type=script_type)  # type: ignore[arg-type]
    for descriptor in descriptors:
        assert descriptor.address(0)
    message = f"invalid {where}: too deep for the branch and the index"
    for depth in (254, 255):
        primary, recovery = call(_DEEP[depth])
        with pytest.raises(BTClibValueError, match=f"^{re.escape(message)}$"):
            recovery_descriptors(primary, recovery, script_type=script_type)  # type: ignore[arg-type]


@pytest.mark.parametrize("script_type", _SCRIPT_TYPES)
@pytest.mark.parametrize("position", _POSITIONS)
@pytest.mark.parametrize("secret", ["xprv", "WIF", "damaged xprv"])
def test_a_private_key_refused_is_not_quoted(
    position: str, secret: str, script_type: Any
) -> None:
    """No piece of a private key is in the refusal, nor in its chain.

    The damaged xprv is one `parse` refuses, so it is refused through
    the other branch of `_account_key`.
    """
    key = {"xprv": _XPRV, "WIF": _WIF, "damaged xprv": f"{_XPRV})"}[secret]
    _, call = _POSITIONS[position]
    primary, recovery = call(key)
    with pytest.raises(BTClibValueError) as refusal:
        recovery_descriptors(primary, recovery, script_type=script_type)  # type: ignore[arg-type]
    assert refusal.value.__cause__ is None
    assert refusal.value.__context__ is None
    assert_secret_free(refusal.value, [key, _XPRV, _WIF, _PRV_KEY, _PRV_KEY.hex()])


_PRV_INT = int.from_bytes(_PRV_KEY)
# every spelling of the private key a refusal could quote
_SECRETS: list[str | bytes] = [_XPRV, _WIF, _PRV_KEY, _PRV_KEY.hex(), str(_PRV_INT)]
# a private key handed where a key belongs, in a type that is no str
_OF_ANOTHER_TYPE: dict[str, object] = {
    "bytes": _PRV_KEY,
    "int": _PRV_INT,
    "WIF bytes": _WIF.encode(),
}


@pytest.mark.parametrize("position", _POSITIONS)
@pytest.mark.parametrize("secret", _OF_ANOTHER_TYPE)
def test_a_private_key_of_another_type_is_not_quoted(
    position: str, secret: str
) -> None:
    """A key that is no str is refused by its type's name alone."""
    value = _OF_ANOTHER_TYPE[secret]
    where, call = _POSITIONS[position]
    primary, recovery = call(value)
    message = f"invalid {where} type: '{type(value).__name__}'"
    with pytest.raises(BTClibTypeError, match=f"^{re.escape(message)}$") as refusal:
        recovery_descriptors(primary, recovery)  # type: ignore[arg-type]
    assert refusal.value.__cause__ is None
    assert refusal.value.__context__ is None
    assert_secret_free(refusal.value, _SECRETS)


_BITS = _PRV_INT.bit_length()
# (primary, recovery, the class refused, its message): a private key
# handed where any other value belongs
_SECRET_ELSEWHERE: dict[str, tuple[object, object, type[Exception], str]] = {
    "primary": (_WIF, _R, BTClibTypeError, "invalid primary type: 'str'"),
    "primary bytes": (
        _PRV_KEY,
        _R,
        BTClibTypeError,
        "invalid primary type: 'bytes'",
    ),
    "recovery": (_P, _WIF, BTClibTypeError, "invalid recovery type: 'str'"),
    "recovery bytes": (
        _P,
        _PRV_KEY,
        BTClibTypeError,
        "invalid recovery type: 'bytes'",
    ),
    "quorum": ([_WIF], _R, BTClibTypeError, "invalid primary quorum 0 type: 'str'"),
    "quorum bytes": (
        [_PRV_KEY],
        _R,
        BTClibTypeError,
        "invalid primary quorum 0 type: 'bytes'",
    ),
    "a quorum of the WIF alone": (
        [(_WIF,)],
        _R,
        BTClibValueError,
        "invalid primary quorum 0: 1 items, not 2",
    ),
    "path": (_P, [_WIF], BTClibTypeError, "invalid recovery path 0 type: 'str'"),
    "keys": (
        [(1, _WIF)],
        _R,
        BTClibTypeError,
        "invalid keys of primary quorum 0 type: 'str'",
    ),
    "keys bytes": (
        [(1, _PRV_KEY)],
        _R,
        BTClibTypeError,
        "invalid keys of primary quorum 0 type: 'bytes'",
    ),
    "threshold": (
        [(_PRV_INT, [A])],
        _R,
        BTClibValueError,
        f"invalid threshold of primary quorum 0: an int of {_BITS} bits, not 1 to 1",
    ),
    "threshold bytes": (
        [(_PRV_KEY, [A])],
        _R,
        BTClibTypeError,
        "invalid threshold of primary quorum 0 type: 'bytes'",
    ),
    "blocks": (
        _P,
        [(1, [B], _PRV_INT)],
        BTClibValueError,
        f"invalid blocks of recovery path 0: an int of {_BITS} bits, not 1 to 65535",
    ),
    "blocks bytes": (
        _P,
        [(1, [B], _PRV_KEY)],
        BTClibTypeError,
        "invalid blocks of recovery path 0 type: 'bytes'",
    ),
}


@pytest.mark.parametrize("case", _SECRET_ELSEWHERE)
def test_a_private_key_anywhere_else_is_not_quoted(case: str) -> None:
    """A private key in place of a quorum, a threshold or the blocks.

    Each refusal names the type, a length or the bits of an int, and no
    piece of the key.
    """
    primary, recovery, refused, message = _SECRET_ELSEWHERE[case]
    with pytest.raises(refused, match=f"^{re.escape(message)}$") as refusal:
        recovery_descriptors(primary, recovery)  # type: ignore[arg-type]
    assert refusal.value.__cause__ is None
    assert refusal.value.__context__ is None
    assert_secret_free(refusal.value, _SECRETS)


# every position a value has: where the refusal says it is, and a call
# with the value there, the script type given, and plain values
# everywhere else
_EVERY_POSITION: dict[
    str, tuple[str, Callable[[object, Any], tuple[Any, Any, Any, Any]]]
] = {
    "primary": ("primary", lambda v, t: (v, _R, "mainnet", t)),
    "recovery": ("recovery", lambda v, t: (_P, v, "mainnet", t)),
    "quorum": ("primary quorum 0", lambda v, t: ([v], _R, "mainnet", t)),
    "path": ("recovery path 0", lambda v, t: (_P, [v], "mainnet", t)),
    "keys of a quorum": (
        "keys of primary quorum 0",
        lambda v, t: ([(1, v)], _R, "mainnet", t),
    ),
    "keys of a path": (
        "keys of recovery path 0",
        lambda v, t: (_P, [(1, v, 144)], "mainnet", t),
    ),
    "threshold of a quorum": (
        "threshold of primary quorum 0",
        lambda v, t: ([(v, [A])], _R, "mainnet", t),
    ),
    "threshold of a path": (
        "threshold of recovery path 0",
        lambda v, t: (_P, [(v, [B], 144)], "mainnet", t),
    ),
    "blocks": (
        "blocks of recovery path 0",
        lambda v, t: (_P, [(1, [B], v)], "mainnet", t),
    ),
    "key of a quorum": (
        "key 0 of primary quorum 0",
        lambda v, t: ([(1, [v])], _R, "mainnet", t),
    ),
    "key of a path": (
        "key 0 of recovery path 0",
        lambda v, t: (_P, [(1, [v], 144)], "mainnet", t),
    ),
    "network": ("network", lambda v, t: (_P, _R, v, t)),
    "script_type": ("script_type", lambda v, _t: (_P, _R, "mainnet", v)),
}


def _called(primary: Any, recovery: Any, network: Any, script_type: Any) -> object:
    """Call `recovery_descriptors`, the script type by its keyword."""
    return recovery_descriptors(primary, recovery, network, script_type=script_type)


@pytest.mark.parametrize("script_type", _SCRIPT_TYPES)
@pytest.mark.parametrize("position", _EVERY_POSITION)
@pytest.mark.parametrize("kind", _SUBCLASSES)
def test_a_subclass_is_refused_in_every_position(
    kind: str, position: str, script_type: Any
) -> None:
    """A subclass of int, str, tuple or list, or an IntEnum, is refused.

    With its position and its type's name, and nothing of it run: each
    method of the hostile ones raises with the WIF, and so does its
    `__class__`; its metaclass's `__name__` is the WIF.
    """
    where, call = _EVERY_POSITION[position]
    message = f"invalid {where} type: '{_SUBCLASS_NAMES[kind]}'"
    with pytest.raises(BTClibTypeError, match=f"^{re.escape(message)}$") as refusal:
        _called(*call(_SUBCLASSES[kind](), script_type))
    assert refusal.value.__cause__ is None
    assert refusal.value.__context__ is None
    assert_secret_free(refusal.value, _SECRETS)


# what is no tuple and no list, where a sequence belongs
_NO_SEQUENCES: dict[str, Callable[[], object]] = {
    "generator": lambda: ((1, [A]) for _ in range(1)),
    "dict": lambda: {0: (1, [A])},
    "set": lambda: {1},
    "range": lambda: range(2),
    "bytes": lambda: b"\x01\x02",
}
_SEQUENCE_POSITIONS = [
    "primary",
    "recovery",
    "quorum",
    "path",
    "keys of a quorum",
    "keys of a path",
]


@pytest.mark.parametrize("script_type", _SCRIPT_TYPES)
@pytest.mark.parametrize("position", _SEQUENCE_POSITIONS)
@pytest.mark.parametrize("kind", _NO_SEQUENCES)
def test_what_is_no_tuple_or_list_is_refused(
    kind: str, position: str, script_type: Any
) -> None:
    """A generator, a dict, a set, a range and bytes, each with its position."""
    where, call = _EVERY_POSITION[position]
    message = f"invalid {where} type: '{kind}'"
    with pytest.raises(BTClibTypeError, match=f"^{re.escape(message)}$"):
        _called(*call(_NO_SEQUENCES[kind](), script_type))


class _ChangingQuorum(list[object]):
    """A quorum that is 2-of-2 when first read, and 1-of-2 after."""

    reads = 0

    @override
    def __iter__(self) -> Any:
        self.reads += 1
        threshold = 2 if self.reads == 1 else 1
        return iter((threshold, _SIGNER_KEYS[:2]))


class _SelfIterator(list[object]):
    """A sequence that is its own iterator, and whose length raises."""

    reads = 0

    @override
    def __iter__(self) -> Any:
        self.reads += 1
        return self

    def __next__(self) -> object:
        raise StopIteration

    @override
    def __len__(self) -> int:
        raise RuntimeError(_WIF)


def test_a_sequence_that_changes_or_iterates_itself_is_refused_unread() -> None:
    """Each is refused with its position, and none of it is read.

    Read, the changing quorum would have the function emit a 1-of-2 for
    the 2-of-2 it validated, and the self iterator's `__len__` would
    leave as a bare RuntimeError. The control: the 2-of-2 the quorum
    shows first needs both signatures.
    """
    quorum = _ChangingQuorum([2, _SIGNER_KEYS[:2]])
    message = "invalid primary quorum 0 type: '_ChangingQuorum'"
    with pytest.raises(BTClibTypeError, match=f"^{re.escape(message)}$"):
        recovery_descriptors([quorum], [(1, [_SIGNER_KEYS[2]], 144)])  # type: ignore[list-item]
    assert quorum.reads == 0
    two_of_two, _ = recovery_descriptors(
        [(2, _SIGNER_KEYS[:2])], [(1, [_SIGNER_KEYS[2]], 144)]
    )
    with pytest.raises(BTClibValueError, match=f"^{re.escape(_NO_SATISFACTION)}$"):
        _spend(two_of_two, [(0, 0)], _NO_LOCK)
    _spend(two_of_two, [(0, 0), (1, 0)], _NO_LOCK)
    for position in _SEQUENCE_POSITIONS:
        for script_type in _SCRIPT_TYPES:
            where, call = _EVERY_POSITION[position]
            sequence = _SelfIterator()
            message = f"invalid {where} type: '_SelfIterator'"
            with pytest.raises(
                BTClibTypeError, match=f"^{re.escape(message)}$"
            ) as refusal:
                _called(*call(sequence, script_type))
            assert sequence.reads == 0
            assert_secret_free(refusal.value, _SECRETS)


def test_the_hostile_values_raise() -> None:
    """The control of the two tests above: each hostile method does raise.

    So a refusal that read any of them would leave with the WIF.
    """
    asks: list[Callable[[Any], object]] = [
        lambda v: format(v, ""),
        len,
        iter,
        lambda v: v == 0,
        lambda v: v.__class__,
    ]
    for make in (_SUBCLASSES[kind] for kind in ("int", "str", "tuple", "list")):
        value = make()
        for ask in asks:
            with pytest.raises(RuntimeError, match=f"^{_WIF}$"):
                ask(value)
        assert type(value).__name__ == _WIF
    with pytest.raises(RuntimeError, match=f"^{_WIF}$"):
        len(_SelfIterator())
    assert list(_ChangingQuorum([])) == [2, _SIGNER_KEYS[:2]]
    # what `isinstance` would have said of the two that claim a type
    assert isinstance(_ClaimsStr(), str)
    assert isinstance(_ClaimsList(), list)
    assert next(iter(_SelfIterator()), None) is None


# the classes `_exploding` built, whose `mro` raises from then on
_BUILT: set[int] = set()


class _Exploding(type):
    """A metaclass whose every method a type check could call raises.

    `mro` returns the usual order while the class is built, which calls
    it, and raises once `_exploding` has recorded the class as built.
    """

    @override
    def __eq__(cls, other: object) -> bool:
        raise RuntimeError(_WIF)

    @override
    def __ne__(cls, other: object) -> bool:
        raise RuntimeError(_WIF)

    @override
    def __hash__(cls) -> int:
        raise RuntimeError(_WIF)

    @override
    def __instancecheck__(cls, instance: object) -> bool:
        raise RuntimeError(_WIF)

    @override
    def __subclasscheck__(cls, subclass: type) -> bool:
        raise RuntimeError(_WIF)

    @property
    @override
    def __name__(cls) -> str:  # type: ignore[override]
        raise RuntimeError(_WIF)

    @override
    def __getattribute__(cls, name: str) -> Any:
        # a class body cannot hold a `__qualname__` of the metaclass's own,
        # so its reading is what raises
        if name == "__qualname__":
            raise RuntimeError(_WIF)
        return type.__getattribute__(cls, name)

    @override
    def __repr__(cls) -> str:
        raise RuntimeError(_WIF)

    # type has no `__bool__` to override, so it is `_raises` itself
    __bool__ = _raises

    @override
    def mro(cls) -> list[type]:
        if id(cls) in _BUILT:
            raise RuntimeError(_WIF)
        return type.mro(cls)


def _exploding(base: type, name: str) -> type:
    """Return a subclass of `base` of metaclass `_Exploding`.

    Its instances' methods raise with the WIF too, as `_hostile`'s do.
    """
    body: dict[str, object] = dict.fromkeys(_METHODS, _raises)
    body["__class__"] = property(_raises)
    cls = _Exploding(name, (base,), body)
    _BUILT.add(id(cls))
    return cls


_EXPLODING = {
    "int": (_exploding(int, "_ExplodingInt"), 2),
    "str": (_exploding(str, "_ExplodingStr"), A),
    "tuple": (_exploding(tuple, "_ExplodingTuple"), (1, [A])),
    "list": (_exploding(list, "_ExplodingList"), [(1, [A])]),
}


@pytest.mark.parametrize("script_type", _SCRIPT_TYPES)
@pytest.mark.parametrize("position", _EVERY_POSITION)
@pytest.mark.parametrize("kind", _EXPLODING)
def test_a_metaclass_runs_nowhere(kind: str, position: str, script_type: Any) -> None:
    """A subclass whose metaclass raises from every method is refused.

    By its position and its class's own name, read by `type`'s descriptor:
    `in`, `==`, `hash`, `isinstance`, `issubclass`, `bool`, `repr` and the
    metaclass's `__name__` would each raise with the WIF.
    """
    where, call = _EVERY_POSITION[position]
    cls, held = _EXPLODING[kind]
    message = f"invalid {where} type: '_Exploding{kind.title()}'"
    with pytest.raises(BTClibTypeError, match=f"^{re.escape(message)}$") as refusal:
        _called(*call(cls(held), script_type))
    assert refusal.value.__cause__ is None
    assert refusal.value.__context__ is None
    assert_secret_free(refusal.value, _SECRETS)


# the classes `_LateMro` leaves str out of the order of, by id
_LEFT_OUT: set[int] = set()


class _LateMro(type):
    """A metaclass that leaves str out of a class's order once told to.

    Told only after the class has made the instance a class is named
    with: on PyPy a class without str in its order takes no argument.
    """

    @override
    def mro(cls) -> list[type]:
        return [cls, object] if id(cls) in _LEFT_OUT else type.mro(cls)

    @property
    @override
    def __name__(cls) -> str:  # type: ignore[override]
        raise RuntimeError(_WIF)


class _NameText(str, metaclass=_LateMro):
    """A str whose methods raise, str in its order."""

    __slots__ = ()

    @override
    def __len__(self) -> int:
        raise RuntimeError(_WIF)

    @override
    def __add__(self, other: str) -> str:
        raise RuntimeError(_WIF)


class _LeftOutText(str, metaclass=_LateMro):
    """A str whose methods raise, str left out of its order below."""

    __slots__ = ()

    @override
    def __len__(self) -> int:
        raise RuntimeError(_WIF)

    @override
    def __add__(self, other: str) -> str:
        raise RuntimeError(_WIF)


_PLAIN_NAME = _NameText("_Plain")
_ARMED_NAME = _LeftOutText("_Renamed")
# assigning the bases asks `mro` again: str leaves _LeftOutText's order
_LEFT_OUT.add(id(_LeftOutText))
_LeftOutText.__bases__ = (str,)

_PYPY = platform.python_implementation() == "PyPy"


def _renamed(name: str) -> type:
    """Return a list subclass whose `__name__` is assigned `name`."""
    renamed = type("_Original", (list,), {})
    renamed.__name__ = name
    return renamed


def test_a_class_named_by_a_str_subclass_is_named() -> None:
    """A class's name can be an instance of a caller's str subclass.

    The refusal names the class all the same, and runs neither the
    metaclass's `__name__` nor any method of the name. On CPython the
    class keeps the instance as its name, on PyPy a str copied from it.
    """
    for name, text in ((_PLAIN_NAME, "_Plain"), (_ARMED_NAME, "_Renamed")):
        message = f"invalid primary type: '{text}'"
        with pytest.raises(BTClibTypeError, match=f"^{re.escape(message)}$") as refusal:
            recovery_descriptors(_renamed(name)(), _R)
        assert_secret_free(refusal.value, _SECRETS)
        with pytest.raises(RuntimeError, match=f"^{_WIF}$"):
            len(name)
        with pytest.raises(RuntimeError, match=f"^{_WIF}$"):
            operator.add(name, "")
    with pytest.raises(RuntimeError, match=f"^{_WIF}$"):
        _ = type(_ARMED_NAME).__name__


@pytest.mark.skipif(_PYPY, reason="PyPy keeps a str copied from a class's name")
def test_a_name_left_out_of_str_is_still_copied() -> None:
    """The control of the test above, where CPython keeps the instance.

    Once str has left its class's order, `isinstance` denies the name is
    a str and `str.__add__` refuses it: `"".join` is what copies it.
    """
    stored = vars(type)["__name__"].__get__(_renamed(_ARMED_NAME), type)
    assert type(stored) is _LeftOutText
    # an object to mypy, which would take a `_LeftOutText` for a str
    text: object = stored
    assert not isinstance(text, str)
    with pytest.raises(TypeError, match="^descriptor '__add__' requires"):
        str.__add__(stored, "")
    # as `_refused_type` copies it: an f-string would call its `__format__`
    copied = "".join((stored,))  # noqa: FLY002
    assert type(copied) is str
    assert copied == "_Renamed"


class _EqualsAnything(type):
    """A metaclass equal to every type."""

    __hash__ = type.__hash__

    @override
    def __eq__(cls, other: object) -> bool:
        return True


class _OneOfTwo(list[object], metaclass=_EqualsAnything):
    """A quorum that holds [2, keys] and whose iteration gives (1, keys)."""

    reads = 0

    @override
    def __iter__(self) -> Any:
        self.reads += 1
        return iter((1, _SIGNER_KEYS[:2]))


class _EqualsRaises(type):
    """A metaclass whose equality raises with the WIF."""

    __hash__ = type.__hash__

    @override
    def __eq__(cls, other: object) -> bool:
        raise RuntimeError(_WIF)


class _RaisingList(list[object], metaclass=_EqualsRaises):
    """A list whose metaclass's equality raises with the WIF."""


@pytest.mark.parametrize("script_type", _SCRIPT_TYPES)
@pytest.mark.parametrize("position", _SEQUENCE_POSITIONS)
def test_a_metaclass_equality_decides_no_type(position: str, script_type: Any) -> None:
    """A metaclass's equality decides no type, in each sequence position.

    Asked through `in`, the one equal to every type would make a 2-of-2
    a 1-of-2, and the one whose equality raises would let the WIF out
    bare.
    """
    where, call = _EVERY_POSITION[position]
    weaker = _OneOfTwo([2, _SIGNER_KEYS[:2]])
    message = f"invalid {where} type: '_OneOfTwo'"
    with pytest.raises(BTClibTypeError, match=f"^{re.escape(message)}$"):
        _called(*call(weaker, script_type))
    assert weaker.reads == 0
    message = f"invalid {where} type: '_RaisingList'"
    with pytest.raises(BTClibTypeError, match=f"^{re.escape(message)}$") as refusal:
        _called(*call(_RaisingList(), script_type))
    assert_secret_free(refusal.value, _SECRETS)


def test_the_metaclasses_answer_otherwise() -> None:
    """The control of the two tests above: each metaclass method does answer.

    So a type check that called any of them would raise with the WIF, or
    take the 1-of-2.
    """
    asks: list[Callable[[type], object]] = [
        lambda c: operator.eq(c, list),
        lambda c: operator.ne(c, list),
        hash,
        lambda c: isinstance([], c),
        lambda c: issubclass(list, c),
        lambda c: c.__name__,
        lambda c: c.__qualname__,
        repr,
        bool,
        lambda c: c.mro(),
    ]
    for cls, _ in _EXPLODING.values():
        for ask in asks:
            with pytest.raises(RuntimeError, match=f"^{_WIF}$"):
                ask(cls)
    assert operator.eq(_OneOfTwo, list)
    assert list(_OneOfTwo([2, _SIGNER_KEYS[:2]])) == [1, _SIGNER_KEYS[:2]]
    with pytest.raises(RuntimeError, match=f"^{_WIF}$"):
        operator.eq(_RaisingList, list)


# a private key handed as the network
_NETWORKS: dict[str, tuple[object, type[Exception], str]] = {
    "WIF": (
        _WIF,
        BTClibValueError,
        f"unknown network (too long to quote); it must be one of {sorted(NETWORKS)}",
    ),
    "bytes": (_PRV_KEY, BTClibTypeError, "invalid network type: 'bytes'"),
    "int": (_PRV_INT, BTClibTypeError, "invalid network type: 'int'"),
}


@pytest.mark.parametrize("secret", _NETWORKS)
def test_a_private_key_as_the_network_is_not_quoted(secret: str) -> None:
    """Its message names the type, or says the name is too long.

    `assert_secret_free` reads the chain's messages, attributes and
    notes, `__notes__` being an attribute.
    """
    network, refused, message = _NETWORKS[secret]
    with pytest.raises(refused, match=f"^{re.escape(message)}$") as refusal:
        recovery_descriptors(_P, _R, network)  # type: ignore[arg-type]
    assert refusal.value.__cause__ is None
    assert refusal.value.__context__ is None
    assert_secret_free(refusal.value, _SECRETS)


# the witness elements of each spend, the primary path's first, with one
# to four one-key recovery paths
_WITNESS_ELEMENTS = [[3, 3], [3, 4, 4], [3, 4, 5, 5], [3, 4, 5, 6, 6]]


@pytest.mark.parametrize("paths", [1, 2, 3, 4])
def test_a_path_lengthens_the_witness_of_the_path_before_it(paths: int) -> None:
    """A path added last lengthens the spends of the path before it alone.

    The selector of the ``or_i()`` that joins it: the primary path and
    the paths before the last one spend with the elements they had.
    """
    keys = _SIGNER_KEYS
    descriptor, _ = recovery_descriptors(
        [(1, [keys[0]])], [(1, [keys[i]], 144) for i in range(1, paths + 1)]
    )
    spends = [_spend(descriptor, [(0, 0)], _NO_LOCK)]
    spends += [_spend(descriptor, [(i, 0)], 144) for i in range(1, paths + 1)]
    elements = [len(s.inputs[0].final_script_witness.stack) for s in spends]
    assert elements == _WITNESS_ELEMENTS[paths - 1]


# BIP341's NUMS point H, x-only, as the BIP spells it
_H = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")


def _unspendable(keys: list[str], network: str = "mainnet") -> str:
    """Return the internal key nobody signs for, as the docstring defines it.

    The xpub of H, its chain code the sha256 of the account keys' public
    keys, each once in the order first named.
    """
    public = b"".join(
        BIP32KeyData.b58decode(key.split("]")[-1]).key for key in dict.fromkeys(keys)
    )
    chain_code = hashlib.sha256(public).digest()
    version = NETWORKS[network].bip32_pub
    return BIP32KeyData(version, 0, bytes(4), 0, chain_code, b"\x02" + _H).b58encode()


def _n(chain: int, *keys: str) -> str:
    """Return the unspendable internal key of these account keys on a chain."""
    return f"{_unspendable(list(keys))}/{chain}/*"


# (primary, recovery, the receive and change descriptors as a function of
# the chain), under tr(): the policies of _POLICIES that tell the shapes
# apart, and two primary quorums of one key each
_TR_POLICIES: dict[
    str,
    tuple[
        list[tuple[int, list[str]]],
        list[tuple[int, list[str], int]],
        Callable[[int], str],
    ],
] = {
    # the primary key is the internal key, and the tree is one leaf
    "simple inheritance": (
        [(1, [A])],
        [(1, [B], 52560)],
        lambda c: (
            f"tr({_keys(c, (A, 0))},and_v(v:pk({_keys(c, (B, 0))}),older(52560)))"
        ),
    ),
    # a primary quorum is a leaf beside the recovery leaf
    "multisig security": (
        [(2, [A, B])],
        [(2, [A, B, C], 4320)],
        lambda c: (
            f"tr({_n(c, A, B, C)},{{multi_a(2,{_keys(c, (A, 0), (B, 0))}),"
            f"and_v(v:multi_a(2,{_keys(c, (A, 2), (B, 2), (C, 0))}),older(4320))}})"
        ),
    ),
    "expanding": (
        [(2, [A, B, C])],
        [(2, [A, B, C, D], 4320)],
        lambda c: (
            f"tr({_n(c, A, B, C, D)},{{multi_a(2,{_keys(c, (A, 0), (B, 0), (C, 0))}),"
            f"and_v(v:multi_a(2,{_keys(c, (A, 2), (B, 2), (C, 2), (D, 0))}),"
            "older(4320))})"
        ),
    ),
    # the recovery leaves nest to the right below the primary leaf
    "decaying twice": (
        [(3, [A, B, C])],
        [(2, [A, B, C], 144), (1, [A, B, C], 4320)],
        lambda c: (
            f"tr({_n(c, A, B, C)},{{multi_a(3,{_keys(c, (A, 0), (B, 0), (C, 0))}),"
            f"{{and_v(v:multi_a(2,{_keys(c, (A, 2), (B, 2), (C, 2))}),older(144)),"
            f"and_v(v:multi_a(1,{_keys(c, (A, 4), (B, 4), (C, 4))}),older(4320))}}}})"
        ),
    ),
    # two primary quorums are one leaf that asks for both
    "two primaries, three paths": (
        [(1, [A]), (2, [A, B])],
        [(1, [C], 144), (2, [D, E], 4320), (1, [F], 52560)],
        lambda c: (
            f"tr({_n(c, A, B, C, D, E, F)},"
            f"{{and_v(v:pk({_keys(c, (A, 0))}),multi_a(2,{_keys(c, (A, 2), (B, 0))})),"
            f"{{and_v(v:pk({_keys(c, (C, 0))}),older(144)),"
            f"{{and_v(v:multi_a(2,{_keys(c, (D, 0), (E, 0))}),older(4320)),"
            f"and_v(v:pk({_keys(c, (F, 0))}),older(52560))}}}}}})"
        ),
    ),
    "two primaries of one key": (
        [(1, [A]), (1, [B])],
        [(1, [C], 144)],
        lambda c: (
            f"tr({_n(c, A, B, C)},{{and_v(v:pk({_keys(c, (A, 0))}),pk({_keys(c, (B, 0))})),"
            f"and_v(v:pk({_keys(c, (C, 0))}),older(144))}})"
        ),
    ),
    # the primary key is the internal key, and the recovery leaves nest
    # to the right from the root
    "one key, five quorums": (
        [(1, [A])],
        [(1, [A], 144), (1, [A], 288), (1, [A], 432), (1, [A], 576)],
        lambda c: (
            f"tr({_keys(c, (A, 0))},{{and_v(v:pk({_keys(c, (A, 2))}),older(144)),"
            f"{{and_v(v:pk({_keys(c, (A, 4))}),older(288)),"
            f"{{and_v(v:pk({_keys(c, (A, 6))}),older(432)),"
            f"and_v(v:pk({_keys(c, (A, 8))}),older(576))}}}}}})"
        ),
    ),
    "equal locks": (
        [(1, [A])],
        [(2, [B, C, D], 52560), (1, [E], 52560)],
        lambda c: (
            f"tr({_keys(c, (A, 0))},"
            f"{{and_v(v:multi_a(2,{_keys(c, (B, 0), (C, 0), (D, 0))}),older(52560)),"
            f"and_v(v:pk({_keys(c, (E, 0))}),older(52560))}})"
        ),
    ),
}


@pytest.mark.parametrize("policy", _TR_POLICIES)
def test_each_tr_policy_is_one_call(policy: str) -> None:
    """Each policy is one call under tr(), which writes the shape it is owed.

    And the text read back is the descriptor returned, checksum included.
    """
    primary, recovery, expected = _TR_POLICIES[policy]
    descriptors = recovery_descriptors(primary, recovery, script_type="p2tr")
    assert tuple(str(descriptor) for descriptor in descriptors) == (
        expected(0),
        expected(1),
    )
    for descriptor in descriptors:
        assert isinstance(descriptor, TrDescriptor)
        assert parse(add_checksum(str(descriptor))) == descriptor


# (the checksum, the address at index 0 and the one at 2**31 - 1) of the
# receive and the change descriptor of _TR_POLICIES that tell the shapes
# apart. Bitcoin Core v32.1's `getdescriptorinfo` and `deriveaddresses`
# gave them, on mainnet, for the text this function writes
_CORE_VECTORS = {
    "simple inheritance": (
        (
            "uujv02pc",
            "bc1pnulajkzf2epqxurmz5wczxa943t26gkq8w3l4x58ctl6e038xheq6a64gs",
            "bc1pvj7xncxaex2yw350tm3gyfgvzvf3ajk8qalfw8s6g3y27wqfhdyqpxwm5g",
        ),
        (
            "5y6g9yua",
            "bc1pmcvjpanauwwyjgl0t9vytentjhf3hlumhwyg7mjhwmq0gdz2l82qezzp2m",
            "bc1psfejplu87s65mrpnjpq9nmdqs3fg6tv2lwf8jj58z9le6l5azt9q2rd9cx",
        ),
    ),
    "multisig security": (
        (
            "7j4kwukq",
            "bc1pqd2nqrk2z2ldqdvlyn7l55yncsm6m32p77yy2tz776c3hfnm8t0q7nda9k",
            "bc1pe52ezc48c7rzarwu9c4fnrk2dvncjdmg5klc9zf9e6v2qgszst9qlgcwdq",
        ),
        (
            "ufmzukc4",
            "bc1pgyc2tn75g3r94clxd4gxyygr0wxsejh86gq70axa62j6tnsqxahqle2zx5",
            "bc1pw445vhklgg80eyear4kssg5susxz8rx58kr4jpfht630fa2jrg2syx0htv",
        ),
    ),
    "decaying twice": (
        (
            "5vdnuvz0",
            "bc1pul9895m49jn556w8nrexucf4r6j2296mnwq6xt86prfptrhlpe4s0vkk2d",
            "bc1pf6fdc73f3skp9mz5s025tzr8zagtdsz6qvvhrrcrhnjt9dwh09zqsq3nk2",
        ),
        (
            "95n0rk0v",
            "bc1pq9saqdttdvalpuwehrv8t8n8ayf9y4mjt2gst8vhcazpsnsw4wyqcy3ygy",
            "bc1ptz0u4f7z076ag6a3ng7axgpk5ups5tjl37atcs5jpcwtghylk4mqxgckh5",
        ),
    ),
    "two primaries, three paths": (
        (
            "38cyw9us",
            "bc1pqvvqh77l06pukhmxsrdpfv0unf00f9jhg4wu24sav0xje7wgua4s2rdg2l",
            "bc1prf7racjqh89l476juuylltaefqnnspe0ntkzx27304mzeez5sdtqvngsz9",
        ),
        (
            "js0m0050",
            "bc1p262kpkkhef254qgqr3xxhvv36cw4g3ve00tce5lyy7mkqqv7472quukaf6",
            "bc1p7pmtzzjhq2qsdh489qqwd9j94ypy9dxrld6m7759emfjxaepq8qqgad0ez",
        ),
    ),
}


@pytest.mark.parametrize("policy", _CORE_VECTORS)
def test_the_tr_addresses_are_bitcoin_cores(policy: str) -> None:
    """The checksum and the addresses Bitcoin Core derives from this text."""
    primary, recovery, _ = _TR_POLICIES[policy]
    descriptors = recovery_descriptors(primary, recovery, script_type="p2tr")
    for descriptor, (checksum, first, last) in zip(
        descriptors, _CORE_VECTORS[policy], strict=True
    ):
        assert add_checksum(str(descriptor)) == f"{descriptor}#{checksum}"
        assert descriptor.address(0) == first
        assert descriptor.address(2**31 - 1) == last


def test_the_unspendable_key_is_bip341s_h_moved_at_each_index() -> None:
    """The internal key's xpub holds H, and each address an H + rG of its own.

    Its chain code is the sha256 of the account keys' public keys, each
    once in the order first named, so a key named again does not change
    it: B in the recovery path is in the primary quorum before.
    """
    for chain, descriptor in enumerate(
        recovery_descriptors([(2, [A, B])], [(1, [B, C], 144)], script_type="p2tr")
    ):
        assert isinstance(descriptor, TrDescriptor)
        internal = descriptor.internal_key
        assert str(internal) == _n(chain, A, B, C)
        data = BIP32KeyData.b58decode(internal.xkey)
        assert data.key == b"\x02" + _H
        assert (data.depth, data.parent_fingerprint, data.index) == (0, bytes(4), 0)
        keys = {internal.sec(index)[1:] for index in (0, 1, 2**31 - 1)}
        assert len(keys) == 3
        assert _H not in keys


@pytest.mark.parametrize("network", ["testnet", "regtest", "signet", "testnet4"])
def test_each_network_takes_its_own_tr_keys(network: str) -> None:
    """Under tr(), the unspendable key takes the network's xpub version too."""
    net = NETWORKS[network]
    roots = [rootxprv_from_seed(bytes([i]) * 16, net.bip32_prv) for i in (1, 2, 3)]
    keys = [xpub_from_xprv(derive(root, "m/48h/1h/0h/2h")) for root in roots]
    descriptors = recovery_descriptors(
        [(2, keys[:2])], [(1, [keys[2]], 144)], network, script_type="p2tr"
    )
    for chain, descriptor in enumerate(descriptors):
        unspendable = _unspendable(keys, network)
        assert str(descriptor) == (
            f"tr({unspendable}/{chain}/*,{{multi_a(2,{keys[0]}/{chain}/*,"
            f"{keys[1]}/{chain}/*),and_v(v:pk({keys[2]}/{chain}/*),older(144))}})"
        )
        for index in (0, 2**31 - 1):
            assert descriptor.address(index).startswith(f"{net.hrp}1p")


def _signed_tr(
    descriptor: Descriptor,
    signers: list[tuple[int, int]],
    sequence: int,
    leaf: int | None,
) -> tuple[Psbt, TxOut]:
    """Return the psbt spending index 3 of a tr() descriptor, signed.

    `leaf` is the leaf's position in the tree, None for the key path;
    `signers` are (signer, branch) pairs, as `_spend` takes them. The
    Updater writes the taproot fields from the descriptor.
    """
    assert isinstance(descriptor, TrDescriptor)
    index = 3
    prevout = TxOut(50_000, descriptor.script_pub_key(index))
    tx = Tx(
        version=2,
        vin=[TxIn(OutPoint(b"\x05" * 32, 0), sequence=sequence)],
        vout=[TxOut(49_000, prevout.script_pub_key)],
    )
    psbt = Psbt.from_tx(tx)
    psbt.inputs[0].witness_utxo = prevout
    psbt = update_psbt_input(descriptor, psbt, 0, index)
    hash_ = None
    if leaf is not None:
        hash_ = leaf_hash(0xC0, descriptor.taproot_tree(index)[leaf][2])
    for signer, branch in signers:
        xprv = derive(_ROOTS[signer], f"{_ACCOUNT}/{branch}/{index}")
        prv_key = int.from_bytes(BIP32KeyData.b58decode(xprv).key[1:])
        if hash_ is None:
            tweaked = output_prvkey_from_merkle_root(
                prv_key, descriptor.taproot_merkle_root(index)
            )
            signature = ssa.sign_(taproot_sig_hash(psbt, 0), tweaked).serialize()
            psbt.inputs[0].taproot_key_spend_signature = signature
            continue
        msg_hash = taproot_sig_hash(psbt, 0, leaf_hash=hash_)
        x_only = PrvKeyData(prv_key).pub.sec[1:]
        signature = ssa.sign_(msg_hash, prv_key).serialize()
        psbt.inputs[0].taproot_script_spend_signatures[x_only + hash_] = signature
    return psbt, prevout


def _tr_spend(
    descriptor: Descriptor,
    signers: list[tuple[int, int]],
    sequence: int,
    leaf: int | None,
) -> Psbt:
    """Return the finalized psbt of `_signed_tr`, which the engine runs.

    And the control: with its first signature emptied, the same spend is
    one the engine refuses.
    """
    psbt, prevout = _signed_tr(descriptor, signers, sequence, leaf)
    final = finalize(psbt, solver=miniscript_solver)
    stack = final.inputs[0].final_script_witness.stack
    spending = final.tx
    spending.vin[0].script_witness = Witness(stack)
    verify_transaction([prevout], spending)
    first = next(i for i, item in enumerate(stack) if len(item) == 64)
    spending.vin[0].script_witness = Witness([*stack[:first], b"", *stack[first + 1 :]])
    with pytest.raises(BTClibValueError):
        verify_transaction([prevout], spending)
    return final


# (primary, recovery, and each path: the blocks it waits, none for the
# primary path, and the (signer, branch pair) that sign it), under tr()
_TR_SPENDS = {
    "simple inheritance": (
        [(1, [0])],
        [(1, [1], 144)],
        [(None, [(0, 0)]), (144, [(1, 0)])],
    ),
    "decaying twice": (
        [(3, [0, 1, 2])],
        [(2, [0, 1, 2], 144), (1, [0, 1, 2], 4320)],
        [
            (None, [(0, 0), (1, 0), (2, 0)]),
            (144, [(0, 2), (2, 2)]),
            (4320, [(1, 4)]),
        ],
    ),
    "two primaries": (
        [(1, [0]), (2, [1, 2])],
        [(1, [3], 144)],
        [(None, [(0, 0), (1, 0), (2, 0)]), (144, [(3, 0)])],
    ),
    "equal locks": (
        [(1, [0])],
        [(2, [1, 2, 3], 144), (1, [4], 144)],
        [(None, [(0, 0)]), (144, [(1, 0), (3, 0)]), (144, [(4, 0)])],
    ),
    "20 of 20": (
        [(20, list(range(20)))],
        [(20, list(range(20)), 144)],
        [
            (None, [(s, 0) for s in range(20)]),
            (144, [(s, 2) for s in range(20)]),
        ],
    ),
    "one key, five quorums": (
        [(1, [0])],
        [(1, [0], 144), (1, [0], 288), (1, [0], 432), (1, [0], 576)],
        [
            (None, [(0, 0)]),
            (144, [(0, 2)]),
            (288, [(0, 4)]),
            (432, [(0, 6)]),
            (576, [(0, 8)]),
        ],
    ),
}

_TR_SPEND_CASES = [
    pytest.param(policy, path, chain, id=f"{policy}-path {path}-chain {chain}")
    for policy, (_, _, paths) in _TR_SPENDS.items()
    for path in range(len(paths))
    for chain in (0, 1)
]

# what `finalize` says of a spend one signature short: no signature at
# all, or a leaf the solver cannot satisfy
_SHORT = f"^(input 0: missing taproot signature|{re.escape(_NO_SATISFACTION)})$"


def _tr_leaf(primary: list[tuple[int, list[int]]], path: int) -> int | None:
    """Return the leaf of a path, None for the key path.

    A primary path of one quorum, of one key, is the internal key, and
    the recovery paths are the leaves; otherwise the primary path is the
    first leaf.
    """
    if len(primary) == 1 and len(primary[0][1]) == 1:
        return None if path == 0 else path - 1
    return path


@pytest.mark.parametrize("policy,path,chain", _TR_SPEND_CASES)
def test_each_tr_path_spends_with_its_signatures_once_its_timelock_has_passed(
    policy: str, path: int, chain: int
) -> None:
    """Sign along one path, and spend: with its signatures, at its timelock.

    `finalize` builds the spend with `miniscript_solver`, and the script
    engine runs it. One signature fewer is refused, and so is a sequence
    one block short of the lock.
    """
    primary, recovery, paths = _TR_SPENDS[policy]
    descriptors = recovery_descriptors(
        [(t, [_SIGNER_KEYS[s] for s in signers]) for t, signers in primary],
        [(t, [_SIGNER_KEYS[s] for s in signers], b) for t, signers, b in recovery],
        script_type="p2tr",
    )
    blocks, signers = paths[path]
    on_chain = [(signer, pair + chain) for signer, pair in signers]
    leaf = _tr_leaf(primary, path)
    sequence = _NO_LOCK if blocks is None else blocks
    psbt, _ = _signed_tr(descriptors[chain], on_chain[:-1], sequence, leaf)
    with pytest.raises(BTClibValueError, match=_SHORT):
        finalize(psbt, solver=miniscript_solver)
    if blocks is not None:
        psbt, _ = _signed_tr(descriptors[chain], on_chain, blocks - 1, leaf)
        with pytest.raises(BTClibValueError, match=f"^{re.escape(_NO_SATISFACTION)}$"):
            finalize(psbt, solver=miniscript_solver)
    final = _tr_spend(descriptors[chain], on_chain, sequence, leaf)
    stack = final.inputs[0].final_script_witness.stack
    if leaf is None:
        # the key path: one signature, of the default sighash
        assert [len(item) for item in stack] == [64]
    else:
        spent = descriptors[chain]
        assert isinstance(spent, TrDescriptor)
        depth = spent.taproot_tree(3)[leaf][0]
        assert len(stack[-1]) == 33 + 32 * depth


# the signer each account key of _TR_POLICIES is replaced by, so that
# every path of each policy can be signed
_TR_SIGNERS = {key: signer for signer, key in enumerate((A, B, C, D, E, F))}


def _tr_paths(
    primary: list[tuple[int, list[str]]], recovery: list[tuple[int, list[str], int]]
) -> list[tuple[int | None, list[tuple[int, int]]]]:
    """Return each path of a policy: its blocks, and who signs it at which pair.

    The first threshold keys of each quorum sign, each key at the pair the
    call gives it: 0 the first time it is named, 2 the second, and so on.
    The primary path is every primary quorum, and waits no blocks.
    """
    named: dict[str, int] = {}

    def signing(threshold: int, keys: list[str]) -> list[tuple[int, int]]:
        pairs = []
        for key in keys:
            pairs.append((_TR_SIGNERS[key], 2 * named.get(key, 0)))
            named[key] = named.get(key, 0) + 1
        return pairs[:threshold]

    paths: list[tuple[int | None, list[tuple[int, int]]]] = [
        (None, [pair for t, keys in primary for pair in signing(t, keys)])
    ]
    paths += [(blocks, signing(t, keys)) for t, keys, blocks in recovery]
    return paths


_TR_POLICY_PATHS = [
    pytest.param(policy, path, id=f"{policy}-path {path}")
    for policy, (primary, recovery, _) in _TR_POLICIES.items()
    for path in range(len(_tr_paths(primary, recovery)))
]


@pytest.mark.parametrize("policy,path", _TR_POLICY_PATHS)
def test_each_path_of_each_tr_policy_spends_through_miniscript_solver(
    policy: str, path: int
) -> None:
    """Spend each path of each policy of _TR_POLICIES, its keys our signers'.

    `finalize` builds the spend with `miniscript_solver`, and the script
    engine runs it. A primary path of one key is the key path, which the
    solver leaves to `finalize`. One signature fewer is refused, and so is
    a sequence one block short of the lock.
    """
    primary, recovery, _ = _TR_POLICIES[policy]
    descriptor, _ = recovery_descriptors(
        [(t, [_SIGNER_KEYS[_TR_SIGNERS[k]] for k in keys]) for t, keys in primary],
        [
            (t, [_SIGNER_KEYS[_TR_SIGNERS[k]] for k in keys], blocks)
            for t, keys, blocks in recovery
        ],
        script_type="p2tr",
    )
    blocks, signers = _tr_paths(primary, recovery)[path]
    one_key = len(primary) == 1 and len(primary[0][1]) == 1
    leaf = (None if path == 0 else path - 1) if one_key else path
    sequence = _NO_LOCK if blocks is None else blocks
    psbt, _ = _signed_tr(descriptor, signers, sequence, leaf)
    if leaf is None:
        assert miniscript_solver(psbt, 0) is None
    final = _tr_spend(descriptor, signers, sequence, leaf)
    stack = final.inputs[0].final_script_witness.stack
    if leaf is not None:
        assert isinstance(descriptor, TrDescriptor)
        assert stack[-2] == descriptor.taproot_tree(3)[leaf][2]

    psbt, _ = _signed_tr(descriptor, signers[:-1], sequence, leaf)
    with pytest.raises(BTClibValueError, match=_SHORT):
        finalize(psbt, solver=miniscript_solver)
    if blocks is not None:
        psbt, _ = _signed_tr(descriptor, signers, blocks - 1, leaf)
        with pytest.raises(BTClibValueError, match=f"^{re.escape(_NO_SATISFACTION)}$"):
            finalize(psbt, solver=miniscript_solver)


@pytest.mark.parametrize("primary", ["one key", "a quorum"])
@pytest.mark.parametrize("paths", [1, 2, 3, 4])
def test_a_tr_path_lengthens_the_control_blocks_of_the_path_before_it(
    primary: str, paths: int
) -> None:
    """A path added last lengthens the spends of the path before it alone.

    Measured on the spends: a primary leaf is at depth one, each recovery
    leaf a level deeper than the one before it, the last two at the same
    depth, and a primary path of one key spends by the key path.
    """
    keys = _SIGNER_KEYS
    quorum = [(1, [keys[0]])] if primary == "one key" else [(2, keys[:2])]
    signers = [(0, 0)] if primary == "one key" else [(0, 0), (1, 0)]
    descriptor, _ = recovery_descriptors(
        quorum,
        [(1, [keys[i]], 144) for i in range(2, paths + 2)],
        script_type="p2tr",
    )
    first = _tr_leaf([(1, [0])] if primary == "one key" else [(2, [0, 1])], 0)
    spends = [_tr_spend(descriptor, signers, _NO_LOCK, first)]
    offset = 0 if first is None else 1
    spends += [
        _tr_spend(descriptor, [(i, 0)], 144, i - 2 + offset)
        for i in range(2, paths + 2)
    ]
    witnesses = [s.inputs[0].final_script_witness.stack for s in spends]
    leaves = len(witnesses) - (first is None)
    depths = [min(j + 1, leaves - 1) for j in range(leaves)]
    expected = [33 + 32 * depth for depth in depths]
    if first is None:
        assert [len(item) for item in witnesses[0]] == [64]
        witnesses = witnesses[1:]
    assert [len(stack[-1]) for stack in witnesses] == expected


def test_finalize_builds_a_timelocked_leaf_with_miniscript_solver() -> None:
    """The docstring's account of `psbt.finalize` under tr(), measured.

    `finalize` alone refuses the leaf with a timelock, and
    `miniscript_solver` is what builds it.
    """
    descriptor, _ = recovery_descriptors(
        [(1, [_SIGNER_KEYS[0]])], [(1, [_SIGNER_KEYS[1]], 144)], script_type="p2tr"
    )
    psbt, _ = _signed_tr(descriptor, [(1, 0)], 144, 0)
    message = (
        "cannot finalize a taproot script path whose leaf script "
        "is neither a single key and OP_CHECKSIG nor a multi_a"
    )
    with pytest.raises(BTClibValueError, match=f"^{re.escape(message)}$"):
        finalize(psbt)
    assert miniscript_solver(psbt, 0) is not None
    assert finalize(psbt, solver=miniscript_solver).inputs[0].final_script_witness


def test_descriptor_satisfy_builds_every_tr_path() -> None:
    """`Descriptor.satisfy` builds a recovery leaf's witness, at its timelock.

    The same witness `finalize` builds through `miniscript_solver`.
    """
    descriptor, _ = recovery_descriptors(
        [(2, _SIGNER_KEYS[:2])], [(1, [_SIGNER_KEYS[2]], 144)], script_type="p2tr"
    )
    psbt, _ = _signed_tr(descriptor, [(2, 0)], 144, 1)
    final = finalize(psbt, solver=miniscript_solver)
    signatures: dict[Octets, Octets] = {
        key[:32]: signature
        for key, signature in psbt.inputs[0].taproot_script_spend_signatures.items()
    }
    script_sig, witness = descriptor.satisfy(
        signatures, index=3, spend=SpendContext(sequence=144, version=2)
    )
    assert script_sig == b""
    assert witness == final.inputs[0].final_script_witness
    with pytest.raises(BTClibValueError):
        descriptor.satisfy(
            signatures, index=3, spend=SpendContext(sequence=143, version=2)
        )


# a script type refused: (the value, the class refused, its message)
_SCRIPT_TYPE_REFUSED: dict[str, tuple[object, type[Exception], str]] = {
    "int": (1, BTClibTypeError, "invalid script_type type: 'int'"),
    "None": (None, BTClibTypeError, "invalid script_type type: 'NoneType'"),
    "unknown": (
        "p2sh",
        BTClibValueError,
        "invalid script_type: 'p2sh', not 'p2wsh' or 'p2tr'",
    ),
    "in capitals": (
        "P2TR",
        BTClibValueError,
        "invalid script_type: 'P2TR', not 'p2wsh' or 'p2tr'",
    ),
    "WIF": (
        _WIF,
        BTClibValueError,
        "invalid script_type: a value of 52 characters, not 'p2wsh' or 'p2tr'",
    ),
    "bytes": (_PRV_KEY, BTClibTypeError, "invalid script_type type: 'bytes'"),
    "private int": (_PRV_INT, BTClibTypeError, "invalid script_type type: 'int'"),
}


@pytest.mark.parametrize("case", _SCRIPT_TYPE_REFUSED)
def test_what_it_refuses_as_the_script_type(case: str) -> None:
    """Each refusal, with its whole message, quoting no private key."""
    value, refused, message = _SCRIPT_TYPE_REFUSED[case]
    with pytest.raises(refused, match=f"^{re.escape(message)}$") as refusal:
        recovery_descriptors(_P, _R, script_type=value)  # type: ignore[arg-type]
    assert refusal.value.__cause__ is None
    assert refusal.value.__context__ is None
    assert_secret_free(refusal.value, _SECRETS)


def _children(count: int) -> list[str]:
    """Return `count` xpubs, the children of one root, derived here."""
    root = rootxprv_from_seed(bytes(16))
    return [xpub_from_xprv(derive(root, f"m/{i}")) for i in range(count)]


# what `parse` refuses of the whole tr() descriptor, in its own words
_TR_REFUSED: dict[str, tuple[Callable[[], tuple[Any, Any]], str]] = {
    # a primary leaf and 129 recovery leaves put the last two at depth 129
    "a tree too deep": (
        lambda: ([(2, [A, B])], [(1, [C], 144 + i) for i in range(129)]),
        "tr() supports at most 128 nesting levels",
    ),
    "a tree too deep below an internal key": (
        lambda: ([(1, [A])], [(1, [C], 144 + i) for i in range(130)]),
        "tr() supports at most 128 nesting levels",
    ),
    "a multi_a() of 1000 keys": (
        lambda: ([(1, _children(1000))], [(1, [A], 144)]),
        "invalid n in k-of-n multi_a: 1000",
    ),
    # two quorums of 500 keys each put 1000 elements on the stack
    "beyond the stack's limit": (
        lambda: ([(1, _children(500)), (1, _children(500))], [(1, [A], 144)]),
        "a sub-expression is not sane: satisfying it may exceed the resource limits",
    ),
}


@pytest.mark.parametrize("case", _TR_REFUSED)
def test_what_parse_refuses_of_a_tr_descriptor(case: str) -> None:
    """Each whole-descriptor refusal, with its whole message and no position.

    The control: one leaf fewer, one key fewer, one key fewer in a
    quorum, each is taken.
    """
    make, message = _TR_REFUSED[case]
    primary, recovery = make()
    with pytest.raises(BTClibValueError, match=f"^{re.escape(message)}$"):
        recovery_descriptors(primary, recovery, script_type="p2tr")
    if len(recovery) > 1:
        recovery = recovery[:-1]
    else:
        *rest, (threshold, keys) = primary
        primary = [*rest, (threshold, keys[:-1])]
    assert recovery_descriptors(primary, recovery, script_type="p2tr")
