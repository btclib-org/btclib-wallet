# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The descriptors of a wallet with timelocked recovery paths.

The primary path spends a coin at any time, and each recovery quorum
spends it once the coin has waited that path's relative timelock.
`recovery_descriptors` writes the miniscript of such a policy and hands
it to `descriptors.parse`, whose sanity rules then hold of what it
returns. It writes one shape for each policy, chosen here once. P is a
primary quorum, and Ri' is ``and_v(v:Ri,older(ti))``, the recovery
quorum Ri after ti blocks. Under ``wsh()``:

- one primary quorum: ``or_i(P,R1')``;
- two primary quorums, which spend together: ``andor(P1,P2,R1')``;
- more recovery paths: R1' above becomes ``or_i(R1',R2')``, nested to
  the right for three or more, as ``or_i(R1',or_i(R2',R3'))``.

The first two are the transit wallet and the vault of
`tests/wallet/custody_wallet_test.py`, deployed on mainnet, whose
descriptors `tests/recovery_paths_test.py` reproduces.

Under ``tr()``, each path is a leaf of the script tree, in the tapscript
dialect, where a quorum of more keys is ``multi_a()``:

- a primary path of one quorum, of one key, is the internal key, and
  the tree holds the recovery leaves: ``tr(K,R1')``, ``tr(K,{R1',R2'})``;
- any other primary path is a leaf, P or ``and_v(v:P1,P2)``, beside the
  recovery leaves, and the internal key is one nobody can sign for:
  ``tr(N,{P,R1'})``, ``tr(N,{P,{R1',R2'}})``;
- more recovery paths nest to the right, as ``{R1',{R2',R3'}}``.

N is an xpub whose key is BIP341's NUMS point H, so no one knows its
private key, and whose chain code is the sha256 of the account keys:
each address then has an internal key of its own, ``H + rG`` as BIP341
recommends, and whoever holds the descriptor can check that its key path
is unspendable.

The miniscript is written here, not compiled from the policy: a compiler
chooses between equivalent scripts by a cost model, and a descriptor that
holds coins must not change when that model does.
"""

from __future__ import annotations

from collections.abc import Sequence
from contextlib import suppress
from dataclasses import replace
from typing import Literal, cast

from btclib.exceptions import BTClibValueError
from btclib.hashes import sha256
from btclib.network import NETWORKS, validated_network_name

from btclib_wallet._refusal import _quoted, _refused_type
from btclib_wallet.bip32 import BIP32KeyData
from btclib_wallet.descriptors import (
    Descriptor,
    KeyExpression,
    multipath_descriptors,
    parse,
)
from btclib_wallet.silent_payments import NUMS_H

__all__ = ["recovery_descriptors"]

# andor() takes two quorums that spend together, and no more
_MAX_PRIMARY = 2

# the most blocks a relative timelock takes, as `recovery_descriptors` says
_MAX_BLOCKS = 0xFFFF

# BIP32's depth is one byte, and the function adds two levels below an
# account key: the branch and the index
_MAX_DEPTH = 0xFF - 2

# the output types `recovery_descriptors` writes, as `script_type` names them
_SCRIPT_TYPES = ("p2wsh", "p2tr")


# Every type is decided by `type(x) is` a built-in, an identity: `in`,
# `==`, `hash`, `isinstance` and `issubclass` can each call a method of
# the caller's class or of its metaclass, which can answer anything


def _items(value: object, name: str) -> list[object]:
    """Return the items of a tuple or a list, exactly one of the two.

    A subclass is refused, so that what is read is what the built-in
    type holds and no method of the caller's runs. A `str` is refused
    too: one xpub handed where the list was meant would be read a
    character at a time.
    """
    if type(value) is not tuple and type(value) is not list:
        raise _refused_type(value, name)
    return list(cast("Sequence[object]", value))


def _entry(value: object, length: int, where: str) -> list[object]:
    """Return the items of an entry, refused unless there are `length`.

    The type is asked first, the length after: run time cannot tell a
    pair from a triple by type, so the length is a value.
    """
    items = _items(value, where)
    if len(items) != length:
        err_msg = f"invalid {where}: {len(items)} items, not {length}"
        raise BTClibValueError(err_msg)
    return items


def _integer(value: object, name: str) -> int:
    """Return an int that is exactly an int.

    A bool, an `IntEnum` and any other subclass are refused: what is
    checked and written is then the built-in int, with none of a
    subclass's own formatting or comparisons.
    """
    if type(value) is not int:
        raise _refused_type(value, name)
    return value


def _account_key(key: object, network: str, where: str) -> KeyExpression:
    """Return the KEY expression of an account key, or refuse it.

    Read as ``pk(KEY)``, a descriptor of one key, so that
    `descriptors.parse` checks its syntax and its network. The descriptor
    is built from the expression parsed, never from the caller's text: a
    key holding a bracket cannot change the descriptor around it.
    """
    if type(key) is not str:
        raise _refused_type(key, where)
    text = key
    prv_keys: dict[str, str] = {}
    expressions: tuple[KeyExpression, ...] = ()
    # refused outside the `except`, so that no `__context__` holds what
    # parse quoted of the key
    with suppress(ValueError):
        expressions = parse(f"pk({text})", network, prv_keys).key_expressions
    if not expressions:
        # a BIP389 step, as ``<0;1>/*``, which `parse` reads only expanded:
        # its first path is enough to refuse the step below
        with suppress(ValueError):
            first = multipath_descriptors(f"pk({text})", network)[0]
            expressions = parse(first, network, prv_keys).key_expressions
    if not expressions:
        err_msg = f"invalid {where}: not a KEY expression of the network"
        raise BTClibValueError(err_msg)
    (expression,) = expressions
    # an xprv is handed back in prv_keys, a WIF leaves its version byte
    if prv_keys or expression.wif_prefix:
        err_msg = f"invalid {where}: a private key, where an xpub belongs"
        raise BTClibValueError(err_msg)
    if not expression.xkey:
        raise BTClibValueError(f"invalid {where}: no extended key")
    if expression.der_path or expression.wildcard is not None:
        err_msg = f"invalid {where}: a derivation step after the account key"
        raise BTClibValueError(err_msg)
    if BIP32KeyData.b58decode(expression.xkey).depth > _MAX_DEPTH:
        err_msg = f"invalid {where}: too deep for the branch and the index"
        raise BTClibValueError(err_msg)
    return expression


def _identity(key: KeyExpression) -> bytes:
    """Return what makes two account keys one: their public key and chain code.

    The rest of an xpub, its depth, its parent's fingerprint and its child
    index, changes no key it derives, so two spellings of one key that
    differ there derive the same public keys.
    """
    data = BIP32KeyData.b58decode(key.xkey)
    return data.key + data.chain_code


def _quorum(
    threshold: object, keys: object, network: str, where: str
) -> tuple[int, list[KeyExpression]]:
    """Return a threshold and its account keys, each checked.

    A key twice in one quorum would take two branch pairs, and so let one
    signer count twice toward the threshold.
    """
    number = _integer(threshold, f"threshold of {where}")
    items = _items(keys, f"keys of {where}")
    if not items:
        raise BTClibValueError(f"invalid {where}: no keys")
    if not 0 < number <= len(items):
        err_msg = f"invalid threshold of {where}: {_quoted(number)}"
        raise BTClibValueError(f"{err_msg}, not 1 to {len(items)}")
    expressions: list[KeyExpression] = []
    # each key's identity once: a ``multi_a()`` takes hundreds of keys
    seen: set[bytes] = set()
    for i, key in enumerate(items):
        expression = _account_key(key, network, f"key {i} of {where}")
        identity = _identity(expression)
        if identity in seen:
            raise BTClibValueError(f"invalid {where}: key {i} repeats a key")
        seen.add(identity)
        expressions.append(expression)
    return number, expressions


def _blocks(blocks: object, after: int, where: str) -> int:
    """Return a relative timelock in blocks, not below the one before it."""
    number = _integer(blocks, f"blocks of {where}")
    if not 0 < number <= _MAX_BLOCKS:
        err_msg = f"invalid blocks of {where}: {_quoted(number)}, not 1 to 65535"
        raise BTClibValueError(err_msg)
    if number < after:
        err_msg = f"invalid blocks of {where}: below the path before it"
        raise BTClibValueError(err_msg)
    return number


def _pair(
    key: KeyExpression, named: dict[bytes, list[KeyExpression]], where: str
) -> int:
    """Return the receive branch of this occurrence of a key; change is next.

    The pairs are the ones `recovery_descriptors` says: ``/0/*`` and
    ``/1/*`` the first time a key is named, the next pair each time after.
    `named` holds each key's occurrences so far, by `_identity`. A key
    named again under another origin, or in another xpub, is refused: each
    is a claim about where the key comes from, and one of the two is
    false.
    """
    occurrences = named.setdefault(_identity(key), [])
    if occurrences and occurrences[0].origin != key.origin:
        err_msg = f"invalid {where}: its xpub has another origin before it"
        raise BTClibValueError(err_msg)
    if occurrences and occurrences[0].xkey != key.xkey:
        err_msg = f"invalid {where}: its key is named before in another xpub"
        raise BTClibValueError(err_msg)
    occurrences.append(key)
    return 2 * (len(occurrences) - 1)


# a quorum as written: its threshold, and its keys on the receive chain
# and on the change chain
_Chains = tuple[int, tuple[list[str], list[str]]]


def _chains(
    quorum: tuple[int, list[KeyExpression]],
    named: dict[bytes, list[KeyExpression]],
    where: str,
) -> _Chains:
    """Return a quorum's threshold and its keys on each chain, as text."""
    threshold, keys = quorum
    receive: list[str] = []
    change: list[str] = []
    for i, key in enumerate(keys):
        branch = _pair(key, named, f"key {i} of {where}")
        receive.append(str(replace(key, der_path=(branch,), wildcard=0)))
        change.append(str(replace(key, der_path=(branch + 1,), wildcard=0)))
    return threshold, (receive, change)


def _fragment(quorum: _Chains, chain: int, multi: str) -> str:
    """Return a quorum's fragment on one chain: pk(), or `multi` of more."""
    threshold, chains = quorum
    keys = chains[chain]
    if len(keys) == 1:
        return f"pk({keys[0]})"
    return f"{multi}({threshold},{','.join(keys)})"


def _recovery_path(path: tuple[_Chains, int], chain: int, multi: str) -> str:
    """Return a recovery path on one chain: its quorum after its blocks."""
    quorum, blocks = path
    return f"and_v(v:{_fragment(quorum, chain, multi)},older({blocks}))"


def _unspendable_key(named: dict[bytes, list[KeyExpression]], network: str) -> str:
    """Return the xpub of the internal key that no one can sign for.

    Its key is BIP341's NUMS point H, lifted to the even y as BIP340
    lifts an x-only key. Its chain code is the sha256 of the account
    keys' public keys, each key once, in the order the call first names
    it. Its depth, parent fingerprint and child index are zero.
    """
    keys = b"".join(BIP32KeyData.b58decode(key[0].xkey).key for key in named.values())
    data = BIP32KeyData(
        NETWORKS[network].bip32_pub, 0, bytes(4), 0, sha256(keys), b"\x02" + NUMS_H
    )
    return data.b58encode()


def _wsh(
    primaries: list[_Chains],
    paths: list[tuple[_Chains, int]],
    chain: int,
    network: str,
) -> Descriptor:
    """Return the ``wsh()`` descriptor of one chain."""
    tail = _recovery_path(paths[-1], chain, "multi")
    for path in reversed(paths[:-1]):
        tail = f"or_i({_recovery_path(path, chain, 'multi')},{tail})"
    first, *second = (_fragment(quorum, chain, "multi") for quorum in primaries)
    if not second:
        return parse(f"wsh(or_i({first},{tail}))", network)
    return parse(f"wsh(andor({first},{second[0]},{tail}))", network)


def _tr(
    primaries: list[_Chains],
    paths: list[tuple[_Chains, int]],
    chain: int,
    unspendable: str,
    network: str,
) -> Descriptor:
    """Return the ``tr()`` descriptor of one chain."""
    leaves = [_recovery_path(path, chain, "multi_a") for path in paths]
    keys = primaries[0][1][chain]
    if len(primaries) == 1 and len(keys) == 1:
        internal_key = keys[0]
    else:
        internal_key = f"{unspendable}/{chain}/*"
        first, *others = (_fragment(quorum, chain, "multi_a") for quorum in primaries)
        leaves.insert(0, f"and_v(v:{first},{others[0]})" if others else first)
    tree = leaves[-1]
    for leaf in reversed(leaves[:-1]):
        tree = f"{{{leaf},{tree}}}"
    return parse(f"tr({internal_key},{tree})", network)


def recovery_descriptors(
    primary: Sequence[tuple[int, Sequence[str]]],
    recovery: Sequence[tuple[int, Sequence[str], int]],
    network: str = "mainnet",
    *,
    script_type: Literal["p2wsh", "p2tr"] = "p2wsh",
) -> tuple[Descriptor, Descriptor]:
    """Return the receive and change descriptors of a timelocked policy.

    `primary` is one quorum, or two that spend together, each a pair of a
    threshold and its keys. `recovery` is one path or more, each a
    threshold, its keys and the blocks after which they spend, in blocks
    that never decrease: paths may open at the same block, as two of three
    lawyers or the heir alone after a year. `script_type` names the
    output, ``"p2wsh"`` or ``"p2tr"``, and the module docstring has the
    miniscript of each. A quorum of one key is ``pk()``, and one of more
    ``multi()`` under ``wsh()`` and ``multi_a()`` under ``tr()``, its keys
    in the order given: BIP379 has no sorted multisig fragment. That
    miniscript fixes the addresses: another wallet that writes the same
    policy in another shape, as ``or_d()`` for ``or_i()``, another tree
    or another internal key, derives other addresses from the same keys.
    Two identical recovery paths are taken.

    Under ``wsh()``, each path after the first costs its script, which
    every spend carries in its witness and whose size and opcodes P2WSH
    bounds, and one witness element, the selector of the ``or_i()`` that
    joins it, on the spends of the path before it and of itself: the
    primary path and the paths before those spend as they did.

    Under ``tr()``, a primary path of one quorum, of one key, spends by
    the key path, with one signature. Every other path spends by its leaf,
    with the leaf's satisfaction, its script and its control block, whose
    33 bytes grow by 32 for each level of the leaf's depth. A primary leaf
    is at depth one. The recovery leaves nest to the right below it, or
    below the root where that one key is the internal key, each one level
    deeper than the one before it, and the last two at the same depth. So
    a path added last lengthens the control blocks of the path before it
    and of itself, and every other path spends as it did.
    `Descriptor.satisfy` builds the witness of every path, a leaf's
    timelock read from its `SpendContext`. `psbt.finalize` builds, from
    the psbt alone, the key path's and that of a primary leaf that is one
    quorum; with ``solver=psbt.miniscript_solver`` it builds every path's,
    a leaf with a timelock or two quorums included.

    Each value is exactly of the type its position takes, and anything
    else, a subclass included, is refused with its position: `primary`,
    `recovery`, each quorum, each path and the keys of each are a tuple
    or a list; a threshold and the blocks are an int, a bool or an
    ``IntEnum`` refused; a key is a str. `network` is a str, which
    `btclib.network.validated_network_name` then reads, ignoring its
    case and the whitespace around it. `script_type` is a str too.

    Each key is an account key: a BIP380 KEY expression of an extended
    public key, its origin included where the signer needs it, as
    ``[d34db33f/48h/0h/0h/2h]xpub...``, with no derivation step after it.
    The function adds the branch and the index. A key named once derives
    from ``/0/*`` in the receive descriptor and ``/1/*`` in the change
    one. A script that holds one public key twice is not sane, so a key
    named again in another quorum, in the same xpub under the same origin,
    takes the next pair, ``/2/*`` and ``/3/*``, and so on: the same
    account keys can then sign a 2-of-3 now and a 1-of-3 after a timelock.
    Two keys are one where their public key and chain code are, whatever
    the rest of their xpubs says. A key named twice in one quorum is
    refused, and so is a key named again under another origin or in
    another xpub. So is a key too deep for the two levels added. The
    unspendable internal key derives from ``/0/*`` and ``/1/*`` too.

    A key refused says where it is, its quorum or path and its index, and
    not why `descriptors.parse` refused it: the refusal carries none of
    `parse`'s exception, which could hold what the caller passed. What
    `parse` refuses of the whole descriptor it refuses in its own words,
    with no position: under ``wsh()``, a ``multi()`` of more than 20 keys,
    a script too large for P2WSH, or one whose spend may exceed P2WSH's
    limits on opcodes and witness elements; under ``tr()``, a
    ``multi_a()`` of more than 999 keys, a tree deeper than 128 levels, or
    a leaf whose spend may exceed the stack's limit.

    The blocks are a relative timelock, from 1 to 65535. BIP68 reads the
    low 16 bits of a sequence, so ``older(65536)``, which
    `descriptors.parse` accepts as Bitcoin Core does, is met at once. A
    time-based relative lock and ``after()`` are not written: what says a
    recovery path is about to open is the coin's confirmations, which
    count blocks (issue btclib-org/btclib-wallet#926).

    Both chains come back because a wallet is both, as
    `bip44.account_descriptors` says, and `descriptors.parse` refuses the
    ``<0;1>`` step that would write them as one.
    """
    # exactly a str, as every other value: `validated_network_name` asks
    # `isinstance`, which reads `__class__`
    if type(network) is not str:
        raise _refused_type(network, "network")
    network = validated_network_name(network)
    # an object to mypy, which reads every statement after this check of a
    # Literal's type as unreachable
    named_type: object = script_type
    if type(named_type) is not str:
        raise _refused_type(named_type, "script_type")
    if script_type not in _SCRIPT_TYPES:
        err_msg = f"invalid script_type: {_quoted(script_type)}"
        raise BTClibValueError(f"{err_msg}, not 'p2wsh' or 'p2tr'")
    quorums = _items(primary, "primary")
    entries = _items(recovery, "recovery")
    if not 0 < len(quorums) <= _MAX_PRIMARY:
        err_msg = f"invalid primary: {len(quorums)} quorums, not one or two"
        raise BTClibValueError(err_msg)
    if not entries:
        raise BTClibValueError("invalid recovery: no path")

    named: dict[bytes, list[KeyExpression]] = {}
    primaries: list[_Chains] = []
    for i, quorum in enumerate(quorums):
        where = f"primary quorum {i}"
        threshold, keys = _entry(quorum, 2, where)
        primaries.append(
            _chains(_quorum(threshold, keys, network, where), named, where)
        )
    paths: list[tuple[_Chains, int]] = []
    after = 0
    for i, path in enumerate(entries):
        where = f"recovery path {i}"
        threshold, keys, blocks = _entry(path, 3, where)
        checked = _quorum(threshold, keys, network, where)
        after = _blocks(blocks, after, where)
        paths.append((_chains(checked, named, where), after))

    if script_type == "p2wsh":
        return _wsh(primaries, paths, 0, network), _wsh(primaries, paths, 1, network)
    unspendable = _unspendable_key(named, network)
    return (
        _tr(primaries, paths, 0, unspendable, network),
        _tr(primaries, paths, 1, unspendable, network),
    )
