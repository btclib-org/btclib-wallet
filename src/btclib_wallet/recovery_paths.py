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
quorum Ri after ti blocks:

- one primary quorum: ``or_i(P,R1')``;
- two primary quorums, which spend together: ``andor(P1,P2,R1')``;
- more recovery paths: R1' above becomes ``or_i(R1',R2')``, nested to
  the right for three or more, as ``or_i(R1',or_i(R2',R3'))``.

The first two are the transit wallet and the vault of
`tests/wallet/custody_wallet_test.py`, deployed on mainnet, whose
descriptors `tests/recovery_paths_test.py` reproduces.

The miniscript is written here, not compiled from the policy: a compiler
chooses between equivalent scripts by a cost model, and a descriptor that
holds coins must not change when that model does.

Only ``wsh()`` is written. A ``tr()`` policy needs choices this module
does not make: the internal key where the primary path is a quorum, the
layout of the tree and the shape of its leaves.
"""

from __future__ import annotations

from collections.abc import Sequence
from contextlib import suppress
from dataclasses import replace
from typing import cast

from btclib.exceptions import BTClibValueError
from btclib.network import validated_network_name

from btclib_wallet._refusal import _quoted, _refused_type
from btclib_wallet.bip32 import BIP32KeyData
from btclib_wallet.descriptors import (
    Descriptor,
    KeyExpression,
    multipath_descriptors,
    parse,
)

__all__ = ["recovery_descriptors"]

# andor() takes two quorums that spend together, and no more
_MAX_PRIMARY = 2

# the most blocks a relative timelock takes, as `recovery_descriptors` says
_MAX_BLOCKS = 0xFFFF

# BIP32's depth is one byte, and the function adds two levels below an
# account key: the branch and the index
_MAX_DEPTH = 0xFF - 2


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
    for i, key in enumerate(items):
        expression = _account_key(key, network, f"key {i} of {where}")
        if any(_identity(other) == _identity(expression) for other in expressions):
            raise BTClibValueError(f"invalid {where}: key {i} repeats a key")
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


def _fragments(
    quorum: tuple[int, list[KeyExpression]],
    named: dict[bytes, list[KeyExpression]],
    where: str,
) -> tuple[str, str]:
    """Return a quorum's receive and change fragments: pk() or multi()."""
    threshold, keys = quorum
    receive: list[str] = []
    change: list[str] = []
    for i, key in enumerate(keys):
        branch = _pair(key, named, f"key {i} of {where}")
        receive.append(str(replace(key, der_path=(branch,), wildcard=0)))
        change.append(str(replace(key, der_path=(branch + 1,), wildcard=0)))
    if len(keys) == 1:
        return f"pk({receive[0]})", f"pk({change[0]})"
    return (
        f"multi({threshold},{','.join(receive)})",
        f"multi({threshold},{','.join(change)})",
    )


def recovery_descriptors(
    primary: Sequence[tuple[int, Sequence[str]]],
    recovery: Sequence[tuple[int, Sequence[str], int]],
    network: str = "mainnet",
) -> tuple[Descriptor, Descriptor]:
    """Return the receive and change descriptors of a timelocked policy.

    `primary` is one quorum, or two that spend together, each a pair of a
    threshold and its keys. `recovery` is one path or more, each a
    threshold, its keys and the blocks after which they spend, in blocks
    that never decrease: paths may open at the same block, as two of three
    lawyers or the heir alone after a year. A quorum of one key is
    ``pk()``, and one of more ``multi()``, its keys in the order given:
    BIP379 has no sorted multisig fragment. The module docstring has the
    miniscript of each. That miniscript fixes the addresses: another
    wallet that writes the same policy in another shape, as ``or_d()`` for
    ``or_i()``, derives other addresses from the same keys. Two identical
    recovery paths are taken. Each path after the first costs its script,
    which every spend carries in its witness and whose size and opcodes
    P2WSH bounds, and one witness element, the selector of the ``or_i()``
    that joins it, on the spends of the path before it and of itself: the
    primary path and the paths before those spend as they did.

    Each value is exactly of the type its position takes, and anything
    else, a subclass included, is refused with its position: `primary`,
    `recovery`, each quorum, each path and the keys of each are a tuple
    or a list; a threshold and the blocks are an int, a bool or an
    ``IntEnum`` refused; a key is a str. `network` is a str, which
    `btclib.network.validated_network_name` then reads, ignoring its
    case and the whitespace around it.

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
    another xpub. So is a key too deep for the two levels added.

    A key refused says where it is, its quorum or path and its index, and
    not why `descriptors.parse` refused it: the refusal carries none of
    `parse`'s exception, which could hold what the caller passed. What
    `parse` refuses of the whole descriptor it refuses in its own words,
    with no position: a ``multi()`` of more than 20 keys, a script too
    large for P2WSH, or one whose spend may exceed P2WSH's limits on
    opcodes and witness elements.

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
    quorums = _items(primary, "primary")
    entries = _items(recovery, "recovery")
    if not 0 < len(quorums) <= _MAX_PRIMARY:
        err_msg = f"invalid primary: {len(quorums)} quorums, not one or two"
        raise BTClibValueError(err_msg)
    if not entries:
        raise BTClibValueError("invalid recovery: no path")

    named: dict[bytes, list[KeyExpression]] = {}
    primaries: list[tuple[str, str]] = []
    for i, quorum in enumerate(quorums):
        where = f"primary quorum {i}"
        threshold, keys = _entry(quorum, 2, where)
        primaries.append(
            _fragments(_quorum(threshold, keys, network, where), named, where)
        )
    paths: list[tuple[str, str]] = []
    after = 0
    for i, path in enumerate(entries):
        where = f"recovery path {i}"
        threshold, keys, blocks = _entry(path, 3, where)
        checked = _quorum(threshold, keys, network, where)
        after = _blocks(blocks, after, where)
        receive, change = _fragments(checked, named, where)
        paths.append(
            (
                f"and_v(v:{receive},older({after}))",
                f"and_v(v:{change},older({after}))",
            )
        )

    def descriptor(chain: int) -> Descriptor:
        tail = paths[-1][chain]
        for path in reversed(paths[:-1]):
            tail = f"or_i({path[chain]},{tail})"
        if len(primaries) == 1:
            return parse(f"wsh(or_i({primaries[0][chain]},{tail}))", network)
        first, second = (fragments[chain] for fragments in primaries)
        return parse(f"wsh(andor({first},{second},{tail}))", network)

    return descriptor(0), descriptor(1)
