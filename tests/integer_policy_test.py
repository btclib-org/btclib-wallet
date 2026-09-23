# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the one policy on integer fields: a bool is not a number.

The policy is btclib's, and `btclib.utils.is_integer` states it; this file
holds the integer fields of this package to it, as btclib's own
`integer_policy_test.py` holds btclib's. What makes it worth a refusal is
the json boundary: `true` decodes to `True`, and a schema mistake would
become one index or one participant instead of failing beside the input
that caused it.
"""

from __future__ import annotations

from collections.abc import Callable
from enum import IntEnum
from typing import Any

import pytest
from btclib.exceptions import BTClibTypeError

from btclib_wallet.bip32 import BIP32KeyData
from btclib_wallet.bip32.bip32 import (
    derive,
    derive_from_account_,
    rootxprv_from_seed,
    xpub_from_xprv,
)
from btclib_wallet.bip32.der_path import (
    bytes_from_der_path,
    indexes_from_der_path,
    str_from_der_path,
    str_from_index_int,
)
from btclib_wallet.mnemonic.entropy import bin_str_entropy_from_wordlist_indexes
from btclib_wallet.psbt.psbt import PSBT_V2, Psbt
from btclib_wallet.wallet.script_wallet import KeyGroup

_XPUB = xpub_from_xprv(rootxprv_from_seed("00" * 32))
# account depth, hardened: what derive_from_account_'s own is_hardened
# check wants
_ACCOUNT_XPRV = derive(rootxprv_from_seed("00" * 32), "m/44h/0h/0h")


def _psbt(**field: Any) -> Psbt:
    """Return the shortest psbt there is, with one field of it replaced.

    Version 2, whose fields are its own: a v0 psbt refuses
    `tx_modifiable` outright, which is a rule about the value of a field
    whose type has to be asked first.
    """
    fields: dict[str, Any] = {
        "tx_version": 1,
        "inputs": [],
        "outputs": [],
        "version": PSBT_V2,
        "hd_key_paths": {},
    }
    return Psbt(**(fields | field), check_validity=False)


# every field whose contract is an integer quantity, with the shortest
# call that reaches its validator
_CASES: list[tuple[str, Callable[[Any], object]]] = [
    # a psbt is asked by `assert_valid`, `check_validity=False` on the way
    # in being what lets a field of any type at all into one
    ("psbt version", lambda v: _psbt(version=v).assert_valid()),
    ("psbt tx modifiable", lambda v: _psbt(tx_modifiable=v).assert_valid()),
    ("psbt fallback lock time", lambda v: _psbt(fallback_lock_time=v).assert_valid()),
    ("key group threshold", lambda v: KeyGroup(v, [_XPUB])),
    (
        "bip32 depth",
        lambda v: BIP32KeyData(
            b"\x04\x88\xad\xe4", v, b"\x00" * 4, 0, b"\x00" * 32, b"\x00" * 33
        ),
    ),
    (
        "bip32 index",
        lambda v: BIP32KeyData(
            b"\x04\x88\xad\xe4", 0, b"\x00" * 4, v, b"\x00" * 32, b"\x00" * 33
        ),
    ),
    ("derivation index", indexes_from_der_path),
    ("derivation index in a sequence", lambda v: indexes_from_der_path([v])),
    ("derivation path as bytes", bytes_from_der_path),
    ("derivation path as text", str_from_der_path),
    ("derivation index as a step", str_from_index_int),
    ("word-list index", lambda v: bin_str_entropy_from_wordlist_indexes([v], 2048)),
    # `_assert_valid_branch` and `_assert_valid_address_index` compare
    # with `<`, `>=` and `in {0, 1}`, none of which a bool fails, so the
    # refusal is this layer's own `is_integer`
    # (issue btclib-org/btclib#1403)
    (
        "bip32 account branch",
        lambda v: derive_from_account_(_ACCOUNT_XPRV, v, 0),
    ),
    (
        "bip32 account address index",
        lambda v: derive_from_account_(_ACCOUNT_XPRV, 0, v),
    ),
    # `max_index` reaches the same two helpers as a bound rather than a
    # derivation value: `branch > max_index` and `address_index >
    # max_index` both hold for `max_index=True` against a
    # branch/address_index of `0`, so without the check the call would
    # answer a key silently narrowed to a range of `{0, 1}`
    # (issue btclib-org/btclib#1413)
    (
        "bip32 account max_index",
        lambda v: derive_from_account_(_ACCOUNT_XPRV, 0, 0, max_index=v),
    ),
]

_IDS = [case[0] for case in _CASES]
_CALLS = [case[1] for case in _CASES]


@pytest.mark.parametrize("call", _CALLS, ids=_IDS)
@pytest.mark.parametrize("value", [True, False], ids=["true", "false"])
def test_a_bool_is_not_an_integer_field(
    call: Callable[[Any], object], *, value: bool
) -> None:
    """Every integer field refuses a boolean, and refuses it as a type.

    `isinstance(True, int)` is what would let each of these through as one
    or zero.
    """
    with pytest.raises(BTClibTypeError):
        call(value)


# the sentence each of these gives back: whichever control reaches the
# value first writes it, so an entry point moves between wordings by
# gaining or losing a check above it and never by choosing one
_WORDINGS = [
    (
        "bip32 account branch",
        lambda v: derive_from_account_(_ACCOUNT_XPRV, v, 0),
        "non-integer branch: True",
    ),
    (
        "bip32 account address index",
        lambda v: derive_from_account_(_ACCOUNT_XPRV, 0, v),
        "non-integer address index: True",
    ),
    (
        "bip32 account max_index",
        lambda v: derive_from_account_(_ACCOUNT_XPRV, 0, 0, max_index=v),
        "non-integer max_index: True",
    ),
]


@pytest.mark.parametrize(
    "call, message",
    [(case[1], case[2]) for case in _WORDINGS],
    ids=[case[0] for case in _WORDINGS],
)
def test_which_check_refuses_the_bool_decides_the_sentence(
    call: Callable[[Any], object], message: str
) -> None:
    """Each wording held to what is raised."""
    with pytest.raises(BTClibTypeError, match=message):
        call(True)


def test_the_integers_a_bool_refusal_must_not_take_with_it() -> None:
    """The same calls with a number, which is what the refusal is around.

    A test that only checks refusals passes just as well when the field
    refuses everything.
    """
    assert _psbt(fallback_lock_time=1).fallback_lock_time == 1
    assert KeyGroup(1, [_XPUB]).threshold == 1
    assert indexes_from_der_path(1) == [1]
    assert indexes_from_der_path([1, 2]) == [1, 2]
    assert bytes_from_der_path(1).hex() == "01000000"
    assert str_from_der_path([1]) == "m/1"
    assert str_from_index_int(1) == "1"
    assert bin_str_entropy_from_wordlist_indexes([1], 2048) == "00000000001"
    assert derive_from_account_(_ACCOUNT_XPRV, 1, 1).depth == 5
    assert derive_from_account_(_ACCOUNT_XPRV, 1, 1, max_index=1).depth == 5

    # the str and bytes spellings of a path are untouched by any of it
    assert indexes_from_der_path("m/44h/0h") == [2147483692, 2147483648]


def test_what_is_no_integer_at_all_is_refused_the_same_way() -> None:
    """The policy is about integers, and a bool is only its sharpest case.

    A derivation index that is no integer at all is refused as a type, and
    not converted through `int()`.
    """
    with pytest.raises(BTClibTypeError, match="invalid derivation index type"):
        indexes_from_der_path([2.0])  # type: ignore[list-item]
    with pytest.raises(BTClibTypeError, match="invalid derivation index type"):
        str_from_index_int(1.0)  # type: ignore[arg-type]


def test_an_int_subclass_that_is_not_a_bool_is_still_an_integer() -> None:
    """`IntEnum` stays a number, which is why the predicate names bool.

    The path step is the case that has to be *answered* with a number and
    not merely accepted as one: `str()` of an `IntEnum` is its name up to
    Python 3.10, so a derivation path of one would read "Index.ONE" there
    and "1" on every later interpreter.
    """

    class Index(IntEnum):
        ONE = 1

    assert indexes_from_der_path(Index.ONE) == [1]
    assert indexes_from_der_path([Index.ONE]) == [1]
    assert str_from_index_int(Index.ONE) == "1"
