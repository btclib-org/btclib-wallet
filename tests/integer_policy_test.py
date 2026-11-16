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
from enum import Enum, IntEnum
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import pytest
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.script.script_pub_key import ScriptPubKey
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx
from btclib.tx.tx_in import TxIn
from btclib.tx.tx_out import TxOut
from typing_extensions import override

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
from btclib_wallet.descriptors import Descriptor, parse
from btclib_wallet.ledger import Ledger
from btclib_wallet.psbt.psbt import PSBT_V2, Psbt
from btclib_wallet.wallet import BIP32KeyWallet, DescriptorWallet, RangedWallet
from btclib_wallet.wallet.script_wallet import KeyGroup, ScriptWallet
from tests.ledger.conftest import FakeChain, source

_XPUB = xpub_from_xprv(rootxprv_from_seed("00" * 32))
# account depth, hardened: what derive_from_account_'s own is_hardened
# check wants
_ACCOUNT_XPRV = derive(rootxprv_from_seed("00" * 32), "m/44h/0h/0h")
_DESCRIPTOR = parse(f"wpkh({_XPUB}/*)")
_CHANGE_DESCRIPTOR = parse(f"wpkh({_XPUB}/1/*)")
_WALLET = DescriptorWallet([_DESCRIPTOR, _CHANGE_DESCRIPTOR])


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


def _new_address(source_id: Any, branch: Any) -> str:
    """Return the address a new ledger of `source()` hands out on a branch.

    The ledger's one source is `source_id` 0.
    """
    with (
        TemporaryDirectory() as tmp,
        Ledger.create(Path(tmp) / "ledger.sqlite", "regtest", FakeChain()) as ledger,
    ):
        ledger.add_source(source(), lookahead=1)
        return ledger.new_address(source_id, branch)


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
    # a search bound: `range(True + 1)` would answer for index 0 and 1 and
    # read as "not this wallet's" past them (issue #407)
    (
        "descriptor index_of last_index",
        lambda v: _DESCRIPTOR.index_of(_DESCRIPTOR.script_pub_key(0), v),
    ),
    (
        "wallet position_of last_index",
        lambda v: _WALLET.position_of(_DESCRIPTOR.script_pub_key(0), v),
    ),
    # a ledger writes the label's str(), and cannot read "True" back
    ("descriptor wallet branch", lambda v: DescriptorWallet({v: _DESCRIPTOR})),
    # `_branch_held` checks membership in `branches`, which `False == 0`
    # and `True == 1` pass (issue #923)
    ("wallet position branch", lambda v: _WALLET.address(v, 0)),
    # `_branch_held` refuses it before the descriptor does (issue #1011)
    ("wallet position index", lambda v: _WALLET.address(0, v)),
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
        "non-integer branch: a bool",
    ),
    (
        "bip32 account address index",
        lambda v: derive_from_account_(_ACCOUNT_XPRV, 0, v),
        "non-integer address index: a bool",
    ),
    (
        "bip32 account max_index",
        lambda v: derive_from_account_(_ACCOUNT_XPRV, 0, 0, max_index=v),
        "non-integer max_index: a bool",
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
    assert derive_from_account_(_ACCOUNT_XPRV, 1, 1).depth == 5
    assert derive_from_account_(_ACCOUNT_XPRV, 1, 1, max_index=1).depth == 5
    assert _DESCRIPTOR.index_of(_DESCRIPTOR.script_pub_key(1), 1) == 1
    assert _WALLET.position_of(_DESCRIPTOR.script_pub_key(1), 1) == (0, 1)
    assert DescriptorWallet({1: _DESCRIPTOR}).branches == (1,)
    assert _WALLET.address(1, 0) == _CHANGE_DESCRIPTOR.script_pub_key(0).address
    assert _WALLET.address(0, 1) == _DESCRIPTOR.script_pub_key(1).address

    # the str and bytes spellings of a path are untouched by any of it
    assert indexes_from_der_path("m/44h/0h") == [2147483692, 2147483648]


def test_what_is_no_integer_at_all_is_refused_the_same_way() -> None:
    """The policy is about integers, and a bool is only its sharpest case.

    A derivation index, a wallet position's branch or index, a ledger's
    branch, or a ledger's source id that is no integer at all is refused
    as a type, and not converted through `int()`.
    """
    with pytest.raises(BTClibTypeError, match="invalid derivation index type"):
        indexes_from_der_path([2.0])  # type: ignore[list-item]
    with pytest.raises(BTClibTypeError, match="invalid derivation index type"):
        str_from_index_int(1.0)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid branch type: float"):
        DescriptorWallet({1.0: _DESCRIPTOR})  # type: ignore[dict-item]
    with pytest.raises(BTClibTypeError, match="invalid branch type: str"):
        DescriptorWallet({"0": _DESCRIPTOR})  # type: ignore[dict-item]
    with pytest.raises(BTClibTypeError, match="invalid branch type: float"):
        _WALLET.address(1.0, 0)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid branch type: str"):
        _WALLET.address("0", 0)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid index type: float"):
        _WALLET.address(0, 1.0)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid index type: str"):
        _WALLET.address(0, "0")  # type: ignore[arg-type]

    claims_int: Any = property(lambda _self: int)

    class Claims:
        __class__ = claims_int

    # isinstance believes it, so the type is what decides
    assert isinstance(Claims(), int)
    with pytest.raises(BTClibTypeError, match="invalid branch type: Claims"):
        DescriptorWallet({Claims(): _DESCRIPTOR})  # type: ignore[dict-item]
    with pytest.raises(BTClibTypeError, match="invalid index type: Claims"):
        _WALLET.address(0, Claims())  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid branch type: Claims"):
        _new_address(0, Claims())
    with pytest.raises(BTClibTypeError, match="invalid source type: Claims"):
        _new_address(Claims(), 0)


def test_an_int_subclass_that_is_not_a_bool_is_still_an_integer() -> None:
    """`IntEnum` stays a number, which is why the predicate names bool.

    The path step and a wallet's branch are the cases that have to be
    *answered* with a number and not merely accepted as one: an `IntEnum`
    whose `str()` is its name, as `Enum.__str__` writes it, would make a
    derivation path read "Index.ONE" rather than "1", and a ledger's file
    hold a branch it cannot read back.
    """

    class Index(IntEnum):
        ONE = 1

        __str__ = Enum.__str__

    assert indexes_from_der_path(Index.ONE) == [1]
    assert indexes_from_der_path([Index.ONE]) == [1]
    assert str_from_index_int(Index.ONE) == "1"
    (branch,) = DescriptorWallet({Index.ONE: _DESCRIPTOR}).branches
    assert type(branch) is int


def test_a_branch_is_the_int_its_label_holds() -> None:
    """Read by `_exact_int`, whatever a subclass's `__int__` answers.

    Through `int()` these would label a chain -1 or 2**70, which a ledger
    cannot hold, or put two descriptors on one branch.
    """

    class Negative(int):
        @override
        def __int__(self) -> int:
            return -1

    class Huge(int):
        @override
        def __int__(self) -> int:
            return 2**70

    class Twin(int):
        __hash__ = int.__hash__

        @override
        def __eq__(self, other: object) -> bool:
            return self is other

    # what `int()` answers for each, which the wallet must not take
    assert (int(Negative(5)), int(Huge(5))) == (-1, 2**70)
    (branch,) = DescriptorWallet({Negative(5): _DESCRIPTOR}).branches
    assert (type(branch), branch) == (int, 5)
    assert DescriptorWallet({Huge(5): _DESCRIPTOR}).branches == (5,)
    other = parse(f"wpkh({_XPUB}/1/*)")
    with pytest.raises(BTClibValueError, match="two labels hold one int"):
        DescriptorWallet({Twin(5): _DESCRIPTOR, 5: other})


def test_a_branch_is_an_int_by_its_type_whatever_its_class_claims() -> None:
    """The type decides, as `_quoted` does, and `__class__` is never read.

    An int subclass is a label whether its `__class__` claims bool or
    raises; `isinstance`, which reads `__class__`, calls the first a bool
    and raises from the second. A ledger decides a source id and a
    branch it is handed the same way.
    """

    def no_class(_self: object) -> type:
        raise RuntimeError("no __class__")

    raises_class: Any = property(no_class)
    claims_bool: Any = property(lambda _self: bool)

    class RaisesClass(int):
        __class__ = raises_class

    class ClaimsBool(int):
        __class__ = claims_bool

    # what isinstance reads of each, which the wallet must not ask
    with pytest.raises(RuntimeError, match="no __class__"):
        isinstance(RaisesClass(5), bool)
    assert isinstance(ClaimsBool(5), bool)
    raising = DescriptorWallet({RaisesClass(5): _DESCRIPTOR})
    assert raising.branches == (5,)
    assert raising.address(RaisesClass(5), 0) == raising.address(5, 0)
    claiming = DescriptorWallet({ClaimsBool(7): _DESCRIPTOR})
    assert claiming.branches == (7,)
    assert claiming.address(ClaimsBool(7), 0) == claiming.address(7, 0)
    wallet = source()
    assert _new_address(0, RaisesClass(0)) == wallet.address(0, 0)
    assert _new_address(0, ClaimsBool(1)) == wallet.address(1, 0)
    assert _new_address(RaisesClass(0), 0) == wallet.address(0, 0)
    assert _new_address(ClaimsBool(0), 1) == wallet.address(1, 0)


class _Liar(int):
    """An int whose `==` holds for anything, so any branch is "in" a tuple."""

    __hash__ = int.__hash__

    @override
    def __eq__(self, other: object) -> bool:
        return True


class _Unhashable(int):
    """An int that cannot be a dict key."""

    __hash__ = None  # type: ignore[assignment]


def _no_class(_self: object) -> type:
    raise RuntimeError("no __class__")


_raises_class: Any = property(_no_class)
_claims_bool: Any = property(lambda _self: bool)


class _RaisesClass(int):
    """An int whose `__class__` raises, as bip32's `is_integer` reads it."""

    __class__ = _raises_class


class _ClaimsBool(int):
    """An int whose `__class__` claims bool."""

    __class__ = _claims_bool


class _Index(IntEnum):
    """An int whose str() is its name, which a derivation path would read."""

    HELD = 1
    NOT_HELD = 99

    __str__ = Enum.__str__


class _Plus(int):
    """An int whose `+` answers a str, so the index after it is no int."""

    @override
    def __add__(self, _other: int) -> Any:
        return "x"


def test_each_branch_shape_is_what_it_claims() -> None:
    """What each subclass below answers when its own methods are asked.

    The wallet must ask none of them, so this is where they run.
    """
    assert _Liar(99) in (0, 1)
    with pytest.raises(TypeError, match="unhashable"):
        hash(_Unhashable(1))
    with pytest.raises(RuntimeError, match="no __class__"):
        isinstance(_RaisesClass(1), bool)
    assert isinstance(_ClaimsBool(1), bool)
    assert str(_Index.HELD) == "_Index.HELD"
    assert _Plus(1) + 1 == "x"


_SUBCLASSES: list[tuple[str, Callable[[int], int]]] = [
    ("liar", _Liar),
    ("unhashable", _Unhashable),
    ("raises class", _RaisesClass),
    ("claims bool", _ClaimsBool),
    ("int enum", _Index),
    ("plus", _Plus),
]

_ACCOUNT_XPUB = xpub_from_xprv(_ACCOUNT_XPRV)
_WALLETS: dict[str, Callable[[], RangedWallet]] = {
    "descriptor": lambda: DescriptorWallet([_DESCRIPTOR, _CHANGE_DESCRIPTOR]),
    "key": lambda: BIP32KeyWallet(rootxprv_from_seed("00" * 32), "m/49h/0h/0h"),
    "script": lambda: ScriptWallet([KeyGroup(1, [_ACCOUNT_XPUB])], "p2sh-p2wsh"),
}


def _spending(wallet: RangedWallet) -> Psbt:
    """Return a psbt whose one input and one output are the wallet's 1/0."""
    script_pub_key = wallet.script_pub_key(1, 0)
    prev_tx = Tx(
        vin=[TxIn(OutPoint(b"\x02" * 32, 0))], vout=[TxOut(1000, script_pub_key)]
    )
    psbt = Psbt.from_tx(
        Tx(vin=[TxIn(OutPoint(prev_tx.id, 0))], vout=[TxOut(900, script_pub_key)])
    )
    psbt.inputs[0].non_witness_utxo = prev_tx
    return psbt


# every public method of the three wallets that takes a branch, and the
# wallets that have it
_METHODS: list[tuple[str, tuple[str, ...], Callable[[Any, Any], object]]] = [
    ("address", ("descriptor", "key", "script"), lambda w, b: w.address(b, 0)),
    (
        "assert_derives",
        ("descriptor", "key", "script"),
        lambda w, b: w.assert_derives([w.script_pub_key(1, 0)], b),
    ),
    ("next_address", ("descriptor", "key", "script"), lambda w, b: w.next_address(b)),
    (
        "redeem_script",
        ("descriptor", "key", "script"),
        lambda w, b: w.redeem_script(b, 0),
    ),
    (
        "script_pub_key",
        ("descriptor", "key", "script"),
        lambda w, b: w.script_pub_key(b, 0),
    ),
    (
        "witness_script",
        ("descriptor", "key", "script"),
        lambda w, b: w.witness_script(b, 0),
    ),
    ("descriptor", ("descriptor", "script"), lambda w, b: w.descriptor(b)),
    ("satisfy", ("descriptor",), lambda w, b: w.satisfy({}, b, 0)),
    (
        "update_psbt_input",
        ("descriptor", "script"),
        lambda w, b: w.update_psbt_input(_spending(w), 0, b, 0),
    ),
    (
        "update_psbt_output",
        ("descriptor", "script"),
        lambda w, b: w.update_psbt_output(_spending(w), 0, b, 0),
    ),
]

_BRANCH_CASES = [
    pytest.param(kind, call, subclass, id=f"{kind}-{method}-{name}")
    for method, kinds, call in _METHODS
    for kind in kinds
    for name, subclass in _SUBCLASSES
]


def _outcome(kind: str, call: Callable[[Any, Any], object], value: int) -> object:
    """Return what a new wallet answers, or raises, and what it then holds.

    What it holds is each address handed out, with the types of the
    branch and the index it is recorded under: a subclass's `==` would
    pass a comparison of the records themselves.
    """
    wallet = _WALLETS[kind]()
    try:
        answer = call(wallet, value)
    except Exception as exc:  # noqa: BLE001 -- the plain int's refusal is compared
        return type(exc), str(exc)
    if isinstance(answer, Psbt):
        answer = answer.b64encode()
    elif isinstance(answer, Descriptor):
        answer = str(answer)
    elif isinstance(answer, ScriptPubKey):
        answer = answer.script
    infos = [wallet.address_info(address) for address in wallet.addresses]
    held = [
        (i.address, i.der_path, type(i.branch), i.branch, type(i.index), i.index)
        for i in infos
    ]
    return answer, held


@pytest.mark.parametrize("value", [1, 99])
@pytest.mark.parametrize("kind, call, subclass", _BRANCH_CASES)
def test_a_branch_past_its_type_check_answers_as_the_int_it_holds(
    kind: str,
    call: Callable[[Any, Any], object],
    subclass: Callable[[int], int],
    value: int,
) -> None:
    """Every wallet method uses the exact int `_branch_held` returns.

    So an int subclass's own `__eq__`, `__hash__`, `__class__` or `str()`
    decides no lookup and no derivation, for a branch the wallet has (1)
    and one it has not (99).
    """
    assert _outcome(kind, call, subclass(value)) == _outcome(kind, call, value)


# every public method of the three wallets that takes a position's index,
# called at branch 1, and the wallets that have it
_INDEX_METHODS: list[tuple[str, tuple[str, ...], Callable[[Any, Any], object]]] = [
    ("address", ("descriptor", "key", "script"), lambda w, i: w.address(1, i)),
    (
        "assert_derives",
        ("descriptor", "key", "script"),
        lambda w, i: w.assert_derives(
            [w.script_pub_key(1, 1), w.script_pub_key(1, 2)], 1, i
        ),
    ),
    (
        "redeem_script",
        ("descriptor", "key", "script"),
        lambda w, i: w.redeem_script(1, i),
    ),
    (
        "script_pub_key",
        ("descriptor", "key", "script"),
        lambda w, i: w.script_pub_key(1, i),
    ),
    (
        "witness_script",
        ("descriptor", "key", "script"),
        lambda w, i: w.witness_script(1, i),
    ),
    ("satisfy", ("descriptor",), lambda w, i: w.satisfy({}, 1, i)),
    (
        "update_psbt_input",
        ("descriptor", "script"),
        lambda w, i: w.update_psbt_input(_spending(w), 0, 1, i),
    ),
    (
        "update_psbt_output",
        ("descriptor", "script"),
        lambda w, i: w.update_psbt_output(_spending(w), 0, 1, i),
    ),
]

_INDEX_CASES = [
    pytest.param(kind, call, subclass, id=f"{kind}-{method}-{name}")
    for method, kinds, call in _INDEX_METHODS
    for kind in kinds
    for name, subclass in _SUBCLASSES
]


@pytest.mark.parametrize("value", [1, 99])
@pytest.mark.parametrize("kind, call, subclass", _INDEX_CASES)
def test_an_index_past_its_type_check_answers_as_the_int_it_holds(
    kind: str,
    call: Callable[[Any, Any], object],
    subclass: Callable[[int], int],
    value: int,
) -> None:
    """Every wallet method uses the exact int `_position_held` returns.

    So an int subclass's own `__add__`, `__class__` or `str()` decides no
    derivation, no record and no next index: each method answers as it
    does for the plain int.
    """
    assert _outcome(kind, call, subclass(value)) == _outcome(kind, call, value)
