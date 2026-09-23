# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The gate for `ec`, the parameter that says which curve is meant.

btclib's own `curve_parameter_test.py` holds every `ec` of btclib to the
rule, and this file holds this package's: a value of a type the
signature does not declare leaves as a `BTClibTypeError`, and a value of
a declared type that no valid input carries as a `BTClibValueError`.

The first half is the whole of the table below. The second half is
answered apart from the table, because **every curve is a valid ec** --
that is what the parameter is for. What can be wrong is a curve the
*key* names: an xpub carries a network, and a network has a curve, so a
mismatch there is a fact about the pair and a `BTClibValueError`.
`test_the_curve_a_key_names_is_still_a_value` is that half, and it is in
this file because the type guard sits in front of that comparison: an ec
of no curve type compares unequal to every network's curve, so a
caller's own mistake would otherwise be reported as a statement about
the key.

`_curve_parameters` reads every public function of the package whose
signature declares a `Curve` or a `CurveGroup`, so
`test_the_table_is_every_curve_parameter` fails on a function this file
does not drive -- a new one, or one that gains the parameter. There is no
exemption list, and that is the state to keep.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from btclib.curves import CURVES, CurveGroup, secp256k1
from btclib.exceptions import BTClibTypeError, BTClibValueError

from btclib_wallet.bip32.bip32 import (
    BIP32KeyData,
    point_from_xpub,
    rootxprv_from_seed,
    xpub_from_xprv,
)

_LIBRARY = Path(__file__).parents[1] / "src" / "btclib_wallet"

# a value of no type any `ec` declares, and both are calls mypy refuses
_WRONG_TYPES: tuple[Any, ...] = (None, 1.5)

_XPUB = xpub_from_xprv(rootxprv_from_seed("00" * 32))

# a group with p, a and b and neither the n nor the G a Curve adds, which
# is the wrong type a check spelled against the base class would let in
_GROUP = CurveGroup(13, 0, 2)


@dataclass(frozen=True)
class _Case:
    """A function taking an ec, and a call of it that works."""

    dotted: str
    function: Any
    # every argument but ec, by keyword
    args: dict[str, Any] = field(default_factory=dict)
    # the valid ec
    ec: CurveGroup = secp256k1


_CASES = (
    # the extended-key parse, which compares `ec` against the curve the
    # version bytes name rather than computing in it
    _Case(
        "btclib_wallet.bip32.bip32.point_from_xpub", point_from_xpub, {"xpub": _XPUB}
    ),
)

_IDS = tuple(case.dotted for case in _CASES)


def _curve_parameters() -> set[str]:
    """Return every public function of the package taking a curve.

    The **annotation** and not the name `ec`, so that a curve parameter
    spelled otherwise is in the table too. `Curve` and `CurveGroup`
    exactly, and not a union containing one: a union is a lookup
    comparing against a curve, where these functions have a curve to
    compute in.

    A method counts, and a private function does not: the guard is what
    those call.
    """
    found: set[str] = set()

    def walk(node: ast.Module | ast.ClassDef, module: str, prefix: str) -> None:
        for child in node.body:
            if isinstance(child, ast.ClassDef):
                walk(child, module, f"{prefix}{child.name}.")
            elif isinstance(child, ast.FunctionDef):
                if child.name.startswith("_") and not child.name.startswith("__"):
                    continue
                arguments = [
                    *child.args.posonlyargs,
                    *child.args.args,
                    *child.args.kwonlyargs,
                ]
                if any(
                    a.annotation is not None
                    and ast.unparse(a.annotation) in {"Curve", "CurveGroup"}
                    for a in arguments
                ):
                    found.add(f"{module}.{prefix}{child.name}")

    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        walk(ast.parse(path.read_text(encoding="utf-8")), module, "")
    return found


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_the_call_works(case: _Case) -> None:
    """The fixture is valid, which is what makes a refusal below a finding.

    Without this a case whose arguments had gone stale would pass every
    test in the file by refusing everything it is handed.
    """
    case.function(**case.args, ec=case.ec)


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_a_wrong_type_leaves_as_a_btclib_type_error(case: _Case) -> None:
    """The rule, with every other argument left valid.

    `BTClibTypeError` and not `BTClibException`: the failure this is
    around is a `BTClibValueError`, which would be the library calling a
    caller's mistake a fact about the key.
    """
    for wrong in _WRONG_TYPES:
        with pytest.raises(BTClibTypeError, match="invalid ec type"):
            case.function(**case.args, ec=wrong)


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_a_curve_group_is_not_a_curve(case: _Case) -> None:
    """The wrong type a check against the group would let through.

    `CurveGroup` is what `Curve` derives from, and it has p, a and b, so a
    check spelled against it would pass an ec that the very next line
    reads an `n` or a `G` off.
    """
    with pytest.raises(BTClibTypeError, match="invalid ec type: CurveGroup"):
        case.function(**case.args, ec=_GROUP)


def test_the_table_is_every_curve_parameter() -> None:
    """No exemption list: a function taking a curve is one driven here.

    The walk is the inventory, so a new `ec` parameter -- or an existing
    function that gains one -- fails here rather than going ungated in
    silence.
    """
    driven = {case.dotted for case in _CASES}
    found = _curve_parameters()
    assert driven == found, f"not driven: {sorted(found - driven)}"


def test_the_walk_reaches_what_it_claims() -> None:
    """A function the walk must find, and the ones it must not.

    A walk that found nothing would fail the test above only while the
    table is not empty.
    """
    found = _curve_parameters()
    assert "btclib_wallet.bip32.bip32.point_from_xpub" in found
    # a function of the same module with no ec at all, and a method
    assert "btclib_wallet.bip32.bip32.xpub_from_xprv" not in found
    assert "btclib_wallet.bip32.bip32.BIP32KeyData.parse" not in found


def test_the_curve_a_key_names_is_still_a_value() -> None:
    """The second rule, which is the one the guard sits in front of.

    An extended key names its network in its version bytes, so an ec that
    is not that network's curve is a fact about the pair and a
    `BTClibValueError`.
    """
    xpub = BIP32KeyData.b58decode(_XPUB)
    with pytest.raises(BTClibValueError, match="ec/xpub version"):
        point_from_xpub(xpub, CURVES["secp256r1"])
