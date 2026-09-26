# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The classes a refusal of this package may leave as, and their test.

btclib's own, and btclib_ecc's wherever an argument reaches that package,
the curve arithmetic and the schemes on it being btclib_ecc's (issue
btclib-org/btclib#2282). `btclib.exceptions` binds btclib_ecc's classes,
each beside the same built-in as btclib's of its kind and none of them a
`BTClibException`, so a test holding a function to the contract names one
of the tuples below rather than btclib's class alone. A bare built-in is
in none of them, which is what the first test asserts.

Where the installed btclib binds no btclib_ecc class, a btclib without
issue btclib-org/btclib#2282, each name below stands for btclib's own
class instead, and a tuple holds btclib's class twice: a test reads the
same against either btclib.

That fallback is silent, so a name spelled other than btclib binds it
reads as a btclib without the issue. `unresolved_ecc_lookups` is what
refuses it: wherever btclib delegates to a package of its own, each name
this suite looks up has to resolve.

Shared test code belongs in `tests/__init__.py`; these tuples are here
rather than there because this module is what tests them.
"""

from __future__ import annotations

import importlib.util
from collections.abc import Mapping

import btclib.exceptions
import pytest
from btclib.curves import set_libsecp256k1_serving
from btclib.exceptions import (
    BTClibException,
    BTClibRuntimeError,
    BTClibTypeError,
    BTClibValueError,
)

from btclib_wallet import bip322
from tests import WALKED_PACKAGES

# the package btclib delegates its curve arithmetic to, as it is imported
ECC_PACKAGE = "btclib_ecc"
# the name `btclib.exceptions` binds each of that package's classes by,
# and btclib's own class of the same kind
_ECC_CLASSES = {
    "BTClibEccValueError": BTClibValueError,
    "BTClibEccTypeError": BTClibTypeError,
    "BTClibEccRuntimeError": BTClibRuntimeError,
    "BTClibEccException": BTClibException,
}


def _ecc(name: str) -> type[Exception]:
    """Return btclib_ecc's class as btclib binds it, or btclib's own."""
    found: type[Exception] = getattr(btclib.exceptions, name, _ECC_CLASSES[name])
    return found


VALUE_ERRORS = (BTClibValueError, _ecc("BTClibEccValueError"))
TYPE_ERRORS = (BTClibTypeError, _ecc("BTClibEccTypeError"))
RUNTIME_ERRORS = (BTClibRuntimeError, _ecc("BTClibEccRuntimeError"))
# the base of each family, for a test whose contract is the base
EXCEPTIONS = (BTClibException, _ecc("BTClibEccException"))


def unresolved_ecc_lookups(
    namespace: Mapping[str, object], dispatch_module: str, *, importable: bool
) -> list[str]:
    """Return what a btclib delegating to a package of its own leaves unbound.

    `namespace` is `btclib.exceptions`' own, `dispatch_module` the module
    defining the libsecp256k1 dispatch, and `importable` whether
    `ECC_PACKAGE` is. btclib delegates wherever that package is
    importable, a name of `btclib.exceptions` starts with `BTClibEcc`, an
    exception class it binds comes from a package other than btclib, or
    the dispatch is defined outside btclib, a built-in class being no
    package's: the last two are what a renamed package still does,
    whatever its names. Where it delegates, each name of `_ECC_CLASSES`
    is bound, `ECC_PACKAGE` is importable, and every package a class or
    the dispatch comes from is `ECC_PACKAGE` and one
    `tests.no_bindings_anywhere` walks. Where it does not, nothing is
    asked, and the list is empty.
    """
    packages = {
        value.__module__.split(".", maxsplit=1)[0]
        for value in namespace.values()
        if isinstance(value, type) and issubclass(value, BaseException)
    } | {dispatch_module.split(".", maxsplit=1)[0]}
    packages -= {"btclib", "builtins"}
    delegates = (
        importable
        or bool(packages)
        or any(n.startswith("BTClibEcc") for n in namespace)
    )
    if not delegates:
        return []
    missing = [name for name in _ECC_CLASSES if name not in namespace]
    if not importable:
        missing.append(ECC_PACKAGE)
    missing += [
        f"package {package}"
        for package in sorted(packages)
        if package != ECC_PACKAGE or package not in WALKED_PACKAGES
    ]
    return missing


@pytest.mark.parametrize(
    "family, own, built_in",
    [
        pytest.param(VALUE_ERRORS, BTClibValueError, ValueError, id="value"),
        pytest.param(TYPE_ERRORS, BTClibTypeError, TypeError, id="type"),
        pytest.param(RUNTIME_ERRORS, BTClibRuntimeError, RuntimeError, id="runtime"),
        pytest.param(EXCEPTIONS, BTClibException, Exception, id="base"),
    ],
)
def test_a_family_holds_the_libraries_classes_and_no_bare_built_in(
    family: tuple[type[Exception], ...],
    own: type[Exception],
    built_in: type[Exception],
) -> None:
    """The class of btclib is in it, of its kind, and a bare one is not.

    The last is the half that makes the tuple a contract: a test naming
    the family still fails on the built-in leaking from underneath.
    """
    assert own in family
    assert all(issubclass(member, built_in) for member in family)
    assert not issubclass(built_in, family)


def test_every_ecc_lookup_resolves_where_btclib_delegates() -> None:
    """The installed btclib leaves no name of this suite's unbound.

    A lookup falling back to btclib's own class where btclib delegates
    reads as a btclib without issue btclib-org/btclib#2282, and narrows
    every family above to btclib's class alone.
    """
    namespace = dict(vars(btclib.exceptions))
    importable = importlib.util.find_spec(ECC_PACKAGE) is not None
    dispatch = set_libsecp256k1_serving.__module__
    assert unresolved_ecc_lookups(namespace, dispatch, importable=importable) == []


def test_bip322_invalid_holds_each_runtime_class() -> None:
    """`bip322._INVALID` catches the runtime class of both libraries."""
    assert set(RUNTIME_ERRORS) <= set(bip322._INVALID)


def _class_of(module: str) -> type[Exception]:
    """Return an exception class `module` defines."""
    return type("Error", (RuntimeError,), {"__module__": module})


@pytest.mark.parametrize(
    "namespace, dispatch, importable, missing",
    [
        pytest.param({}, "btclib.curves.curve", False, [], id="own"),
        pytest.param(
            dict.fromkeys(_ECC_CLASSES, _class_of("btclib_ecc.exceptions")),
            "btclib_ecc.curves.curve",
            True,
            [],
            id="delegating",
        ),
        pytest.param(
            {},
            "btclib.curves.curve",
            True,
            [*_ECC_CLASSES],
            id="importable-names-unbound",
        ),
        pytest.param(
            {"BTClibEccValueError": ValueError},
            "btclib.curves.curve",
            True,
            [n for n in _ECC_CLASSES if n != "BTClibEccValueError"],
            id="one-name-bound",
        ),
        pytest.param(
            {"BTClibEccValueError": ValueError},
            "btclib.curves.curve",
            False,
            [*(n for n in _ECC_CLASSES if n != "BTClibEccValueError"), ECC_PACKAGE],
            id="name-alone",
        ),
        pytest.param(
            {"RenamedError": _class_of("renamed.exceptions")},
            "renamed.curves.curve",
            False,
            [*_ECC_CLASSES, ECC_PACKAGE, "package renamed"],
            id="renamed",
        ),
        pytest.param(
            {},
            "renamed.curves.curve",
            False,
            [*_ECC_CLASSES, ECC_PACKAGE, "package renamed"],
            id="dispatch-renamed",
        ),
    ],
)
def test_unresolved_ecc_lookups(
    namespace: dict[str, object], dispatch: str, *, importable: bool, missing: list[str]
) -> None:
    """Each way of delegating asks for every name, and not delegating none."""
    assert unresolved_ecc_lookups(namespace, dispatch, importable=importable) == missing
