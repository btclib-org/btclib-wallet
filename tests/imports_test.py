# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the import graph of the `btclib_wallet` package.

Every module must be importable *first*, with no other module of this
package or of `btclib` in sys.modules yet. Nothing else in the suite
establishes that: a test module reaches its subject through whatever the
modules imported before it have already pulled in, so a cycle that only
bites the caller who happens to arrive from the other side stays
invisible.

And every module must reach the units of this package by this package's
name. The units were cut out of `btclib`. Where btclib still publishes
one at its old path, a stale import of it would import, run and pass
against a copy nobody maintains here.

And `bip32` and `psbt` import only the units below them, and so do the
units `psbt` uses, so that each can be split into a distribution of its
own by moving files.
"""

from __future__ import annotations

import ast
import importlib
import importlib.util
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

import btclib_wallet
import btclib_wallet.exceptions
from tests import module_names


def _is_ours(name: str) -> bool:
    """Answer whether a dotted name is this package's, btclib's or ecc's.

    `btclib_secp256k1`, the bindings, is none of the three: reimporting a
    cffi extension module is another matter entirely, so the boundary is
    the three package names and their submodules, not a bare `startswith`.
    """
    return any(
        name == root or name.startswith(f"{root}.")
        for root in ("btclib", "ecc", "btclib_wallet")
    )


def loaded_modules() -> list[str]:
    """Return the modules of this package, of btclib and of ecc."""
    return [name for name in sys.modules if _is_ours(name)]


@pytest.fixture
def unimported() -> Iterator[None]:
    """Hide every module of this package and of btclib, then put it back.

    A subprocess per module would be the obvious way to get a virgin
    interpreter, and it costs an interpreter start-up per module for
    nothing: the import machinery decides what to execute by consulting
    sys.modules and nothing else.

    What the modules imported inside the fixture must not do is outlive
    it. They are fresh objects, so a class reimported here is not the
    class the rest of the suite already holds a reference to, and an
    isinstance check across the two would fail.
    """
    saved = {name: sys.modules[name] for name in loaded_modules()}
    for name in saved:
        del sys.modules[name]
    try:
        yield
    finally:
        for name in loaded_modules():
            del sys.modules[name]
        sys.modules.update(saved)


@pytest.mark.parametrize("module_name", module_names())
def test_import_first(module_name: str, unimported: None) -> None:
    """Import each module first, with nothing of either package loaded."""
    assert importlib.import_module(module_name).__name__ == module_name


def test_the_tests_package_imports_no_submodule() -> None:
    """Importing the `tests` package alone reaches no submodule of either.

    `tests/__init__.py` is imported by every test module before that
    module's own body runs -- before any fixture, `unimported` included,
    so this probe is a subprocess rather than that fixture. The coverage
    floor reads what the import itself reaches, so a helper built at the
    module scope of `tests/__init__.py` by calling into btclib would be
    measured as reached by every module that asks it nothing.
    """
    probe = (
        "import sys, tests; "
        "print(sorted(m for m in sys.modules "
        "if m.split('.')[0] in ('btclib', 'btclib_wallet')))"
    )
    loaded = subprocess.run(  # noqa: S603
        [sys.executable, "-c", probe],
        check=True,
        capture_output=True,
        encoding="utf-8",
        cwd=Path(__file__).resolve().parents[1],
    ).stdout
    assert ast.literal_eval(loaded) == ["btclib_wallet"]


# the top-level units of this package, any of which btclib may still
# carry under its own name. `exceptions` is a module of both packages, so
# what is stale there is a class this package declares, imported from
# btclib's module
_UNITS = tuple(sorted(set(btclib_wallet.__all__) - {"exceptions"}))
_CLASSES = frozenset(
    f"btclib.exceptions.{name}" for name in btclib_wallet.exceptions.__all__
)


def _stale_units_imported_by(path: Path) -> set[str]:
    """Return every `btclib.<unit>`, or moved class, a file's imports name.

    `from btclib import bip32`, `from btclib.bip32 import BIP32Key` and
    `import btclib.bip32.bip32` name the same unit three ways, and each is
    read: the `from` module with each of its aliases covers the first two,
    and an `import` is a complete dotted name on its own.

    A moved class can also be reached as an attribute of btclib's module:
    `btclib.exceptions.FetchError` after `import btclib.exceptions`, and
    `exceptions.FetchError` after `from btclib import exceptions`. Each name
    a file binds to that module is read, and so is every attribute of it.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    # the local spellings of btclib.exceptions in this file
    module_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
            module_names.update(
                alias.asname or alias.name
                for alias in node.names
                if alias.name == "btclib.exceptions"
            )
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
            if node.module == "btclib":
                module_names.update(
                    alias.asname or alias.name
                    for alias in node.names
                    if alias.name == "exceptions"
                )
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and ast.unparse(node.value) in module_names:
            names.add(f"btclib.exceptions.{node.attr}")
    return {
        name
        for name in names
        if name in _CLASSES
        or any(name == f"btclib.{u}" or name.startswith(f"btclib.{u}.") for u in _UNITS)
    }


def test_the_stale_unit_scan_finds_a_planted_import(tmp_path: Path) -> None:
    """`_stale_units_imported_by` reports each spelling of a stale import.

    The real tree has no such import -- that is what the test below
    measures -- so this is the only green run that crosses the branch
    reporting one, and a scan that stopped seeing a spelling would leave
    the test below green over a tree that has it.
    """
    planted = tmp_path / "planted.py"
    planted.write_text(
        "from btclib import b58, bip32\n"
        "from btclib.psbt.psbt import Psbt\n"
        "import btclib.wallet\n"
        "from btclib.script import taproot\n"
        "from btclib.exceptions import BTClibValueError, FetchError\n"
        "import btclib.exceptions\n"
        "btclib.exceptions.RpcError, btclib.exceptions.BTClibTypeError\n"
        "from btclib import exceptions as btclib_exceptions\n"
        "btclib_exceptions.SignerError\n"
        "from btclib_wallet import exceptions\n"
        "exceptions.HttpError\n"
        "from btclib_wallet import mnemonic\n",
        encoding="utf-8",
    )
    assert _stale_units_imported_by(planted) == {
        "btclib.bip32",
        "btclib.exceptions.FetchError",
        "btclib.exceptions.RpcError",
        "btclib.exceptions.SignerError",
        "btclib.psbt.psbt",
        "btclib.psbt.psbt.Psbt",
        "btclib.wallet",
    }


@pytest.mark.parametrize("root", ["src", "tests"])
def test_no_module_imports_a_unit_by_btclibs_name(root: str) -> None:
    """Every import of a unit of this package names this package.

    Static rather than a probe of `sys.modules`: where btclib still carries
    a unit, a stale import of it resolves and runs, and nothing at run time
    says which of the two copies answered. The sources are the checkout's,
    which is what the suite runs: the package is installed editable.
    """
    base = Path(__file__).resolve().parents[1] / root
    stale = {
        str(path.relative_to(base)): found
        for path in sorted(base.rglob("*.py"))
        if (found := _stale_units_imported_by(path))
    }
    assert stale == {}


# `silent_payments` is the top-level module; `psbt.silent_payments` belongs
# to `psbt`.
_ALLOWED_UNITS = {
    "_fee": frozenset(),
    "bip32": frozenset(),
    "psbt": frozenset({"_fee", "bip32", "silent_payments"}),
    "silent_payments": frozenset(),
}


def _units_imported_by(path: Path, package: str) -> set[str]:
    """Return every unit of `btclib_wallet` one source file's imports reach.

    A unit is the first name below `btclib_wallet`: a top-level module or a
    subpackage. `package` is the dotted package the file sits in, which a
    relative import is resolved against. `from btclib_wallet import psbt`
    and `from . import psbt` in the root name the unit as an alias, so the
    aliases are read where the module is the root itself, and `import
    btclib_wallet` alone is reported as the root. Imports inside a function
    are found too, `ast.walk` visiting every node.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    units: set[str] = set()
    for node in ast.walk(tree):
        modules: list[tuple[str, list[str]]]
        if isinstance(node, ast.Import):
            modules = [(alias.name, []) for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                parts = package.split(".")
                base = ".".join(parts[: len(parts) - node.level + 1])
                module = f"{base}.{module}" if module else base
            modules = [(module, [alias.name for alias in node.names])]
        else:
            continue
        for module, aliases in modules:
            parts = module.split(".")
            if parts[0] != "btclib_wallet":
                continue
            if len(parts) > 1:
                units.add(parts[1])
            elif aliases:
                units.update(aliases)
            else:
                units.add("btclib_wallet")
    return units


def _package_of(path: Path, src: Path) -> str:
    """Return the dotted package a source file under `src` sits in."""
    return ".".join(path.relative_to(src).parent.parts)


def _layer_violations(src: Path) -> dict[str, set[str]]:
    """Return, per file of a constrained unit, the units it may not import."""
    violations: dict[str, set[str]] = {}
    for path in sorted((src / "btclib_wallet").rglob("*.py")):
        unit = path.relative_to(src).parts[1].removesuffix(".py")
        if unit not in _ALLOWED_UNITS:
            continue
        found = _units_imported_by(path, _package_of(path, src))
        if forbidden := found - _ALLOWED_UNITS[unit] - {unit}:
            violations[path.relative_to(src).as_posix()] = forbidden
    return violations


def _plant(src: Path, relative: str, line: str) -> None:
    """Write a module with one import line under a fake `src`."""
    path = src / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(line + "\n", encoding="utf-8")


@pytest.mark.parametrize(
    "relative, line, forbidden",
    [
        (
            "btclib_wallet/psbt/psbt.py",
            "from btclib_wallet.descriptors import parse",
            {"descriptors"},
        ),
        (
            "btclib_wallet/psbt/psbt.py",
            "def f():\n    import btclib_wallet.wallet.wallet",
            {"wallet"},
        ),
        (
            "btclib_wallet/psbt/psbt.py",
            "from .. import descriptors",
            {"descriptors"},
        ),
        (
            "btclib_wallet/psbt/psbt.py",
            "from ..descriptors.descriptors import parse",
            {"descriptors"},
        ),
        (
            "btclib_wallet/psbt/psbt.py",
            "from btclib_wallet import descriptors",
            {"descriptors"},
        ),
        ("btclib_wallet/psbt/psbt.py", "import btclib_wallet", {"btclib_wallet"}),
        ("btclib_wallet/bip32/bip32.py", "from ..psbt import Psbt", {"psbt"}),
        (
            "btclib_wallet/bip32/__init__.py",
            "from btclib_wallet.bip44 import purpose",
            {"bip44"},
        ),
    ],
)
def test_the_layer_scan_finds_a_planted_import(
    tmp_path: Path, relative: str, line: str, forbidden: set[str]
) -> None:
    """`_layer_violations` reports each spelling of an upward import.

    The real tree has none, so only this test exercises a report.
    """
    _plant(tmp_path, relative, line)
    assert _layer_violations(tmp_path) == {relative: forbidden}


@pytest.mark.parametrize(
    "relative, line",
    [
        ("btclib_wallet/psbt/psbt.py", "from btclib_wallet.bip32 import BIP32Key"),
        ("btclib_wallet/psbt/psbt.py", "from btclib_wallet import _fee"),
        ("btclib_wallet/psbt/psbt.py", "from .. import silent_payments"),
        ("btclib_wallet/psbt/psbt.py", "from .silent_payments import x"),
        ("btclib_wallet/psbt/psbt.py", "from btclib_wallet.psbt.psbt_in import x"),
        ("btclib_wallet/bip32/bip32.py", "from .der_path import DerPath"),
        ("btclib_wallet/bip32/bip32.py", "from btclib.bip32 import x"),
        ("btclib_wallet/descriptors/descriptors.py", "from ..psbt import Psbt"),
    ],
)
def test_the_layer_scan_admits_the_allowed_imports(
    tmp_path: Path, relative: str, line: str
) -> None:
    """`_layer_violations` leaves a unit's own and allowed imports alone."""
    _plant(tmp_path, relative, line)
    assert _layer_violations(tmp_path) == {}


def test_bip32_and_psbt_import_only_the_units_below_them() -> None:
    """Keep `bip32`, `psbt` and what `psbt` uses to `_ALLOWED_UNITS`.

    So each can move to a distribution of its own.
    """
    assert _layer_violations(Path(btclib_wallet.__path__[0]).parent) == {}


def test_btclib_imports_nothing_of_btclib_wallet() -> None:
    """No module of the installed `btclib` imports `btclib_wallet`.

    The units were cut out of `btclib`, which must not depend on the
    package that now holds them.
    """
    spec = importlib.util.find_spec("btclib")
    assert spec is not None
    assert spec.submodule_search_locations is not None
    (base,) = (Path(location) for location in spec.submodule_search_locations)
    found = {
        str(path.relative_to(base)): units
        for path in sorted(base.rglob("*.py"))
        if (
            units := _units_imported_by(
                path, ".".join(("btclib", *path.relative_to(base).parent.parts))
            )
        )
    }
    assert found == {}


@pytest.mark.parametrize(
    "module_name, heavy_expected",
    [
        ("btclib_wallet.electrum", False),
        ("btclib_wallet.exceptions", False),
        ("btclib_wallet.fetch", True),
    ],
)
def test_the_codec_and_the_exceptions_open_nothing(
    module_name: str, heavy_expected: bool
) -> None:
    """Importing either loads no client, no HTTP and no TLS.

    `btclib_wallet.fetch`'s `__init__` imports every fetcher, and
    `urllib`, `ssl` and `socket` behind them. A server of the Electrum
    protocol imports the codec alone, and every module catching a
    `FetchError` imports the exceptions alone: neither pays for a client.

    `socket` is not asserted absent: `importlib.metadata`, which reads the
    version of btclib, imports it through `email.utils` on interpreters
    before 3.13. A subprocess, because `unimported` leaves in
    `sys.modules` a `bitcoin_core_rpc` an earlier test imported.
    `btclib_wallet.fetch` is the control, which loads them.
    """
    probe = f"import {module_name}, sys; print(sorted(sys.modules))"
    loaded = subprocess.run(  # noqa: S603
        [sys.executable, "-c", probe],
        check=True,
        capture_output=True,
        encoding="utf-8",
    ).stdout
    heavy = {"bitcoin_core_rpc", "http.client", "ssl", "urllib.request"}
    assert bool(set(ast.literal_eval(loaded)) & heavy) is heavy_expected
