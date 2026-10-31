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
name. The units were cut out of `btclib`, which still publishes them at
its old paths, so a `btclib.bip32` left behind would import, run and pass
against a copy nobody maintains here.

And `bip32` and `psbt` import only the units below them, and so do the
units `psbt` uses, so that each can be split into a distribution of its
own by moving files. The files that move with `bip32` and `descriptors`
import nothing of the package but those two units, and nothing of the
suite but each other and the helpers a split copies.
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


# the top-level units of this package, which btclib also still carries
# under its own name until its side of btclib-org/btclib#2129 removes them
_UNITS = tuple(sorted(btclib_wallet.__all__))


def _stale_units_imported_by(path: Path) -> set[str]:
    """Return every `btclib.<unit>` one source file's own imports name.

    `from btclib import bip32`, `from btclib.bip32 import BIP32Key` and
    `import btclib.bip32.bip32` name the same unit three ways, and each is
    read: the `from` module with each of its aliases covers the first two,
    and an `import` is a complete dotted name on its own.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
    return {
        name
        for name in names
        if any(name == f"btclib.{u}" or name.startswith(f"btclib.{u}.") for u in _UNITS)
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
        "from btclib_wallet import mnemonic\n",
        encoding="utf-8",
    )
    assert _stale_units_imported_by(planted) == {
        "btclib.bip32",
        "btclib.psbt.psbt",
        "btclib.psbt.psbt.Psbt",
        "btclib.wallet",
    }


@pytest.mark.parametrize("root", ["src", "tests"])
def test_no_module_imports_a_unit_by_btclibs_name(root: str) -> None:
    """Every import of a unit of this package names this package.

    Static rather than a probe of `sys.modules`: btclib still carries the
    units, so a stale import resolves and runs, and nothing at run time
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
    "descriptors": frozenset({"bip32"}),
    "psbt": frozenset({"_fee", "bip32", "descriptors", "silent_payments"}),
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
    units: set[str] = set()
    for module, aliases in _imports_of(path, package):
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


def _imports_of(path: Path, package: str) -> Iterator[tuple[str, list[str]]]:
    """Yield each module one source file imports, and the names it takes.

    An `import` takes none, and `_units_imported_by` says what `package`
    is.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, []
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                parts = package.split(".")
                base = ".".join(parts[: len(parts) - node.level + 1])
                module = f"{base}.{module}" if module else base
            yield module, [alias.name for alias in node.names]


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
            "from btclib_wallet.wallet import DescriptorWallet",
            {"wallet"},
        ),
        (
            "btclib_wallet/psbt/psbt.py",
            "def f():\n    import btclib_wallet.wallet.wallet",
            {"wallet"},
        ),
        (
            "btclib_wallet/psbt/psbt.py",
            "from .. import tx_builder",
            {"tx_builder"},
        ),
        (
            "btclib_wallet/psbt/psbt.py",
            "from ..wallet.wallet import Wallet",
            {"wallet"},
        ),
        (
            "btclib_wallet/psbt/psbt.py",
            "from btclib_wallet import bip44",
            {"bip44"},
        ),
        ("btclib_wallet/psbt/psbt.py", "import btclib_wallet", {"btclib_wallet"}),
        ("btclib_wallet/bip32/bip32.py", "from ..psbt import Psbt", {"psbt"}),
        (
            "btclib_wallet/descriptors/descriptors.py",
            "from btclib_wallet.wallet import DescriptorWallet",
            {"wallet"},
        ),
        (
            "btclib_wallet/descriptors/descriptors.py",
            "from ..psbt import Psbt",
            {"psbt"},
        ),
        (
            "btclib_wallet/descriptors/descriptors.py",
            "from ..bip44 import account_descriptors",
            {"bip44"},
        ),
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
        ("btclib_wallet/psbt/psbt_updater.py", "from ..descriptors import parse"),
        ("btclib_wallet/psbt/psbt.py", "from .silent_payments import x"),
        ("btclib_wallet/psbt/psbt.py", "from btclib_wallet.psbt.psbt_in import x"),
        ("btclib_wallet/bip32/bip32.py", "from .der_path import DerPath"),
        ("btclib_wallet/bip32/bip32.py", "from btclib.bip32 import x"),
        (
            "btclib_wallet/descriptors/descriptors.py",
            "from ..bip32 import BIP32KeyOrigin",
        ),
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


# the units that move with their tests, and what of the suite a file that
# moves with them may import: the tests of those units, and the helpers a
# split copies, among them the names of `tests/__init__.py` those files use
_MOVING_UNITS = ("bip32", "descriptors")
_COPIED_HELPERS = (
    *(f"tests.{unit}" for unit in _MOVING_UNITS),
    "tests.NOT_STRIPPED",
    "tests.chained_text",
    "tests.conftest.JsonGolden",
    "tests.exception_family_test.TYPE_ERRORS",
    "tests.exception_family_test.VALUE_ERRORS",
    "tests.load",
    "tests.needs_bindings",
    "tests.no_bindings",
    "tests.no_bindings_anywhere",
    "tests.replace_unchecked",
    "tests.secret_free",
    "tests.vector_id",
)
# the files that move with `bip32` and `descriptors` and that the sdist
# carries; `tests/moving_imports_test.py` holds the others
_MOVING_FILES = ("tests/bip32", "tests/descriptors", "tests/integration/infer_test.py")


def _moving_file_violations(root: Path, moving: tuple[str, ...]) -> dict[str, set[str]]:
    """Return, per file under `root` that moves, what it may not import.

    `moving` names files and directories relative to `root`, a directory
    standing for every `*.py` below it. A unit of `btclib_wallet` is
    reported by its name, and a name of the suite by its dotted path below
    `tests`: `from tests import load` reaches `tests.load`.
    """
    violations: dict[str, set[str]] = {}
    for entry in moving:
        top = root / entry
        for path in [top] if top.suffix == ".py" else sorted(top.rglob("*.py")):
            package = _package_of(path, root)
            suite = {
                f"{module}.{alias}" if alias else module
                for module, aliases in _imports_of(path, package)
                if module.split(".")[0] == "tests"
                for alias in aliases or [""]
            }
            forbidden = (_units_imported_by(path, package) - set(_MOVING_UNITS)) | {
                name
                for name in suite
                if not any(
                    name == a or name.startswith(f"{a}.") for a in _COPIED_HELPERS
                )
            }
            if forbidden:
                violations[path.relative_to(root).as_posix()] = forbidden
    return violations


@pytest.mark.parametrize(
    "relative, line, forbidden",
    [
        (
            "tests/descriptors/x_test.py",
            "from btclib_wallet.psbt import Psbt",
            {"psbt"},
        ),
        ("tests/descriptors/x_test.py", "from btclib_wallet import bip44", {"bip44"}),
        ("tests/bip32/x_test.py", "import btclib_wallet", {"btclib_wallet"}),
        (
            "tests/bip32/x_test.py",
            "def f():\n    from btclib_wallet.wallet import Wallet",
            {"wallet"},
        ),
        (
            "tests/descriptors/x_test.py",
            "from tests.strategies import psbt",
            {"tests.strategies.psbt"},
        ),
        (
            "tests/descriptors/x_test.py",
            "from tests import strategies",
            {"tests.strategies"},
        ),
        ("tests/descriptors/x_test.py", "from .. import conftest", {"tests.conftest"}),
        (
            "tests/bip32/x_test.py",
            "from tests.conftest import tmp_golden",
            {"tests.conftest.tmp_golden"},
        ),
        (
            "tests/bip32/x_test.py",
            "from tests import module_names",
            {"tests.module_names"},
        ),
        ("tests/bip32/x_test.py", "from tests import _private", {"tests._private"}),
        (
            "tests/bip32/x_test.py",
            "import tests.exception_family_test",
            {"tests.exception_family_test"},
        ),
        (
            "tests/bip32/x_test.py",
            "from tests.exception_family_test import EXCEPTIONS",
            {"tests.exception_family_test.EXCEPTIONS"},
        ),
        ("tests/bip32/x_test.py", "import tests", {"tests"}),
        (
            "tests/integration/infer_test.py",
            "from btclib_wallet.wallet import Wallet",
            {"wallet"},
        ),
    ],
)
def test_the_moving_file_scan_finds_a_planted_import(
    tmp_path: Path, relative: str, line: str, forbidden: set[str]
) -> None:
    """`_moving_file_violations` reports each spelling of an import that stays.

    The real files have none, so only this test exercises a report. The
    files `_MOVING_FILES` names one by one are planted empty first, since
    a missing one is an error rather than nothing to report.
    """
    _plant(tmp_path, "tests/integration/infer_test.py", "")
    _plant(tmp_path, relative, line)
    assert _moving_file_violations(tmp_path, _MOVING_FILES) == {relative: forbidden}


@pytest.mark.parametrize(
    "relative, line",
    [
        ("tests/descriptors/x_test.py", "from btclib_wallet.bip32 import derive"),
        ("tests/bip32/x_test.py", "from btclib_wallet import descriptors"),
        ("tests/bip32/x_test.py", "from btclib.psbt import Psbt"),
        ("tests/bip32/x_test.py", "from tests import load"),
        ("tests/bip32/x_test.py", "from tests.conftest import JsonGolden"),
        (
            "tests/bip32/x_test.py",
            "from tests.exception_family_test import VALUE_ERRORS",
        ),
        ("tests/bip32/x_test.py", "from ..secret_free import assert_secret_free"),
        ("tests/descriptors/x_test.py", "from . import infer_test"),
        (
            "tests/integration/infer_test.py",
            "from tests.descriptors.infer_test import _text",
        ),
    ],
)
def test_the_moving_file_scan_admits_the_allowed_imports(
    tmp_path: Path, relative: str, line: str
) -> None:
    """`_moving_file_violations` admits the moving units and the helpers."""
    _plant(tmp_path, "tests/integration/infer_test.py", "")
    _plant(tmp_path, relative, line)
    assert _moving_file_violations(tmp_path, _MOVING_FILES) == {}


def test_the_files_moving_with_bip32_and_descriptors_import_only_what_moves() -> None:
    """Keep the files that move with `bip32` and `descriptors` to what moves.

    An `ast` walk rather than a `git grep`, since the suite also runs from
    an unpacked sdist, where there is no `.git`.
    """
    root = Path(__file__).resolve().parents[1]
    assert _moving_file_violations(root, _MOVING_FILES) == {}


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
