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

And `psbt` imports only the units below it, and so do the units it
uses, so that it can be split into a distribution of its own by moving
files.

And nothing imports a private name of `bip32_descriptors`, the package
`bip32` and `descriptors` are read from: what it does not publish can
change in any of its releases.
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
    assert not stale


# `silent_payments` is the top-level module; `psbt.silent_payments` belongs
# to `psbt`.
_ALLOWED_UNITS = {
    "_fee": frozenset({"_refusal"}),
    "_refusal": frozenset(),
    "psbt": frozenset({"_fee", "_refusal", "silent_payments"}),
    "silent_payments": frozenset({"_refusal"}),
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
        (
            "btclib_wallet/silent_payments.py",
            "from .psbt import Psbt",
            {"psbt"},
        ),
        (
            "btclib_wallet/_fee.py",
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
        ("btclib_wallet/psbt/psbt.py", "from bip32_descriptors.bip32 import BIP32Key"),
        ("btclib_wallet/psbt/psbt.py", "from btclib_wallet import _fee"),
        ("btclib_wallet/psbt/psbt.py", "from .. import silent_payments"),
        (
            "btclib_wallet/psbt/psbt_updater.py",
            "from bip32_descriptors.descriptors import parse",
        ),
        ("btclib_wallet/psbt/psbt.py", "from .silent_payments import x"),
        ("btclib_wallet/psbt/psbt.py", "from btclib_wallet.psbt.psbt_in import x"),
        ("btclib_wallet/silent_payments.py", "from ._refusal import _quoted"),
        ("btclib_wallet/_fee.py", "from btclib.fee import x"),
    ],
)
def test_the_layer_scan_admits_the_allowed_imports(
    tmp_path: Path, relative: str, line: str
) -> None:
    """`_layer_violations` leaves a unit's own and allowed imports alone."""
    _plant(tmp_path, relative, line)
    assert _layer_violations(tmp_path) == {}


def test_psbt_imports_only_the_units_below_it() -> None:
    """Keep `psbt` and what it uses to `_ALLOWED_UNITS`.

    So it can move to a distribution of its own.
    """
    assert _layer_violations(Path(btclib_wallet.__path__[0]).parent) == {}


_PACKAGE_OF_THE_SPLIT = "bip32_descriptors"


def _is_private(name: str) -> bool:
    """Answer whether a part of a dotted name is private and no dunder."""
    return any(
        part.startswith("_") and not part.endswith("__") for part in name.split(".")
    )


def _imported_names(node: ast.AST) -> dict[str, str]:
    """Return each local name an import binds of `bip32_descriptors`, by path.

    `import bip32_descriptors.bip32` binds `bip32_descriptors`, which names
    itself; with `as`, the alias names the whole path.
    """
    if isinstance(node, ast.Import):
        return {
            alias.asname or alias.name.split(".")[0]: (
                alias.name if alias.asname else alias.name.split(".")[0]
            )
            for alias in node.names
            if alias.name.split(".")[0] == _PACKAGE_OF_THE_SPLIT
        }
    if (
        isinstance(node, ast.ImportFrom)
        and node.level == 0
        and (node.module or "").split(".")[0] == _PACKAGE_OF_THE_SPLIT
    ):
        return {
            alias.asname or alias.name: f"{node.module}.{alias.name}"
            for alias in node.names
        }
    return {}


# the nodes that open a scope of their own
_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_SCOPES = (*_DEFS, ast.Lambda, *_COMPREHENSIONS)


def _outside(scope: ast.AST) -> list[ast.AST]:
    """Return the parts of a scope's node that the enclosing scope evaluates.

    These are a def's decorators, defaults and annotations, a class's
    decorators, bases and keywords, a lambda's defaults, and a
    comprehension's first iterable and the targets of its `:=`.
    """
    if isinstance(scope, _COMPREHENSIONS):
        return [scope.generators[0].iter, *_walrus_targets(scope)]
    parts: list[ast.AST | None] = []
    if isinstance(scope, _DEFS):
        parts.extend(scope.decorator_list)
    if isinstance(scope, ast.ClassDef):
        parts.extend((*scope.bases, *scope.keywords))
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        arguments = scope.args
        parts.extend((*arguments.defaults, *arguments.kw_defaults))
        parts.extend(argument.annotation for argument in _parameters(arguments))
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        parts.append(scope.returns)
    return [part for part in parts if part is not None]


def _walrus_targets(comprehension: ast.AST) -> list[ast.AST]:
    """Return the target of each `:=` in a comprehension, nested ones too.

    Python binds them in the scope enclosing the comprehension.
    """
    targets: list[ast.AST] = []
    stack = list(ast.iter_child_nodes(comprehension))
    while stack:
        node = stack.pop()
        if isinstance(node, ast.NamedExpr):
            targets.append(node.target)
        if not isinstance(node, (*_DEFS, ast.Lambda)):
            stack.extend(ast.iter_child_nodes(node))
    return targets


def _parameters(arguments: ast.arguments) -> list[ast.arg]:
    """Return the parameters of a def or a lambda."""
    return [
        argument
        for argument in (
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
            arguments.vararg,
            arguments.kwarg,
        )
        if argument is not None
    ]


def _own_nodes(scope: ast.AST) -> list[ast.AST]:
    """Return the nodes a scope evaluates.

    A nested scope's node is one of them, with the parts of it that
    `_outside` returns, but not its body.
    """
    skip = {id(part) for part in _outside(scope)}
    own: list[ast.AST] = []
    stack = [
        child
        for child in ast.iter_child_nodes(scope)
        if not isinstance(child, ast.arguments)
    ]
    while stack:
        node = stack.pop()
        if id(node) in skip:
            continue
        own.append(node)
        if isinstance(node, _SCOPES):
            stack.extend(_outside(node))
        else:
            stack.extend(ast.iter_child_nodes(node))
    return own


def _bound_names(node: ast.AST) -> set[str]:
    """Return the names one node binds in the scope that evaluates it."""
    names: set[str | None] = set()
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
        names = {node.id}
    elif isinstance(node, _DEFS):
        names = {node.name}
    elif isinstance(node, (ast.Import, ast.ImportFrom)):
        # `import a.b` binds `a`; a name `from` imports holds no dot
        names = {alias.asname or alias.name.split(".")[0] for alias in node.names}
    elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
        names = {node.name}
    elif isinstance(node, ast.MatchMapping):
        names = {node.rest}
    return {name for name in names if name}


def _local_names(scope: ast.AST, own: list[ast.AST]) -> set[str]:
    """Return the names a scope binds itself.

    These are its parameters, and what its assignments, loops,
    comprehension targets, defs, imports, `except ... as` and `match`
    captures bind.
    """
    names: set[str] = set()
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        names |= {argument.arg for argument in _parameters(scope.args)}
    for node in own:
        names |= _bound_names(node)
    return names


def _import_paths(node: ast.AST) -> set[str]:
    """Return the path of each name of `bip32_descriptors` an import reads."""
    if isinstance(node, ast.Import):
        return {
            alias.name
            for alias in node.names
            if alias.name.split(".")[0] == _PACKAGE_OF_THE_SPLIT
        }
    return set(_imported_names(node).values())


def _dotted(node: ast.expr) -> str | None:
    """Return the dotted name an expression is, as `a.b.c`, else None."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    return ".".join((node.id, *reversed(parts)))


def _scope_names(scope: ast.AST, inherited: dict[str, str]) -> set[str]:
    """Return each name of `bip32_descriptors` a scope and those in it reach.

    `inherited` maps each name an enclosing scope binds to that package,
    by path. A name the scope binds anywhere shadows it in the whole
    scope, unless an import of the scope binds it; a class body's names
    do not reach its methods. `_private_names_imported_by` says where
    this differs from Python.
    """
    own = _own_nodes(scope)
    found: set[str] = set()
    here: dict[str, str] = {}
    for node in own:
        found |= _import_paths(node)
        here |= _imported_names(node)
    local = _local_names(scope, own)
    bound = {name: path for name, path in inherited.items() if name not in local}
    bound |= here
    for node in own:
        if isinstance(node, ast.Attribute):
            owner = _dotted(node.value)
            if owner is not None and (root := owner.split(".")[0]) in bound:
                found.add(f"{bound[root]}{owner[len(root) :]}.{node.attr}")
        elif isinstance(node, _SCOPES):
            enclosing = inherited if isinstance(scope, ast.ClassDef) else bound
            found |= _scope_names(node, enclosing)
    return found


def _private_names_imported_by(path: Path) -> set[str]:
    """Return each private name of `bip32_descriptors` a file imports or reads.

    A name is private where a part of its dotted path starts with an
    underscore and is no dunder: `_x` in
    `from bip32_descriptors.descriptors.miniscript import _x`,
    `import bip32_descriptors._refusal`, and an attribute `_x` read off a
    name bound by importing from `bip32_descriptors`, as `miniscript._x`
    after `from bip32_descriptors.descriptors import miniscript`, or off
    a dotted name below it. An attribute of anything else, as the `_cache`
    of `miniscript.parse(text)._cache`, is an attribute of an object and
    no name of the package. Imports inside a function are found too. A
    name read in other ways is not found, as `getattr(miniscript, "_x")`
    or `miniscript._x` inside a quoted annotation.

    A name is read in the scope Python reads it in, and any other binding
    of the same name in that scope shadows the import there, wherever in
    the scope it stands. Python answers otherwise for what this does not
    follow: a `global` or `nonlocal` declaration, a `del`, a PEP 695 type
    parameter, and a read in a class body before the body binds the name.
    No file in src or tests applies one of them to a name it imports from
    `bip32_descriptors`.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {name for name in _scope_names(tree, {}) if _is_private(name)}


def test_the_private_name_scan_finds_a_planted_import(tmp_path: Path) -> None:
    """`_private_names_imported_by` reports each spelling of a private name.

    The real tree has none, so only this test exercises a report, and the
    public names planted beside them are the control it leaves alone.
    """
    planted = tmp_path / "planted.py"
    planted.write_text(
        "from bip32_descriptors.descriptors.miniscript import _x, parse\n"
        "from bip32_descriptors.descriptors import miniscript as ms\n"
        "import bip32_descriptors._refusal\n"
        "import bip32_descriptors.bip32\n"
        "from bip32_descriptors import bip32\n"
        "ms._y, ms.parse, bip32.derive, ms.Miniscript.__str__\n"
        "bip32_descriptors.bip32.bip32._z\n"
        "def f():\n"
        "    from bip32_descriptors.bip32.bip32 import _derive\n"
        # an alias of one function is no name of another, a parameter or
        # an assignment shadows one, and a class's names miss its methods
        "def g():\n"
        "    from bip32_descriptors import bip32 as item\n"
        "    return item\n"
        "def h(item, ms):\n"
        "    return item._cache, ms._shadowed\n"
        "def k():\n"
        "    ms = object()\n"
        "    return ms._assigned, (lambda ms: ms._lambda)\n"
        "def n():\n"
        "    return ms._inner\n"
        "class C:\n"
        "    from bip32_descriptors import bip32 as cb\n"
        "    cb._seen\n"
        "    def m(self):\n"
        "        return cb._hidden\n"
        "from btclib_wallet.psbt.psbt import _lacks_only_keys\n",
        encoding="utf-8",
    )
    assert _private_names_imported_by(planted) == {
        "bip32_descriptors.descriptors.miniscript._x",
        "bip32_descriptors.descriptors.miniscript._y",
        "bip32_descriptors._refusal",
        "bip32_descriptors.bip32.bip32._z",
        "bip32_descriptors.bip32.bip32._derive",
        "bip32_descriptors.bip32._seen",
        "bip32_descriptors.descriptors.miniscript._inner",
    }


@pytest.mark.parametrize(
    "body, expected",
    [
        pytest.param(
            "def f(y):\n    z = [ms for ms in y]\n    return z, ms._comp\n",
            {"_comp"},
            id="a comprehension's target binds in the comprehension",
        ),
        pytest.param(
            "def f(y):\n    return [ms._target for ms in y]\n",
            set(),
            id="a comprehension's target shadows inside it",
        ),
        pytest.param(
            "def f():\n    return [ms for ms in ms._iter]\n",
            {"_iter"},
            id="a comprehension's first iterable is read outside it",
        ),
        pytest.param(
            "def f(y):\n    [(ms := v) for v in y]\n    return ms._walrus\n",
            set(),
            id="a comprehension's := binds outside it",
        ),
        pytest.param(
            "def f(ms=ms._default):\n    return ms._param\n",
            {"_default"},
            id="a default is read outside the def",
        ),
        pytest.param(
            "def f():\n    return lambda ms=ms._default: ms._param\n",
            {"_default"},
            id="a lambda's default is read outside it",
        ),
        pytest.param(
            "@ms._decorator\ndef f(ms):\n    return ms\n",
            {"_decorator"},
            id="a decorator is read outside the def",
        ),
        pytest.param(
            "def f(ms: ms._annotation) -> ms._returns:\n    return ms\n",
            {"_annotation", "_returns"},
            id="an annotation is read outside the def",
        ),
        pytest.param(
            "class C(ms._base):\n    ms = 1\n",
            {"_base"},
            id="a base is read outside the class",
        ),
        pytest.param(
            "def f():\n"
            "    try:\n"
            "        pass\n"
            "    except ValueError:\n"
            "        return ms._kept\n",
            {"_kept"},
            id="an except without as binds nothing",
        ),
        pytest.param(
            "def f():\n"
            "    try:\n"
            "        pass\n"
            "    except ValueError as ms:\n"
            "        return ms._caught\n",
            set(),
            id="except as binds",
        ),
        pytest.param(
            "def f(x):\n"
            "    match x:\n"
            "        case [*_] | {'k': 1} | _:\n"
            "            return ms._kept\n",
            {"_kept"},
            id="an unnamed match pattern binds nothing",
        ),
        pytest.param(
            "def f(x):\n    match x:\n        case ms:\n            return ms._captured\n",
            set(),
            id="a match capture binds",
        ),
        pytest.param(
            "def f(x):\n    match x:\n        case [*ms]:\n            return ms._starred\n",
            set(),
            id="a match star binds",
        ),
        pytest.param(
            "def f(x):\n    match x:\n        case {**ms}:\n            return ms._rest\n",
            set(),
            id="a match rest binds",
        ),
        pytest.param(
            "def f():\n    import json as ms\n    return ms._json\n",
            set(),
            id="an import of another package binds",
        ),
        pytest.param(
            "ms.parse('x')._cache, ms.TABLE[0]._item, ms.A.b._dotted\n",
            {"A.b._dotted"},
            id="an attribute of a call or an item is no name of the package",
        ),
    ],
)
def test_the_private_name_scan_reads_a_name_where_python_does(
    tmp_path: Path, body: str, expected: set[str]
) -> None:
    """A name of `bip32_descriptors` is found in the scope Python reads it in.

    `ms` is the module's name for `miniscript`, and each body reads it
    where a binding of its own may or may not shadow it.
    """
    planted = tmp_path / "planted.py"
    planted.write_text(
        "from bip32_descriptors.descriptors import miniscript as ms\n" + body,
        encoding="utf-8",
    )
    assert _private_names_imported_by(planted) == {
        f"bip32_descriptors.descriptors.miniscript.{name}" for name in expected
    }


@pytest.mark.parametrize("root", ["src", "tests"])
def test_no_module_imports_a_private_name_of_bip32_descriptors(root: str) -> None:
    """Every name of `bip32_descriptors` read here is one it publishes."""
    base = Path(__file__).resolve().parents[1] / root
    found = {
        str(path.relative_to(base)): names
        for path in sorted(base.rglob("*.py"))
        if (names := _private_names_imported_by(path))
    }
    assert not found


@pytest.mark.parametrize("package", ["btclib", "bip32_descriptors"])
def test_a_dependency_imports_nothing_of_btclib_wallet(package: str) -> None:
    """No module of the installed `btclib` or `bip32_descriptors` imports it.

    The units were cut out of `btclib`, and `bip32` and `descriptors` out
    of this package, and neither of the two packages that hold them may
    depend on this one.
    """
    spec = importlib.util.find_spec(package)
    assert spec is not None
    assert spec.submodule_search_locations is not None
    (base,) = (Path(location) for location in spec.submodule_search_locations)
    found = {
        str(path.relative_to(base)): units
        for path in sorted(base.rglob("*.py"))
        if (
            units := _units_imported_by(
                path, ".".join((package, *path.relative_to(base).parent.parts))
            )
        )
    }
    assert not found


@pytest.mark.parametrize(
    "module_name, heavy_expected",
    [
        ("btclib_wallet.bip44", False),
        ("btclib_wallet.electrum", False),
        ("btclib_wallet.exceptions", False),
        ("btclib_wallet.fetch", True),
    ],
)
def test_these_modules_open_no_client(module_name: str, heavy_expected: bool) -> None:
    """Importing any of them loads no client, no HTTP and no TLS.

    `btclib_wallet.fetch`'s `__init__` imports every fetcher, and
    `urllib`, `ssl` and `socket` behind them. A server of the Electrum
    protocol imports the codec alone, and every module catching a
    `FetchError` imports the exceptions alone: neither pays for a client.
    ARCHITECTURE.md says why `bip44` pays for none.

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
