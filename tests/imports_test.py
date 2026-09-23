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
"""

from __future__ import annotations

import ast
import importlib
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest

import btclib_wallet
from tests import module_names


def _is_ours(name: str) -> bool:
    """Answer whether a dotted name is this package's or btclib's.

    `btclib_secp256k1`, the bindings, is neither: reimporting a cffi
    extension module is another matter entirely, so the boundary is the
    two package names and their submodules, not a bare `startswith`.
    """
    return any(
        name == root or name.startswith(f"{root}.")
        for root in ("btclib", "btclib_wallet")
    )


def loaded_modules() -> list[str]:
    """Return the modules of this package and of btclib in sys.modules."""
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


# what is heavier than the stdlib basics. Not `socket`: the root of either
# package reads `__version__` through `importlib.metadata`, which pulls in
# `email.utils` and, through it, `socket`, on every interpreter before
# 3.13, so asserting its absence would be a fact about the interpreter
# rather than about the candidate
_HEAVY_MODULES = ("urllib.request", "ssl", "http.client", "bitcoin_core_rpc")


def _loaded_after_importing(module_name: str) -> list[str]:
    """Import one module in a fresh interpreter and return sorted(sys.modules).

    A fresh subprocess rather than `unimported`: that fixture only hides
    the two packages' own modules from `sys.modules`, so a third-party
    package an earlier test already imported -- `bitcoin_core_rpc`, most
    concretely -- would still answer present, and the absence a lightness
    check exists to prove would mean nothing.
    """
    probe = f"import {module_name}, sys; print(sorted(sys.modules))"
    stdout = subprocess.run(  # noqa: S603
        [sys.executable, "-c", probe], check=True, capture_output=True, encoding="utf-8"
    ).stdout
    return cast("list[str]", ast.literal_eval(stdout))


def test_mnemonic_stays_stdlib_light() -> None:
    """`btclib_wallet.mnemonic` reaches `bip32` and btclib's curves, no more.

    BIP39, SLIP39 and Electrum stop at the seed, and a mnemonic package of
    their own is the next cut: `btclib-org/btclib#2129` moves them out and
    leaves the four functions that build a key from a seed here. Those
    four are why this reaches `bip32`, `network` and `curves` today --
    `bip39.mxprv_from_mnemonic`, `slip39.mxprv_from_mnemonics` and
    `electrum.mxprv_from_mnemonic` build an extended private key, and
    `electrum.old_master_pub_key_from_mnemonic` a public-key point. What
    this checks is that the reach, wherever it stops, never leaves
    stdlib-light territory on the way, and never widens without an edit
    here: subset rather than equal, because a removed edge is the next
    cut's progress and a new one is the defect.
    """
    loaded = _loaded_after_importing("btclib_wallet.mnemonic")
    assert {m for m in loaded if _is_ours(m)} <= {
        "btclib_wallet",
        "btclib_wallet.mnemonic",
        "btclib_wallet.mnemonic.bip39",
        "btclib_wallet.mnemonic.dispatch",
        "btclib_wallet.mnemonic.electrum",
        "btclib_wallet.mnemonic.entropy",
        "btclib_wallet.mnemonic.mnemonic",
        "btclib_wallet.mnemonic.slip39",
        "btclib_wallet.bip32",
        "btclib_wallet.bip32.bip32",
        "btclib_wallet.bip32.der_path",
        "btclib_wallet.bip32.key_origin",
        "btclib",
        "btclib.alias",
        "btclib.exceptions",
        "btclib.utils",
        "btclib.base58",
        "btclib.hashes",
        "btclib._ripemd160",
        "btclib.var_int",
        "btclib.curves",
        "btclib.curves.curve",
        "btclib.curves.curve_group",
        "btclib.curves.curve_group_2",
        "btclib.curves.curve_group_f",
        "btclib.curves.sec_point",
        "btclib.number_theory",
        "btclib._libsecp256k1",
        "btclib.network",
        "btclib.consensus",
    }
    assert not set(loaded) & set(_HEAVY_MODULES)


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
