# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The census of `ec`, the parameter that says which curve is meant.

btclib's own `curve_parameter_test.py` holds every `ec` of btclib to the
rule, and bip32-descriptors' holds its own: a value of a type the
signature does not declare leaves as a `BTClibTypeError`, and a value of
a declared type that no valid input carries as a `BTClibValueError`.

No public function of this package takes a curve. `_curve_parameters`
reads every one whose signature declares a `Curve` or a `CurveGroup`, so
`test_no_function_takes_a_curve` fails on a function that gains the
parameter, until this file drives it to that rule as btclib's does.
"""

from __future__ import annotations

import ast
from pathlib import Path

_LIBRARY = Path(__file__).parents[1] / "src" / "btclib_wallet"


def _curve_parameters(library: Path) -> set[str]:
    """Return every public function under `library` taking a curve.

    The **annotation** and not the name `ec`, so that a curve parameter
    spelled otherwise is found too. `Curve` and `CurveGroup` exactly, and
    not a union containing one: a union is a lookup comparing against a
    curve, where these functions would have a curve to compute in.

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

    for path in sorted(library.rglob("*.py")):
        module = ".".join(path.relative_to(library.parent).with_suffix("").parts)
        walk(ast.parse(path.read_text(encoding="utf-8")), module, "")
    return found


def test_no_function_takes_a_curve() -> None:
    """A function that gains an `ec` fails here until it is driven."""
    assert _curve_parameters(_LIBRARY) == set()


def test_the_walk_reaches_what_it_claims(tmp_path: Path) -> None:
    """The functions the walk must find, and the ones it must not.

    The real tree has none, so only this test exercises a find.
    """
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "mod.py").write_text(
        "def point(xpub: str, ec: Curve) -> None: ...\n"
        "def group(ec: CurveGroup) -> None: ...\n"
        "def union(ec: Curve | None) -> None: ...\n"
        "def plain(xpub: str) -> None: ...\n"
        "def _private(ec: Curve) -> None: ...\n"
        "class Key:\n"
        "    def at(self, ec: Curve) -> None: ...\n"
        "    def _at(self, ec: Curve) -> None: ...\n",
        encoding="utf-8",
    )
    assert _curve_parameters(package) == {
        "pkg.mod.point",
        "pkg.mod.group",
        "pkg.mod.Key.at",
    }
