# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `check_validity` convention.

`check_validity` is keyword-only throughout the package, which is a rule
about signatures rather than about any one of them: it is the flag most of
them carry, and it is forwarded by hand from one to the next, so the guard
has to be the rule itself. A new signature spelling it positionally is
what this module fails on. btclib's own `check_validity_test.py` holds
btclib's signatures to the same rule.

How many carry it is not written down here, because a number in prose
drifts where a walk does not: `_signatures` is what answers instead, and
`len(_signatures())` is the count whenever one is wanted.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from btclib_wallet.bip32.key_origin import BIP32KeyOrigin

PACKAGE = pathlib.Path(__file__).parent.parent / "src" / "btclib_wallet"


def _signatures() -> list[tuple[str, int, str, list[str]]]:
    """Return every signature of the package that takes check_validity."""
    out = []
    for path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            args = node.args
            positional = [a.arg for a in args.posonlyargs + args.args]
            keyword_only = [a.arg for a in args.kwonlyargs]
            if "check_validity" in positional + keyword_only:
                out.append(
                    (
                        str(path.relative_to(PACKAGE.parent)),
                        node.lineno,
                        node.name,
                        positional,
                    )
                )
    return out


def test_check_validity_is_keyword_only() -> None:
    """Verify no signature takes check_validity positionally."""
    signatures = _signatures()

    # an assertion that the walk found the signatures at all, a broken one
    # passing vacuously; `BIP32KeyOrigin.__init__` is one of them
    assert ("btclib_wallet/bip32/key_origin.py", "__init__") in {
        (path, name) for path, _, name, _ in signatures
    }

    offenders = [
        f"{path}:{lineno} {name}"
        for path, lineno, name, pos in signatures
        if "check_validity" in pos
    ]
    assert not offenders, "check_validity must be keyword-only: " + ", ".join(offenders)


def test_check_validity_positional_is_a_type_error() -> None:
    """The hazard the rule exists for.

    Were the flag positional, a signature growing a parameter before it
    would silently move it into another slot. As a TypeError it fails at
    the call, rather than wherever the wrong value landed.
    """
    with pytest.raises(TypeError, match="positional argument"):
        BIP32KeyOrigin("deadbeef", "m/0h", False)  # type: ignore[call-arg]
    assert BIP32KeyOrigin("deadbeef", "m/0h", check_validity=False).der_path
