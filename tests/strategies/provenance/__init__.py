# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Read the upstream pin and the committed lock, and hash copied definitions."""

import ast
import hashlib
import shutil
import subprocess
import tomllib
from pathlib import Path
from typing import Any

# resolved once: a bare "git" in a subprocess list is a partial executable
# path
_GIT = shutil.which("git") or "git"


def _definition_hashes(source: bytes) -> dict[str, str]:
    """Hash top-level assignments and functions, decorators included.

    The span is made of the original lines rather than an AST rendering:
    whitespace, comments within a definition and spelling all count.
    Imports, the module docstring and comments outside a span do not. Any
    other top-level node is refused rather than skipped.
    """
    lines = source.splitlines(keepends=True)
    hashes = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign):
            assert len(node.targets) == 1
            target = node.targets[0]
            assert isinstance(target, ast.Name)
            name = target.id
            start = node.lineno
        elif isinstance(node, ast.FunctionDef):
            name = node.name
            start = min([node.lineno, *(item.lineno for item in node.decorator_list)])
        elif isinstance(node, ast.Import | ast.ImportFrom) or (
            isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
        ):
            continue
        else:
            msg = f"unsupported top-level node: {type(node).__name__}"
            raise TypeError(msg)
        assert node.end_lineno is not None
        assert name not in hashes, f"duplicate definition: {name}"
        definition = b"".join(lines[start - 1 : node.end_lineno])
        hashes[name] = hashlib.sha256(definition).hexdigest()
    return hashes


def _provenance() -> dict[str, Any]:
    """Read the pin captured from btclib's released source archive."""
    path = Path(__file__).with_name("manifest.toml")
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _committed_lock(root: Path) -> dict[str, Any]:
    """Parse the ``uv.lock`` a tree ships rather than one re-resolved over it.

    deps-oldest and deps-latest rewrite the working ``uv.lock`` before the
    suite runs, so a checkout's lock is read from ``HEAD``. An unpacked
    sdist has no history, and its ``uv.lock`` is the one it was built with.
    """
    if (root / ".git").exists():
        text = subprocess.run(  # noqa: S603
            [_GIT, "-C", str(root), "show", "HEAD:uv.lock"],
            capture_output=True,
            check=True,
            encoding="utf-8",
        ).stdout
    else:
        text = (root / "uv.lock").read_text(encoding="utf-8")
    return tomllib.loads(text)
