# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Copied transaction strategies stay byte-for-byte at the locked release."""

import hashlib
import tomllib
from pathlib import Path

import pytest

from tests.strategies.provenance import _definition_hashes, _provenance


def test_copied_definitions_match_the_upstream_hashes() -> None:
    """Every copied definition, and no unpinned one, matches upstream."""
    source = Path(__file__).with_name("__init__.py").read_bytes()
    assert _definition_hashes(source) == _provenance()["definitions"]


def test_upstream_pin_is_the_locked_btclib_release() -> None:
    """A lock upgrade asks for a new comparison with the released source."""
    lock_path = Path(__file__).parents[2] / "uv.lock"
    packages = tomllib.loads(lock_path.read_text(encoding="utf-8"))["package"]
    (package,) = [item for item in packages if item["name"] == "btclib"]
    provenance = _provenance()
    assert package["version"] == provenance["version"]
    assert package["sdist"]["hash"] == "sha256:" + provenance["sdist_sha256"]


def test_hashes_include_decorators_and_preserve_source_bytes() -> None:
    """A rendering or a stripped decorator cannot stand in for source."""
    assignment = b"VALUE = (\n    1,  # keep this comment\n)\n"
    function = '@decorate\ndef function():\n    return "é"\n'.encode()
    source = b'"""Ignored module prose."""\nimport ast\n\n' + assignment
    source += b"\n# Outside either definition.\n" + function
    expected = {
        "VALUE": hashlib.sha256(assignment).hexdigest(),
        "function": hashlib.sha256(function).hexdigest(),
    }
    assert _definition_hashes(source) == expected
    assert _definition_hashes(source.replace(b"    1,", b"     1,")) != expected
    assert _definition_hashes(source.replace(b"@decorate\n", b"")) != expected


@pytest.mark.parametrize("source", [b"a = b = 1\n", b"a, b = 1, 2\n"])
def test_unsupported_assignments_are_not_silently_partly_hashed(source: bytes) -> None:
    """Every assignment in the pinned copy binds one ordinary name."""
    with pytest.raises(AssertionError):
        _definition_hashes(source)


@pytest.mark.parametrize(
    "source",
    [b"X: int = 1\n", b"class C:\n    pass\n", b"async def f() -> None:\n    pass\n"],
)
def test_unhashed_node_kinds_are_refused(source: bytes) -> None:
    """A node the hashes would skip cannot hide in the copy."""
    with pytest.raises(TypeError, match="unsupported top-level node"):
        _definition_hashes(source)


def test_duplicate_names_cannot_hide_an_extra_definition() -> None:
    """A second binding cannot overwrite the first one's provenance."""
    with pytest.raises(AssertionError, match="duplicate definition: a"):
        _definition_hashes(b"a = 1\na = 2\n")
