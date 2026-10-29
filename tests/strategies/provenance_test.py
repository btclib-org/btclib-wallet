# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Copied transaction strategies stay byte-for-byte at the locked release."""

import hashlib
import subprocess
from pathlib import Path

import pytest

from tests.strategies.provenance import (
    _GIT,
    _committed_lock,
    _definition_hashes,
    _git_environment,
    _provenance,
)


def test_copied_definitions_match_the_upstream_hashes() -> None:
    """Every copied definition, and no unpinned one, matches upstream."""
    source = Path(__file__).with_name("__init__.py").read_bytes()
    assert _definition_hashes(source) == _provenance()["definitions"]


def test_upstream_pin_is_the_locked_btclib_release() -> None:
    """A lock upgrade asks for a new comparison with the released source."""
    packages = _committed_lock(Path(__file__).parents[2])["package"]
    (package,) = [item for item in packages if item["name"] == "btclib"]
    provenance = _provenance()
    assert package["version"] == provenance["version"]
    assert package["sdist"]["hash"] == "sha256:" + provenance["sdist_sha256"]


def _git(root: Path, *args: str) -> str:
    return subprocess.run(  # noqa: S603
        [_GIT, "-C", str(root), *args],
        capture_output=True,
        check=True,
        encoding="utf-8",
        env=_git_environment(),
    ).stdout.strip()


def _commit_lock(root: Path, content: bytes) -> None:
    """Make ``root`` a repository whose ``HEAD`` holds ``uv.lock``."""
    (root / "uv.lock").write_bytes(content)
    _git(root, "init", "--quiet")
    _git(root, "add", "uv.lock")
    tree = _git(root, "write-tree")
    # commit-tree rather than commit: it does not sign, whatever
    # commit.gpgsign says, so the test asks for no key
    identity = ("-c", "user.name=test", "-c", "user.email=test@example.invalid")
    _git(
        root,
        "update-ref",
        "HEAD",
        _git(root, *identity, "commit-tree", "-m", "lock", tree),
    )


def test_a_checkout_reads_the_lock_at_head(tmp_path: Path) -> None:
    """A lock re-resolved over the commit, as deps-oldest does, is not read."""
    _commit_lock(tmp_path, b"committed = true\n")
    (tmp_path / "uv.lock").write_bytes(b"committed = false\n")
    assert _committed_lock(tmp_path) == {"committed": True}


def test_a_hook_environment_leaves_its_repository_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The GIT_DIR and GIT_INDEX_FILE a hook inherits are not followed."""
    hooked = tmp_path / "hooked"
    hooked.mkdir()
    _commit_lock(hooked, b"hooked = true\n")
    head = _git(hooked, "rev-parse", "HEAD")
    index = (hooked / ".git" / "index").read_bytes()
    monkeypatch.setenv("GIT_DIR", str(hooked / ".git"))
    monkeypatch.setenv("GIT_INDEX_FILE", str(hooked / ".git" / "index"))
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    _commit_lock(checkout, b"committed = true\n")
    (checkout / "uv.lock").write_bytes(b"committed = false\n")
    assert _committed_lock(checkout) == {"committed": True}
    assert _git(hooked, "rev-parse", "HEAD") == head
    assert (hooked / ".git" / "index").read_bytes() == index


def test_an_unpacked_sdist_reads_its_own_lock(tmp_path: Path) -> None:
    """Outside a checkout the lock on disk is the one shipped."""
    (tmp_path / "uv.lock").write_bytes(b"committed = true\n")
    assert _committed_lock(tmp_path) == {"committed": True}


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
