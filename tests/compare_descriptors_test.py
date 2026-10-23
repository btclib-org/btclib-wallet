# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `.github/scripts/compare_descriptors.py`.

The script is loaded by path, `.github/scripts` being no package, as the
other scripts under it are tested. Neither `bitcoind` nor `cargo` is needed:
`disagreements` reads verdicts, and the Rust program is a stub.
"""

from __future__ import annotations

import importlib.util
import stat
import sys
from pathlib import Path
from types import ModuleType

import pytest

_SCRIPT = Path(__file__).parents[1] / ".github" / "scripts" / "compare_descriptors.py"


@pytest.fixture
def script() -> ModuleType:
    """Return the script, imported by path."""
    spec = importlib.util.spec_from_file_location("compare_descriptors", _SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_disagreements_flags_a_refusal_by_rust_alone(script: ModuleType) -> None:
    """Core and `parse` accept what rust-miniscript refuses."""
    accepted = script.Verdict(True)
    refused = script.Verdict(False)

    assert script.disagreements(accepted, accepted, refused) == ["acceptance"]


def test_disagreements_flags_an_acceptance_by_core_alone(script: ModuleType) -> None:
    """Core accepts what `parse` and rust-miniscript refuse."""
    accepted = script.Verdict(True)
    refused = script.Verdict(False)

    assert script.disagreements(accepted, refused, refused) == ["acceptance"]


def test_disagreements_flags_a_refusal_by_core_alone(script: ModuleType) -> None:
    """Core refuses what `parse` and rust-miniscript accept."""
    accepted = script.Verdict(True)
    refused = script.Verdict(False)

    assert script.disagreements(refused, accepted, accepted) == ["acceptance"]


def test_disagreements_flags_an_acceptance_by_rust_alone(script: ModuleType) -> None:
    """Only rust-miniscript accepts."""
    accepted = script.Verdict(True)
    refused = script.Verdict(False)

    assert script.disagreements(refused, refused, accepted) == ["acceptance"]


def test_disagreements_flags_an_acceptance_by_parse_alone(script: ModuleType) -> None:
    """Only `parse` accepts."""
    accepted = script.Verdict(True)
    refused = script.Verdict(False)

    assert script.disagreements(refused, accepted, refused) == ["acceptance"]


def test_disagreements_is_empty_where_all_refuse(script: ModuleType) -> None:
    """A descriptor that all three refuse is no disagreement."""
    refused = script.Verdict(False)

    assert script.disagreements(refused, refused, refused) == []


def test_disagreements_is_empty_where_all_accept_alike(script: ModuleType) -> None:
    """The same script and address from all three is no disagreement."""
    core = script.Verdict(True, addresses=("bc1qa",))
    ours = script.Verdict(True, scripts=("0014aa",), addresses=("bc1qa",))
    rust = script.Verdict(True, scripts=("0014aa",), addresses=("bc1qa",))

    assert script.disagreements(core, ours, rust) == []


def test_disagreements_flags_a_different_script(script: ModuleType) -> None:
    """All three accept, and `parse` and rust-miniscript derive other scripts."""
    core = script.Verdict(True)
    ours = script.Verdict(True, scripts=("0014aa",))
    rust = script.Verdict(True, scripts=("0014bb",))

    assert script.disagreements(core, ours, rust) == ["script parse/rust"]


def test_disagreements_flags_a_different_address(script: ModuleType) -> None:
    """All three accept, and each pair of addresses that differs is named."""
    core = script.Verdict(True, addresses=("bc1qa",))
    ours = script.Verdict(True, addresses=("bc1qb",))
    rust = script.Verdict(True, addresses=("bc1qc",))

    assert script.disagreements(core, ours, rust) == [
        "address parse/core",
        "address rust/core",
        "address parse/rust",
    ]


def _stub(directory: Path) -> Path:
    """Return a program that answers like the Rust one, and stops at `crash`.

    It reads one hex-encoded input per line and answers each with a row of
    the tab-separated form `index status script address note`, the index
    counted from its own first line. At `crash` it exits with 3 and no row.
    """
    path = directory / "stub"
    path.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        "for index, line in enumerate(sys.stdin):\n"
        "    text = bytes.fromhex(line.strip()).decode()\n"
        "    if text == 'crash':\n"
        "        sys.exit(3)\n"
        "    print(f'{index}\\taccepted\\t{text.encode().hex()}\\t-\\t-', flush=True)\n",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def test_read_with_rust_answers_every_input(script: ModuleType, tmp_path: Path) -> None:
    """A run that answers every input needs no restart."""
    verdicts = script.read_with_rust(_stub(tmp_path), ["a", "b"])

    assert [verdict.accepted for verdict in verdicts] == [True, True]
    assert [verdict.scripts for verdict in verdicts] == [
        ("61",),
        ("62",),
    ]


def test_read_with_rust_restarts_after_a_crash(
    script: ModuleType, tmp_path: Path
) -> None:
    """The input a run stopped on is a refusal, and the rest are asked again."""
    verdicts = script.read_with_rust(_stub(tmp_path), ["a", "crash", "b", "c"])

    assert [verdict.accepted for verdict in verdicts] == [True, False, True, True]
    assert verdicts[1].note == "rust-miniscript stopped with 3"
    assert verdicts[2].scripts == (b"b".hex(),)
    assert verdicts[3].scripts == (b"c".hex(),)


def test_read_with_rust_survives_a_crash_on_the_first_input(
    script: ModuleType, tmp_path: Path
) -> None:
    """A run that stops before any answer still moves past its input."""
    verdicts = script.read_with_rust(_stub(tmp_path), ["crash", "a"])

    assert [verdict.accepted for verdict in verdicts] == [False, True]
