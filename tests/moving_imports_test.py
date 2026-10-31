# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The files that move with `bip32` and `descriptors` outside the sdist.

`tests/imports_test.py` holds the files that move with the two units to
what moves with them. The fuzz harnesses and the descriptor comparison
script, with its test, are not in the sdist, so the test that reads them
is here, in a module pyproject.toml's `source-exclude` names.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.imports_test import _moving_file_violations, _plant

_MOVING_OUTSIDE_THE_SDIST = (
    ".github/scripts/compare_descriptors.py",
    "fuzz/fuzz_bip32.py",
    "fuzz/fuzz_descriptor.py",
    "tests/compare_descriptors_test.py",
)


@pytest.mark.parametrize(
    "relative, line, forbidden",
    [
        ("fuzz/fuzz_bip32.py", "from btclib_wallet.psbt import Psbt", {"psbt"}),
        (
            ".github/scripts/compare_descriptors.py",
            "from tests.strategies import psbt",
            {"tests.strategies.psbt"},
        ),
    ],
)
def test_the_scan_finds_an_import_planted_outside_the_sdist(
    tmp_path: Path, relative: str, line: str, forbidden: set[str]
) -> None:
    """`_moving_file_violations` reports an import that stays in these files."""
    for moving in _MOVING_OUTSIDE_THE_SDIST:
        _plant(tmp_path, moving, "")
    _plant(tmp_path, relative, line)
    assert _moving_file_violations(tmp_path, _MOVING_OUTSIDE_THE_SDIST) == {
        relative: forbidden
    }


def test_the_files_outside_the_sdist_import_only_what_moves() -> None:
    """Keep the moving harnesses and scripts to what moves with them."""
    root = Path(__file__).resolve().parents[1]
    assert _moving_file_violations(root, _MOVING_OUTSIDE_THE_SDIST) == {}
