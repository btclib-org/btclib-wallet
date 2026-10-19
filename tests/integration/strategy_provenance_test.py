# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Compare transaction strategy copies with the actual pinned upstream file."""

import hashlib
import os
from pathlib import Path

import pytest

from tests.strategies.provenance import _definition_hashes, _provenance

pytestmark = pytest.mark.skipif(
    "BTCLIB_BTCLIB_STRATEGIES" not in os.environ,
    reason="set BTCLIB_BTCLIB_STRATEGIES to btclib's tests/strategies/__init__.py",
)


def test_upstream_source_and_copied_definitions_match() -> None:
    """The supplied upstream bytes hold every digest pinned in the manifest."""
    source = Path(os.environ["BTCLIB_BTCLIB_STRATEGIES"]).read_bytes()
    provenance = _provenance()
    assert hashlib.sha256(source).hexdigest() == provenance["source_sha256"]
    upstream = _definition_hashes(source)
    expected = provenance["definitions"]
    assert {name: upstream[name] for name in expected} == expected
    copy = Path(__file__).parents[1] / "strategies" / "__init__.py"
    assert _definition_hashes(copy.read_bytes()) == expected
