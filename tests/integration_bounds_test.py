# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The integration tests' bounds hold the waits they count.

`tests/integration/conftest.py`'s `_RPC_TIMEOUT` says how a test's
waits count it, and `pyproject.toml`'s `timeout` what a test does whose
waits pass the suite's bound. These tests read the constants and the
`timeout` marks, and start nothing.
"""

from __future__ import annotations

from types import ModuleType

import pytest

from btclib_wallet.hwi import DEFAULT_TIMEOUT
from tests.integration import (
    compact_filters_test,
    electrs_reorg_test,
    electrs_test,
    floresta_test,
    hwi_device_test,
)
from tests.integration.conftest import _RPC_TIMEOUT, _STARTUP_TIMEOUT


def _bounds(module: ModuleType, test: str | None) -> list[float]:
    """Return the `timeout` marks of the test, then of its module."""
    function = None if test is None else getattr(module, test)
    marks = list(getattr(function, "pytestmark", []))
    # a module's `pytestmark` is one mark or a list of them
    own = module.pytestmark
    marks += [own] if isinstance(own, pytest.MarkDecorator) else own
    return [float(mark.args[0]) for mark in marks if mark.name == "timeout"]


def test_a_stalled_call_fails_before_the_suites_timeout(
    pytestconfig: pytest.Config,
) -> None:
    """The node's start and one call fit in the suite's `timeout`."""
    assert float(pytestconfig.getini("timeout")) > _STARTUP_TIMEOUT + _RPC_TIMEOUT


@pytest.mark.parametrize(
    "module, test, waits",
    [
        (electrs_test, None, electrs_test._WAITS),
        (
            electrs_reorg_test,
            "test_fetchers_follow_the_chain_that_replaced_a_block",
            electrs_reorg_test._REPLACED_BLOCK_WAITS,
        ),
        (
            electrs_reorg_test,
            "test_the_history_follows_a_confirmation_a_mempool_arrival_and_a_reorg",
            electrs_reorg_test._HISTORY_WAITS,
        ),
        (
            compact_filters_test,
            "test_a_peer_serving_a_wrong_filter_is_dropped_and_the_payment_found",
            compact_filters_test._SHARED_CHAIN_WAITS,
        ),
        (
            compact_filters_test,
            "test_a_sync_over_v2_reads_the_blocks_a_sync_over_v1_reads",
            compact_filters_test._SHARED_CHAIN_WAITS,
        ),
        (floresta_test, None, floresta_test._SETUP_WAITS),
        # three HWI calls, `node`'s start and its blocks mined in one call
        (
            hwi_device_test,
            "test_the_device_signs_what_btclib_built",
            3 * DEFAULT_TIMEOUT + _STARTUP_TIMEOUT + _RPC_TIMEOUT,
        ),
    ],
)
def test_a_test_whose_waits_pass_the_suites_timeout_outlasts_them(
    pytestconfig: pytest.Config, module: ModuleType, test: str | None, waits: float
) -> None:
    """The waits pass the suite's `timeout`, and the test's bound is longer."""
    assert float(pytestconfig.getini("timeout")) < waits < _bounds(module, test)[0]


def test_a_test_whose_waits_stay_under_the_suites_timeout_has_no_bound(
    pytestconfig: pytest.Config,
) -> None:
    """One node, its chain mined in one call: the suite's `timeout` holds it."""
    test = "test_the_blocks_that_touch_a_script_are_the_ones_downloaded"
    suite = float(pytestconfig.getini("timeout"))
    assert suite > compact_filters_test._ONE_NODE_WAITS
    assert _bounds(compact_filters_test, test) == []
