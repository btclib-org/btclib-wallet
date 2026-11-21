# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for btclib_wallet.fetch.fee_estimator: `FeeQuote` and the target guard.

The `FeeEstimator` protocol itself has no behaviour of its own to test --
each backend's `estimate_fee` is tested where it is implemented,
`tests/fetch/bitcoin_core_test.py`, `tests/fetch/electrum_test.py` and
`tests/fetch/esplora_test.py`.
"""

from __future__ import annotations

import pytest
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.fee import FeeRate

from btclib_wallet.fetch.fee_estimator import FeeQuote, valid_confirmation_target
from tests.ledger import Conforming, NotBelow


def test_fee_quote_carries_the_rate_and_its_own_target() -> None:
    """A quote is a rate and the target it is valid for, nothing derived."""
    quote = FeeQuote(rate=FeeRate(sats_per_kvbyte=1000), target=2)
    assert quote.rate == FeeRate(sats_per_kvbyte=1000)
    assert quote.target == 2


def test_valid_confirmation_target_returns_a_positive_int() -> None:
    """The ordinary case: a positive int passes through unchanged."""
    assert valid_confirmation_target(6) == 6


def test_valid_confirmation_target_returns_the_exact_int_of_a_subclass() -> None:
    """A positive int subclass is reduced to its held value and plain type."""
    target = valid_confirmation_target(Conforming(6))
    assert target == 6
    assert type(target) is int


@pytest.mark.parametrize("target", [0, -1])
def test_valid_confirmation_target_refuses_a_non_positive_one(target: int) -> None:
    """A target of zero or below is refused: no backend answers for it."""
    with pytest.raises(BTClibValueError, match="invalid confirmation target"):
        valid_confirmation_target(target)


def test_valid_confirmation_target_refuses_a_subclass_that_lies_about_order() -> None:
    """A subclass holding zero cannot bypass the positive-target check."""
    with pytest.raises(BTClibValueError, match="invalid confirmation target"):
        valid_confirmation_target(NotBelow(0))


@pytest.mark.parametrize("target", ["6", 6.0, None, True])
def test_valid_confirmation_target_refuses_a_non_integer(target: object) -> None:
    """A non-int target is refused before it reaches a backend at all."""
    with pytest.raises(BTClibTypeError, match="invalid confirmation target type"):
        valid_confirmation_target(target)  # type: ignore[arg-type]
