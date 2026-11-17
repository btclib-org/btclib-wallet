# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests that a parser bounds the numbers it reads from text.

Python's `int()` refuses a string of more than 4300 digits with a built-in
`ValueError`, which no caller catching this library's errors expects.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from base58_bech32.bech32 import bech32_encode
from btclib.exceptions import BTClibValueError

from btclib_wallet.bolt11 import _SIGNATURE_WORDS, Bolt11Invoice
from tests.exception_family_test import VALUE_ERRORS

# more than the 4300 digits int() takes, which a bound of ten digits
# refuses long before
_LONG = "9" * 5000


def _invoice_with_amount(digits: str) -> str:
    """Return an invoice text, valid as bech32, with `digits` as its amount."""
    words = [0] * (7 + _SIGNATURE_WORDS)
    return bech32_encode(f"lnbc{digits}m", words, m=1, limit=None).decode()


LONG_NUMBER_CASES: dict[str, Callable[[], Any]] = {
    "invoice amount": lambda: Bolt11Invoice.from_invoice(_invoice_with_amount(_LONG)),
}


@pytest.mark.parametrize(
    "parse", LONG_NUMBER_CASES.values(), ids=list(LONG_NUMBER_CASES.keys())
)
def test_a_number_over_4300_digits_is_refused_as_btclib_value_error(
    parse: Callable[[], Any],
) -> None:
    """Refuse as `BTClibValueError`, and never as the built-in `ValueError`."""
    with pytest.raises(VALUE_ERRORS) as raised:
        parse()
    assert isinstance(raised.value, BTClibValueError)
