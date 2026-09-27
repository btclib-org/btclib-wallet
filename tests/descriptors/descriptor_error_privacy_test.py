# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Malformed descriptor errors must not expose caller-supplied key text."""

import pytest
from btclib.exceptions import BTClibValueError

from btclib_wallet.descriptors import parse, strip_checksum
from btclib_wallet.descriptors.descriptors import _parse_tree
from btclib_wallet.descriptors.key_expression import _split_arguments, _split_function


def test_malformed_descriptor_errors_do_not_echo_key_material() -> None:
    """Name the structural fault without repeating a secret-bearing input."""
    canary = "canary_private_material"
    cases = (
        (lambda: strip_checksum(f"wpkh({canary})#first#second"), "more than one"),
        (lambda: _split_arguments(f"{canary})"), "unbalanced brackets"),
        (lambda: _split_arguments(f"({canary}"), "unbalanced brackets"),
        (lambda: _split_function(f"pk({canary}"), "not a descriptor expression"),
        (lambda: _parse_tree(f"{{{canary}", {}, 0), "unbalanced braces"),
    )
    for action, message in cases:
        with pytest.raises(BTClibValueError, match=message) as error:
            action()
        assert canary not in str(error.value)

    with pytest.raises(BTClibValueError) as error:
        parse(f"pk({canary}")
    assert canary not in str(error.value)
