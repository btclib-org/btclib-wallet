# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Malformed closed multisigs, as Bitcoin Core v31.1 reports them.

Issue btclib-org/btclib-wallet#476. Core's miniscript parser refuses a
multisig outside its own context before it reads a key, and reads each key
of one in its own context up to the next comma, counting no bracket.
"""

import pytest
from btclib.exceptions import BTClibValueError
from btclib.key import PrvKeyData

from btclib_wallet.descriptors import parse
from btclib_wallet.descriptors.miniscript import P2WSH, TAPSCRIPT
from btclib_wallet.descriptors.miniscript import parse as parse_miniscript

_KEY = PrvKeyData(1).pub.sec.hex()
_X_ONLY = _KEY[2:]
_P2WSH_FAULT = "^A function is needed within P2WSH$"
_TR_LEAF_FAULT = r"^tr\(\) leaf is not a valid descriptor function$"
_KEY_FAULT = "^invalid key expression$"


@pytest.mark.parametrize(
    "descriptor,message",
    [
        (
            f"tr({_X_ONLY},and_v(v:pk({_X_ONLY}),multi(1,[dead]]{_X_ONLY},{_X_ONLY})))",
            _TR_LEAF_FAULT,
        ),
        (
            f"tr({_X_ONLY},and_v(v:pk({_X_ONLY}),multi(1,{_X_ONLY},{_X_ONLY})))",
            _TR_LEAF_FAULT,
        ),
        (
            f"tr({_X_ONLY},{{pk({_X_ONLY}),and_v(v:pk({_X_ONLY}),multi(1,nope))}})",
            _TR_LEAF_FAULT,
        ),
        (
            f"wsh(and_v(v:pk({_KEY}),multi_a(1,[dead]]{_KEY},{_KEY})))",
            _P2WSH_FAULT,
        ),
        (
            f"sh(wsh(and_v(v:pk({_KEY}),multi_a(1,[dead]]{_KEY},{_KEY}))))",
            _P2WSH_FAULT,
        ),
        (f"wsh(and_v(v:pk({_KEY}),multi_a(1,{_KEY},{_KEY})))", _P2WSH_FAULT),
    ],
)
def test_a_multisig_outside_its_context_reads_no_key(
    descriptor: str, message: str
) -> None:
    """Core names its fallback for the context, not a key of the multisig."""
    with pytest.raises(BTClibValueError, match=message):
        parse(descriptor)


@pytest.mark.parametrize(
    "descriptor,message",
    [
        (f"tr({_X_ONLY},and_v(v:multi_a(1,{_X_ONLY}{{),pk({_X_ONLY})))", _KEY_FAULT),
        (
            f"tr({_X_ONLY},and_v(v:multi_a(1,{_X_ONLY},{_X_ONLY}{{),pk({_X_ONLY})))",
            _KEY_FAULT,
        ),
        (
            f"tr({_X_ONLY},and_v(v:multi_a(1,[dead]]{_X_ONLY},{_X_ONLY}{{),pk({_X_ONLY})))",
            r"^more than one '\]' in a single key expression$",
        ),
        (f"wsh(and_v(v:multi(1,{_KEY}{{),pk({_KEY})))", _KEY_FAULT),
    ],
)
def test_a_bracket_in_a_multisig_key_is_the_key_fault(
    descriptor: str, message: str
) -> None:
    """Core reads the key a stray bracket sits in before the structure."""
    with pytest.raises(BTClibValueError, match=message):
        parse(descriptor)


@pytest.mark.parametrize(
    "descriptor",
    [
        f"tr({_X_ONLY},and_v(v:multi_a(x,{_X_ONLY}{{),pk({_X_ONLY})))",
        f"tr({_X_ONLY},and_v(v:multi_a(1,,{_X_ONLY}{{),pk({_X_ONLY})))",
    ],
)
def test_no_key_past_a_bad_threshold_or_an_empty_key_is_read(descriptor: str) -> None:
    """Core stops before the bracketed key, so no key fault is named.

    Core then names its fallback for the leaf, where parse names the
    brackets.
    """
    with pytest.raises(BTClibValueError, match="^unbalanced brackets$"):
        parse(descriptor)


@pytest.mark.parametrize(
    "expression,context,message",
    [
        (f"multi(1,[dead]]{_X_ONLY})", TAPSCRIPT, "^multi.. is not allowed in a"),
        (f"multi_a(1,[dead]]{_KEY})", P2WSH, "^multi_a.. is only allowed in a"),
    ],
)
def test_the_standalone_parser_names_the_context(
    expression: str, context: str, message: str
) -> None:
    """The language parser keeps its own diagnostic, read before any key."""
    with pytest.raises(BTClibValueError, match=message):
        parse_miniscript(expression, context)
