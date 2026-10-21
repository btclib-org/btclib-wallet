# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Timelock parse failures, as Bitcoin Core v31.1 reports them.

Issues btclib-org/btclib-wallet#437 and btclib-org/btclib-wallet#475. A
step inside a timelock argument is not a derivation path: miniscript
refuses the number, and Core's descriptor reader reports its fallback for
wsh() or for a tr() leaf rather than a later key or path fault.
"""

from __future__ import annotations

import pytest
from btclib.exceptions import BTClibValueError
from btclib.key import PrvKeyData

from btclib_wallet.bip32 import rootxprv_from_seed, xpub_from_xprv
from btclib_wallet.descriptors import add_checksum, multipath_descriptors, parse
from btclib_wallet.descriptors.miniscript import parse as parse_miniscript

_XPUB = xpub_from_xprv(rootxprv_from_seed(bytes(range(16))))
_X_ONLY = PrvKeyData(1).pub.sec.hex()[2:]
_P2WSH_FAULT = "^A function is needed within P2WSH$"
_TR_LEAF_FAULT = r"^tr\(\) leaf is not a valid descriptor function$"


@pytest.mark.parametrize("fragment", ["older", "after"])
@pytest.mark.parametrize("argument", ["<1;2>", "x", "+1", "0", "2147483648"])
@pytest.mark.parametrize("wrapped", [False, True])
def test_a_bad_timelock_reports_the_p2wsh_fallback(
    fragment: str, argument: str, wrapped: bool
) -> None:
    """Parsing and multipath expansion report the same fault inside wsh."""
    text = f"wsh(and_v(v:pk({_XPUB}/0/*),{fragment}({argument})))"
    if wrapped:
        text = f"sh({text})"
    with pytest.raises(BTClibValueError, match=_P2WSH_FAULT):
        parse(text)
    with pytest.raises(BTClibValueError, match=_P2WSH_FAULT):
        multipath_descriptors(text)


@pytest.mark.parametrize("fragment", ["older", "after"])
@pytest.mark.parametrize("argument", ["<1;2>", "x", "+1", "0", "2147483648"])
@pytest.mark.parametrize(
    "tree",
    [
        "{leaf}",
        "and_v(v:pk({key}),{leaf})",
        "{{pk({key}),and_v(v:pk({key}),{leaf})}}",
    ],
)
def test_a_bad_timelock_in_a_tr_leaf_reports_the_leaf_fallback(
    fragment: str, argument: str, tree: str
) -> None:
    """Parsing and multipath expansion report the same fault in a tr() leaf."""
    leaf = f"{fragment}({argument})"
    text = f"tr({_X_ONLY},{tree.format(key=f'{_XPUB}/0/*', leaf=leaf)})"
    with pytest.raises(BTClibValueError, match=_TR_LEAF_FAULT):
        parse(text)
    with pytest.raises(BTClibValueError, match=_TR_LEAF_FAULT):
        multipath_descriptors(text)


def test_a_key_fault_before_the_timelock_in_a_tr_leaf_is_preserved() -> None:
    """A leaf's fallback does not hide the key its reader reached first."""
    text = f"tr({_X_ONLY},and_v(v:pk(nope),older(0)))"
    with pytest.raises(BTClibValueError, match="^invalid key expression$"):
        parse(text)


@pytest.mark.parametrize("fragment", ["older", "after"])
def test_a_multipath_key_does_not_expand_a_timelock_argument(fragment: str) -> None:
    """The reported step fault follows a valid multipath key, not its length."""
    text = f"wsh(and_v(v:pk({_XPUB}/<0;1>/*),{fragment}(<1;2>)))"
    with pytest.raises(BTClibValueError, match=_P2WSH_FAULT):
        multipath_descriptors(text)
    with pytest.raises(
        BTClibValueError,
        match="^multipath key expression: use multipath_descriptors first$",
    ):
        parse(text)


def test_a_key_fault_before_the_timelock_is_preserved() -> None:
    """A fallback does not hide the key the miniscript reader reached first."""
    text = "wsh(and_v(v:pk(nope),older(<1;2>)))"
    with pytest.raises(BTClibValueError, match="^invalid key expression$"):
        multipath_descriptors(text)


def test_a_timelock_fault_before_a_key_is_not_replaced_by_it() -> None:
    """A later key is not read once the timelock's number has failed."""
    text = "wsh(and_v(v:older(<1;2>),pk(nope)))"
    with pytest.raises(BTClibValueError, match=_P2WSH_FAULT):
        multipath_descriptors(text)


@pytest.mark.parametrize("fragment", ["older", "after"])
def test_a_valid_timelock_keeps_its_multipath_expansions(fragment: str) -> None:
    """Both derived paths retain the timelock and valid descriptor checksums."""
    text = f"wsh(and_v(v:pk({_XPUB}/<0;1>/*),{fragment}(1)))"
    expanded = multipath_descriptors(text)
    assert expanded == [
        add_checksum(text.replace("<0;1>", str(step))) for step in (0, 1)
    ]
    assert all(add_checksum(str(parse(item))) == item for item in expanded)


@pytest.mark.parametrize("fragment", ["older", "after"])
def test_a_standalone_miniscript_keeps_its_number_diagnostic(fragment: str) -> None:
    """The standalone language parser keeps its own diagnostic."""
    with pytest.raises(
        BTClibValueError, match=rf"^invalid {fragment}\(\) number: digits expected$"
    ):
        parse_miniscript(f"{fragment}(<1;2>)")
