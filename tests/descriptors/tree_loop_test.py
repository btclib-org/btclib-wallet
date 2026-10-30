# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A tr() tree read leaf by leaf, as Bitcoin Core v31.1's ``tr()`` loop reads.

Issue btclib-org/btclib-wallet#610. Core takes each "{", cuts one leaf
with ``Expr`` and reads it, then takes a "}" for each right subtree the
leaf ends and a "," after a left one. A leaf that runs on into the
tree's own "}" or "," is read before the tree, so its fault comes first.
Every row was checked against ``getdescriptorinfo`` on an offline regtest
bitcoind v31.1.0.
"""

import pytest
from btclib.exceptions import BTClibValueError
from btclib.key import PrvKeyData

from btclib_wallet.descriptors import parse

_K = PrvKeyData(1).pub.sec.hex()
_K2 = PrvKeyData(2).pub.sec.hex()
_X = _K[2:]
_X2 = _K2[2:]
_NOT_A_KEY = "^not a key expression$"
_INVALID_KEY = "^invalid key expression$"
_UNBALANCED = "^unbalanced braces$"


@pytest.mark.parametrize(
    "descriptor,message",
    [
        # Core: key 'X){,pk(X2)' is not valid
        (f"tr({_X},{{and_v(v:pk({_X}){{,pk({_X2})),pk({_X2})}}}})", _NOT_A_KEY),
        (
            f"tr({_X},{{{{and_v(v:pk({_X}){{,pk({_X2})),pk({_X2})}},pk({_X})}})",
            _NOT_A_KEY,
        ),
        # Core: key 'X)(,pk(X2)' is not valid
        (f"tr({_X},{{and_v(v:pk({_X})(,pk({_X2})),pk({_X2}))", _NOT_A_KEY),
        (f"tr({_X},{{pk({_X}),and_v(v:pk({_X})(,pk({_X2})),pk({_X2}))}})", _NOT_A_KEY),
        # Core: key 'X2(' is not valid, the last key ending at the first ")"
        (f"tr({_X},{{pk({_X}),multi_a(1,{_X},{_X2}()}})", _NOT_A_KEY),
        (f"tr({_X},{{pk({_X}),multi_a(1,nope()}})", _NOT_A_KEY),
    ],
)
def test_a_leaf_that_runs_into_the_tree_is_read_first(
    descriptor: str, message: str
) -> None:
    """Core names the key of a leaf that takes in the tree's own brackets."""
    with pytest.raises(BTClibValueError, match=message):
        parse(descriptor)


@pytest.mark.parametrize(
    "descriptor",
    [
        # Core: key 'K}' is not valid
        f"wsh(and_v(v:multi(1,{_K}}}),pk({_K2})))",
        # Core: key 'X}' is not valid
        f"tr({_X},and_v(v:multi_a(1,{_X}}}),pk({_X2})))",
        # Core: key '{K}' is not valid
        f"wsh(and_v(v:pk({{{_K}}}),pk({_K2})))",
    ],
)
def test_a_brace_in_a_miniscript_key_is_the_key_fault(descriptor: str) -> None:
    """Core reads the key a brace is in before any brace is refused.

    Issue btclib-org/btclib-wallet#582.
    """
    with pytest.raises(BTClibValueError, match=_INVALID_KEY):
        parse(descriptor)


@pytest.mark.parametrize(
    "descriptor,message",
    [
        # Core: tr(): expected ',' after script expression
        (f"tr({_X},{{pk({_X})}})", r"^a tr\(\) branch takes two subtrees, 1 given$"),
        # Core: tr(): expected '}' after script expression
        (
            f"tr({_X},{{pk({_X}),pk({_X2}),pk({_X})}})",
            r"^a tr\(\) branch takes two subtrees, 3 given$",
        ),
        (
            f"tr({_X},{{pk({_X}),pk({_X2}),pk({_X}),pk({_X2})}})",
            r"^a tr\(\) branch takes two subtrees, 4 given$",
        ),
        (
            f"tr({_X},{{pk({_X}),{{pk({_X2}),pk({_X}),pk({_X2})}}}})",
            r"^a tr\(\) branch takes two subtrees, 3 given$",
        ),
        # the third subtree is not read
        (
            f"tr({_X},{{pk({_X}),pk({_X2}),pk(nope)}})",
            r"^a tr\(\) branch takes two subtrees, 3 given$",
        ),
        (f"tr({_X},{{pk({_X}),{{pk({_X2}),pk({_X})}})", _UNBALANCED),
        (f"tr({_X},{{pk({_X}),pk({_X2}))", _UNBALANCED),
        (f"tr({_X},{{pk({_X}),{{pk({_X2}),pk({_X})}}x}})", _UNBALANCED),
        # Core: tr(): expected ',' after script expression
        (f"tr({_X},{{{{pk({_X}),pk({_X2})}}x,pk({_X})}})", _UNBALANCED),
        # Core: tr(): expected ')' after script expression
        (f"tr({_X},{{pk({_X}),pk({_X2})}}{{)", _UNBALANCED),
        (
            f"tr({_X},{{pk({_X}),pk({_X2})}},pk({_X}))",
            r"^tr\(\) takes a key and at most one tree, 3 given$",
        ),
        (f"tr({_X},{{pk({_X}),pk({_X2})}}}}(x))", "^unbalanced brackets$"),
        (f"tr({_X},pk({_X})}}(x))", "^unbalanced brackets$"),
    ],
)
def test_the_tree_is_refused_where_core_finds_it_wrong(
    descriptor: str, message: str
) -> None:
    """Core finds a "}" or a "," missing after a leaf it has read."""
    with pytest.raises(BTClibValueError, match=message):
        parse(descriptor)


@pytest.mark.parametrize(
    "descriptor",
    [
        f"tr({_X},{{{{pk(nope),pk({_X2})}},pk({_X})}})",
        f"tr({_X},{{pk({_X}),{{pk({_X2}),pk(nope)}}}})",
    ],
)
def test_a_fault_in_a_leaf_comes_before_the_rest(descriptor: str) -> None:
    """Core: pk(): key 'nope' is not valid."""
    with pytest.raises(BTClibValueError, match=_INVALID_KEY):
        parse(descriptor)


@pytest.mark.parametrize(
    "tree",
    [
        f"pk({_X2})",
        f"{{pk({_X}),pk({_X2})}}",
        f"{{{{pk({_X}),pk({_X2})}},pk({_X})}}",
        f"{{pk({_X}),{{pk({_X2}),multi_a(1,{_X},{_X2})}}}}",
        f"{{{{pk({_X}),pk({_X2})}},{{and_v(v:pk({_X}),older(1)),pk({_X2})}}}}",
    ],
)
def test_a_tree_is_read_back_as_written(tree: str) -> None:
    """The loop builds the tree the text spells, its leaves in order."""
    descriptor = f"tr({_X},{tree})"
    assert str(parse(descriptor)).partition("#")[0] == descriptor
