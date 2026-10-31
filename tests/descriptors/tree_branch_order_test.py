# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A tr() branch with a wrong count of subtrees, as Bitcoin Core v31.1 reads it.

Issue btclib-org/btclib-wallet#608. Core reads a branch's first subtree,
and its second where there is a comma after the first, before it finds
the count wrong, so a fault inside one of them comes first.
"""

import pytest
from btclib.exceptions import BTClibValueError
from btclib.key import PrvKeyData

from btclib_wallet.descriptors import parse

_X = PrvKeyData(1).pub.sec.hex()[2:]
_X2 = PrvKeyData(2).pub.sec.hex()[2:]
_NOT_A_KEY = "^not a key expression$"
_INVALID_KEY = "^invalid key expression$"
_TR_LEAF_FAULT = r"^tr\(\) leaf is not a valid descriptor function$"


@pytest.mark.parametrize(
    "descriptor,message",
    [
        (f"tr({_X},{{and_v(v:pk({_X}){{,pk({_X2})),pk({_X2})}})", _NOT_A_KEY),
        (f"tr({_X},{{and_v(v:pk({_X})(,pk({_X2})),pk({_X2})}})", _NOT_A_KEY),
        (f"tr({_X},{{and_v(v:pkh({_X}){{,pk({_X2})),pk({_X2})}})", _NOT_A_KEY),
        (f"tr({_X},{{and_v(v:pk({_X}){{,pk({_X2}))}})", _NOT_A_KEY),
        (f"tr({_X},{{pk(nope)}})", _INVALID_KEY),
        (f"tr({_X},{{and_v(v:pk({_X}),older(0))}})", _TR_LEAF_FAULT),
        (f"tr({_X},{{pk(nope),pk({_X2}),pk({_X})}})", _INVALID_KEY),
        (f"tr({_X},{{pk({_X2}),pk(nope),pk({_X})}})", _INVALID_KEY),
        (
            f"tr({_X},{{and_v(v:pk({_X}),older(0)),pk({_X2}),pk({_X})}})",
            _TR_LEAF_FAULT,
        ),
    ],
)
def test_a_fault_in_a_subtree_comes_before_the_count(
    descriptor: str, message: str
) -> None:
    """Core names the fault of a subtree it reads before the count."""
    with pytest.raises(BTClibValueError, match=message):
        parse(descriptor)


@pytest.mark.parametrize(
    "descriptor,message",
    [
        (f"tr({_X},{{pk({_X})}})", "1 given"),
        (f"tr({_X},{{pk({_X}),pk({_X2}),pk({_X})}})", "3 given"),
        (f"tr({_X},{{pk({_X2}),pk({_X}),pk(nope)}})", "3 given"),
    ],
)
def test_the_count_is_the_fault_where_the_subtrees_read_are_sound(
    descriptor: str, message: str
) -> None:
    """A third subtree is not read: Core stops at the comma before it."""
    err_msg = rf"^a tr\(\) branch takes two subtrees, {message}$"
    with pytest.raises(BTClibValueError, match=err_msg):
        parse(descriptor)
