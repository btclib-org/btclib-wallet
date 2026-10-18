# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Read a malformed multisig's keys before the structure that follows it.

Bitcoin Core v31.1's ``ParseScript`` falls through to miniscript when a
multi() or multi_a() expression does not end in a closing parenthesis.
The key reader can fail before that miniscript's trailing text is found.
"""

from collections.abc import Callable

import pytest
from btclib.exceptions import BTClibValueError
from btclib.key import PrvKeyData

from btclib_wallet.descriptors import Descriptor, multipath_descriptors, parse

_KEY = PrvKeyData(1).pub.sec.hex()
_X_ONLY = _KEY[2:]
_STRUCTURAL = "not a descriptor expression: expected name(arguments)"


@pytest.mark.parametrize("read", [parse, multipath_descriptors])
@pytest.mark.parametrize(
    "descriptor",
    [
        f"wsh(multi(1,[dead]]{_KEY})junk))",
        f"sh(wsh(multi(1,[dead]]{_KEY})junk)))",
        f"tr({_X_ONLY},multi_a(1,[dead]]{_KEY})junk))",
        f"tr({_X_ONLY},{{multi_a(1,[dead]]{_KEY}))),pk({_X_ONLY})}})",
    ],
)
def test_a_multisig_key_is_read_before_its_trailing_structure(
    descriptor: str, read: Callable[[str], Descriptor | list[str]]
) -> None:
    """Core names the repeated origin end before it finds the structure."""
    with pytest.raises(
        BTClibValueError, match=r"^more than one '\]' in a single key expression$"
    ):
        read(descriptor)


@pytest.mark.parametrize("read", [parse, multipath_descriptors])
@pytest.mark.parametrize(
    "descriptor",
    [
        f"wsh(multi(1,{_KEY})junk))",
        f"sh(wsh(multi(1,{_KEY})junk)))",
        f"tr({_X_ONLY},multi_a(1,{_KEY})junk))",
    ],
)
def test_a_valid_key_does_not_make_trailing_structure_valid(
    descriptor: str, read: Callable[[str], Descriptor | list[str]]
) -> None:
    """Reading the key cannot turn the trailing text into a descriptor."""
    with pytest.raises(BTClibValueError):
        read(descriptor)


@pytest.mark.parametrize(
    "descriptor",
    [
        f"sh(multi(1,[dead]]{_KEY})junk))",
        f"wsh(multi(1,[dead]]{_KEY}",
        f"tr({_X_ONLY},multi_a(1,[dead]]{_KEY}",
    ],
)
def test_no_miniscript_key_is_read_without_a_function_close(descriptor: str) -> None:
    """No closing parenthesis leaves Core no inner function to read."""
    with pytest.raises(BTClibValueError) as caught:
        parse(descriptor)
    assert str(caught.value) == _STRUCTURAL


@pytest.mark.parametrize(
    "descriptor",
    [
        f"wsh(multi(1,{_KEY}))",
        f"sh(wsh(multi(1,{_KEY})))",
        f"tr({_X_ONLY},multi_a(1,{_KEY}))",
    ],
)
def test_a_closed_multisig_keeps_its_script(descriptor: str) -> None:
    """A well-formed expression still has its checksummed round trip."""
    parsed = parse(descriptor)
    assert parse(str(parsed)).script_pub_key() == parsed.script_pub_key()
