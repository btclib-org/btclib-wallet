# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every public callable taking `prv_keys` refuses a non-mapping.

`descriptors.parse` checks `prv_keys` with `assert_type`, and the methods
that take the mapping back did not: a string left as the `AttributeError`
of its missing `get` (issue btclib-org/btclib-wallet#215). The rule is
the one in `input_validation_test.py`, a malformed argument leaving as a
`BTClibTypeError`, and that walk cannot drive these: their other
arguments need a descriptor, a key or a psbt.

So the callables are found here and driven from a table. The first test
is the walk: every public callable of every module's `__all__` that
this package defines and that takes a `PrvKeys` parameter must be a
row, so a new entry cannot escape. The second passes each row a string
and expects a `BTClibTypeError` naming `prv_keys`. Where a callee would
raise the same error, the row does not show that the callable's own
check is there.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from collections.abc import Callable
from typing import Any

import pytest
from bip32_descriptors.bip32.bip32 import rootxprv_from_seed, xpub_from_xprv
from bip32_descriptors.descriptors import Descriptor
from bip32_descriptors.descriptors import parse as parse_descriptor
from btclib.exceptions import BTClibTypeError

import btclib_wallet
from btclib_wallet.psbt import Psbt, update_psbt_input, update_psbt_output
from btclib_wallet.wallet import DescriptorWallet
from tests import defined_here

_XPUB = xpub_from_xprv(rootxprv_from_seed(b"\x01" * 32))
_DESCRIPTOR = parse_descriptor(f"tr({_XPUB}/1h,pk({_XPUB}/2))")
# stands where a key would: none is read before `prv_keys` is
_NOTHING: Any = None
# a psbt with no input and no output: the updaters ask the descriptor
# about `prv_keys` before they look for the map
_EMPTY_PSBT = Psbt(1, [], [], 2, {})


def _walk() -> set[str]:
    """Return `Class.method` of each public callable with a `prv_keys`.

    A routine `btclib_wallet` does not define is skipped: those of
    bip32_descriptors take `prv_keys` too, and are that package's to
    hold, and one a class inherits from elsewhere takes none. Its
    signature may not even be readable: before Python 3.13,
    `inspect.signature` refuses builtins an exception class inherits,
    such as `add_note`.
    """
    found: set[str] = set()
    for info in pkgutil.walk_packages(btclib_wallet.__path__, "btclib_wallet."):
        module = importlib.import_module(info.name)
        for name in getattr(module, "__all__", ()):
            member = getattr(module, name)
            if inspect.isroutine(member):
                callables = [member]
            elif inspect.isclass(member):
                callables = [
                    method
                    for attribute, method in inspect.getmembers(member)
                    if (not attribute.startswith("_") or attribute == "__init__")
                    and inspect.isroutine(method)
                ]
            else:
                continue
            found.update(
                function.__qualname__
                for function in callables
                if defined_here(function)
                and "prv_keys" in inspect.signature(function).parameters
                and "PrvKeys" in str(inspect.signature(function).parameters["prv_keys"])
            )
    return found


def _call(entry: Callable[..., object], *args: object) -> Callable[[], object]:
    return lambda: entry(*args, prv_keys="foo")


_ROWS: dict[str, Callable[[], object]] = {
    "update_psbt_input": _call(update_psbt_input, _DESCRIPTOR, _EMPTY_PSBT, 0, 0),
    "update_psbt_output": _call(update_psbt_output, _DESCRIPTOR, _EMPTY_PSBT, 0, 0),
    "DescriptorWallet.__init__": _call(DescriptorWallet, _DESCRIPTOR),
    "DescriptorWallet.from_account": _call(
        DescriptorWallet.from_account, _NOTHING, _NOTHING
    ),
}


def test_every_callable_with_prv_keys_is_a_row() -> None:
    """A new entry taking `prv_keys` is a row here, or the run is red."""
    assert _walk() == set(_ROWS)


@pytest.mark.parametrize("name", _ROWS)
def test_a_non_mapping_prv_keys_is_a_type_error(name: str) -> None:
    """Each row refuses a string, naming `prv_keys`."""
    with pytest.raises(BTClibTypeError, match="prv_keys"):
        _ROWS[name]()


def test_the_rows_are_real_objects() -> None:
    """The fixtures are the types the table names."""
    assert isinstance(_DESCRIPTOR, Descriptor)
