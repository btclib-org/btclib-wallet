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
is the walk: every public callable of every module's `__all__` with a
`PrvKeys` parameter must be a row, so a new entry cannot escape. The
second passes each row a string and expects a `BTClibTypeError` naming
`prv_keys`. Where a callee would raise the same error, the row does not
show that the callable's own check is there; the `update_psbt_*` rows,
fed `None` for the psbt, do.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from collections.abc import Callable
from typing import Any, cast

import pytest
from btclib.exceptions import BTClibTypeError

import btclib_wallet
from btclib_wallet.bip32.bip32 import rootxprv_from_seed, xpub_from_xprv
from btclib_wallet.descriptors import (
    Descriptor,
    KeyExpression,
    Miniscript,
    TrDescriptor,
)
from btclib_wallet.descriptors import normalized as normalized_descriptor
from btclib_wallet.descriptors import parse as parse_descriptor
from btclib_wallet.descriptors.miniscript import parse as parse_miniscript
from btclib_wallet.wallet import DescriptorWallet

_XPUB = xpub_from_xprv(rootxprv_from_seed(b"\x01" * 32))
_DESCRIPTOR = parse_descriptor(f"tr({_XPUB}/1h,pk({_XPUB}/2))")
_TR = cast(TrDescriptor, _DESCRIPTOR)
_KEY = _DESCRIPTOR.key_expressions[0]
_MINISCRIPT = parse_miniscript(f"pk({_XPUB}/3)")
# stands where a psbt or a key would: none is read before `prv_keys` is
_NOTHING: Any = None


def _walk() -> set[str]:
    """Return `Class.method` of each public callable with a `prv_keys`."""
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
                if "prv_keys" in inspect.signature(function).parameters
                and "PrvKeys" in str(inspect.signature(function).parameters["prv_keys"])
            )
    return found


def _call(entry: Callable[..., object], *args: object) -> Callable[[], object]:
    return lambda: entry(*args, prv_keys="foo")


_ROWS: dict[str, Callable[[], object]] = {
    "Descriptor.script_pub_keys": _call(_DESCRIPTOR.script_pub_keys, 0),
    "Descriptor.script_pub_key": _call(_DESCRIPTOR.script_pub_key, 0),
    "Descriptor.redeem_script": _call(_DESCRIPTOR.redeem_script, 0),
    "Descriptor.address": _call(_DESCRIPTOR.address, 0),
    "Descriptor.addresses": _call(_DESCRIPTOR.addresses, 0),
    "Descriptor.provider": _call(_DESCRIPTOR.provider, 0),
    "Descriptor.expand": _call(_DESCRIPTOR.expand, 0),
    "Descriptor.satisfy": _call(_DESCRIPTOR.satisfy, {}, 0),
    "Descriptor.index_of": _call(_DESCRIPTOR.index_of, b"\x51", -1),
    "Descriptor.update_psbt_input": _call(
        _DESCRIPTOR.update_psbt_input, _NOTHING, 0, 0
    ),
    "Descriptor.update_psbt_output": _call(
        _DESCRIPTOR.update_psbt_output, _NOTHING, 0, 0
    ),
    "TrDescriptor.taproot_leaf_scripts": _call(_TR.taproot_leaf_scripts, 0),
    "TrDescriptor.taproot_merkle_root": _call(_TR.taproot_merkle_root, 0),
    "TrDescriptor.taproot_tree": _call(_TR.taproot_tree, 0),
    "KeyExpression.sec": _call(_KEY.sec, 0, "mainnet"),
    "KeyExpression.participant_keys": _call(_KEY.participant_keys, 0, "mainnet"),
    "KeyExpression.aggregate": _call(_KEY.aggregate, 0, "mainnet"),
    "Miniscript.script": _call(_MINISCRIPT.script, 0, "mainnet"),
    "Miniscript.has_duplicate_keys": _call(_MINISCRIPT.has_duplicate_keys),
    "Miniscript.is_sane_subexpression": _call(_MINISCRIPT.is_sane_subexpression),
    "Miniscript.is_sane": _call(_MINISCRIPT.is_sane),
    "Miniscript.insane_sub": _call(_MINISCRIPT.insane_sub),
    "Miniscript.satisfy": _call(_MINISCRIPT.satisfy, None, None, 0, "mainnet"),
    "normalized": _call(normalized_descriptor, _DESCRIPTOR),
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
    assert isinstance(_KEY, KeyExpression)
    assert isinstance(_MINISCRIPT, Miniscript)
