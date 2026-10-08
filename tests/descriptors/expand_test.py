# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `Descriptor.expand`, Bitcoin Core's `Descriptor::Expand`.

It answers the scripts and the provider of one index from one derivation
of each key. The derivations are counted at `derive_`, the one function
every key derives through.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

import pytest
from btclib.exceptions import BTClibValueError
from btclib.network import NETWORKS
from btclib_ecc.ecc.musig2 import key_agg

from btclib_wallet.bip32 import derive, xpub_from_xprv
from btclib_wallet.bip32.bip32 import derive_, rootxprv_from_seed
from btclib_wallet.descriptors import Descriptor, key_expression, parse
from btclib_wallet.descriptors.key_expression import _derived_once

ROOT = rootxprv_from_seed("0f" * 16, NETWORKS["regtest"].bip32_prv)
KEYS = {f"@{i}": xpub_from_xprv(derive(ROOT, f"m/86h/1h/{i}h")) for i in range(3)}
ACCOUNT_XPRV = derive(ROOT, "m/86h/1h/0h")

# a descriptor and the derivations one index of it takes: one per key
SHAPES = {
    "wpkh": ("wpkh(@0/0/*)", 1),
    "combo": ("combo(@0/0/*)", 1),
    "wsh-multi": ("wsh(multi(2,@0/0/*,@1/0/*,@2/0/*))", 3),
    "sh-wsh-pk": ("sh(wsh(pk(@0/0/*)))", 1),
    "tr-tree": ("tr(@0/0/*,multi_a(2,@1/0/*,@2/0/*))", 3),
    "tr-musig": ("tr(musig(@0/0/*,@1/0/*))", 2),
    "miniscript": ("wsh(or_d(pk(@0/0/*),and_v(v:pkh(@1/0/*),older(10))))", 2),
    "tr-repeats-a-key": ("tr(@0/0/*,pk(@0/0/*))", 1),
}


@pytest.fixture
def derivations(monkeypatch: pytest.MonkeyPatch) -> Callable[[], int]:
    """Return the number of `derive_` calls made since the last answer."""
    count = [0]

    def counting(*args: Any, **kwargs: Any) -> Any:
        count[0] += 1
        return derive_(*args, **kwargs)

    monkeypatch.setattr(f"{key_expression.__name__}.derive_", counting)

    def taken() -> int:
        taken_, count[0] = count[0], 0
        return taken_

    return taken


def _parsed(template: str) -> Descriptor:
    text = template
    for name, xpub in KEYS.items():
        text = text.replace(name, xpub)
    return parse(text, "regtest")


@pytest.mark.parametrize("shape", SHAPES)
def test_expand_answers_what_the_two_methods_answer(shape: str) -> None:
    """`expand` is `script_pub_keys` and `provider`, answered together."""
    template, _ = SHAPES[shape]
    descriptor = _parsed(template)
    for index in (0, 7):
        assert descriptor.expand(index) == (
            descriptor.script_pub_keys(index),
            descriptor.provider(index),
        )


@pytest.mark.parametrize("shape", SHAPES)
def test_expand_derives_each_key_once(
    shape: str, derivations: Callable[[], int]
) -> None:
    """`expand` derives each key once; the two methods apart, once each."""
    template, keys = SHAPES[shape]
    descriptor = _parsed(template)
    derivations()
    descriptor.expand(3)
    assert derivations() == keys
    # the two methods called one after the other share nothing
    descriptor.script_pub_keys(3)
    descriptor.provider(3)
    assert derivations() == 2 * keys


def test_a_musig_is_aggregated_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """The key a ``musig()`` aggregates to is computed once."""
    aggregations = []

    def counting(*args: Any, **kwargs: Any) -> Any:
        aggregations.append(1)
        return key_agg(*args, **kwargs)

    monkeypatch.setattr(f"{key_expression.__name__}.key_agg", counting)
    descriptor = _parsed(SHAPES["tr-musig"][0])
    descriptor.expand(3)
    assert len(aggregations) == 1


def test_a_key_is_remembered_by_its_index() -> None:
    """Two indexes of one key are two derivations."""
    descriptor = _parsed("wpkh(@0/0/*)")
    key = descriptor.key_expressions[0]
    with _derived_once(None):
        assert key.sec(1, "regtest") != key.sec(2, "regtest")


def test_an_aggregate_is_remembered_by_its_index() -> None:
    """The participants of a ``musig()`` derive at the index asked."""
    key = _parsed("tr(musig(@0/0/*,@1/0/*))").key_expressions[0]
    with _derived_once(None):
        assert key.aggregate(1, "regtest") != key.aggregate(2, "regtest")


def test_a_key_is_remembered_by_its_network() -> None:
    """A key of another network is refused, remembered or not."""
    key = _parsed("wpkh(@0/0/*)").key_expressions[0]
    with _derived_once(None):
        key.sec(1, "regtest")
        with pytest.raises(BTClibValueError):
            key.sec(1, "mainnet")


def test_a_hardened_step_is_derived_once(derivations: Callable[[], int]) -> None:
    """A key with a hardened step is derived once, with its `prv_keys`."""
    prv_keys: dict[str, str] = {}
    descriptor = parse(f"combo({ACCOUNT_XPRV}/0h/0h/*)", "regtest", prv_keys)
    derivations()
    assert descriptor.expand(1, prv_keys) == (
        descriptor.script_pub_keys(1, prv_keys),
        descriptor.provider(1, prv_keys),
    )
    assert derivations() == 3
    derivations()
    descriptor.expand(1, prv_keys)
    assert derivations() == 1


def test_another_prv_keys_is_another_expansion(
    derivations: Callable[[], int],
) -> None:
    """What `_derived_once` remembers belongs to the `prv_keys` it had."""
    prv_keys: dict[str, str] = {}
    other: dict[str, str] = {}
    descriptor = _parsed("wpkh(@0/0/*)")
    key = descriptor.key_expressions[0]
    derivations()
    with _derived_once(prv_keys):
        first = key.sec(1, "regtest", prv_keys)
        assert key.sec(1, "regtest", other) == first
        assert key.sec(1, "regtest", other) == first
        assert derivations() == 3
        with _derived_once(other):
            assert key.sec(1, "regtest", other) == first
            assert key.sec(1, "regtest", other) == first
            assert derivations() == 1
        with _derived_once(prv_keys):
            assert key.sec(1, "regtest", prv_keys) == first
        assert derivations() == 0
    assert key.sec(1, "regtest", prv_keys) == first
    assert derivations() == 1


def test_nothing_is_remembered_after_the_expansion(
    derivations: Callable[[], int],
) -> None:
    """Two calls apart derive the key twice."""
    descriptor = _parsed("wpkh(@0/0/*)")
    derivations()
    descriptor.script_pub_keys(1)
    descriptor.script_pub_keys(1)
    assert derivations() == 2


def test_an_exception_leaves_no_expansion_behind(
    derivations: Callable[[], int],
) -> None:
    """A scope left by an exception remembers nothing."""
    descriptor = _parsed("wpkh(@0/0/*)")
    key = descriptor.key_expressions[0]
    with pytest.raises(ZeroDivisionError), _derived_once(None):
        raise ZeroDivisionError
    derivations()
    key.sec(1, "regtest")
    key.sec(1, "regtest")
    assert derivations() == 2


def test_a_thread_started_outside_the_scope_is_outside_it() -> None:
    """Another thread's expansion is not this one's."""
    seen: list[object] = []
    entered, read = threading.Event(), threading.Event()

    def look() -> None:
        entered.wait()
        seen.append(key_expression._DERIVED.get())
        read.set()

    thread = threading.Thread(target=look)
    thread.start()
    with _derived_once(None):
        entered.set()
        read.wait()
    thread.join()
    assert seen == [None]
