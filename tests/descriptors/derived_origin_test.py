# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `descriptors.derived_origin`, the origin of a key at an index."""

from __future__ import annotations

from typing import Any

import pytest
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash160

from btclib_wallet.bip32 import (
    BIP32KeyOrigin,
    fingerprint,
    pub_keyinfo_from_xkey,
    rootxprv_from_seed,
    xpub_from_xprv,
)
from btclib_wallet.descriptors import KeyExpression, derived_origin, parse

_XPUB = xpub_from_xprv(rootxprv_from_seed(b"\x01" * 32))
_XPUB_2 = xpub_from_xprv(rootxprv_from_seed(b"\x02" * 32))
_SEC = pub_keyinfo_from_xkey(_XPUB)[0]
_H = 0x80000000


def _key(expression: str) -> KeyExpression:
    """Return the one key of `wpkh(expression)`."""
    return parse(f"wpkh({expression})").key_expressions[0]


def test_an_origin_is_extended_by_the_derivation() -> None:
    """The key origin, then the path, then the wildcard step at the index."""
    key = _key(f"[deadbeef/84h/0h/0h]{_XPUB}/1/*")
    expected = BIP32KeyOrigin(bytes.fromhex("deadbeef"), [84 + _H, _H, _H, 1, 5])
    assert derived_origin(key, 5) == expected


def test_a_hardened_wildcard_adds_its_offset() -> None:
    """`/*h` steps to the index plus 2**31."""
    key = _key(f"[deadbeef]{_XPUB}/*h")
    assert derived_origin(key, 3).der_path == [3 + _H]


def test_a_key_without_an_origin_is_its_own_master() -> None:
    """An extended key under its own fingerprint, a fixed key its hash160's."""
    assert derived_origin(_key(f"{_XPUB}/0/*"), 2) == BIP32KeyOrigin(
        fingerprint(_XPUB), [0, 2]
    )
    assert derived_origin(_key(_SEC.hex())) == BIP32KeyOrigin(hash160(_SEC)[:4], [])


def test_an_unranged_key_ignores_the_index() -> None:
    """The index steps a wildcard, and a key without one has nothing to step."""
    key = _key(f"[deadbeef/0]{_XPUB}/1")
    assert derived_origin(key, 7) == derived_origin(key)


@pytest.mark.parametrize("wrong", [None, 1.5, _XPUB])
def test_a_key_of_another_type_is_refused(wrong: Any) -> None:
    """A text or anything else that is no `KeyExpression` is a type error."""
    with pytest.raises(BTClibTypeError, match="key"):
        derived_origin(wrong, 0)


@pytest.mark.parametrize(
    "index, error",
    [
        (None, BTClibTypeError),
        (1.5, BTClibTypeError),
        (-1, BTClibValueError),
        (_H, BTClibValueError),
    ],
)
def test_an_index_outside_a_wildcard_range_is_refused(
    index: Any, error: type[Exception]
) -> None:
    """The range `KeyExpression.sec` takes, refused for an unranged key too."""
    with pytest.raises(error, match="derivation index"):
        derived_origin(_key(f"{_XPUB}/1"), index)


def test_an_aggregate_key_is_refused() -> None:
    """A ``musig()`` key's origin takes its participants' keys to compute."""
    key = parse(f"tr(musig({_XPUB},{_XPUB_2})/0/*)").key_expressions[0]
    assert key.is_aggregate
    with pytest.raises(BTClibValueError, match="aggregate"):
        derived_origin(key, 0)
