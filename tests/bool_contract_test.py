# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The gate for the bool contract, over what only a fixture can reach.

btclib's rule that every public function validates its inputs states
rules about a function that answers a `bool`, and btclib's own
`bool_contract_test.py` holds its verifications to them. A signature
verification takes a valid message, address and signature, which no
vocabulary of wrong values can build, so the calls here are
hand-written: "a hand-written table of name, and the shortest call that
reaches the validator", issue btclib-org/btclib#776's answer to what an
automatic walk cannot reach. Each case names a function, a call of it
that answers True, a wrong value for each position worth driving, and a
structurally invalid one for each position where the two diverge. Three
rules, asked one position at a time with the others left valid:

- a **wrong type** leaves as a `BTClibTypeError`. A bool is an answer
  about a value, so a type the signature does not declare is not
  something it answers about.
- a **wrong value** of a declared type is `False`. That is what the bool
  is for, and what a caller filtering signatures off the wire relies on.
- a value of a declared type whose size or encoding makes it
  **structurally invalid** -- one no valid input could ever carry, as
  opposed to one that is merely not authentic -- is a `BTClibValueError`.
  A verification is not the question that value answers, so it is
  refused rather than read as a forged signature.

A case marked `ecc=True` hands its arguments on to btclib_ecc, and the
first and the third rule then accept the classes of
`tests/exception_family_test.py`'s families (btclib-org/btclib#2282).

Issue btclib-org/btclib#814 settled the second rule, and issue
btclib-org/btclib#2181 carried the third into `bip322.verify`, where the
encoding stands in for the size.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest
from btclib import b58
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.key import PrvKeyData, PubKeyData
from btclib_ecc.curves import mult

from btclib_wallet import bip322, dlc
from tests.dlc.dlc_vectors_test import _TX, _dlc
from tests.exception_family_test import TYPE_ERRORS, VALUE_ERRORS

_Q = 12
_PUB = PrvKeyData(_Q).pub.sec
_MSG = b"Satoshi Nakamoto"
_ADDR = b58.p2pkh(PubKeyData(_PUB))
# BIP322 declares a `Sig` of its own, and it is not bms's: the two are
# distinct classes
_BIP322_SIG = bip322.sign(_MSG, PrvKeyData(_Q), _ADDR)

# the DLC adaptor signature: a refund transaction of the first dlcspecs
# transaction vector, its funding key's adaptor signature under the point
# of 5*G, and the same under 6*G for a wrong value
_DLC_TERMS = _dlc(_TX[0]["inputs"])
_DLC_BUILT = dlc.build_transactions(_DLC_TERMS)
_DLC_TX = _DLC_BUILT.refund_tx
_DLC_KEY = int(_TX[0]["inputs"]["offerParams"]["fundingPrivKey"], 16)
_DLC_PUB = _DLC_TERMS.offer.funding_pub_key
_DLC_POINT = mult(5)
_DLC_ADAPTOR = dlc.adaptor_sign(_DLC_TERMS, _DLC_TX, _DLC_KEY, _DLC_POINT, bytes(32))
_DLC_OTHER = dlc.adaptor_sign(_DLC_TERMS, _DLC_TX, _DLC_KEY, mult(6), bytes(32))

# a value of a declared type that no valid input carries, spelled per
# position because a hand-written call knows which alias each of its
# arguments is
_WRONG_OCTETS_VALUE = "not hex at all"
_WRONG_STRING_VALUE = "not an address"

# a value of no type any of these positions declares
_WRONG_TYPES = (None, 1.5)


@dataclass(frozen=True)
class _Case:
    """A bool function, a call that answers True, and what to drive."""

    label: str
    function: Any
    args: tuple[Any, ...]
    # position -> a wrong value of the type that position declares, one
    # a valid input could carry -- False is the answer
    wrong_values: dict[int, Any]
    # position -> a value of the declared type whose size or encoding
    # makes the question unanswerable -- a raise is the answer (issue
    # btclib-org/btclib#2170). Empty for every case this issue leaves alone
    structurally_invalid_values: dict[int, Any] = field(default_factory=dict)
    # whether the function hands its arguments to btclib_ecc, whose own
    # error classes then leave it
    ecc: bool = False


_CASES = (
    _Case(
        "bip322.verify",
        bip322.verify,
        (_MSG, _ADDR, _BIP322_SIG),
        {0: _WRONG_OCTETS_VALUE},
        # the address is the challenge `to_spend` is built from, and the
        # signature is written in one of the encodings this module reads
        # or in none
        {1: _WRONG_STRING_VALUE, 2: _WRONG_STRING_VALUE},
    ),
    _Case(
        "dlc.verify_adaptor",
        dlc.verify_adaptor,
        (_DLC_TERMS, _DLC_TX, _DLC_ADAPTOR, _DLC_PUB, _DLC_POINT),
        # a CET in place of the refund, an adaptor signature under another
        # point, another key, another point
        {
            1: _DLC_BUILT.cets[0],
            2: _DLC_OTHER,
            3: _DLC_TERMS.accept.funding_pub_key,
            4: mult(6),
        },
        # a truncated adaptor signature, a key and a point that are on no
        # curve
        {
            2: _DLC_ADAPTOR[:-1],
            3: b"\2" + b"\xff" * 32,
            4: (1, 2),
        },
        ecc=True,
    ),
)

_IDS = tuple(case.label for case in _CASES)


def _call(case: _Case, position: int, wrong: Any) -> Any:
    """Return the answer of the case's call with one position replaced."""
    args = list(case.args)
    args[position] = wrong
    return case.function(*args)


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_the_call_answers_true(case: _Case) -> None:
    """The fixture is valid, which is what makes False an answer below.

    Without this a case whose arguments had gone stale would pass every
    test in the file by answering False to everything.
    """
    assert case.function(*case.args) is True


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_a_wrong_type_leaves_as_a_type_error(case: _Case) -> None:
    """The first rule, one position at a time, the others left valid."""
    for position in range(len(case.args)):
        for wrong in _WRONG_TYPES:
            with pytest.raises(TYPE_ERRORS if case.ecc else BTClibTypeError):
                _call(case, position, wrong)


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_a_wrong_value_answers_false(case: _Case) -> None:
    """The second rule: a value of a declared type is answered, not refused."""
    for position, wrong in sorted(case.wrong_values.items()):
        assert _call(case, position, wrong) is False


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_a_structurally_invalid_value_raises(case: _Case) -> None:
    """The third rule: an unanswerable question is refused.

    An address or a signature whose encoding no valid input could carry
    is not a value the verification ever reaches, so it is a value error
    rather than a False that would read as a forged signature (issue
    btclib-org/btclib#2170).
    """
    for position, wrong in sorted(case.structurally_invalid_values.items()):
        with pytest.raises(VALUE_ERRORS if case.ecc else BTClibValueError):
            _call(case, position, wrong)
