# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests that a parser bounds the work and the numbers it reads from text.

Python's `int()` refuses a string of more than 4300 digits with a built-in
`ValueError`, which no caller catching this library's errors expects. And
a `thresh()` costs time quadratic in its arguments, so the size limit has
to refuse an over-limit one before that analysis starts.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import pytest
from btclib.bech32 import encode as bech32_encode
from btclib.exceptions import BTClibValueError

from btclib_wallet import descriptors
from btclib_wallet.bip32.der_path import int_from_index_str
from btclib_wallet.bolt11 import _SIGNATURE_WORDS, Bolt11Invoice
from btclib_wallet.descriptors import miniscript
from tests.exception_family_test import VALUE_ERRORS

_KEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"  # pragma: allowlist secret
_XONLY = _KEY[2:]
_XPUB = (
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjq"  # pragma: allowlist secret
    "JoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"  # pragma: allowlist secret
)

_KEY_INFO = descriptors.parse(f"pk({_XPUB})").key_expressions[0]

# more than the 4300 digits int() takes, which a bound of ten digits
# refuses long before
_LONG = "9" * 5000
# the same value as 1, spelled with the zeros no bound may count
_PADDED_ONE = "0" * 5000 + "1"


def _invoice_with_amount(digits: str) -> str:
    """Return an invoice text, valid as bech32, with `digits` as its amount."""
    words = [0] * (7 + _SIGNATURE_WORDS)
    return bech32_encode("lnbc" + digits + "m", words, 1).decode()


LONG_NUMBER_CASES: dict[str, Callable[[], Any]] = {
    "invoice amount": lambda: Bolt11Invoice.from_invoice(_invoice_with_amount(_LONG)),
    "der_path index": lambda: int_from_index_str(_LONG),
    "der_path hardened index": lambda: int_from_index_str(_LONG + "h"),
    "miniscript older": lambda: miniscript.parse(f"older({_LONG})"),
    "miniscript after": lambda: miniscript.parse(f"after({_LONG})"),
    "miniscript thresh k": lambda: miniscript.parse(
        f"thresh({_LONG},pk({_KEY}),s:pk({_KEY}))"
    ),
    "miniscript multi k": lambda: miniscript.parse(f"multi({_LONG},{_KEY})"),
    "miniscript multi_a k": lambda: miniscript.parse(
        f"multi_a({_LONG},{_XONLY})", miniscript.TAPSCRIPT
    ),
    "descriptor derivation": lambda: descriptors.parse(f"wpkh({_XPUB}/{_LONG})"),
    "descriptor multi k": lambda: descriptors.parse(f"wsh(multi({_LONG},{_KEY}))"),
    "descriptor sortedmulti k": lambda: descriptors.parse(
        f"wsh(sortedmulti({_LONG},{_KEY}))"
    ),
    "descriptor multi_a k": lambda: descriptors.parse(
        f"tr({_XONLY},multi_a({_LONG},{_XONLY}))"
    ),
    "wallet policy index": lambda: descriptors.wallet_policy_address(
        f"wpkh(@{'1' * 5000}/**)", (), 0
    ),
    "wallet policy musig index": lambda: descriptors.wallet_policy_address(
        f"tr(musig(@0,@{'1' * 5000})/**)", (), 0
    ),
    "wallet policy multipath": lambda: descriptors.wallet_policy_address(
        f"wpkh(@0/<{_LONG};1>/*)", (_KEY_INFO,), 0
    ),
}


@pytest.mark.parametrize(
    "parse", LONG_NUMBER_CASES.values(), ids=list(LONG_NUMBER_CASES.keys())
)
def test_a_number_over_4300_digits_is_refused_as_btclib_value_error(
    parse: Callable[[], Any],
) -> None:
    """Refuse as `BTClibValueError`, and never as the built-in `ValueError`."""
    with pytest.raises(VALUE_ERRORS) as raised:
        parse()
    assert isinstance(raised.value, BTClibValueError)


def test_leading_zeros_are_no_digits_of_the_number() -> None:
    """Read `0` repeated and then `1` as 1: zeros change no value."""
    assert int_from_index_str(_PADDED_ONE) == 1
    assert int_from_index_str(_PADDED_ONE + "h") == 0x80000001
    assert miniscript.parse(f"older({_PADDED_ONE})").threshold == 1
    assert int_from_index_str("0" * 5000) == 0


def _thresh(count: int, key: str) -> str:
    """Return a `thresh()` of `count` arguments over one key."""
    return f"thresh(1,pk({key})" + f",s:pk({key})" * (count - 1) + ")"


def _forbid_the_quadratic_step(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replace the quadratic analyses of a `thresh()` with recorders.

    The recorders raise and note their call, so that a refusal reached
    through them is told from one reached before them.
    """
    calls: list[str] = []

    def recorder(name: str) -> Callable[[Any], Any]:
        def called(_node: Any) -> Any:
            calls.append(name)
            raise AssertionError(f"{name} ran")

        return called

    monkeypatch.setattr(miniscript, "_thresh_stack", recorder("stack"))
    monkeypatch.setattr(miniscript, "_thresh_ops", recorder("ops"))
    return calls


def test_the_control_reaches_the_quadratic_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prove the recorders are where a `thresh()` is analysed."""
    calls = _forbid_the_quadratic_step(monkeypatch)
    with pytest.raises(AssertionError, match="ops ran"):
        miniscript.parse(_thresh(3, _KEY))
    assert calls == ["ops"]


# each refused by the limit that applies: the script size of a p2wsh, and the
# number of arguments where the size of a tapscript is no bound at all
OVER_LIMIT_THRESH: dict[str, tuple[Callable[[], Any], str]] = {
    "miniscript": (lambda: miniscript.parse(_thresh(1000, _KEY)), "too large"),
    "wsh": (lambda: descriptors.parse(f"wsh({_thresh(1000, _KEY)})"), "too large"),
    "tapscript": (
        lambda: miniscript.parse(_thresh(1001, _XONLY), miniscript.TAPSCRIPT),
        "at most 1000 arguments",
    ),
    "tr": (
        lambda: descriptors.parse(f"tr({_XONLY},{_thresh(1001, _XONLY)})"),
        "at most 1000 arguments",
    ),
}


@pytest.mark.parametrize(
    "parse, message",
    OVER_LIMIT_THRESH.values(),
    ids=list(OVER_LIMIT_THRESH.keys()),
)
def test_an_over_limit_thresh_is_refused_before_it_is_analysed(
    monkeypatch: pytest.MonkeyPatch, parse: Callable[[], Any], message: str
) -> None:
    """Refuse on the size or the count, with no stack or ops analysis run.

    The cost of the analysis is quadratic in the arguments, and a timing
    would depend on the machine, so what is asserted is that neither
    analysis is entered.
    """
    calls = _forbid_the_quadratic_step(monkeypatch)
    with pytest.raises(BTClibValueError, match=message):
        parse()
    assert calls == []


def _count_the_quadratic_step(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Wrap the quadratic analyses of a `thresh()`, noting each call."""
    calls: list[str] = []

    def counted(name: str) -> Callable[[Any], Any]:
        original = getattr(miniscript, name)

        def called(node: Any) -> Any:
            calls.append(name)
            return original(node)

        return called

    monkeypatch.setattr(miniscript, "_thresh_stack", counted("_thresh_stack"))
    monkeypatch.setattr(miniscript, "_thresh_ops", counted("_thresh_ops"))
    return calls


def _nested_thresh(count: int, inner: str) -> str:
    """Return a `thresh()` of `count` arguments, each the `inner` one."""
    return "thresh(1," + inner + (",a:" + inner) * (count - 1) + ")"


def test_nested_thresh_is_refused_by_the_running_total_of_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refuse many `thresh()` each below the limit once their sum passes it.

    Each of these is analysed in quadratic time, and only the sum of their
    sizes passes the limit: the first is analysed, and the second is
    refused as it is added, however many follow.
    """
    calls = _count_the_quadratic_step(monkeypatch)
    inner = _thresh(60, _KEY)
    miniscript.parse(inner)  # one alone is within the limit
    calls.clear()
    with pytest.raises(BTClibValueError, match="too large for P2WSH"):
        descriptors.parse(f"wsh({_nested_thresh(200, inner)})")
    assert calls == ["_thresh_ops", "_thresh_stack"]


def test_nested_thresh_is_refused_by_the_running_total_in_tapscript(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hold a tapscript to its limit as a p2wsh is, the limit lowered for speed.

    The limit of a tapscript is so large that a test of it as it is would
    analyse a hundred `thresh()`.
    """
    monkeypatch.setattr(miniscript, "_MAX_TAPSCRIPT_SIZE", 15_000)
    inner = _thresh(300, _XONLY)
    assert miniscript.parse(inner, miniscript.TAPSCRIPT).script_size < 15_000
    calls = _count_the_quadratic_step(monkeypatch)
    with pytest.raises(BTClibValueError, match="too large for tapscript"):
        descriptors.parse(f"tr({_XONLY},{_nested_thresh(50, inner)})")
    assert calls == ["_thresh_ops", "_thresh_stack"]


def test_a_wide_and_nested_thresh_is_refused_quickly() -> None:
    """Refuse a `thresh()` of 60 of 60 of 60 `thresh()` quickly.

    It takes 0.5 s to refuse, and 12 s without the running total, which lets
    the analysis of every `thresh()` run before the size is checked. The
    bound is ten times the first, so that a loaded machine does not fail it.
    """
    text = _nested_thresh(60, _nested_thresh(60, _thresh(60, _XONLY)))
    start = time.perf_counter()
    with pytest.raises(BTClibValueError, match="too large for tapscript"):
        miniscript.parse(text, miniscript.TAPSCRIPT)
    assert time.perf_counter() - start < 5
