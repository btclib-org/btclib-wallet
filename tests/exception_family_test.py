# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The classes a refusal of this package may leave as, and their test.

btclib's own, and ellipticcurves' wherever an argument reaches that
package, the curve arithmetic and the schemes on it being ellipticcurves'
(issue btclib-org/btclib#2282). `btclib.exceptions` binds ellipticcurves'
classes, each beside the same built-in as btclib's of its kind and none
of them a `BTClibException`, so a test holding a function to the contract
names one of the tuples below rather than btclib's class alone. A bare
built-in is in none of them, which is what the test at the end asserts.

Where the installed btclib binds no ellipticcurves class, a btclib
without issue btclib-org/btclib#2282, each name below stands for btclib's
own class instead, and a tuple holds btclib's class twice: a test reads
the same against either btclib.

Shared test code belongs in `tests/__init__.py`; these tuples are here
rather than there because this module is what tests them.
"""

from __future__ import annotations

import btclib.exceptions
import pytest
from btclib.exceptions import (
    BTClibException,
    BTClibRuntimeError,
    BTClibTypeError,
    BTClibValueError,
)


def _ellipticcurves(name: str, btclib_class: type[Exception]) -> type[Exception]:
    """Return ellipticcurves' class as btclib binds it, or btclib's own."""
    found: type[Exception] = getattr(btclib.exceptions, name, btclib_class)
    return found


VALUE_ERRORS = (
    BTClibValueError,
    _ellipticcurves("EllipticCurvesValueError", BTClibValueError),
)
TYPE_ERRORS = (
    BTClibTypeError,
    _ellipticcurves("EllipticCurvesTypeError", BTClibTypeError),
)
RUNTIME_ERRORS = (
    BTClibRuntimeError,
    _ellipticcurves("EllipticCurvesRuntimeError", BTClibRuntimeError),
)
# the base of each family, for a test whose contract is the base
EXCEPTIONS = (
    BTClibException,
    _ellipticcurves("EllipticCurvesException", BTClibException),
)


@pytest.mark.parametrize(
    "family, own, built_in",
    [
        pytest.param(VALUE_ERRORS, BTClibValueError, ValueError, id="value"),
        pytest.param(TYPE_ERRORS, BTClibTypeError, TypeError, id="type"),
        pytest.param(RUNTIME_ERRORS, BTClibRuntimeError, RuntimeError, id="runtime"),
        pytest.param(EXCEPTIONS, BTClibException, Exception, id="base"),
    ],
)
def test_a_family_holds_the_libraries_classes_and_no_bare_built_in(
    family: tuple[type[Exception], ...],
    own: type[Exception],
    built_in: type[Exception],
) -> None:
    """The class of btclib is in it, of its kind, and a bare one is not.

    The last is the half that makes the tuple a contract: a test naming
    the family still fails on the built-in leaking from underneath.
    """
    assert own in family
    assert all(issubclass(member, built_in) for member in family)
    assert not issubclass(built_in, family)
