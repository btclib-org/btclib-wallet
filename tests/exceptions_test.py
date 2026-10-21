# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `btclib_wallet.exceptions`, and for what an exception carries.

The classes with nothing added to their base need no test of their own:
what they are is the base, and every module raising one asserts the
message it raised. What is tested here is the classes carrying a field,
and specifically that a field survives leaving the process it was raised
in: pytest-xdist sends a report as text, so no exception object crosses
between workers.
"""

from __future__ import annotations

import copy
import pickle
from concurrent.futures import ProcessPoolExecutor
from typing import Any

import pytest
from btclib.exceptions import BTClibException, BTClibRuntimeError, BTClibValueError

from btclib_wallet import exceptions
from btclib_wallet.exceptions import FetchError, HttpError, RpcError, SignerError

HTTP_MESSAGE = "getblockcount at http://127.0.0.1:8332: HTTP 503"

# the exception, the `args` it is expected to carry, its message, and the
# fields a caller reads. Constructed here and shared by every test below:
# none of them mutates one
CASES = [
    pytest.param(
        HttpError(HTTP_MESSAGE, 503),
        (HTTP_MESSAGE, 503),
        HTTP_MESSAGE,
        {"status": 503},
        id="HttpError",
    ),
    pytest.param(
        RpcError("getrawtransaction: not found", -5, {"txid": "00"}),
        ("getrawtransaction: not found", -5, {"txid": "00"}),
        "getrawtransaction: not found (rpc error code -5)",
        {"code": -5, "data": {"txid": "00"}},
        id="RpcError",
    ),
    pytest.param(
        RpcError("getblock: block not found", -5),
        ("getblock: block not found", -5, None),
        "getblock: block not found (rpc error code -5)",
        {"code": -5, "data": None},
        id="RpcError-without-data",
    ),
    pytest.param(
        SignerError("the device said no", -14),
        ("the device said no", -14),
        "the device said no (signer error code -14)",
        {"code": -14},
        id="SignerError",
    ),
    pytest.param(
        SignerError("no answer that was json"),
        ("no answer that was json", None),
        "no answer that was json",
        {"code": None},
        id="SignerError-without-code",
    ),
]


def _assert_same(back: BaseException, error: BaseException, fields: Any) -> None:
    assert type(back) is type(error)
    assert str(back) == str(error)
    assert back.args == error.args
    for name, value in fields.items():
        assert getattr(back, name) == value


@pytest.mark.parametrize("error, args, message, fields", CASES)
def test_a_field_carrying_exception_says_what_it_carries(
    error: BaseException, args: tuple[Any, ...], message: str, fields: Any
) -> None:
    """`args` is the constructor's arguments and `str` is the message."""
    assert error.args == args
    assert str(error) == message
    for name, value in fields.items():
        assert getattr(error, name) == value
    assert repr(error) == f"{type(error).__name__}{args!r}"


@pytest.mark.parametrize("error, args, message, fields", CASES)
def test_a_field_carrying_exception_survives_pickle_and_copy(
    error: BaseException, args: tuple[Any, ...], message: str, fields: Any
) -> None:
    """The class, the message and every field come back, twice over.

    A message composed in `__init__` from an argument that is itself a
    composed message would grow a second `(rpc error code -5)` at each
    round trip, which the second one shows.
    """
    back: BaseException = error
    for _ in range(2):
        back = pickle.loads(pickle.dumps(back))  # noqa: S301
        _assert_same(back, error, fields)
    for back in (copy.copy(error), copy.deepcopy(error)):
        _assert_same(back, error, fields)
    assert back.args == args
    assert str(back) == message


def test_an_exception_adding_nothing_round_trips_too() -> None:
    """The control: a class taking a message alone was never affected."""
    error = FetchError("no answer from http://127.0.0.1:8332")
    for back in (pickle.loads(pickle.dumps(error)), copy.copy(error)):  # noqa: S301
        assert type(back) is type(error)
        assert str(back) == str(error)
        assert back.args == error.args


def test_every_class_is_a_btclib_class_of_its_kind() -> None:
    """`except BTClibException` catches each, and the built-in still does.

    The classes are found rather than listed, so one added to the module
    is one this covers.
    """
    classes = [getattr(exceptions, name) for name in exceptions.__all__]
    assert all(isinstance(cls, type) for cls in classes)
    for cls in classes:
        assert issubclass(cls, BTClibException), cls.__name__
        assert issubclass(cls, (BTClibRuntimeError, BTClibValueError)), cls.__name__


def _raise_http_error() -> None:
    raise HttpError(HTTP_MESSAGE, 503)


def test_a_field_carrying_exception_crosses_a_process_boundary() -> None:
    """What the field is for: a fetch fanned out across processes.

    A worker that cannot send its exception back does not merely lose the
    diagnosis: `ProcessPoolExecutor` reports a `BrokenProcessPool`. The
    same raise in this process is the control.
    """
    with pytest.raises(HttpError) as local:
        _raise_http_error()

    with ProcessPoolExecutor(max_workers=1) as pool, pytest.raises(HttpError) as remote:
        pool.submit(_raise_http_error).result()

    assert type(remote.value) is type(local.value)
    assert str(remote.value) == str(local.value)
    assert remote.value.status == local.value.status == 503
