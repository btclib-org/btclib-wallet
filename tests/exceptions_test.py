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
import http.client
import pickle
import socket
import ssl
import urllib.error
from concurrent.futures import ProcessPoolExecutor
from typing import Any

import pytest
from btclib.exceptions import BTClibException, BTClibRuntimeError, BTClibValueError
from typing_extensions import override

from btclib_wallet import exceptions
from btclib_wallet.exceptions import (
    FetchError,
    HttpError,
    RpcError,
    SignerError,
    _as_built,
    _failure_class,
)
from btclib_wallet.fetch.transport import _time_left

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


class _CallersRefusalError(ConnectionRefusedError):
    """A failure of a class of the caller's, deriving from the builtin's."""


class _Meta(type):
    """A metaclass of the caller's, answering a class's `__mro__` itself."""

    @property
    @override
    def __mro__(cls) -> tuple[type, ...]:
        """Fail the test, as code of the caller's that ran."""
        raise AssertionError(cls.__name__)


class _MetaError(OSError, metaclass=_Meta):
    """A failure whose `__mro__` its metaclass answers."""


@pytest.mark.parametrize(
    "value, held",
    [
        (TimeoutError, TimeoutError),
        (ssl.SSLCertVerificationError, ssl.SSLCertVerificationError),
        (socket.gaierror, socket.gaierror),
        (http.client.RemoteDisconnected, http.client.RemoteDisconnected),
        (urllib.error.URLError, urllib.error.URLError),
        (_CallersRefusalError, ConnectionRefusedError),
        (_MetaError, OSError),
        (int, BaseException),
        ("TimeoutError", BaseException),
        (TimeoutError("timed out"), BaseException),
    ],
    ids=[
        "builtin",
        "ssl",
        "socket",
        "http.client",
        "urllib.error",
        "the caller's",
        "the caller's metaclass",
        "no exception",
        "a name",
        "an instance",
    ],
)
def test_failure_type_holds_a_class_of_the_standard_library(
    value: object, held: type[BaseException]
) -> None:
    """A class of the caller's is held as the one it derives from.

    Anything but a class is `BaseException`. Each class held pickles.
    """
    assert _failure_class(value) is held
    assert pickle.loads(pickle.dumps(held)) is held  # noqa: S301


def test_failure_type_asks_no_metaclass_for_the_bases() -> None:
    """The control: `__mro__` read as an attribute runs the caller's code."""
    with pytest.raises(AssertionError, match="_MetaError"):
        _ = _MetaError.__mro__
    assert _failure_class(_MetaError) is OSError


@pytest.mark.parametrize("cls", [FetchError, HttpError, RpcError])
def test_a_refusal_holds_no_failure_unless_one_is_set(cls: type[FetchError]) -> None:
    """`failure_type` is None on the class, so on each refusal by default."""
    assert cls.failure_type is None


def test_a_refusal_holding_a_failure_stays_the_packages_and_round_trips() -> None:
    """Set after the refusal is built, the member does not make it the caller's.

    `_caller_errors` relays a refusal of the package as it is only where
    `_as_built` reads it as built. A copy and a pickled one keep the member.
    """
    with pytest.raises(FetchError, match="timeout expired") as e:
        _time_left(0.0, 1.0, "here")
    assert _as_built(e.value)
    assert e.value.failure_type is TimeoutError
    for back in (pickle.loads(pickle.dumps(e.value)), copy.copy(e.value)):  # noqa: S301
        assert type(back) is type(e.value)
        assert str(back) == str(e.value)
        assert back.failure_type is TimeoutError
