# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A rule: what can run the caller's code refuses its `FetchError` (#935).

Section 7 of the btclib-org standard, *A refusal carries no secret*: a
`FetchError` the caller's code built holds what that code gave it, and
`btclib_wallet.exceptions._caller_errors` refuses it by its class. The
caller's code runs wherever the package reads an attribute of, or calls,
a `Fetcher`, a reader, a broadcaster, a client or a transport the caller
supplies, and wherever a method of the package calls a method or reads
an attribute that the caller's own subclass can override. Each of those
runs inside a public function or method of the package, which is
`_guarded`, so the rule is checked there.

The kinds of object the caller supplies are read off the package: the
protocols and the `Fetcher` classes of `btclib_wallet.fetch`, its
callable aliases, such as `LineTransport`, and the classes it imports
from `bitcoin_core_rpc` that are neither an exception nor an enum, such
as `BitcoinCoreRpcClient`. A public function with a
parameter of one of those kinds is `_guarded`. So is each public method
and property of a public class that derives from `Fetcher`, that takes an
object of one of those kinds, or that is a transport of
`btclib_wallet.fetch`, as `_guarded_methods` guards them.
"""

from __future__ import annotations

import collections.abc
import importlib
import inspect
import re
from collections.abc import Callable, Iterator
from dataclasses import is_dataclass
from enum import Enum
from types import FunctionType
from typing import Any, TypeVar, get_origin

import bitcoin_core_rpc
import pytest
from btclib.tx import Tx
from typing_extensions import override

from btclib_wallet.exceptions import FetchError, HttpError, _guarded, _guarded_methods
from btclib_wallet.fetch.bitcoin_core_rest import BitcoinCoreRestFetcher
from btclib_wallet.fetch.decorators import CachingFetcher, FallbackFetcher
from btclib_wallet.fetch.esplora import EsploraFetcher
from btclib_wallet.fetch.fetcher import Fetcher, tx_from_raw
from tests import defined_here, module_names
from tests.fetch import TX_ID, Recorded, StubFetcher, recorded_body
from tests.fetch.compact_filters_test import build
from tests.fetch.esplora_test import BASE
from tests.refused_value_test import HEX, SPELLINGS
from tests.secret_free import assert_secret_free

_GUARD = _guarded(lambda: None).__code__
_F = TypeVar("_F", bound=Fetcher)
_NO_ANSWER = "no usable answer from the server: FetchError$"
_RAW = recorded_body("esplora_tx_hex.txt").decode().strip()


def _kinds() -> set[str]:
    """Return the names of the kinds of object a caller supplies."""
    kinds: set[str] = set()
    for module_name in module_names():
        if not module_name.startswith("btclib_wallet.fetch"):
            continue
        for name, value in vars(importlib.import_module(module_name)).items():
            if not inspect.isclass(value):
                if get_origin(value) is collections.abc.Callable:
                    kinds.add(name)
            elif defined_here(value):
                if getattr(value, "_is_protocol", False) or issubclass(value, Fetcher):
                    kinds.add(name)
            elif value.__module__.startswith(
                bitcoin_core_rpc.__name__
            ) and not issubclass(value, (BaseException, Enum)):
                kinds.add(name)
    return kinds


_KINDS = _kinds()


def _takes_a_kind(function: Callable[..., Any]) -> bool:
    """Return whether a parameter of `function` is of a caller's kind."""
    for parameter in inspect.signature(function).parameters.values():
        annotation = parameter.annotation
        if annotation is inspect.Parameter.empty:
            continue
        if _KINDS & set(re.findall(r"\w+", str(annotation))):
            return True
    return False


def _functions(cls: type) -> Iterator[tuple[str, Callable[..., Any]]]:
    """Yield each public function, accessor and dunder of the body of `cls`."""
    for name, member in vars(cls).items():
        if name.startswith("_") and not name.endswith("__"):
            continue
        if isinstance(member, property):
            accessors = (member.fget, member.fset, member.fdel)
            yield from ((name, f) for f in accessors if f is not None)
        elif isinstance(member, (classmethod, staticmethod)):
            yield name, member.__func__
        elif isinstance(member, FunctionType) and not getattr(
            member, "__isabstractmethod__", False
        ):
            yield name, member


def _a_transport(module_name: str, cls: type) -> bool:
    """Return whether `cls` is a class of `btclib_wallet.fetch` holding state.

    A transport, which a fetcher of the package or the caller calls, takes
    an `ssl.SSLContext` the caller can supply, as a fetcher takes a client.
    A protocol, an exception, an enum or a dataclass holds none.
    """
    return (
        module_name.startswith("btclib_wallet.fetch")
        and not issubclass(cls, (BaseException, Enum))
        and not is_dataclass(cls)
    )


def _unguarded() -> list[str]:
    """Return each function the rule asks to be `_guarded` and is not."""
    asked: list[tuple[str, Callable[..., Any]]] = []
    for module_name in module_names():
        module = importlib.import_module(module_name)
        for name, value in vars(module).items():
            if name.startswith("_") or getattr(value, "__module__", "") != module_name:
                continue
            if isinstance(value, FunctionType):
                if _takes_a_kind(value):
                    asked.append((f"{module_name}.{name}", value))
            elif inspect.isclass(value) and not getattr(value, "_is_protocol", False):
                functions = list(_functions(value))
                if (
                    issubclass(value, Fetcher)
                    or _a_transport(module_name, value)
                    or any(_takes_a_kind(f) for _, f in functions)
                ):
                    asked += [
                        (f"{module_name}.{name}.{member}", f) for member, f in functions
                    ]
    return [label for label, f in asked if f.__code__ is not _GUARD]


def test_every_call_reaching_the_callers_code_is_guarded() -> None:
    """The kinds are read off the package, and so is what takes them."""
    assert {"Fetcher", "HistoryReader", "LineTransport", "PeerTransport"} <= _KINDS
    assert _unguarded() == []


@_guarded_methods
class _Toy:
    """A class of the caller's, guarded as a class of the package is."""

    def __init__(self, error: Exception) -> None:
        self.error = error

    def ask(self) -> None:
        """Raise the error this was given."""
        raise self.error

    @property
    def field(self) -> None:
        """Raise the error this was given."""
        raise self.error

    @field.setter
    def field(self, _value: object) -> None:
        raise self.error

    @classmethod
    def made(cls) -> None:
        """Raise a refusal holding the key."""
        raise FetchError(f"no class for {HEX}")

    @staticmethod
    def kept() -> None:
        """Raise a refusal holding the key."""
        raise FetchError(f"no answer for {HEX}")

    def abstract(self) -> None:
        """Left as it is, as `abstractmethod` marks it."""

    abstract.__isabstractmethod__ = True  # type: ignore[attr-defined]

    def _private(self) -> None:
        raise self.error

    answer = 42


def test_guarded_methods_refuse_the_callers_fetch_error() -> None:
    """Methods, accessors and dunders are guarded; the rest are left."""
    toy = _Toy(FetchError(f"no answer for {HEX}"))
    calls: list[tuple[str, Callable[[], object]]] = [
        ("_Toy.ask", toy.ask),
        ("_Toy.field", lambda: toy.field),
        ("_Toy.field", lambda: setattr(toy, "field", 1)),
        ("_Toy.made", _Toy.made),
        ("_Toy.kept", _Toy.kept),
    ]
    for request, call in calls:
        with pytest.raises(FetchError, match=f"^{request}: {_NO_ANSWER}") as e:
            call()
        assert e.value.__cause__ is None
        assert e.value.__context__ is None
        assert_secret_free(e.value, SPELLINGS)
    with pytest.raises(FetchError, match=f"no answer for {HEX}"):
        toy._private()
    assert _Toy.abstract.__code__ is not _GUARD
    assert _Toy.answer == 42
    assert _Toy.__init__.__code__ is _GUARD


def test_a_guarded_method_passes_the_packages_refusal_as_it_is() -> None:
    """One the package built is the same object at the caller (#935)."""
    with pytest.raises(FetchError) as built:
        tx_from_raw(_RAW, "00" * 32, "mainnet")
    with pytest.raises(FetchError) as e:
        _Toy(built.value).ask()
    assert e.value is built.value
    error = ValueError(HEX)
    with pytest.raises(ValueError, match=HEX):
        _Toy(error).ask()


def _lazy(cls: type[_F], name: str) -> type[_F]:
    """Return a subclass of `cls` whose `name` raises where it is read.

    The refusal holds the key; setting `name` keeps nothing.
    """

    def read(_self: object) -> object:
        raise FetchError(f"no {name} for {HEX}")

    return type(f"_Lazy{cls.__name__}", (cls,), {name: property(read, _keep)})


def _keep(_self: object, _value: object) -> None:
    """Keep nothing of what is set."""


@pytest.mark.parametrize(
    "make, request_",
    [
        (CachingFetcher, "CachingFetcher.__init__"),
        (lambda fetcher: FallbackFetcher([fetcher]), "FallbackFetcher.__init__"),
    ],
    ids=["caching", "fallback"],
)
def test_a_constructor_reading_the_callers_fetcher_refuses_its_error(
    make: Callable[[Fetcher], Fetcher], request_: str
) -> None:
    """`network` is a read of the caller's object, as a call is (#935)."""
    fetcher = _lazy(StubFetcher, "network")(Tx.parse(_RAW))
    with pytest.raises(FetchError, match=f"^{request_}: {_NO_ANSWER}") as e:
        make(fetcher)
    assert e.value.__cause__ is None
    assert e.value.__context__ is None
    assert_secret_free(e.value, SPELLINGS)


def _refuse() -> None:
    """Close as the caller's own subclass can: raising its text."""
    raise FetchError(f"no close for {HEX}")


def test_a_close_of_the_callers_own_after_the_chain_is_agreed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failure past the chain question closes the peers (#935).

    The close the fetcher calls, and the one `__exit__` calls, are the
    caller's here.
    """
    fetcher, peer = build()
    fetcher.get_block_count()
    assert fetcher._agreed

    def fail(*_args: object) -> None:
        raise FetchError("peer unavailable")

    monkeypatch.setattr(peer, "send", fail)
    monkeypatch.setattr(fetcher, "close", _refuse)
    err_msg = f"^CompactFilterFetcher.get_block_count: {_NO_ANSWER}"
    with pytest.raises(FetchError, match=err_msg) as e:
        fetcher.get_block_count()
    refusals = [e.value]
    with (
        pytest.raises(
            FetchError, match=f"^CompactFilterFetcher.__exit__: {_NO_ANSWER}"
        ) as e,
        fetcher,
    ):
        pass
    refusals.append(e.value)
    for refusal in refusals:
        assert refusal.__cause__ is None
        assert refusal.__context__ is None
        assert_secret_free(refusal, SPELLINGS)


def test_an_attribute_of_the_callers_own_subclass_refuses_its_error() -> None:
    """A package method reads `base_url`, which the subclass answers (#935)."""
    fetcher = _lazy(EsploraFetcher, "base_url")(
        BASE, transport=Recorded((200, b"")), verify_network=False
    )
    err_msg = f"^EsploraFetcher.get_tx: {_NO_ANSWER}"
    with pytest.raises(FetchError, match=err_msg) as e:
        fetcher.get_tx(TX_ID)
    assert e.value.__cause__ is None
    assert e.value.__context__ is None
    assert_secret_free(e.value, SPELLINGS)


def _refuse_with_the_key() -> None:
    """Raise a refusal of the caller's code holding the key."""
    raise FetchError(f"no answer for {HEX}")


def _package_refusal() -> None:
    """Raise a refusal an `EsploraFetcher` builds, an `HttpError`."""
    transport = Recorded((503, b""))
    EsploraFetcher(BASE, transport=transport, verify_network=False).text("/x")


class _HandlingClient(bitcoin_core_rpc.BitcoinCoreRestClient):
    """A client of the caller's asking the package inside its own `except`."""

    @override
    def get_json(self, *args: Any, **kwargs: Any) -> Any:
        """Ask an `EsploraFetcher` while handling a refusal holding the key."""
        try:
            _refuse_with_the_key()
        except FetchError:
            _package_refusal()


def test_a_package_refusal_raised_in_the_callers_except_chains_nothing() -> None:
    """Python sets the caller's error as its context, and the guard cuts it."""
    fetcher = BitcoinCoreRestFetcher(
        _HandlingClient("http://example.invalid"), verify_network=False
    )
    with pytest.raises(HttpError, match="^HTTP 503 from the path asked$") as e:
        fetcher.get_block_count()
    assert e.value.__cause__ is None
    assert e.value.__context__ is None
    assert_secret_free(e.value, SPELLINGS)


def _nested() -> None:
    """Raise a refusal of the package, inside the package's own `except`.

    That `except` handles a refusal the package raised inside an `except`
    of the caller's code; `tx_from_raw` is guarded nowhere, so nothing cut
    the chain before this function returns.
    """
    try:
        _refuse_with_the_key()
    except FetchError:
        try:
            tx_from_raw(_RAW, "00" * 32, "mainnet")
        except FetchError:
            tx_from_raw(_RAW, "11" * 32, "regtest")


_through = _guarded(lambda call: call())


def test_the_chain_is_cut_at_the_first_link_of_the_callers() -> None:
    """The package's own links are kept, the caller's error dropped (#935)."""
    with pytest.raises(FetchError) as unguarded:
        _nested()
    held = unguarded.value.__context__
    assert held is not None
    assert HEX in str(held.__context__)
    with pytest.raises(FetchError) as e:
        _through(_nested)
    first = e.value.__context__
    assert isinstance(first, FetchError)
    assert first.__context__ is None
    assert e.value.__suppress_context__ is False
    assert_secret_free(e.value, SPELLINGS)


def _added_a_note(error: FetchError) -> None:
    error.add_note(f"for {HEX}")


def _set_an_attribute(error: FetchError) -> None:
    error.key = HEX  # type: ignore[attr-defined]


def _set_the_args(error: FetchError) -> None:
    error.args = (f"for {HEX}",)


class _RenamedError(FetchError):
    """A class of the caller's that a built refusal is given."""


def _set_the_class(error: FetchError) -> None:
    error.__class__ = _RenamedError


def _set_the_status(error: FetchError) -> None:
    error.status = int(HEX, 16)  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "change, err_msg",
    [
        (_added_a_note, "the server answered HTTP 503"),
        (_set_an_attribute, "the server answered HTTP 503"),
        (_set_the_args, "the server answered HTTP 503"),
        (_set_the_class, "no usable answer from the server: _RenamedError"),
        (_set_the_status, "the server answered HTTP 0"),
    ],
    ids=["note", "attribute", "args", "class", "status"],
)
def test_a_refusal_the_callers_code_changed_is_refused_by_its_class(
    change: Callable[[FetchError], None], err_msg: str
) -> None:
    """Changed, a refusal of the package holds what the caller gave it."""

    def changed() -> None:
        try:
            _package_refusal()
        except FetchError as error:
            change(error)
            raise

    with pytest.raises(FetchError, match=f"^<lambda>: {err_msg}$") as e:
        _through(changed)
    assert e.value.__cause__ is None
    assert e.value.__context__ is None
    assert_secret_free(e.value, SPELLINGS)


class _HidingGroup(ExceptionGroup[Exception]):
    """A group of the caller's whose `exceptions` and `derive` raise."""

    @property
    @override
    def exceptions(self) -> tuple[Exception, ...]:
        """Raise a refusal holding the key."""
        raise FetchError(  # pragma: no cover -- the walk reads the base's own
            f"no members for {HEX}"
        )

    @override
    def derive(self, excs: Any) -> ExceptionGroup[Exception]:  # type: ignore[override]
        """Raise a refusal holding the key."""
        raise FetchError(  # pragma: no cover -- split and subgroup are not called
            f"no group for {HEX}"
        )


@pytest.mark.parametrize(
    "group",
    [
        ExceptionGroup("failures", [FetchError(f"no answer for {HEX}")]),
        ExceptionGroup(
            "failures",
            [TypeError("a bug"), ExceptionGroup("inner", [FetchError(HEX)])],
        ),
        _HidingGroup("failures", [FetchError(f"no answer for {HEX}")]),
    ],
    ids=["leaf", "nested", "hiding"],
)
def test_a_group_holding_a_fetch_error_is_refused_by_its_class(
    group: ExceptionGroup[Exception],
) -> None:
    """`except* FetchError` would hand the caller what the group holds."""

    def grouped() -> None:
        raise group

    name = type(group).__name__
    err_msg = f"^no usable answer from the server: {name}$"
    with pytest.raises(FetchError, match=err_msg) as e:
        _through(grouped)
    assert type(e.value) is FetchError
    assert e.value.__cause__ is None
    assert e.value.__context__ is None
    assert_secret_free(e.value, SPELLINGS)


_BUG = ExceptionGroup("inner", [TypeError("a bug")])


@pytest.mark.parametrize(
    "group",
    [
        ExceptionGroup("failures", [TypeError("a bug")]),
        ExceptionGroup("failures", [_BUG, _BUG]),
    ],
    ids=["leaf", "twice"],
)
def test_a_group_holding_no_fetch_error_passes_as_it_is(
    group: ExceptionGroup[Exception],
) -> None:
    """A group of the caller's bugs stays one, as a bare `TypeError` does.

    A group held twice is read once.
    """

    def grouped() -> None:
        raise group

    with pytest.raises(ExceptionGroup) as e:
        _through(grouped)
    assert e.value is group


def test_a_chain_looping_through_the_packages_refusals_is_walked_once() -> None:
    """Each link is read once, so a chain that loops ends the walk."""
    with pytest.raises(FetchError) as first:
        tx_from_raw(_RAW, "00" * 32, "mainnet")
    with pytest.raises(FetchError) as second:
        tx_from_raw(_RAW, "11" * 32, "regtest")
    first.value.__context__ = second.value
    second.value.__context__ = first.value
    with pytest.raises(FetchError) as e:
        _through(lambda: _raise(first.value))
    assert e.value is first.value
    assert e.value.__context__ is second.value
    assert second.value.__context__ is first.value


def _raise(error: Exception) -> None:
    raise error


class _CallerGroup(BaseExceptionGroup[BaseException]):
    """A group class of the caller's, kept even where every leaf is one."""


class _Cancelled(BaseException):
    """An interrupt of the caller's own, such as a framework's cancel."""


def test_a_base_group_holding_a_fetch_error_is_refused_by_its_class() -> None:
    """A `BaseExceptionGroup` subclass of the caller's is a group too."""
    group = _CallerGroup("failures", [FetchError(f"no answer for {HEX}")])

    def grouped() -> None:
        raise group

    err_msg = "^no usable answer from the server: _CallerGroup$"
    with pytest.raises(FetchError, match=err_msg) as e:
        _through(grouped)
    assert type(e.value) is FetchError
    assert e.value.__cause__ is None
    assert e.value.__context__ is None
    assert_secret_free(e.value, SPELLINGS)


@pytest.mark.parametrize(
    "leaf, kind, code",
    [
        (KeyboardInterrupt(HEX), KeyboardInterrupt, None),
        (GeneratorExit(HEX), GeneratorExit, None),
        (SystemExit(2), SystemExit, True),
        (SystemExit(HEX), SystemExit, True),
        (SystemExit(0), SystemExit, False),
        (SystemExit(), SystemExit, False),
        (_Cancelled(HEX), BaseException, None),
    ],
    ids=["interrupt", "exit", "exit 2", "exit text", "exit 0", "exit none", "other"],
)
def test_a_group_holding_an_interrupt_and_a_fetch_error_raises_the_interrupt(
    leaf: BaseException, kind: type[BaseException], code: object
) -> None:
    """The interrupt is not lost, and holds nothing of the caller's (#935).

    It is the first leaf that is no `Exception`, in the group's order: the
    one inside a group ahead of a `KeyboardInterrupt` ahead of the rest.
    """
    group = BaseExceptionGroup(
        "failures",
        [
            FetchError(f"no answer for {HEX}"),
            BaseExceptionGroup("inner", [leaf]),
            KeyboardInterrupt(),
        ],
    )

    def grouped() -> None:
        raise group

    with pytest.raises(BaseException) as e:
        _through(grouped)
    # a new one, of the leaf's kind, or a bare `BaseException`
    assert e.value is not leaf
    assert isinstance(e.value, kind)
    assert not isinstance(e.value, (Exception, _Cancelled))
    assert e.value.args == (() if code is None else (code,))
    assert e.value.__cause__ is None
    assert e.value.__context__ is None
    assert_secret_free(e.value, SPELLINGS)


def test_a_base_group_holding_no_fetch_error_passes_as_it_is() -> None:
    """An interrupt in a group of the caller's stays where it was."""
    group = BaseExceptionGroup("failures", [KeyboardInterrupt(), TypeError("a bug")])

    def grouped() -> None:
        raise group

    with pytest.raises(BaseExceptionGroup) as e:
        _through(grouped)
    assert e.value is group
