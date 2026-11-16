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

import builtins
import collections.abc
import copy
import importlib
import inspect
import json
import pickle
import platform
import re
import sys
import threading
from collections.abc import Callable, Iterator, Sized
from concurrent.futures import ThreadPoolExecutor
from dataclasses import is_dataclass
from enum import Enum, IntEnum
from types import FunctionType
from typing import Any, TypeVar, get_origin

import bitcoin_core_rpc
import pytest
from btclib.tx import Tx
from typing_extensions import override

from btclib_wallet import exceptions
from btclib_wallet.electrum import decode_response
from btclib_wallet.exceptions import (
    FetchError,
    HttpError,
    RpcError,
    _guarded,
    _guarded_methods,
)
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


def _appended_an_arg(error: FetchError) -> None:
    error.args = (*error.args, HEX)


def _cut_the_args(error: FetchError) -> None:
    error.args = error.args[:-1]


class _Text(str):
    """A text of the caller's, equal to the one it stands for."""

    __slots__ = ()

    @override
    def __str__(self) -> str:  # pragma: no cover -- a refusal reads no arg of it
        return f"for {HEX}"


def _set_an_equal_text(error: FetchError) -> None:
    text, *rest = error.args
    error.args = (_Text(text), *rest)


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
        (_appended_an_arg, "the server answered HTTP 503"),
        (_cut_the_args, "the server answered HTTP 503"),
        (_set_an_equal_text, "the server answered HTTP 503"),
        (_set_the_class, "no usable answer from the server: _RenamedError"),
        (_set_the_status, "the server answered HTTP 0"),
    ],
    ids=[
        "note",
        "attribute",
        "args",
        "appended",
        "prefix",
        "equal text",
        "class",
        "status",
    ],
)
def test_a_refusal_the_callers_code_changed_is_refused_by_its_class(
    change: Callable[[FetchError], None], err_msg: str
) -> None:
    """Changed, a refusal of the package holds what the caller gave it.

    Changed and raised once caught. While it is handled, PyPy rebuilds an
    error given a class that is no subclass of the one it was raised with
    as one of that class, holding it, and an `HttpError` cannot be built
    from an error alone.
    """

    def changed() -> None:
        with pytest.raises(FetchError) as built:
            _package_refusal()
        change(built.value)
        raise built.value

    with pytest.raises(FetchError, match=f"^<lambda>: {err_msg}$") as e:
        _through(changed)
    assert e.value.__cause__ is None
    assert e.value.__context__ is None
    assert_secret_free(e.value, SPELLINGS)


def _rpc_refusal() -> None:
    """Raise a refusal the package's Electrum codec builds, an `RpcError`."""
    error = {"code": -32601, "message": "unknown method"}
    decode_response(json.dumps({"id": 1, "error": error}).encode(), 1, "server.ping")


def _set_the_last_arg(error: FetchError) -> None:
    error.args = (*error.args[:-1], HEX)


def _set_the_second_arg(error: FetchError) -> None:
    error.args = (error.args[0], HEX, *error.args[2:])


_RPC_REFUSED = r"the server answered an rpc error \(rpc error code -32601\)"


@pytest.mark.parametrize(
    "refuse, change, err_msg",
    [
        (_package_refusal, _set_the_last_arg, "the server answered HTTP 503"),
        (_rpc_refusal, _set_the_last_arg, _RPC_REFUSED),
        (_rpc_refusal, _set_the_second_arg, _RPC_REFUSED),
    ],
    ids=["http last", "rpc last", "rpc middle"],
)
def test_a_refusal_given_another_arg_in_its_place_is_refused_by_its_class(
    refuse: Callable[[], None], change: Callable[[FetchError], None], err_msg: str
) -> None:
    """Each arg is read: an `RpcError`'s `code` is its second arg."""

    def changed() -> None:
        with pytest.raises(FetchError) as built:
            refuse()
        count = len(built.value.args)
        change(built.value)
        assert len(built.value.args) == count
        raise built.value

    with pytest.raises(FetchError, match=f"^<lambda>: {err_msg}$") as e:
        _through(changed)
    assert_secret_free(e.value, SPELLINGS)


class _ShownFields(dict[str, Any]):
    """A `__dict__` of the caller's, which shows other fields than it holds.

    Each read a copy of it can make shows the fields shown.
    """

    def __init__(self, held: dict[str, Any], shown: dict[str, Any]) -> None:
        super().__init__(held)
        self.shown = shown

    @override
    def __len__(self) -> int:  # pragma: no cover -- the guard reads no subclass
        return len(self.shown)

    @override
    def __iter__(
        self,
    ) -> Iterator[str]:  # pragma: no cover -- the guard reads no subclass
        return iter(self.shown)

    @override
    def keys(self) -> Any:  # pragma: no cover -- the guard reads no subclass
        return self.shown.keys()

    @override
    def __getitem__(
        self, key: str
    ) -> Any:  # pragma: no cover -- the guard reads no subclass
        return self.shown[key]

    @override
    def get(
        self, key: str, default: Any = None
    ) -> Any:  # pragma: no cover -- the guard reads no subclass
        return self.shown.get(key, default)


class _NotingClient(bitcoin_core_rpc.BitcoinCoreRestClient):
    """A client of the caller's that notes the key on a refusal of the package.

    The note goes into a `__dict__` that shows the fields it was built with.
    """

    @override
    def get_json(self, *args: Any, **kwargs: Any) -> Any:
        """Raise a refusal of the package, noted."""
        try:
            _package_refusal()
        except FetchError as error:
            shown = dict(vars(error))
            error.__dict__ = _ShownFields({**shown, "__notes__": [HEX]}, shown)
            raise


def test_a_refusal_whose_dict_shows_other_fields_is_refused_by_its_class() -> None:
    """The note does not reach the caller, through a public call."""
    fetcher = BitcoinCoreRestFetcher(
        _NotingClient("http://example.invalid"), verify_network=False
    )
    with pytest.raises(HttpError, match="the server answered HTTP 503$") as e:
        fetcher.get_block_count()
    assert not hasattr(e.value, "__notes__")
    assert_secret_free(e.value, SPELLINGS)


def test_a_refusal_whose_field_names_are_the_callers_is_refused_by_its_class() -> None:
    """A name of the caller's runs its code where it is compared."""
    fields: dict[str, Any] = {}

    class Name(str):
        """A name equal to the one it stands for, which notes the key."""

        __slots__ = ()

        @override
        def __eq__(self, other: object) -> bool:  # pragma: no cover -- not compared
            fields["__notes__"] = [HEX]
            return str.__eq__(self, other)

        __hash__ = str.__hash__

    def changed() -> None:
        with pytest.raises(HttpError) as built:
            _package_refusal()
        fields.update({Name(name): value for name, value in vars(built.value).items()})
        built.value.__dict__ = fields
        raise built.value

    with pytest.raises(
        HttpError, match="^<lambda>: the server answered HTTP 503$"
    ) as e:
        _through(changed)
    assert_secret_free(e.value, SPELLINGS)


def test_a_refusal_whose_fields_change_while_read_is_read_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A thread of the caller's can change the fields between two reads.

    The change is made at the read of each name, which `type` makes there:
    the first adds a note, and the second takes it away, as a thread could
    between them. Read as a copy, the fields are those built, and the
    refusal passes as the same object, holding no note.
    """
    with pytest.raises(FetchError) as built:
        _rpc_refusal()
    live = vars(built.value)
    assert len(live) > 1
    reads: list[str] = []

    def read_type(value: object) -> type:
        if builtins.type(value) is str and value in live:
            reads.append(value)
            if len(reads) == 1:
                live["__notes__"] = [HEX]
            else:
                live.pop("__notes__", None)
        return builtins.type(value)

    monkeypatch.setattr(exceptions, "type", read_type, raising=False)
    with pytest.raises(FetchError) as e:
        _through(lambda: _raise(built.value))
    monkeypatch.undo()
    assert reads == list(live)
    assert e.value is built.value
    assert_secret_free(e.value, SPELLINGS)


def test_a_refusal_given_a_field_once_counted_is_refused_by_its_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A thread of the caller's adds a note between the count and the copy.

    The note is added once the count of the refusal's own `dict` is read,
    which `len` reads there: the copy holds the note, and is counted again.
    """
    with pytest.raises(FetchError) as built:
        _rpc_refusal()
    live = vars(built.value)
    counted: list[int] = []

    def count(value: Sized) -> int:
        size = builtins.len(value)
        if value is live and not counted:
            counted.append(size)
            live["__notes__"] = [HEX]
        return size

    monkeypatch.setattr(exceptions, "len", count, raising=False)
    with pytest.raises(FetchError, match=f"^<lambda>: {_RPC_REFUSED}$") as e:
        _through(lambda: _raise(built.value))
    monkeypatch.undo()
    assert counted == [len(live) - 1]
    assert_secret_free(e.value, SPELLINGS)


def test_a_refusal_given_many_fields_is_refused_without_a_copy() -> None:
    """The fields are counted off the refusal's own `dict`, before a copy.

    A copy of every field the caller's code added would cost the guard
    their size in memory at each call. PyPy has no `tracemalloc`.
    """
    tracemalloc = pytest.importorskip("tracemalloc")
    with pytest.raises(HttpError) as built:
        _package_refusal()
    fields = vars(built.value)
    fields |= dict.fromkeys(f"field{i}" for i in range(10**5))
    tracemalloc.start()
    try:
        with pytest.raises(
            FetchError, match="^<lambda>: the server answered HTTP 503$"
        ) as e:
            _through(lambda: _raise(built.value))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < sys.getsizeof(fields) // 10
    assert_secret_free(e.value, SPELLINGS)


class _RaisingClient(bitcoin_core_rpc.BitcoinCoreRestClient):
    """A client of the caller's that raises one refusal it holds, every call."""

    def __init__(self, held: FetchError) -> None:
        super().__init__("http://example.invalid")
        self.held = held

    @override
    def get_json(self, *args: Any, **kwargs: Any) -> Any:
        """Raise the refusal held."""
        self.held.__traceback__ = None
        raise self.held


def test_a_refusal_a_thread_changes_while_it_is_read_is_still_answered() -> None:
    """A thread of the caller's adds and takes away a note, on and on.

    The fields change while they are read, and every call still answers
    the `RpcError`.
    """
    with pytest.raises(RpcError) as built:
        _rpc_refusal()
    fields = vars(built.value)
    stop = threading.Event()

    def change() -> None:
        while not stop.is_set():
            fields["__notes__"] = [HEX]
            fields.pop("__notes__", None)

    fetcher = BitcoinCoreRestFetcher(_RaisingClient(built.value), verify_network=False)
    answered: set[type[BaseException]] = set()
    interval = sys.getswitchinterval()
    changing = threading.Thread(target=change)
    sys.setswitchinterval(1e-6)
    changing.start()
    try:
        for _ in range(300):
            with pytest.raises(BaseException) as e:
                fetcher.get_block_count()
            answered.add(type(e.value))
    finally:
        stop.set()
        changing.join()
        sys.setswitchinterval(interval)
    assert answered == {RpcError}


_ARGS = vars(BaseException)["args"]


def _new_args_at_each_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make each read of a `FetchError`'s args a new tuple, as PyPy does (#994).

    So that CPython runs what PyPy runs, where `args is args` is False for
    args that hold any. The tuple of no args is one object on both.
    """

    def read(error: BaseException) -> tuple[object, ...]:
        return (*_ARGS.__get__(error),)

    monkeypatch.setattr(FetchError, "args", property(read, _ARGS.__set__))


def test_a_package_refusal_passes_where_each_read_of_args_is_new(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Its args are read one by one, not as the tuple it was built with."""
    _new_args_at_each_read(monkeypatch)
    with pytest.raises(HttpError, match="^HTTP 503 from the path asked$") as built:
        _package_refusal()
    assert built.value.args is not built.value.args
    with pytest.raises(HttpError) as e:
        _through(lambda: _raise(built.value))
    assert e.value is built.value
    with pytest.raises(FetchError) as chained:
        _through(_nested)
    first = chained.value.__context__
    assert isinstance(first, FetchError)
    assert first.__context__ is None


def _set_the_same_args(error: FetchError) -> None:
    error.args = (*error.args,)


@pytest.mark.parametrize("new_args", [False, True], ids=["kept", "new"])
def test_a_refusal_given_its_own_args_again_passes_as_it_is(
    monkeypatch: pytest.MonkeyPatch, new_args: bool
) -> None:
    """A new tuple of the same objects quotes nothing of the caller's."""
    if new_args:
        _new_args_at_each_read(monkeypatch)

    def changed() -> None:
        try:
            _package_refusal()
        except FetchError as error:
            _set_the_same_args(error)
            raise

    with pytest.raises(HttpError, match="^HTTP 503 from the path asked$"):
        _through(changed)


def test_a_refusal_given_other_args_is_refused_where_each_read_is_new(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Read one by one, an arg of the caller's still makes it the caller's."""
    _new_args_at_each_read(monkeypatch)

    def changed() -> None:
        try:
            _package_refusal()
        except FetchError as error:
            _set_the_args(error)
            raise

    with pytest.raises(
        HttpError, match="^<lambda>: the server answered HTTP 503$"
    ) as e:
        _through(changed)
    assert_secret_free(e.value, SPELLINGS)


@pytest.mark.parametrize(
    "copied",
    [
        copy.copy,
        copy.deepcopy,
        lambda error: pickle.loads(pickle.dumps(error)),  # noqa: S301 -- bytes just dumped
    ],
    ids=["copy", "deepcopy", "pickle"],
)
def test_a_copy_of_a_package_refusal_is_refused_by_its_class(
    copied: Callable[[FetchError], FetchError],
) -> None:
    """A copy is built by the caller's code, through `copy` or `pickle`."""
    with pytest.raises(HttpError) as built:
        _package_refusal()
    with pytest.raises(
        HttpError, match="^<lambda>: the server answered HTTP 503$"
    ) as e:
        _through(lambda: _raise(copied(built.value)))
    assert e.value.__cause__ is None
    assert e.value.__context__ is None


def test_a_package_refusal_raised_in_a_worker_thread_passes_as_it_is() -> None:
    """`Future.result` raises the same object the worker raised."""
    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(_package_refusal)
        with pytest.raises(HttpError, match="^HTTP 503 from the path asked$") as e:
            _through(future.result)
    assert e.value is future.exception()


class _UnrelatedError(Exception):
    """A class of the caller's, no `FetchError`, whose text holds the key."""

    @override
    def __str__(self) -> str:
        return f"no answer for {HEX}"


class _InterruptOfTheCallers(BaseException):
    """An interrupt of the caller's, which no `except Exception` catches."""


def _build(*args: object) -> FetchError:
    return FetchError(*args)


# `_build`, as a function of a module of the package
_built_in_the_package = FunctionType(
    _build.__code__, {"__name__": "btclib_wallet._test", "FetchError": FetchError}
)


@pytest.mark.parametrize(
    "held",
    [
        (_UnrelatedError(),),
        (_InterruptOfTheCallers(f"no answer for {HEX}"),),
        ("the package's text", _UnrelatedError()),
        ("the package's text", None, _UnrelatedError()),
    ],
    ids=["exception", "base exception", "after a text", "third"],
)
def test_a_refusal_holding_an_exception_is_the_callers_wherever_built(
    held: tuple[object, ...],
) -> None:
    """PyPy builds one in a frame of the package, from the caller's error."""
    built = _built_in_the_package("the package's text")
    with pytest.raises(FetchError) as e:
        _through(lambda: _raise(built))
    assert e.value is built
    holding = _built_in_the_package(*held)
    with pytest.raises(FetchError, match=f"^<lambda>: {_NO_ANSWER}") as e:
        _through(lambda: _raise(holding))
    assert_secret_free(e.value, SPELLINGS)


# the second refusal is raised in the `except` with no `from`: the context
# Python gives it is what the test reads
def _refuse_after(  # sourcery skip: raise-from-previous-error
    first: Callable[[], None], hook: Callable[[BaseException], None]
) -> None:
    try:
        first()
    except FetchError as error:
        hook(error)
        raise FetchError("the second refusal")  # noqa: B904


# `_refuse_after`, as a function of a module of the package
_refused_in_the_package = FunctionType(
    _refuse_after.__code__,
    {"__name__": "btclib_wallet._test", "FetchError": FetchError},
)


def _give_another_class(error: BaseException) -> None:
    error.__class__ = _UnrelatedError


def test_a_refusal_raised_where_the_caller_gave_another_class_chains_none() -> None:
    """Its context is the caller's error, or what PyPy built of it.

    CPython sets the caller's error as the context, and PyPy a new
    `FetchError` holding it, which the exception-arg rule leaves the
    caller's: the guard cuts either.
    """
    first = FetchError("the first refusal")
    with pytest.raises(FetchError, match="^the second refusal$") as e:
        _through(
            lambda: _refused_in_the_package(lambda: _raise(first), _give_another_class)
        )
    assert e.value.__context__ is None
    assert_secret_free(e.value, SPELLINGS)


def test_a_close_of_the_callers_giving_its_error_another_class_quotes_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The close runs inside the fetcher's `except`, which raises again.

    CPython raises the caller's own error, given its class, and PyPy a new
    `FetchError` holding it, which is refused by its class.
    """
    fetcher, peer = build()
    fetcher.get_block_count()

    def fail(*_args: object) -> None:
        raise FetchError("peer unavailable")

    def reclass() -> None:
        handled = sys.exception()
        assert handled is not None
        handled.__class__ = _UnrelatedError

    monkeypatch.setattr(peer, "send", fail)
    monkeypatch.setattr(fetcher, "close", reclass)
    with pytest.raises(Exception) as e:
        fetcher.get_block_count()
    pypy = platform.python_implementation() == "PyPy"
    assert type(e.value) is (FetchError if pypy else _UnrelatedError)
    refused = re.match(
        f"^CompactFilterFetcher.get_block_count: {_NO_ANSWER}", str(e.value)
    )
    assert (refused is not None) is pypy
    assert (e.value.__cause__, e.value.__context__) == (None, None)


# `_refuse_after`, raising the error handled again
def _raise_again(
    first: Callable[[], None], hook: Callable[[BaseException], None]
) -> None:
    try:
        first()
    except FetchError as error:
        hook(error)
        raise


# `_raise_again`, as a function of a module of the package
_raised_again_in_the_package = FunctionType(
    _raise_again.__code__,
    {"__name__": "btclib_wallet._test", "FetchError": FetchError},
)


@pytest.mark.parametrize(
    "refuse, missing",
    [(_package_refusal, "status"), (_rpc_refusal, "code")],
    ids=["http", "rpc"],
)
@pytest.mark.parametrize("bare", [True, False], ids=["bare raise", "new refusal"])
def test_a_refusal_given_another_class_where_handled_is_a_type_error_on_pypy(
    refuse: Callable[[], None], missing: str, bare: bool
) -> None:
    """The caller's code gives an `HttpError` or `RpcError` another class.

    It does so in the package's `except` handling it. PyPy cannot build
    the class handled from the error alone, and raises a `TypeError` in
    place of what the `except` raises, its text naming the arg missing.
    After a bare `raise`, that `TypeError` takes the error handled as its
    context, and PyPy leaves that error as `sys.exception()` once the call
    is over, so the call is made in a thread of its own. CPython raises
    what the `except` raises: the caller's error as it is, or the package's
    new refusal.
    """
    handled: list[BaseException] = []

    def hook(error: BaseException) -> None:
        handled.append(error)
        _give_another_class(error)

    package_frame = _raised_again_in_the_package if bare else _refused_in_the_package

    def ask() -> tuple[BaseException, BaseException | None]:
        with pytest.raises(Exception) as e:
            _through(lambda: package_frame(refuse, hook))
        return e.value, sys.exception()

    with ThreadPoolExecutor(1) as pool:
        error, left = pool.submit(ask).result()
    pypy = platform.python_implementation() == "PyPy"
    raised = "TypeError" if bare else "FetchError"
    type_error = (
        f"couldn't record exception context for exception '{raised}', got: "
        rf"TypeError\(\"\w+\.__init__\(\) missing 1 required positional "
        rf"argument: '{missing}'\"\)"
    )
    expected = _UnrelatedError if bare else FetchError
    assert type(error) is (TypeError if pypy else expected)
    text = re.escape(f"no answer for {HEX}") if bare else "the second refusal"
    assert re.fullmatch(type_error if pypy else text, str(error))
    assert (error is handled[0]) is (bare and not pypy)
    assert error.__cause__ is None
    kept = handled[0] if bare and pypy else None
    assert error.__context__ is kept
    assert left is kept
    if pypy or not bare:
        # a context, checked above, is the caller's own error
        error.__context__ = None
        assert_secret_free(error, SPELLINGS)


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


class _Status(IntEnum):
    """Exit codes of the caller's, one of which `sys.exit` reads as success."""

    OK = 0
    FAILED = 1

    @override
    def __eq__(self, other: object) -> bool:
        """Raise, as a method of the caller's can."""
        raise FetchError(  # pragma: no cover -- int's own __eq__ is called
            f"no comparison for {HEX}"
        )

    __hash__ = IntEnum.__hash__


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
        (SystemExit(False), SystemExit, False),
        (SystemExit(_Status.OK), SystemExit, False),
        (SystemExit(_Status.FAILED), SystemExit, True),
        (SystemExit(), SystemExit, False),
        (_Cancelled(HEX), BaseException, None),
    ],
    ids=[
        "interrupt",
        "exit",
        "exit 2",
        "exit text",
        "exit 0",
        "exit false",
        "exit enum 0",
        "exit enum 1",
        "exit none",
        "other",
    ],
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
