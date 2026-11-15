# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The public exception classes this package raises and btclib does not.

Each derives from btclib's class of its kind, so `except BTClibException`
catches these as it catches btclib's own, and `except ValueError` or
`except RuntimeError` catches them too.

The classes carrying a field hand every constructor argument to
`BaseException.__init__` and compose the message in `__str__`. That is
what keeps them picklable, for the reason `btclib.exceptions`' own
docstring gives.
"""

from __future__ import annotations

import functools
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from types import FrameType, FunctionType, TracebackType
from typing import Any, Literal, ParamSpec, TypeVar, cast
from weakref import ref

from btclib.exceptions import BTClibRuntimeError, BTClibValueError
from typing_extensions import override

from btclib_wallet._refusal import _code

__all__ = [
    "FetchError",
    "HttpError",
    "InconclusiveError",
    "NoDescriptorError",
    "RpcError",
    "SignerError",
    "SignerNotFoundError",
]


class FetchError(BTClibRuntimeError):
    """A backend did not answer, or did not answer this.

    A RuntimeError and not a ValueError, which is the distinction worth
    keeping: nothing the caller passed is wrong. The node is down, the
    credentials are stale, the explorer sent html, the transaction is not
    in the index -- retrying later can work, and correcting the argument
    cannot.

    It covers the conversion of an answer too. A backend that replies with
    something which is not a transaction has failed, and reporting that as
    the BTClibValueError `Tx.parse` raised would name the parser rather
    than the host that has to be fixed.

    Declared here rather than taken from `bitcoin_core_rpc`, which raises
    a class of the same name: that package declares zero dependencies and
    imports nothing of btclib's, so its `FetchError` derives from a
    `BTClibRuntimeError` of its own, and an `except BTClibRuntimeError`
    written against btclib would not catch it.
    `btclib_wallet.fetch.fetcher.client_errors` is the one place the two meet.

    One built by a module of this package is told apart from one the
    caller's code built, and `_caller_errors` says what becomes of each.
    """

    def __init__(self, *args: object) -> None:
        # what `BaseException.__init__` does: the census of
        # `tests/refusal_census_test.py` reads a `super().__init__` as any
        # `__init__` of the package, some of which raise
        self.args = args
        if _built_by_the_package():
            # named first: the census reads a call in the subscript of an
            # assignment as a binding of the name called
            key = id(self)
            fields = tuple(vars(self).items())
            _BUILT[key] = (ref(self, _forgotten(key)), type(self), args, fields)


class HttpError(FetchError):
    """A backend failed at the HTTP layer, and `status` is what it said.

    A field because acting on a status is the caller's job and this
    package retries nothing: a 401 says the credentials are wrong and will
    stay wrong until they are changed, while a 503 from bitcoind says its
    rpc work queue is full and the same request works when the queue
    drains. A caller writing that policy needs to recognise the status,
    and matching on the text of a message is what a field spares them.

    Not every FetchError carries one, and that is the distinction: a
    refused connection and an expired timeout are failures of an exchange
    that never produced a status, and stay a plain FetchError. A status
    that is no integer, or does not fit in 16 signed bits, is 0.

    A FetchError still, so code catching that keeps catching this.
    """

    def __init__(self, message: str, status: int) -> None:
        self.status = status
        super().__init__(message, status)

    @override
    def __str__(self) -> str:
        # the message alone, which is what BaseException returns for a
        # single argument and not for the two this carries
        return str(self.args[0])


class RpcError(FetchError):
    """A backend answered with a JSON-RPC error object, and this is it.

    `code` is the backend's number where it is an integer that fits in 16
    signed bits, and 0 otherwise: JSON bounds no integer, so a code can
    hold the scalar of a key. From bitcoind, `src/rpc/protocol.h`
    (bitcoin/bitcoin@f0de87f040): -5 is RPC_INVALID_ADDRESS_OR_KEY, which
    is what `getrawtransaction` returns for a transaction it cannot find
    -- including every non-wallet transaction on a node running without
    `-txindex`. From an Electrum server (`btclib_wallet.electrum`), the
    field carries that server's own JSON-RPC 2.0 code instead, nothing
    here asking anything bitcoind-specific of it. A caller that means to
    tell "no such transaction" from "the backend is unreachable" needs the
    number, and parsing it back out of the message is what having a field
    avoids.

    The message names the method where the error is read with one:
    `BitcoinCoreFetcher` names it for each client call it wraps, and
    `btclib_wallet.electrum`'s codec for each error it decodes. A
    `bitcoin_core_rpc.RpcError` that a transport or a client of the
    caller's own raises under another fetcher is wrapped without a
    method, so that refusal names none. `data`, JSON-RPC's optional
    third member of an error object, is None. The backend's own text and
    `data` are dropped, since they can quote the request:
    `btclib_wallet.electrum`'s `_raise_rpc_error` says why.

    A FetchError still, so code catching that keeps catching this.
    """

    def __init__(self, message: str, code: int, data: Any = None) -> None:
        self.code = code
        self.data = data
        super().__init__(message, code, data)

    @override
    def __str__(self) -> str:
        return f"{self.args[0]} (rpc error code {self.code})"


class SignerError(BTClibRuntimeError):
    """An external signer failed, and `code` is the number it gave.

    What `btclib_wallet.psbt_signer`'s contract fails with, and what
    `btclib_wallet.hwi` raises around HWI's structured errors: the JSON CLI
    answers `{"error": <msg>, "code": <n>}`, and the number is the part a
    caller acts on. -14 is ACTION_CANCELED, which is somebody pressing the
    button that says no and is not worth a retry; -3 is DEVICE_CONN_ERROR,
    which is a cable and is worth one; -9 is UNAVAILABLE_ACTION, which
    says this model will never do it. Matching on the text of a message is
    what a field spares a caller writing that policy.

    A RuntimeError for the reason `FetchError` is one: nothing the caller
    passed is wrong. The device is unplugged, locked, busy, or its owner
    said no -- retrying can work, and correcting an argument cannot. The
    numbers HWI reserves for a bad argument (-2, -7) arrive here too, that
    being the one thing the code says and the class cannot.

    `code` is None where the failure produced no number: a backend that
    could not be started, an answer that was not JSON, an output past the
    limit. Those are failures of the exchange rather than of the device.
    """

    def __init__(self, message: str, code: int | None = None) -> None:
        self.code = code
        super().__init__(message, code)

    @override
    def __str__(self) -> str:
        if self.code is None:
            return str(self.args[0])
        return f"{self.args[0]} (signer error code {self.code})"


class SignerNotFoundError(SignerError):
    """The backend an adapter runs is not installed.

    A `SignerError` still, so a caller catching that keeps catching this,
    and separate because it is the one failure that is not about a
    device: nothing is unplugged, locked or busy, and no retry will
    change it. A caller that offers signers of several kinds tells "there
    is no hardware here" from "the hardware could not be reached" on this
    class, and the two are not the same thing to report before a signing
    operation.

    Without it the distinction is not recoverable. `btclib_wallet.hwi` turns
    every `OSError` into a `SignerError` -- a missing executable and a
    permission the udev rules do not grant arrive as one class with one
    `code` of None -- so a caller had to either match on the text of a
    message or look for the executable itself, and looking for it is
    asking a second question that can disagree with the first.

    `code` is None, as for every failure of the exchange rather than of a
    device.
    """


class InconclusiveError(BTClibValueError):
    """Not invalid, and not something today's rules can call valid.

    BIP322 answers a signature with one of three states rather than two,
    and this is the third: a `to_sign` whose version is neither 0 nor 2,
    an upgradeable NOP, a witness program of an unknown version. Each of
    them satisfies the script as it runs today, and each is what a soft
    fork can give a meaning to, so a validator saying "valid" would be
    speaking for rules it does not have.

    The text of a proof of funds over the bound of `btclib_wallet.bip322`
    is one too, as the comment on its `_MAX_PAYLOAD_SIZES` says.

    A BTClibValueError, so code catching that keeps catching this, and
    so that `btclib_wallet.bip322.verify` answers False without a second
    `except`: an inconclusive signature is not one that verified. A
    caller that means to tell the two apart names this class.
    """


class NoDescriptorError(BTClibValueError):
    """No output descriptor states this script: it is not that a lift failed.

    What `btclib_wallet.wallet.ScriptWallet.descriptor` refuses with, and
    the one refusal there that is a fact about the wallet rather than about
    the code asking: a script spelling its timelock `<n> OP_CSV OP_DROP`, or
    ordering a quorum after derivation inside a combinator, is a script
    BIP380 to BIP390 cannot write down -- and will still be one at the
    next release. A caller catching this has an answer ("watch these
    addresses instead"), where a caller catching a parse failure has a
    bug report.

    A BTClibValueError, so code catching that keeps catching this: the
    refusal it most often stands in front of is
    `btclib_wallet.descriptors.miniscript.from_script`'s, which is one.
    """


_P = ParamSpec("_P")
_R = TypeVar("_R")
_C = TypeVar("_C", bound=type)

# each `FetchError` a module of this package built, by its id: a weak
# reference to it, and its class, args and attributes as it was built
_BUILT: dict[
    int,
    tuple[ref[FetchError], type[FetchError], tuple[object, ...], tuple[Any, ...]],
] = {}


def _forgotten(key: int) -> Callable[[ref[FetchError]], None]:
    """Return what drops the entry of `_BUILT` at `key` once it is gone."""

    def forget(_reference: ref[FetchError]) -> None:
        # called as the error is freed, before its id can name another
        _BUILT.pop(key, None)

    return forget


def _as_built(error: FetchError) -> bool:
    """Return whether this package built `error`, and nothing changed it since.

    Its class, its args and its attributes are those it was built with, read
    by identity: code of the caller's that reassigns its args or its
    `__class__`, sets an attribute or adds a note, which is an attribute,
    makes it the caller's. The class is read first, so that what is read
    after is read off a class of this package.
    """
    entry = _BUILT.get(id(error))
    if entry is None or entry[0]() is not error or type(error) is not entry[1]:
        return False
    fields = vars(error)
    return (
        error.args is entry[2]
        and len(fields) == len(entry[3])
        and all(fields.get(name, fields) is value for name, value in entry[3])
    )


def _cut_at_the_callers(error: FetchError) -> None:
    """Cut the chain of `error` at each link this package did not build.

    A link is the `__cause__` or the `__context__` of an exception of the
    chain. One that is no `FetchError` `_as_built` is dropped, and the
    chain goes on through each one that is. Python sets a `__context__`
    where an exception is raised inside an `except`, which may be a
    handler of the caller's code that this package's code runs inside. No
    refusal of this package is chained on purpose: each is raised outside
    the `except` that caught what it refuses. `__suppress_context__` keeps
    the value it had, which setting `__cause__` changes.
    """
    seen: set[int] = set()
    todo = [error]
    while todo:
        link = todo.pop()
        if id(link) in seen:
            continue
        seen.add(id(link))
        hidden = link.__suppress_context__
        for name in ("__cause__", "__context__"):
            linked = getattr(link, name)
            if linked is None:
                continue
            if issubclass(type(linked), FetchError) and _as_built(linked):
                todo.append(linked)
            else:
                setattr(link, name, None)
        link.__suppress_context__ = hidden


def _built_by_the_package() -> bool:
    """Return whether this package builds the `FetchError` being built.

    The builder is the module of the first frame past `FetchError.__init__`
    that is no `__init__` of this module. A subclass the caller defines is
    then the caller's, and so is a class of this module that the caller's
    code builds.
    """
    # the frame that called `FetchError.__init__`
    frame: FrameType | None = sys._getframe(2)
    while (
        frame is not None
        and frame.f_code.co_name == "__init__"
        and frame.f_globals.get("__name__") == __name__
    ):
        frame = frame.f_back
    module = "" if frame is None else str(frame.f_globals.get("__name__", ""))
    return module == "btclib_wallet" or module.startswith("btclib_wallet.")


@contextmanager
def _caller_errors(request: str) -> Iterator[None]:
    """Refuse by its class a `FetchError` the caller's code built.

    Wrapped around a call of an object the caller can supply, such as a
    `Fetcher`, a reader, a broadcaster, a client or a transport. A
    `FetchError` a module of this package built, and that nothing changed
    since, as `_as_built` says, passes as the same object: its text is
    composed where the census of `tests/refusal_census_test.py` reads it.
    Its chain is cut first, as `_cut_at_the_callers` says. Any other holds
    what the caller's code gave it, which the census does not read. Its
    text is not relayed, and nothing is chained to the refusal, which
    `_failed` reads: an `RpcError` keeps its code and an `HttpError` its
    status, as `_code` bounds them, and any other names its class. An
    `ExceptionGroup` is refused as `_GROUPS` says, and any other exception
    passes as it is. `request` names the call, empty for none.
    """
    head = f"{request}: " if request else ""
    kind = failure = ""
    code = 0
    try:
        with _GROUPS:
            yield
    except FetchError as e:
        if _as_built(e):
            _cut_at_the_callers(e)
            raise
        kind, code, failure = _failed(e, RpcError, HttpError)
    else:
        return
    refusal: FetchError
    match kind:
        case "rpc":
            refusal = RpcError(f"{head}the server answered an rpc error", code)
        case "http":
            refusal = HttpError(f"{head}the server answered HTTP {code}", code)
        case _:
            refusal = FetchError(f"{head}no usable answer from the server: {failure}")
    try:
        raise refusal
    finally:
        # raised inside the `with` statement's handling of what its block
        # raised, which Python sets as the refusal's `__context__`
        refusal.__context__ = None


class _CallersGroups:
    """Refuse by its class an `ExceptionGroup` holding a `FetchError`.

    This package raises no group, so each is the caller's code's, and
    `except* FetchError` would hand the caller a `FetchError` it holds,
    which `_holds_a_fetch_error` looks for. Any other group passes as it
    is, as any exception that is no `FetchError` does. A context manager
    and not an `except`: one lets an exception through by returning
    False, where an `except` would have to raise it again. The refusal is
    a `FetchError` that `_caller_errors` passes, without its `request`.
    """

    def __enter__(self) -> None:
        """Enter the block, holding nothing."""

    def __exit__(
        self,
        _kind: type[BaseException] | None,
        error: BaseException | None,
        _traceback: TracebackType | None,
    ) -> Literal[False]:
        """Return False for what passes, and raise the refusal of the rest.

        What `error` is, is read off its type and not off its `__class__`.
        """
        if not issubclass(type(error), ExceptionGroup):
            return False
        if not _holds_a_fetch_error(cast("ExceptionGroup[Exception]", error)):
            return False
        refusal = FetchError(f"no usable answer from the server: {_class_name(error)}")
        try:
            raise refusal
        finally:
            # raised while the `with` statement handles the group, which
            # Python sets as the refusal's `__context__`
            refusal.__context__ = None


_GROUPS = _CallersGroups()


# the descriptor answering `exceptions`, which a subclass can override
_MEMBERS = vars(BaseExceptionGroup)["exceptions"]


def _holds_a_fetch_error(group: ExceptionGroup[Exception]) -> bool:
    """Return whether a `FetchError` is among the leaves of `group`.

    Each group is read through `BaseExceptionGroup`'s own `exceptions`,
    and each member by its type: a subclass of the caller's can answer
    `exceptions`, `__class__` or `derive`, which `split` and `subgroup`
    call, otherwise.
    """
    todo: list[BaseExceptionGroup[BaseException]] = [group]
    seen: set[int] = set()
    while todo:
        each = todo.pop()
        if id(each) in seen:
            continue
        seen.add(id(each))
        for member in _MEMBERS.__get__(each, BaseExceptionGroup):
            if issubclass(type(member), FetchError):
                return True
            if issubclass(type(member), BaseExceptionGroup):
                todo.append(member)
    return False


def _class_name(value: object) -> str:
    """Return the name of the class of `value`, read off its type.

    Not off its `__class__`, which a class can answer with another. A
    name a metaclass of the caller's answers is read as a name only where
    it is a `str` and no subclass of one, which could run code where it is
    formatted. Any other is "an unnamed class", and so is one whose read
    raises.
    """
    name: object = "an unnamed class"
    with suppress(Exception):
        name = type(value).__name__
    return name if type(name) is str else "an unnamed class"


def _failed(
    error: BaseException,
    rpc_error: type[BaseException],
    http_error: type[BaseException],
) -> tuple[str, int, str]:
    """Return the kind of refusal answering `error`, its code and its class.

    The kind is read off the type of `error`, and not off its `__class__`:
    "rpc" for an `rpc_error`, with what `_code` answers for its `code`;
    "http" for an `http_error`, with that of its `status`; and "fetch",
    with 0, for any other. A field of the caller's class can run its
    code, as a property does: where reading one raises, the kind is
    "fetch", and nothing that read raised is chained to a refusal.
    """
    kind = type(error)
    name = _class_name(error)
    with suppress(Exception):
        for refused, cls, field in (
            ("rpc", rpc_error, "code"),
            ("http", http_error, "status"),
        ):
            if issubclass(kind, cls):
                # read with no default: a field missing is a read that raises
                return refused, _code(getattr(error, field)), name
    return "fetch", 0, name


def _guarded(function: Callable[_P, _R]) -> Callable[_P, _R]:
    """Return `function`, run inside `_caller_errors`.

    For a public function or method of this package that reaches what the
    caller supplies, or a method of the caller's own subclass: whatever
    that runs, a `FetchError` the caller's code built leaves the call as
    `_caller_errors` refuses it. The call is named by the qualified name
    of `function`.
    """
    request = function.__qualname__

    @functools.wraps(function)
    def guarded(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        with _caller_errors(request):
            return function(*args, **kwargs)

    return guarded


def _guarded_methods(cls: _C) -> _C:
    """Return `cls`, each public method and property of its own `_guarded`.

    Public includes the dunder methods, such as `__init__`, `__enter__`
    and `__exit__`, and the classmethods and staticmethods. An abstract
    method is left as it is: the caller's subclass gives its body.
    `tests/caller_errors_test.py` checks which classes take this.
    """
    for name, member in list(vars(cls).items()):
        if name.startswith("_") and not name.endswith("__"):
            continue
        guarded: object
        if isinstance(member, property):
            fget, fset, fdel = (
                None if f is None else _guarded(f)
                for f in (member.fget, member.fset, member.fdel)
            )
            guarded = property(fget, fset, fdel, member.__doc__)
        elif isinstance(member, (classmethod, staticmethod)):
            guarded = type(member)(_guarded(member.__func__))
        elif isinstance(member, FunctionType) and not getattr(
            member, "__isabstractmethod__", False
        ):
            guarded = _guarded(member)
        else:
            continue
        setattr(cls, name, guarded)
    return cls
