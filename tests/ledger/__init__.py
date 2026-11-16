# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Non-regression tests for btclib_wallet.ledger."""

from typing_extensions import override


class Conforming(int):
    """An int whose own methods answer other values than the int it holds.

    `__conform__` is what `sqlite3` binds in its place, and each copy
    that calls one of its methods, `|`, `+` or `*` included, gets another
    number.
    """

    def __conform__(self, _protocol: object) -> str:
        return "conformed"

    @override
    def __int__(self) -> int:
        return 99

    @override
    def __index__(self) -> int:
        return 98

    @override
    def __str__(self) -> str:
        return "97"

    @override
    def __or__(self, _other: int) -> int:
        return 99

    @override
    def __ror__(self, _other: int) -> int:
        return 99

    @override
    def __add__(self, _other: int) -> int:
        return 99

    @override
    def __radd__(self, _other: int) -> int:
        return 99

    @override
    def __mul__(self, _other: int) -> int:
        return 99

    @override
    def __rmul__(self, _other: int) -> int:
        return 99


class ConformingStr(str):
    """A str whose own methods answer other values than the str it holds.

    `__conform__` is what `sqlite3` binds in its place, and each copy
    that calls one of its methods, `+`, `*`, a slice or `len` included,
    gets another text.
    """

    __slots__ = ()

    def __conform__(self, _protocol: object) -> str:
        return "conformed"

    @override
    def __str__(self) -> str:
        return "str"

    @override
    def __add__(self, _other: str) -> str:
        return "wrong"

    def __radd__(self, _other: str) -> str:
        return "wrong"

    @override
    def __getitem__(self, _key: object) -> str:
        return "wrong"

    @override
    def __len__(self) -> int:
        return 0

    @override
    def __mul__(self, _other: object) -> str:
        return "wrong"

    @override
    def __rmul__(self, _other: object) -> str:
        return "wrong"


class ConformingBytes(bytes):
    """Bytes whose own methods answer other values than the bytes they hold.

    `__conform__` is what `sqlite3` binds in their place, and each copy
    that calls one of their methods, `+`, `*`, a slice, `len` or the
    buffer protocol included, gets other bytes.
    """

    def __conform__(self, _protocol: object) -> bytes:
        return b"conformed"

    @override
    def __bytes__(self) -> bytes:
        return b"bytes"

    @override
    def hex(self, *_args: object) -> str:
        return "beef"

    @override
    def __buffer__(self, _flags: int, /) -> memoryview:
        return memoryview(b"buffer")

    @override
    def __add__(self, _other: object) -> bytes:
        return b"wrong"

    def __radd__(self, _other: object) -> bytes:
        return b"wrong"

    @override
    def __getitem__(self, _key: object) -> bytes:  # type: ignore[override]
        return b"wrong"

    @override
    def __len__(self) -> int:
        return 0

    @override
    def __mul__(self, _other: object) -> bytes:
        return b"wrong"

    @override
    def __rmul__(self, _other: object) -> bytes:
        return b"wrong"


class Twin(int):
    """An int equal to nothing but itself, hashed as an object is."""

    __hash__ = object.__hash__

    @override
    def __eq__(self, other: object) -> bool:
        return self is other


class Alias(int):
    """An int that hashes and compares as 0, whatever int it holds."""

    @override
    def __hash__(self) -> int:
        return hash(0)

    @override
    def __eq__(self, other: object) -> bool:
        return other == 0


class Below(int):
    """An int that says it is below any other."""

    @override
    def __lt__(self, _other: int) -> bool:
        return True


class NotBelow(int):
    """An int that says it is below no other."""

    @override
    def __lt__(self, _other: int) -> bool:
        return False


class TwinStr(str):
    """A str equal to nothing but itself, hashed as an object is."""

    __slots__ = ()
    __hash__ = object.__hash__

    @override
    def __eq__(self, other: object) -> bool:
        return self is other


class Star(str):
    """A str that compares equal to "*", whatever str it holds."""

    __slots__ = ()
    __hash__ = str.__hash__

    @override
    def __eq__(self, other: object) -> bool:
        return other == "*" or str.__eq__(self, other)
