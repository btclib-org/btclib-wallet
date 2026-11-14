# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""How a refusal shows the value it refuses.

Section 7 of the btclib-org standard, *A refusal carries no secret*, says
an argument in the wrong place may be a key. A refusal describes such a
value with `_message_text`, and quotes a value refused where a name
belongs only up to `_QUOTED_MAX` characters, too short for a key.
"""

from collections.abc import Collection

__all__: list[str] = []

_QUOTED_MAX = 16

# A signed 16-bit integer: JSON-RPC 2.0's reserved codes, -32768 to -32000,
# Bitcoin Core's, and the codes electrs, ElectrumX, Fulcrum and Floresta
# assign lie in it, and it is too narrow to carry a key
_RPC_CODES = range(-(2**15), 2**15)


def _exact_int(value: int) -> int:
    """Return the value of an int or int subclass as an int.

    `int.__or__` with 0 reads the value's digits and none of its
    methods, on CPython and on PyPy alike. `int()` calls the value's own
    `__int__`, and on PyPy so do `int.__index__` and, for some values,
    `int.__abs__`.
    """
    return int.__or__(value, 0)


def _code(value: object) -> int:
    """Return an error code a refusal may carry, 0 where it cannot carry it.

    The value of an int that lies in `_RPC_CODES`, a bool excepted, and 0
    for anything else: a code another program answers is bounded by no
    format, so it can hold the scalar of a key.
    """
    kind = type(value)
    if issubclass(kind, int) and kind is not bool and isinstance(value, int):
        number = _exact_int(value)
        if number in _RPC_CODES:
            return number
    return 0


def _hex_field(value: object) -> str:
    """Return a field a format defines, such as a sig_hash type, in hex.

    Section 7 lets a refusal print a field of at most 4 bytes: an int that
    fits in 32 unsigned bits, a bool excepted, is written as `hex` writes
    it, and anything else as `_quoted` shows it.
    """
    kind = type(value)
    if issubclass(kind, int) and kind is not bool and isinstance(value, int):
        number = _exact_int(value)
        if 0 <= number < 2**32:
            return hex(number)
    return _quoted(value)


def _quoted(value: object) -> str:
    """Return a refused parameter as a refusal may print it.

    An int or a str is quoted up to `_QUOTED_MAX` characters, and
    described by its length past them. Anything else is described as
    `_message_text` describes it.
    """
    # issubclass on the type decides. isinstance asks a value of another
    # type for its `__class__`, which can claim bool, int or str, or raise,
    # so it runs only where the type already decided, to narrow it for
    # mypy. An exact int or str copied from the value is what is then
    # measured and written: a subclass can override the comparison, the
    # length and the formatting
    kind = type(value)
    if kind is bool:
        # bool's own repr, True or False, where int's writes a digit
        return repr(value)
    if issubclass(kind, int) and isinstance(value, int):
        number = _exact_int(value)
        # an int past the interpreter's digit limit has no str
        if not -(10**_QUOTED_MAX) < number < 10**_QUOTED_MAX:
            return f"a value of more than {_QUOTED_MAX} digits"
        quoted = repr(number)
        length = len(quoted)
    elif issubclass(kind, str) and isinstance(value, str):
        # concatenation with "" returns an exact str, on CPython and on PyPy,
        # and reads none of the value's methods
        text = str.__add__(value, "")
        quoted = repr(text)
        length = len(text)
    else:
        return _message_text(value)
    return f"a value of {length} characters" if length > _QUOTED_MAX else quoted


def _label(value: object, known: Collection[str]) -> str:
    """Return a label a refusal names an item by, as a refusal may print it.

    Section 7 says which item failed by where it is: the map, the field,
    the key type. A helper taking that label as a parameter prints it
    where it is one of `known`, the package's own labels, which hold no
    byte of a caller's value; anything else is shown as `_quoted` shows
    it. The label printed is the element of `known`, not the value.
    """
    kind = type(value)
    if issubclass(kind, str) and isinstance(value, str):
        text = str.__add__(value, "")
        for label in known:
            if label == text:
                return label
    return _quoted(value)


def _message_text(value: object) -> str:
    """Return the description of a value for a refusal's message, never raising.

    No value is written out: an argument in the wrong place may be a key,
    in an int, a str of its hex, a Decimal or a float of its digits, or
    its bytes. Section 7 lets a refusal print a value's type name and
    length, and not its digits or characters.

    An int, a bool excepted, is described by its sign and bit length.
    Anything else, a bool included, is described by its type name, and
    by its length where `len()` gives one: "a str of length 64", "an
    object". The article is "an" before a name whose first letter, past
    any underscore, is a vowel. This is what btclib's own `_message_text`
    writes, copied since this package imports only btclib's public names.

    Neither reads the value's `str()`. That of an int past
    `sys.get_int_max_str_digits()` digits raises ValueError, which would
    leave through the refusal the description is for.
    """
    kind = type(value)
    if issubclass(kind, int) and kind is not bool and isinstance(value, int):
        # the type as `_quoted` reads it, and the value as `_exact_int`
        # returns it: a subclass can override the comparison and bit_length
        number = _exact_int(value)
        sign = "a negative" if number < 0 else "an"
        return f"{sign} int of {number.bit_length()} bits"
    name = type(value).__name__
    article = "an" if name.lstrip("_")[:1].lower() in tuple("aeiou") else "a"
    description = f"{article} {name}"
    # every Exception and not only TypeError: a `__len__` of the caller's
    # own can raise anything, and no failure to describe a value may
    # replace the refusal the description is for
    try:
        return f"{description} of length {len(value)}"  # type: ignore[arg-type]
    except Exception:  # noqa: BLE001
        return description
