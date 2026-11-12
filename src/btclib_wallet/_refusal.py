# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""How a refusal shows the value it refuses.

Section 7 of the btclib-org standard, *A refusal carries no secret*, says
an argument in the wrong place may be a key. A refusal describes such a
value with `_message_text`, and quotes a value refused where a name
belongs only up to `_QUOTED_MAX` characters, too short for a key.
"""

__all__: list[str] = []

_QUOTED_MAX = 16


def _quoted(value: int | str) -> str:
    """Return a refused parameter as a refusal may print it.

    It is quoted up to `_QUOTED_MAX` characters, and described by its
    length past them.
    """
    # an int past the interpreter's digit limit has no str
    if isinstance(value, int) and not -(10**_QUOTED_MAX) < value < 10**_QUOTED_MAX:
        return f"a value of more than {_QUOTED_MAX} digits"
    text = str(value)
    if len(text) > _QUOTED_MAX:
        return f"a value of {len(text)} characters"
    return repr(value)


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
    if isinstance(value, int) and not isinstance(value, bool):
        # int's own methods, not the value's: a subclass can override the
        # comparison and bit_length
        sign = "a negative" if int.__lt__(value, 0) else "an"
        return f"{sign} int of {int.bit_length(value)} bits"
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
