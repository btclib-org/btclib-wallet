# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""How a refusal shows a refused name or short parameter.

Section 7 of the btclib-org standard, *A refusal carries no secret*, lets
a refusal quote a value refused where a name belongs only up to
`_QUOTED_MAX` characters, too short for a key.
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
