# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BIP32 derivation path and key origin.

`DerPath` names the representations a derivation path is accepted in.

Three hardening symbols are read and two are written, which is not an
oversight: BIP32 spells its own test vectors "m/0H/1/2H", while BIP380
lists "[deadbeef/0H/0H/0H]" among its invalid hardened indicators, beside
"0f" and "-0". So a path is read leniently, and `bip380_enforced` is the
stricter reading a descriptor needs -- the two symbols it allows, and no
leading m, empty step or whitespace. Both readings spell a step's number
in ASCII decimal digits alone, which is what Bitcoin Core reads.
"""

from __future__ import annotations

import re
import string
from collections.abc import Iterable, Sequence

from btclib.alias import Octets
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import assert_type, is_integer

__all__ = [
    "DerPath",
    "bytes_from_der_path",
    "hardenings_from_der_path",
    "indexes_from_der_path",
    "int_from_index_str",
    "str_from_der_path",
    "str_from_index_int",
]

# the symbols a hardened step is read with, and the two of them BIP380
# allows. Writing takes the second list: an uppercase H is a path Bitcoin
# Core's own parsers refuse, both the descriptor one -- `last == '\'' ||
# last == 'h'` -- and `ParseHDKeypath`, which takes the apostrophe alone
_HARDENINGS = ("'", "h", "H")
_BIP380_HARDENINGS = ("'", "h")

# the symbol written where the caller names none, and the one Core's
# FormatHDKeypath writes when it is not echoing an apostrophe it read
_HARDENING = "h"

# a step's number, in either reading: ASCII decimal digits and nothing else,
# which is the `[0-9]+` Bitcoin Core's ParseKeyPathElement reads through
# ToIntegral. `int` alone would also take "+1", "-0", "1_0", the digits of
# every other script and the Unicode whitespace around them (issue #107)
_INDEX = re.compile(r"[0-9]+")

# the most digits, leading zeros apart, that a number read from text may
# have: 2**32 has ten. `int()` refuses more than 4300 digits with a built-in
# `ValueError`, and a caller catching this library's errors would miss it
_MAX_DIGITS = 10


def _int_from_digits(digits: str, what: str) -> int:
    """Return the number that ASCII `digits` spell, refusing a long one.

    Leading zeros are not counted, since they change no value. `digits`
    is already known to be one or more of `0` to `9`.
    """
    significant = digits.lstrip("0")
    if len(significant) > _MAX_DIGITS:
        raise BTClibValueError(f"invalid {what}: more than {_MAX_DIGITS} digits")
    return int(significant or "0")


# the offset a hardened index carries: BIP32 splits the 2**32 indexes in
# half at 2**31, so an index is hardened when it reaches this value, and
# what a path spells before the hardening symbol is what is left under it.
# The symbol and the offset are one fact in its two spellings, which is
# why they sit together -- and why bip32, mnemonic.electrum and bip44
# import this rather than write the literal again: a hardened test is the
# same test wherever it appears, and a literal repeated is a set of places
# to read before believing they agree
_HARDENED_OFFSET = 0x80000000


def _index_and_hardening_from_str(s: str, *, bip380_enforced: bool) -> tuple[int, str]:
    """Return a step's index and the hardening symbol it was spelled with.

    The symbol comes back rather than a bool because it is what writing
    the step again takes: BIP380 gives "h" and "'" one meaning and two
    spellings, and a descriptor is the string, so which one was read is
    the difference between handing back the descriptor and handing back
    a different one with the same meaning and another checksum.
    """
    symbols = _BIP380_HARDENINGS if bip380_enforced else _HARDENINGS
    if not bip380_enforced:
        # ASCII whitespace alone, around the step and before its symbol
        s = s.strip(string.whitespace)
    hardening = s[-1] if s and s[-1] in symbols else ""
    number = s[:-1] if hardening else s
    if not bip380_enforced:
        number = number.rstrip(string.whitespace)
    # neither refusal quotes the step: it is caller text, and a key written
    # after a path with no separator between them is read as its last step
    if not _INDEX.fullmatch(number):
        raise BTClibValueError("invalid derivation index: not ASCII decimal digits")
    index = _int_from_digits(number, "derivation index")
    if index >= _HARDENED_OFFSET:
        raise BTClibValueError("invalid index: not below 2**31")
    return index + (_HARDENED_OFFSET if hardening else 0), hardening


def _assert_valid_index(i: int) -> None:
    """Refuse anything one step of a BIP32 path cannot be.

    A step is one of the 2**32 indexes, hardened or not. What makes the
    check worth its own name is that the two places needing it fail
    differently without it: writing a path out reaches
    `int.to_bytes(4, signed=False)` and an out-of-range index surfaces
    there as `OverflowError`, which is an `ArithmeticError` and so
    outside every `except ValueError` written against this library,
    while `indexes_from_der_path` hands its list straight back and
    answers `[-5]` for `[-5]` -- no error at all.

    A bool is no index either: `True` is not the first child of
    anything, and `str(True)` is "True" where a path step wants "1".
    """
    if not is_integer(i):
        raise BTClibTypeError(f"invalid derivation index type: {type(i).__name__}")
    if not 0 <= i <= 0xFFFFFFFF:
        raise BTClibValueError(f"invalid index: {i}")


def int_from_index_str(s: str, *, bip380_enforced: bool = False) -> int:
    """Return one path step as its index: "0h" is 0x80000000.

    Any of the three hardening symbols is read, uppercase "H" included,
    which is how BIP32 spells its own vectors, and ASCII whitespace
    around the step and before its symbol is dropped. `bip380_enforced`
    reads the two symbols a descriptor may hold instead, and no
    whitespace; see the module docstring for why the two readings
    differ. The number is ASCII decimal digits in both. An index at or
    above the hardened offset must be spelled with a symbol, not as the
    number.
    """
    assert_type(s, str, "derivation index")
    return _index_and_hardening_from_str(s, bip380_enforced=bip380_enforced)[0]


def str_from_index_int(i: int, hardening: str = _HARDENING) -> str:
    """Return one index as a path step, the chosen symbol for hardened.

    Two symbols, where the reader above takes three: an uppercase "H" is
    a hardened indicator BIP380 lists as invalid and Bitcoin Core's
    parsers refuse, so this writes no path a descriptor cannot hold.
    """
    if hardening not in _BIP380_HARDENINGS:
        raise BTClibValueError(f"invalid hardening symbol: {hardening}")
    _assert_valid_index(i)
    # int() of an int, because a subclass of int may define a str() that
    # is not the number -- its *name*, "Sighash.ALL" where a path step
    # wants "1". Accepting a deliberate integer subclass, which is what
    # `is_integer` is for, means answering with the number it is
    index = int(i)
    if index < _HARDENED_OFFSET:
        return str(index)
    return str(index - _HARDENED_OFFSET) + hardening


def _pairs_from_der_path_str(
    der_path: str, skip_m: bool, *, bip380_enforced: bool
) -> tuple[list[int], list[str]]:
    """Return a path string's indexes, and the symbols it spelled them with.

    The lenient reading strips ASCII whitespace around each step, drops
    an empty step, which is what makes a trailing slash a path of the
    same depth, and skips a leading m. The BIP380 one does none of them:
    its grammar has no whitespace, no m and no empty step, so each is an
    index that does not parse.
    """
    steps = der_path.split("/")
    if not bip380_enforced:
        # ASCII whitespace alone (issue #107)
        steps = [s.strip(string.whitespace) for s in steps]
        if skip_m and steps[0].lower() == "m":
            steps = steps[1:]
        steps = [s for s in steps if s]

    pairs = [
        _index_and_hardening_from_str(s, bip380_enforced=bip380_enforced) for s in steps
    ]

    if len(pairs) > 255:
        err_msg = f"depth greater than 255: {len(pairs)}"
        raise BTClibValueError(err_msg)
    return [index for index, _ in pairs], [hardening for _, hardening in pairs]


def _indexes_from_der_path_str(der_path: str, skip_m: bool) -> list[int]:
    return _pairs_from_der_path_str(der_path, skip_m, bip380_enforced=False)[0]


# the buffer arm is `bytes | bytearray | memoryview`, the same union
# `alias.Octets` spells for every other packed-octets consumer -- not
# `Octets` itself, which also admits `str`, a spelling this alias already
# gives a different meaning (the path string, not packed octets)
#: An "m/44h/0'/1H/0/10" string, a sequence of int indexes (a single int
#: included), or bytes, bytearray or memoryview, each a multiple of a
#: 4-byte index.
DerPath = str | Sequence[int] | int | bytes | bytearray | memoryview


def _pairs_from_der_path(
    der_path: DerPath, *, bip380_enforced: bool
) -> tuple[list[int], list[str]]:
    """Return the indexes of a path, and the symbols it spelled them with.

    Only a string spells anything, so every other DerPath answers with
    an empty symbol per index: "the path did not say", which is what a
    caller writing it out again defaults for.
    """
    if isinstance(der_path, str):
        return _pairs_from_der_path_str(der_path, True, bip380_enforced=bip380_enforced)
    indexes = _indexes_from_der_path(der_path)
    return indexes, [""] * len(indexes)


def indexes_from_der_path(
    der_path: DerPath, *, bip380_enforced: bool = False
) -> list[int]:
    """Return the path as a list of indexes, whatever spelling it came in.

    The DerPath spellings of the module docstring are all read: a
    string with or without the leading m, a single int, the 4-byte
    little-endian concatenation, or any iterable of ints.
    `bip380_enforced` is the stricter reading of a string, and says
    nothing about the spellings that are not text.
    """
    return _pairs_from_der_path(der_path, bip380_enforced=bip380_enforced)[0]


def hardenings_from_der_path(
    der_path: DerPath, *, bip380_enforced: bool = False
) -> list[str]:
    """Return the hardening symbol each step of the path was spelled with.

    One entry per index, and "" where the step is unhardened or the path
    is not text. What it is for is writing the path out as it came in:
    "0h" and "0'" are one index and two strings, and a descriptor is
    the string -- BIP380's own valid vectors include the mixed
    "[deadbeef/0'/0h/0']".
    """
    return _pairs_from_der_path(der_path, bip380_enforced=bip380_enforced)[1]


def _indexes_from_der_path(
    der_path: Sequence[int] | int | bytes | bytearray | memoryview,
) -> list[int]:
    """Return the indexes of every DerPath spelling that is not a string."""
    if isinstance(der_path, int):
        _assert_valid_index(der_path)
        return [der_path]

    # a buffer means packed octets everywhere else this tree reads Octets,
    # so a bytearray or a memoryview -- a caller's slice out of a larger
    # field, say -- is read the same way bytes is, not as one index per
    # byte: `Sequence[int]` below is for a genuine sequence of indexes
    if isinstance(der_path, (bytes, bytearray, memoryview)):
        if len(der_path) % 4 != 0:
            err_msg = f"index are not a multiple of 4-bytes: {len(der_path)}"
            raise BTClibValueError(err_msg)
        return [
            int.from_bytes(der_path[n : n + 4], byteorder="little", signed=False)
            for n in range(0, len(der_path), 4)
        ]

    # what is left went to `list()` untouched, which answers a float with
    # "'float' object is not iterable" -- a complaint about iteration, from
    # underneath the library, about a path
    assert_type(der_path, Iterable, "derivation path")

    # an iterable of int, and of int alone: int() here would coerce a bool
    # into the index one, where the annotation already says Sequence[int]
    indexes = list(der_path)
    for index in indexes:
        _assert_valid_index(index)
    return indexes


def _str_from_der_path(der_path: DerPath, hardening: str) -> str:
    indexes = indexes_from_der_path(der_path)
    return "/".join(str_from_index_int(i, hardening) for i in indexes)


def str_from_der_path(
    der_path: DerPath,
    master_fingerprint: Octets | None = None,
    hardening: str = _HARDENING,
) -> str:
    """Return the path as text, led by m or by the master fingerprint.

    With a fingerprint this is the key-origin spelling a descriptor
    brackets; without, the m/ path BIP32 writes.
    """
    result = _str_from_der_path(der_path, hardening)
    if master_fingerprint:
        if isinstance(master_fingerprint, str):
            # ASCII whitespace alone (issue #102)
            first_element = master_fingerprint.strip(string.whitespace)
        else:
            first_element = master_fingerprint.hex()
        if len(first_element) != 8:
            err_msg = f"invalid master fingerprint length: {first_element}"
            raise BTClibValueError(err_msg)
    else:
        first_element = "m"

    return first_element + (f"/{result}" if result else "")


def bytes_from_der_path(der_path: DerPath) -> bytes:
    """Return the path as bytes: each index in 4 bytes, little-endian."""
    indexes = indexes_from_der_path(der_path)
    result = [i.to_bytes(4, byteorder="little", signed=False) for i in indexes]
    return b"".join(result)
