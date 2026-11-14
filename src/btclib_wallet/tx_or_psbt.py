# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""One entry point for a transaction or a psbt, in whatever it arrives as.

A transaction copied from a block explorer is hex, a
`walletcreatefundedpsbt` reply is base64, a QR code and a file are
bytes -- and which of `Tx.parse`, `Psbt.parse` and `Psbt.b64decode`
applies is a question a caller holding one of them should not have to
answer first. It is also a question with an unambiguous answer:
BIP174's five-byte `<magic>` is what a psbt begins with and what a
transaction cannot, which is the very reason the `0xff` is in it.

So this module sniffs, and delegates. The parsers stay whole -- one
refuses what does not deserialize, the other refuses what follows a
psbt (issue btclib-org/btclib#179) -- and no byte either of them reads is read
here: merging the two into one lenient reader is how a dispatcher stops being a
dispatcher, and it is the parsers that would pay for it.

It sits above `tx` and `psbt` rather than inside either, because its
answer is one or the other and `tx` may not import `psbt`.
"""

from __future__ import annotations

import string
from contextlib import suppress

from btclib.alias import String
from btclib.exceptions import BTClibValueError
from btclib.tx import Tx
from btclib.utils import bytes_from_octets

from btclib_wallet.psbt.psbt import (
    _MAX_PSBT_SIZE,
    PSBT_MAGIC_BYTES,
    Psbt,
    _assert_decoded_size,
    _assert_text_size,
    _b64_size,
    _b64decode,
    _non_ascii_position,
)

__all__ = [
    "tx_or_psbt_from_any",
]


def _octets_from_text(text: str) -> bytes:
    """Return the bytes a hex-string or a base64 string encodes.

    Hex first, because a hex-string whose length is a multiple of four
    is also a valid base64 encoding -- of something else entirely. The
    other way round there is nothing to resolve: base64's alphabet has
    every letter, so a base64 string is almost never hex, and BIP174's
    magic makes one of them start with `cHNidP8`.

    Either encoding of a psbt over `_MAX_PSBT_SIZE` is refused, as the
    comment on it says. No transaction a block can hold is longer: its
    size is at most its weight, which `MAX_BLOCK_WEIGHT` bounds.
    """
    # before the whitespace is dropped, so that the position is the one in
    # the text as given
    if not text.isascii():
        position = _non_ascii_position(text)
        err_msg = f"neither hex nor base64: non-ascii character at position {position}"
        raise BTClibValueError(err_msg)
    # ASCII whitespace and nothing else is dropped, since base64 arrives
    # wrapped as often as not -- and bytes.fromhex skips exactly that set
    # anyway, so this only makes the two consistent (issue #102). It is
    # counted first, so that a text over the hex bound is not copied either
    size = len(text) - sum(map(text.count, string.whitespace))
    _assert_text_size(size, 2 * _MAX_PSBT_SIZE, "text")
    packed = text.translate(str.maketrans("", "", string.whitespace))

    try:
        return bytes.fromhex(packed)
    except ValueError:
        pass

    _assert_text_size(size, _b64_size(_MAX_PSBT_SIZE), "base64 text")
    # canonical base64 alone (issue #114), refused after `suppress`, so
    # that it chains nothing
    decoded = None
    with suppress(BTClibValueError):
        decoded = _b64decode(packed)
    if decoded is None:
        raise BTClibValueError("neither hex nor base64")
    _assert_decoded_size(decoded, "base64 text")
    return decoded


def _octets_from_any(data: String) -> bytes:
    """Return the bytes behind hex, base64, or bytes.

    Bytes are text when they are ascii and decode as hex or base64, and
    are themselves otherwise: `Path.read_bytes` is how a psbt or a
    transaction comes out of a file, whichever of the three encodings
    the file holds, and a caller who read one that way should not have
    to know which. Nothing is lost to the ambiguity -- a serialized
    transaction begins with a four-byte version that is not printable,
    and a serialized psbt with a `0xff` that is not ascii at all.
    """
    if isinstance(data, str):
        return _octets_from_text(data)

    # the refusal of what is neither text nor bytes is bytes_from_octets's
    # to give, `translate` above being str's and `decode` bytes': a memoryview
    # has no `decode`, and the coercion is what makes it bytes
    raw = bytes_from_octets(data)
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return raw
    try:
        return _octets_from_text(text)
    except BTClibValueError:
        return raw


def tx_or_psbt_from_any(data: String, *, check_validity: bool = True) -> Tx | Psbt:
    """Return the Psbt or the Tx the data holds, in whatever encoding.

    hex, base64 or bytes; a `Psbt` when BIP174's magic is what the bytes
    begin with, a `Tx` when it is not.
    """
    if not (octets := _octets_from_any(data)):
        # what Tx.parse would answer here is "not enough binary data for
        # var_int", which describes a field the caller never had
        raise BTClibValueError("no data")

    return (
        Psbt.parse(octets, check_validity=check_validity)
        if octets.startswith(PSBT_MAGIC_BYTES)
        else Tx.parse(octets, check_validity=check_validity)
    )
