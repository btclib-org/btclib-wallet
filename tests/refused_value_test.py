# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A refusal describes the value it refuses, and does not print it.

Section 7 of the btclib-org standard, *A refusal carries no secret*: an
argument in the wrong place may be a key. Each test feeds a fixed random
key where another value belongs, and checks the refusal's chain with
`assert_secret_free`.
"""

from __future__ import annotations

from collections.abc import Callable
from hashlib import shake_256

import pytest
from base58_bech32.bech32 import BECH32_M_CONST, bech32_encode
from btclib.b32 import power_of_2_base_conversion
from btclib.exceptions import BTClibValueError
from ecc.curves import bytes_from_point, mult

from btclib_wallet import silent_payments
from btclib_wallet.bip322 import Sig
from btclib_wallet.electrum import (
    block_header_request,
    block_headers_request,
    decode_response,
    transaction_get_request,
)
from btclib_wallet.psbt import Psbt
from btclib_wallet.tx_or_psbt import tx_or_psbt_from_any
from tests.secret_free import assert_secret_free

KEY = shake_256(b"btclib-wallet issues 745 and 749").digest(32)
SCALAR = int.from_bytes(KEY)
# each spelling of the key a refusal could print, the decimal included
SPELLINGS: list[str | bytes] = [KEY, KEY.hex(), str(SCALAR), f"{SCALAR:x}"]


@pytest.mark.parametrize(
    "call",
    [
        lambda: decode_response(b'{"id": 1, "result": 0}\n', SCALAR),
        lambda: block_header_request(1, -SCALAR),
        lambda: block_headers_request(1, -SCALAR, 1),
        lambda: block_headers_request(1, 0, -SCALAR),
        lambda: transaction_get_request(1, str(SCALAR)),
        lambda: transaction_get_request(1, f"{SCALAR:#066x}"),
    ],
    ids=[
        "request id",
        "negative height",
        "negative start_height",
        "negative count",
        "tx_id of decimal digits",
        "tx_id of 0x-prefixed hex",
    ],
)
def test_electrum_describes_a_refused_int_or_tx_id(call: Callable[[], object]) -> None:
    """An int by its sign and bit length, a str by its length (issue #745)."""
    with pytest.raises(BTClibValueError) as e:
        call()
    assert_secret_free(e.value, SPELLINGS)


@pytest.mark.parametrize(
    "reader, err_msg",
    [
        (Psbt.b64decode, "^non-ascii character in base64 psbt at position 66$"),
        (Sig.b64decode, "^non-ascii character in base64 signature at position 66$"),
        (
            tx_or_psbt_from_any,
            "^neither hex nor base64: non-ascii character at position 66$",
        ),
    ],
    ids=["psbt", "bip322 signature", "tx or psbt"],
)
def test_base64_refuses_a_non_ascii_character_by_position(
    reader: Callable[[str], object], err_msg: str
) -> None:
    """The codec's error, which holds the whole text, is not chained.

    A key's hex is base64 alphabet, so the character outside ASCII after
    it is what is refused. Its position counts the whitespace the reader
    strips (issue #749).
    """
    with pytest.raises(BTClibValueError, match=err_msg) as e:
        reader("  " + KEY.hex() + "\N{LATIN SMALL LETTER E WITH ACUTE}")
    assert_secret_free(e.value, SPELLINGS)


def _address(hrp: str) -> str:
    """Return a bech32m silent payment address of a v0 payload."""
    payload = bytes_from_point(mult(2)) + bytes_from_point(mult(3))
    data = [0, *power_of_2_base_conversion(payload, 8, 5)]
    return bech32_encode(hrp, data, m=BECH32_M_CONST).decode("ascii")


def test_silent_payments_quotes_a_refused_hrp_only_up_to_16_characters() -> None:
    """A longer hrp is described by its length (issue #749)."""
    hrp = KEY.hex()
    with pytest.raises(
        BTClibValueError, match="^invalid hrp: a value of 64 characters$"
    ) as e:
        silent_payments.keys_from_address(_address(hrp))
    assert_secret_free(e.value, SPELLINGS)
    with pytest.raises(BTClibValueError, match=f"^invalid hrp: '{hrp[:16]}'$"):
        silent_payments.keys_from_address(_address(hrp[:16]))
    with pytest.raises(
        BTClibValueError, match="^invalid hrp: a value of 17 characters$"
    ):
        silent_payments.keys_from_address(_address(hrp[:17]))
