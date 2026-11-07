# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Two psbts that crashed rust-bitcoin's combiner are read here.

`psbt_fuzz1.hex` and `psbt_fuzz2.hex` are rust-bitcoin's regression
inputs for that crash; `tests/_data/README.md` pins and describes them.
Each is well-formed on its own: a psbt with no input and no output, and
one global xpub with an origin of one or two steps. The Bitcoin Core
release `integration-bitcoind.yml` pins reads both, and prints the origin
asserted below, with:

    bitcoin-cli decodepsbt "$(xxd -r -p tests/psbt/_data/psbt_fuzz1.hex |
        base64 | tr -d '[:space:]')"

and the same with `psbt_fuzz2.hex`, under `global_xpubs`. So `Psbt.parse`
is asked to read them, not to refuse them, and to write back the bytes it
was given.
"""

from __future__ import annotations

import base64

import pytest

from btclib_wallet.psbt import Psbt
from tests import load_bin

# the fingerprint and derivation path of the one global xpub; Core's
# `m/11/65536` for the first psbt is the list [11, 65536]
_ORIGINS = {
    1: ("08080800", [11, 65536]),
    2: ("00000000", [268435456]),
}


def _octets(number: int) -> bytes:
    hex_ = load_bin("psbt", "_data", f"psbt_fuzz{number}.hex")
    return bytes.fromhex(hex_.decode("ascii").strip())


@pytest.mark.parametrize("number", _ORIGINS)
def test_the_psbt_is_read(number: int) -> None:
    """The one global xpub is read with the origin Core prints for it."""
    psbt = Psbt.parse(_octets(number))
    assert not psbt.inputs
    assert not psbt.outputs
    assert psbt.version == 0
    (origin,) = psbt.hd_key_paths.values()
    fingerprint, der_path = _ORIGINS[number]
    assert origin.master_fingerprint.hex() == fingerprint
    assert origin.der_path == der_path


@pytest.mark.parametrize("number", _ORIGINS)
def test_the_psbt_round_trips(number: int) -> None:
    """Both forms write back the bytes that were read."""
    data = _octets(number)
    psbt = Psbt.parse(data)
    assert psbt.serialize() == data
    assert psbt.b64encode() == base64.b64encode(data).decode("ascii")
    assert Psbt.b64decode(psbt.b64encode()) == psbt
