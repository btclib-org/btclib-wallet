# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib_wallet.mnemonic.slip39` module."""

import pytest
from btclib_mnemonics.exceptions import BTClibMnemonicsTypeError

from btclib_wallet.mnemonic import slip39
from tests import load, vector_id

# the passphrase SLIP-0039 uses for every valid set of mnemonics in its
# own vectors, and the one value that makes their answers reproducible:
# a passphrase a standard publishes is a fixture and not a
# credential; the name says which it is, so renaming it past the S105
# heuristic would hide the fact rather than the finding
PASSPHRASE = "TREZOR"  # noqa: S105

_VECTORS = load("mnemonic", "_data", "vectors.json")

# the vectors that recover a master secret, and so carry an xprv: the
# ones whose combining must fail are `btclib_mnemonics`' to test
VECTORS = [
    pytest.param(vector[1], vector[3], id=vector_id(index, vector[0]))
    for index, vector in enumerate(_VECTORS)
    if vector[2]
]


@pytest.mark.parametrize("mnemonics, xprv", VECTORS)
def test_vectors(mnemonics: list[str], xprv: str) -> None:
    """SLIP-0039 test vectors, to the root xprv.

    https://github.com/trezor/python-shamir-mnemonic/blob/master/vectors.json

    The file SLIP-0039 names as its own; tests/_data/README.md pins the
    revision.
    """
    assert slip39.mxprv_from_mnemonics(mnemonics, PASSPHRASE) == xprv
    # a tuple of the same shares is the same sequence
    assert slip39.mxprv_from_mnemonics(tuple(mnemonics), PASSPHRASE) == xprv


@pytest.mark.parametrize("passphrase", [0, [], b""])
def test_mxprv_refuses_a_falsy_passphrase_of_another_type(passphrase: object) -> None:
    """None is the empty passphrase, and no other falsy value is.

    A value of another type is refused whether or not it is empty, and
    the refusal is `btclib_mnemonics`' own class, a `TypeError`.
    """
    shares = _VECTORS[0][1]
    xprv = slip39.mxprv_from_mnemonics(shares)
    assert slip39.mxprv_from_mnemonics(shares, None) == xprv
    assert slip39.mxprv_from_mnemonics(shares, "") == xprv
    err_msg = f"invalid passphrase type: {type(passphrase).__name__}"
    with pytest.raises(BTClibMnemonicsTypeError, match=err_msg):
        slip39.mxprv_from_mnemonics(shares, passphrase)  # type: ignore[arg-type]


def test_mxprv_on_testnet() -> None:
    """The network picks the version bytes of the same master key."""
    shares = _VECTORS[0][1]
    assert slip39.mxprv_from_mnemonics(shares, network="testnet").startswith("tprv")
