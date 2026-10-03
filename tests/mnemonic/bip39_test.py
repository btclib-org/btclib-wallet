# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib_wallet.mnemonic.bip39` module.

The vector files are upstream's, byte for byte, and tests/_data/README.md
pins them; their seed columns are `btclib_mnemonics`' to test, and what
is asserted here is the extended key each vector carries.
"""

import pytest
from btclib_mnemonics.exceptions import (
    BTClibMnemonicsTypeError,
    BTClibMnemonicsValueError,
)

from btclib_wallet.mnemonic import bip39
from tests import load, vector_id

VECTORS = load("mnemonic", "_data", "bip39_test_vectors.json", encoding="utf-8")

# every array of the file, whatever language it is keyed by: the language
# is read off the words, so it is not handed over
BIP39_VECTORS = [
    pytest.param(vector[1], vector[3], id=vector_id(index, name, vector[0]))
    for name, vectors in VECTORS.items()
    for index, vector in enumerate(vectors)
]


@pytest.mark.parametrize("mnemonic, xprv", BIP39_VECTORS)
def test_vectors(mnemonic: str, xprv: str) -> None:
    """BIP39 test vectors, every language of them, to the root xprv.

    https://github.com/trezor/python-mnemonic/blob/master/vectors.json
    """
    assert bip39.mxprv_from_mnemonic(mnemonic, "TREZOR") == xprv


JP_VECTORS = [
    pytest.param(vector, id=vector_id(index, vector["entropy"]))
    for index, vector in enumerate(
        load("mnemonic", "_data", "test_JP_BIP39.json", encoding="utf-8")
    )
]


@pytest.mark.parametrize("vector", JP_VECTORS)
def test_japanese_vectors(vector: dict[str, str]) -> None:
    """The japanese vectors BIP39 cites beside the reference implementation's.

    https://github.com/bip32JP/bip32JP.github.io/blob/master/test_JP_BIP39.json

    The passphrase is `㍍ガバヴァぱばぐゞちぢ十人十色`, whose NFKD form is
    another string entirely: it reaches the seed unaltered from here.
    """
    xprv = bip39.mxprv_from_mnemonic(vector["mnemonic"], vector["passphrase"])
    assert xprv == vector["bip32_xprv"]


def test_mxprv_from_mnemonic() -> None:
    """Reproduce the rootxprv a known mnemonic derives to, on either network.

    None is the empty passphrase, and the network picks the version bytes.
    """
    mnemonic = "abandon abandon atom trust ankle walnut oil across awake bunker divorce abstract"
    exp = "xprv9s21ZrQH143K3ZxBCax3Wu25iWt3yQJjdekBuGrVa5LDAvbLeCT99U59szPSFdnMe5szsWHbFyo8g5nAFowWJnwe8r6DiecBXTVGHG124G1"
    assert bip39.mxprv_from_mnemonic(mnemonic, "") == exp
    assert bip39.mxprv_from_mnemonic(mnemonic) == exp
    assert bip39.mxprv_from_mnemonic(mnemonic, network="testnet").startswith("tprv")


def test_a_refusal_of_btclib_mnemonics_is_a_value_error() -> None:
    """A checksum refusal raised inside btclib_mnemonics is a `ValueError`.

    `except ValueError` catches it, which is what a caller of this package
    writes to catch the refusals of both, and the checksum can be skipped.
    """
    mnemonic = " ".join(["abandon"] * 12)
    with pytest.raises(ValueError, match="invalid checksum") as excinfo:
        bip39.mxprv_from_mnemonic(mnemonic)
    assert isinstance(excinfo.value, BTClibMnemonicsValueError)
    assert bip39.mxprv_from_mnemonic(mnemonic, verify_checksum=False).startswith("xprv")


@pytest.mark.parametrize("passphrase", [0, False, [], b""])
def test_mxprv_refuses_a_falsy_passphrase_of_another_type(passphrase: object) -> None:
    """None and "" are the empty passphrase, and no other falsy value is.

    A value of another type is refused whether or not it is empty, and
    the refusal is `btclib_mnemonics`' own class, a `TypeError`.
    """
    mnemonic = " ".join(["abandon"] * 11 + ["about"])
    xprv = bip39.mxprv_from_mnemonic(mnemonic)
    assert bip39.mxprv_from_mnemonic(mnemonic, None) == xprv
    assert bip39.mxprv_from_mnemonic(mnemonic, "") == xprv
    err_msg = f"invalid passphrase type: {type(passphrase).__name__}"
    with pytest.raises(BTClibMnemonicsTypeError, match=err_msg):
        bip39.mxprv_from_mnemonic(mnemonic, passphrase)  # type: ignore[arg-type]
