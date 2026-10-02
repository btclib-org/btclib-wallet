# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib_wallet.mnemonic.electrum` module.

Most of the vectors here are electrum's own, from `spesmilo/electrum`'s
`tests/test_mnemonic.py`, `tests/test_wallet_vertical.py` and
`tests/test_storage_upgrade.py`, because the question this module answers
is whether btclib agrees with electrum and nothing btclib generates can
settle that. `electrum_test_vectors.json` is the exception: it has no
upstream at all.
"""

import btclib_mnemonics.electrum
import pytest
from btclib.exceptions import BTClibValueError
from btclib.network import NETWORKS
from btclib_mnemonics.exceptions import (
    BTClibMnemonicsTypeError,
    BTClibMnemonicsValueError,
)

from btclib_wallet import slip132
from btclib_wallet.bip32 import bip32
from btclib_wallet.mnemonic import bip39, electrum
from tests import load, vector_id

# electrum's own "standard" vector, from tests/test_mnemonic.py
STANDARD = "diagram crouch ball canal then hat panda spatial company liberty fetch awful ability"


def test_mxprv_from_mnemonic() -> None:
    """A "standard" mnemonic is derived at "m", on the network asked for."""
    xprv = "xprv9s21ZrQH143K2ASM657UjJdfQ83QaZcdZ1RVsmMbcZxTA3eyQP1arqav4L9TVQz1tf2kXhwy87vAxjngxL61rudpNqyDvtJv8LCxmzNrM2U"
    assert electrum.mxprv_from_mnemonic(STANDARD) == xprv
    assert electrum.mxprv_from_mnemonic(STANDARD, None) == xprv
    assert electrum.mxprv_from_mnemonic(STANDARD, "") == xprv
    assert electrum.mxprv_from_mnemonic(STANDARD, network="testnet").startswith("tprv")


def test_unmanaged_versions() -> None:
    """Only "standard" and "segwit" have a BIP32 master key to answer with.

    A sentence that is no electrum one is `btclib_mnemonics`' refusal, a
    `ValueError`; a version this function derives no key for is this
    package's own.
    """
    unkn_ver = "ability awful fetch liberty company spatial panda hat then canal ball cross video"
    with pytest.raises(
        ValueError, match="unknown electrum mnemonic version; "
    ) as excinfo:
        electrum.mxprv_from_mnemonic(unkn_ver)
    assert isinstance(excinfo.value, BTClibMnemonicsValueError)

    # a twelve-word entropy, which is what "2fa" needs
    entropy = 0x110AAAA03974D093EDA670121023CD077
    for mnemonic_type in ("2fa", "2fa_segwit"):
        mnemonic = btclib_mnemonics.electrum.mnemonic_from_entropy(
            mnemonic_type, entropy, "en"
        )
        err_msg = f"^unmanaged electrum mnemonic version: {mnemonic_type}$"
        with pytest.raises(BTClibValueError, match=err_msg):
            electrum.mxprv_from_mnemonic(mnemonic)

    # the pre-2.0 scheme has a master public key and no BIP32 one
    old = "cell dumb heartbeat north boom tease ship baby bright kingdom rare squeeze"
    err_msg = "^unmanaged electrum mnemonic version: old; "
    err_msg += "use old_master_pub_key_from_mnemonic$"
    with pytest.raises(BTClibValueError, match=err_msg):
        electrum.mxprv_from_mnemonic(old)


ELECTRUM_VECTORS = [
    pytest.param(*vector, id=vector_id(index, vector[4]))
    for index, vector in enumerate(
        load("mnemonic", "_data", "electrum_test_vectors.json")
    )
]


@pytest.mark.parametrize(
    "mnemonic, passphrase, rmxprv, rmxpub, address", ELECTRUM_VECTORS
)
def test_vectors(
    mnemonic: str, passphrase: str, rmxprv: str, rmxpub: str, address: str
) -> None:
    """Electrum vectors, and the only vendored file with no upstream at all.

    They are in no repository -- not in spesmilo/electrum's `tests/`, and a
    code search for the first mnemonic returns btclib and a fork of btclib
    -- so they were produced by running the application, and which version
    produced them is not recorded anywhere. Treat them as btclib's own:
    nothing upstream will ever refresh them. tests/_data/README.md says the
    same at greater length.
    """
    assert rmxprv == electrum.mxprv_from_mnemonic(mnemonic, passphrase)
    assert rmxpub == bip32.xpub_from_xprv(rmxprv)
    xprv = bip32.derive(rmxprv, "m/0h/0")
    assert address == slip132.address_from_xkey(xprv)


# electrum's own pre-2.0 fixtures, each a mnemonic and the master public
# key a test or a wallet file of spesmilo/electrum holds for it. The
# scheme has no specification to check against -- it predates the BIPs --
# so an invented vector would be testing btclib against btclib.
#
# 1. tests/test_wallet_vertical.py, test_electrum_seed_old: mnemonic, hex
#    seed and master public key of one wallet, restored from either form.
# 2. tests/test_wallet_vertical.py,
#    test_sending_offline_old_electrum_seed_online_mpk: a mnemonic and
#    the master public key its watch-only half is built from.
# 3. tests/test_storage_upgrade.py: a real pre-2.0 wallet file, holding
#    the hex seed and the "master_public_key" beside it.
OLD_MNEMONIC = "powerful random nobody notice nothing important anyway look away hidden message over"
OLD_MASTER_PUB_KEY = (
    "e9d4b7866dd1e91c862aebf62a49548c7dbf7bcc6e4b7b8c9da820c7737968df"
    "9c09d5a3e271dc814a29981f81b3faaf2737b551ef5dcc6189cf0f8252c442b3"
)
OLD_VECTORS = [
    pytest.param(OLD_MNEMONIC, OLD_MASTER_PUB_KEY, id="wallet-vertical"),
    pytest.param(
        "alone body father children lead goodbye phone twist exist grass kick join",
        "cd805ed20aec61c7a8b409c121c6ba60a9221f46d20edbc2be83ebd91460e979"
        "37cd7d782e77c1cb08364c6bc1c98bc040fdad53f22f29f7d3a85c8e51f9c875",
        id="offline-signing",
    ),
    pytest.param(
        "2605aafe50a45bdf2eb155302437e678",
        "756d1fe6ded28d43d4fea902a9695feb785447514d6e6c3bdf369f7c3432fdde"
        "4409e4efbffbcf10084d57c5a98d1f34d20ac1f133bdb64fa02abf4f7bde1dfb",
        id="storage-upgrade",
    ),
]


@pytest.mark.parametrize("mnemonic, master_pub_key", OLD_VECTORS)
def test_old_vectors(mnemonic: str, master_pub_key: str) -> None:
    """The pre-2.0 master public key, as an electrum wallet file holds it.

    The storage-upgrade wallet holds a hex seed and no words, and a hex
    seed is one electrum restores from as readily as the words.
    """
    assert electrum.old_master_pub_key_from_mnemonic(mnemonic) == master_pub_key


def test_old_no_passphrase() -> None:
    """The pre-2.0 scheme has no passphrase, and says so.

    None and the empty string are "no passphrase"; any other is
    `btclib_mnemonics`' refusal, a `ValueError`.
    """
    pub_key = electrum.old_master_pub_key_from_mnemonic(OLD_MNEMONIC, None)
    assert pub_key == OLD_MASTER_PUB_KEY
    pub_key = electrum.old_master_pub_key_from_mnemonic(OLD_MNEMONIC, "")
    assert pub_key == OLD_MASTER_PUB_KEY
    with pytest.raises(ValueError, match="cannot have a passphrase") as excinfo:
        electrum.old_master_pub_key_from_mnemonic(
            OLD_MNEMONIC, "Did you ever hear the tragedy of Darth Plagueis"
        )
    assert isinstance(excinfo.value, BTClibMnemonicsValueError)


def test_p2wpkh_p2sh() -> None:
    """Test generation of a p2wpkh-p2sh wallet."""
    # https://bitcoinelectrum.com/creating-a-p2sh-segwit-wallet-with-electrum/
    # https://www.youtube.com/watch?v=-1DBJWwA2Cw

    p2wpkh_p2sh_xkey_version = NETWORKS["mainnet"].slip132_p2wpkh_p2sh_prv
    mnemonics = [
        "matrix fitness cook logic peace mercy dinosaur sign measure rescue alert turtle",
        "chief popular furnace myth decline subject actual toddler plunge rug mixed unlock",
    ]
    versions = ["segwit", "standard"]
    addresses = [
        "38Ysa2TRwGAGLEE1pgV2HCX7MAw6XsP6BJ",
        "3A5u2RTjs3t33Kyc48zHA7Dfsr8Zsfwkoo",
    ]
    for mnemonic, version, p2wpkh_p2sh_address in zip(
        mnemonics, versions, addresses, strict=True
    ):
        # this is an electrum mnemonic
        assert btclib_mnemonics.electrum.version_from_mnemonic(mnemonic)[0] == version
        # of course, it is invalid as BIP39 mnemonic
        with pytest.raises(ValueError, match="invalid checksum: "):
            bip39.mxprv_from_mnemonic(mnemonic, "")
        # nonetheless, let's use it as BIP39 mnemonic
        rootxprv = bip39.mxprv_from_mnemonic(mnemonic, "", verify_checksum=False)
        # and force the xkey version to p2wpkh_p2sh
        mxprv = bip32.derive(rootxprv, "m/49h/0h/0h", p2wpkh_p2sh_xkey_version)
        mxpub = bip32.xpub_from_xprv(mxprv)
        # finally, verify the first receiving address
        xpub = bip32.derive_from_account(mxpub, 0, 0)
        assert p2wpkh_p2sh_address == slip132.address_from_xkey(xpub)


@pytest.mark.parametrize("passphrase", [0, False, [], b""])
def test_mxprv_refuses_a_falsy_passphrase_of_another_type(passphrase: object) -> None:
    """None is the empty passphrase, and no other falsy value is.

    A value of another type is refused whether or not it is empty, and
    the refusal is `btclib_mnemonics`' own class, a `TypeError`.
    """
    mnemonic = ELECTRUM_VECTORS[0].values[0]
    assert isinstance(mnemonic, str)
    xprv = electrum.mxprv_from_mnemonic(mnemonic)
    assert electrum.mxprv_from_mnemonic(mnemonic, None) == xprv
    assert electrum.mxprv_from_mnemonic(mnemonic, "") == xprv
    err_msg = f"invalid passphrase type: {type(passphrase).__name__}"
    with pytest.raises(BTClibMnemonicsTypeError, match=err_msg):
        electrum.mxprv_from_mnemonic(mnemonic, passphrase)  # type: ignore[arg-type]
