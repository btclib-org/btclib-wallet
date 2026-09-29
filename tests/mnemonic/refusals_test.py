# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What a refusal of `btclib_wallet.mnemonic` says, and what it does not.

Two properties. A wrong type leaves as a `BTClibTypeError` naming the
parameter, not as a builtin raised from underneath the package (issue
#134) nor as a value refusal (issue #136): these are the calls
`tests/input_validation_test.py`'s walk does not reach, each taking a
plain `str`, `int` or sequence of them, or being a method. And no
refusal quotes secret material -- a word of the sentence, a checksum, a
padding bit, a hash prefix -- because an exception message ends up in
logs and crash reports (issue #135).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from btclib.exceptions import BTClibTypeError, BTClibValueError

from btclib_wallet.mnemonic import bip39, dispatch, electrum, entropy, mnemonic, slip39
from tests import load

_ABOUT = "abandon " * 11 + "about"


class _BytesPath:
    """A path object whose path is bytes, which no word-list is named by."""

    def __fspath__(self) -> bytes:
        """Return the path, as bytes."""
        return b"english.txt"


# issue #134's table, one row per call, and what the refusal names
_WRONG_TYPES: list[tuple[str, Callable[[], Any], str]] = [
    (
        "bip39.seed_from_mnemonic",
        lambda: bip39.seed_from_mnemonic(_ABOUT, b""),  # type: ignore[arg-type]
        "invalid passphrase type: bytes",
    ),
    (
        "electrum.old_mnemonic_from_hex_seed",
        lambda: electrum.old_mnemonic_from_hex_seed(1),  # type: ignore[arg-type]
        "invalid hex_seed type: int",
    ),
    (
        "mnemonic.data_file",
        lambda: mnemonic.data_file(1),  # type: ignore[arg-type]
        "invalid filename type: int",
    ),
    (
        "mnemonic.mnemonic_from_indexes",
        lambda: mnemonic.mnemonic_from_indexes(1, "en"),  # type: ignore[arg-type]
        "invalid indexes type: int",
    ),
    (
        "mnemonic.WORDLISTS.index",
        lambda: mnemonic.WORDLISTS.index(1, "en"),  # type: ignore[arg-type]
        "invalid word type: int",
    ),
    (
        "mnemonic.WORDLISTS.langs_of_words",
        lambda: mnemonic.WORDLISTS.langs_of_words(1),  # type: ignore[arg-type]
        "invalid words type: int",
    ),
    # issue #136: a lang reaches WordLists.load_lang from every function
    # taking one, which unchecked would refuse it as a missing language
    # file
    (
        "bip39.entropy_from_mnemonic(lang=int)",
        lambda: bip39.entropy_from_mnemonic(_ABOUT, 1),  # type: ignore[arg-type]
        "invalid lang type: int",
    ),
    (
        "mnemonic.indexes_from_mnemonic(lang=None)",
        lambda: mnemonic.indexes_from_mnemonic(_ABOUT, None),  # type: ignore[arg-type]
        "invalid lang type: NoneType",
    ),
    (
        "bip39.mnemonic_from_entropy(lang=int)",
        lambda: bip39.mnemonic_from_entropy("0" * 128, 1),  # type: ignore[arg-type]
        "invalid lang type: int",
    ),
    (
        "mnemonic.WORDLISTS.load_lang(filename=int)",
        lambda: mnemonic.WordLists().load_lang("xx", 1),  # type: ignore[arg-type]
        "invalid filename type: int",
    ),
    (
        "mnemonic.data_file(bytes path)",
        lambda: mnemonic.data_file(_BytesPath()),  # type: ignore[arg-type]
        "invalid filename type: bytes",
    ),
    # dispatch answers "" for a sentence no scheme claims, which is a fact
    # about the sentence; a lang of another type is the caller's mistake
    (
        "dispatch.seed_type_from_mnemonic(lang=int)",
        lambda: dispatch.seed_type_from_mnemonic(_ABOUT, 1),  # type: ignore[arg-type]
        "invalid lang type: int",
    ),
    (
        "dispatch.all_seed_types_from_mnemonic(lang=None)",
        lambda: dispatch.all_seed_types_from_mnemonic(_ABOUT, None),  # type: ignore[arg-type]
        "invalid lang type: NoneType",
    ),
    (
        "entropy.bin_str_entropy_from_random",
        lambda: entropy.bin_str_entropy_from_random("x"),  # type: ignore[arg-type]
        "invalid bits type: str",
    ),
    # the shapes around those rows: a lone str where its words go, an
    # element of the wrong type, and a bool where an index goes
    (
        "mnemonic.WORDLISTS.langs_of_words(str)",
        lambda: mnemonic.WORDLISTS.langs_of_words("abandon"),
        "invalid words type: str",
    ),
    (
        "mnemonic.WORDLISTS.langs_of_words([int])",
        lambda: mnemonic.WORDLISTS.langs_of_words([1]),  # type: ignore[list-item]
        "invalid word type: int",
    ),
    (
        "mnemonic.mnemonic_from_indexes(str)",
        lambda: mnemonic.mnemonic_from_indexes("12", "en"),  # type: ignore[arg-type]
        "invalid indexes type: str",
    ),
    (
        "mnemonic.mnemonic_from_indexes([bool])",
        lambda: mnemonic.mnemonic_from_indexes([True], "en"),
        "invalid index type: bool",
    ),
]


@pytest.mark.parametrize(
    "call, err_msg", [row[1:] for row in _WRONG_TYPES], ids=[r[0] for r in _WRONG_TYPES]
)
def test_a_wrong_type_is_the_packages_refusal(
    call: Callable[[], Any], err_msg: str
) -> None:
    """A `BTClibTypeError` naming the parameter, and no builtin."""
    with pytest.raises(BTClibTypeError, match=f"^{err_msg}$"):
        call()


def test_the_type_checks_let_the_right_types_through() -> None:
    """The same calls with the types they declare, which still answer."""
    assert len(bip39.seed_from_mnemonic(_ABOUT, "")) == 64
    words = electrum.old_mnemonic_from_hex_seed("00" * 16).split()
    assert len(words) == 12
    assert mnemonic.data_file("english.txt").endswith("english.txt")
    # a path object names a file as well as its str does, so it is taken
    assert mnemonic.data_file(Path("english.txt")) == mnemonic.data_file("english.txt")
    word_lists = mnemonic.WordLists()
    word_lists.load_lang("xx", Path(mnemonic.data_file("english.txt")))
    assert word_lists.language_files["xx"] == mnemonic.data_file("english.txt")
    assert dispatch.seed_type_from_mnemonic(_ABOUT, "en") == "bip39"
    assert mnemonic.mnemonic_from_indexes((0, 2047), "en") == "abandon zoo"
    assert mnemonic.WORDLISTS.index("zoo", "en") == 2047
    assert "en" in mnemonic.WORDLISTS.langs_of_words(["abandon", "zoo"])
    assert len(entropy.bin_str_entropy_from_random(128)) == 128


@pytest.mark.parametrize("index", [-1, 2048], ids=["negative", "past the end"])
def test_an_index_out_of_range_is_refused_by_its_position(index: int) -> None:
    """Refused where it would have read the wrong word, or none.

    A negative index would otherwise read from the end of the list, and
    the value is not quoted, being a digit of the secret: the anchored
    pattern is the whole message, so it holds no number but the position
    and the bound.
    """
    err_msg = r"^invalid index at position 2: not in \[0, 2048\)$"
    with pytest.raises(BTClibValueError, match=err_msg):
        mnemonic.mnemonic_from_indexes([0, index], "en")


def test_an_unknown_word_is_refused_by_its_position() -> None:
    """The misspelled word is one letter from a word of the secret."""
    # a spanish word and no english one, so the misspelling is a word
    # the spell checker leaves alone
    sentence = _ABOUT.replace("about", "abaco")
    err_msg = "^unknown 'en' word at position 12$"
    for call in (
        lambda: mnemonic.indexes_from_mnemonic(sentence, "en"),
        lambda: bip39.entropy_from_mnemonic(sentence, "en"),
    ):
        with pytest.raises(BTClibValueError, match=err_msg) as excinfo:
            call()
        assert "abaco" not in str(excinfo.value)
        # the word-list's own refusal is not left chained behind it
        assert excinfo.value.__suppress_context__


def test_an_unknown_language_is_refused_as_itself() -> None:
    """Not as an unknown word, which the per-word loop would call it."""
    with pytest.raises(BTClibValueError, match="^Missing file for language 'xx'$"):
        mnemonic.indexes_from_mnemonic(_ABOUT, "xx")


def test_a_bip39_checksum_refusal_quotes_no_checksum() -> None:
    """Both checksums are bits of the entropy or of its hash."""
    sentence = "abandon " * 12 + "abandon"
    sentence = " ".join(sentence.split()[:12])
    with pytest.raises(BTClibValueError, match="^invalid checksum: 12 words$"):
        bip39.entropy_from_mnemonic(sentence, "en")


def test_a_slip39_padding_refusal_quotes_no_bit() -> None:
    """The padding bits are bits of the share."""
    vectors = load("mnemonic", "_data", "vectors.json")
    ((share,),) = [v[1] for v in vectors if "invalid padding (128 bits)" in v[0]]
    with pytest.raises(BTClibValueError, match="^invalid padding: must be all zeros$"):
        slip39.share_from_mnemonic(share)


def test_an_unknown_electrum_version_quotes_no_hash_prefix() -> None:
    """For a sentence that is no electrum one, the prefix is a secret's hash."""
    prefix = electrum._seed_version(_ABOUT)[:3]
    with pytest.raises(
        BTClibValueError, match="^unknown electrum mnemonic version; "
    ) as excinfo:
        electrum.version_from_mnemonic(_ABOUT)
    assert prefix not in str(excinfo.value)
