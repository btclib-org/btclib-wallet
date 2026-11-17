# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Which file a path handed to a `Ledger` names (issue #1020).

A str is read as the str it holds, and a `PathLike` through
`os.fspath` once, whatever their own methods answer: the file made,
opened, copied or removed is the one that str names. A str holding a
NUL names none, and is refused (issue #1028). One holding a surrogate
is refused too (issue #1048).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from btclib.exceptions import BTClibTypeError, BTClibValueError
from typing_extensions import override

from btclib_wallet.ledger import Ledger
from tests import raises_alone
from tests.ledger import ObjectClaimingStr, StrWithNoClass
from tests.ledger.conftest import FakeChain, source
from tests.refused_value_test import KEY, SPELLINGS
from tests.secret_free import assert_secret_free


class Lying(str):
    """A path whose own methods answer other files than the one it holds.

    Its length is 0, it equals anything under one hash, and its
    `__fspath__` and `str()` each name a file beside it.
    """

    __slots__ = ()

    @override
    def __len__(self) -> int:
        return 0

    def __fspath__(self) -> str:
        return str.__add__(self, ".fspath")

    @override
    def __eq__(self, _other: object) -> bool:
        return True

    @override
    def __hash__(self) -> int:
        return 0

    @override
    def __str__(self) -> str:
        return str.__add__(self, ".str")


class Answering:
    """A `PathLike` whose `__fspath__` answers `first`, then `second`."""

    def __init__(self, first: Any, second: Any) -> None:
        self.answers = (first, second)
        self.calls = 0

    def __fspath__(self) -> str:
        answer: str = self.answers[min(self.calls, 1)]
        self.calls += 1
        return answer


# `isinstance` reads `__class__`, so a value of this class is believed a str
_claims_str: Any = property(lambda _self: str)


class AnsweringClaimingStr(Answering):
    """An `Answering` whose `__class__` claims str."""

    __class__ = _claims_str


class RaisingTypeError:
    """A `PathLike` whose `__fspath__` raises a TypeError holding a key."""

    def __fspath__(self) -> str:
        raise TypeError(KEY.hex())


def _files(folder: Path) -> list[str]:
    return sorted(p.name for p in folder.iterdir())


def test_a_lying_path_lies() -> None:
    """The control: each method the ledger does not read names another file."""
    path = Lying("/a")
    assert len(path) == 0
    assert path.__fspath__() == "/a.fspath"
    assert path == "/b"
    assert hash(path) == 0
    assert str(path) == "/a.str"


def _interrupted(*_args: object, **_kwargs: object) -> int:
    raise KeyboardInterrupt


_RESTORED = ["ledger.bak", "ledger.sqlite", "policy.sqlite", "restored.sqlite"]


def test_a_str_subclass_names_the_file_it_holds(
    chain: FakeChain, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Its own length, `__fspath__`, `==`, hash and `str()` are not read."""
    path = tmp_path / "ledger.sqlite"
    with Ledger.create(Lying(path), "regtest", chain) as created:
        created.add_source(source())
    with Ledger.load(Lying(path), "regtest", chain) as ledger:
        assert len(ledger.sources) == 1
        ledger.backup(Lying(tmp_path / "ledger.bak"))
        policy = ledger.export_policy()
    restored = tmp_path / "restored.sqlite"
    with Ledger.restore(
        Lying(tmp_path / "ledger.bak"), Lying(restored), "regtest", chain
    ) as ledger:
        assert len(ledger.sources) == 1
    ledger, _ = Ledger.restore_policy(
        policy, Lying(tmp_path / "policy.sqlite"), "regtest", chain
    )
    with ledger:
        assert len(ledger.sources) == 1
    assert _files(tmp_path) == _RESTORED

    # a restore that fails after making its file removes the file the str names
    with pytest.raises(BTClibValueError, match="^not a testnet ledger file"):
        Ledger.restore(
            Lying(tmp_path / "ledger.bak"), Lying(tmp_path / "x"), "testnet", chain
        )
    monkeypatch.setattr(Ledger, "add_source", _interrupted)
    with pytest.raises(KeyboardInterrupt):
        Ledger.restore_policy(policy, Lying(tmp_path / "x"), "regtest", chain)
    assert _files(tmp_path) == _RESTORED


def test_a_pathlike_is_read_once(
    chain: FakeChain, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A second read of `__fspath__` would name another file.

    Each answer is a `Lying` str, read as the str it holds.
    """

    def once(name: str) -> Answering:
        return Answering(Lying(tmp_path / name), Lying(tmp_path / "second"))

    paths = [once("ledger.sqlite") for _ in range(2)]
    with Ledger.create(paths[0], "regtest", chain) as created:
        created.add_source(source())
    paths += [once("ledger.bak") for _ in range(2)] + [once("restored.sqlite")]
    with Ledger.load(paths[1], "regtest", chain) as ledger:
        ledger.backup(paths[2])
        policy = ledger.export_policy()
    Ledger.restore(paths[3], paths[4], "regtest", chain).close()
    paths.append(once("policy.sqlite"))
    Ledger.restore_policy(policy, paths[5], "regtest", chain)[0].close()
    paths += [once("ledger.bak"), once("x"), once("x")]
    with pytest.raises(BTClibValueError, match="^not a testnet ledger file"):
        Ledger.restore(paths[6], paths[7], "testnet", chain)
    monkeypatch.setattr(Ledger, "add_source", _interrupted)
    with pytest.raises(KeyboardInterrupt):
        Ledger.restore_policy(policy, paths[8], "regtest", chain)
    assert [path.calls for path in paths] == [1] * len(paths)
    assert _files(tmp_path) == _RESTORED


def test_a_pathlike_claiming_str_is_read_through_fspath(
    chain: FakeChain, tmp_path: Path
) -> None:
    """Its type decides, not the `__class__` it claims."""
    path = AnsweringClaimingStr(
        Lying(tmp_path / "ledger.sqlite"), Lying(tmp_path / "second")
    )
    Ledger.create(path, "regtest", chain).close()
    assert path.calls == 1
    assert _files(tmp_path) == ["ledger.sqlite"]


def test_a_str_whose_class_raises_is_read_as_a_str(
    chain: FakeChain, tmp_path: Path
) -> None:
    """Its type decides, and its `__class__` is not read."""
    Ledger.create(StrWithNoClass(tmp_path / "ledger.sqlite"), "regtest", chain).close()
    assert _files(tmp_path) == ["ledger.sqlite"]


def _calls(
    ledger: Ledger, chain: FakeChain, folder: Path, make: Callable[[], Any]
) -> list[tuple[str, Callable[[], object]]]:
    """Return each public call taking a path, `make()` its path, by its name.

    `folder` holds `ledger.bak`, a backup no ledger holds. `ledger` holds
    a source, so that its policy restores.
    """
    backup = folder / "ledger.bak"
    policy = ledger.export_policy()
    return [
        ("path", lambda: Ledger.create(make(), "regtest", chain)),
        ("path", lambda: Ledger.load(make(), "regtest", chain)),
        ("backup", lambda: Ledger.restore(make(), folder / "x", "regtest", chain)),
        ("path", lambda: Ledger.restore(backup, make(), "regtest", chain)),
        ("path", lambda: ledger.backup(make())),
        ("path", lambda: Ledger.restore_policy(policy, make(), "regtest", chain)),
    ]


@pytest.fixture
def held(chain: FakeChain, tmp_path: Path) -> Iterator[Ledger]:
    """Yield a one-source ledger in `ledger.sqlite`, beside its `ledger.bak`."""
    with Ledger.create(tmp_path / "ledger.sqlite", "regtest", chain) as ledger:
        ledger.add_source(source())
        ledger.backup(tmp_path / "ledger.bak")
        yield ledger


_BYTES = KEY.hex().encode()
# a class named by a key's hex, which the refusal does not print
_KEY_NAMED = type(KEY.hex(), (), {})


@pytest.mark.parametrize(
    "make, shown",
    [
        (lambda: _BYTES, "'bytes'"),
        (lambda: Answering(_BYTES, _BYTES), "'Answering'"),
        (lambda: Answering(int.from_bytes(KEY), 0), "'Answering'"),
        (RaisingTypeError, "'RaisingTypeError'"),
        # `_quoted` describes a name past `_QUOTED_MAX` characters by its length
        (ObjectClaimingStr, "a value of 17 characters"),
        (_KEY_NAMED, "a value of 64 characters"),
        (lambda: None, "'NoneType'"),
    ],
    ids=[
        "bytes",
        "answers-bytes",
        "answers-int",
        "raises",
        "claims-str",
        "key-named",
        "none",
    ],
)
def test_what_names_no_str_is_refused_by_its_type(
    held: Ledger,
    chain: FakeChain,
    tmp_path: Path,
    make: Callable[[], Any],
    shown: str,
) -> None:
    """Bytes, and what `os.fspath` refuses, are refused by the type alone.

    The refusal holds nothing of the value or of what its `__fspath__`
    answered or raised, and chains nothing.
    """
    for name, call in _calls(held, chain, tmp_path, make):
        with raises_alone(BTClibTypeError, f"^invalid {name} type: {shown}$") as e:
            call()
        assert_secret_free(e.value, SPELLINGS)
    assert _files(tmp_path) == ["ledger.bak", "ledger.sqlite", "ledger.sqlite-journal"]


@pytest.mark.parametrize(
    "wrap",
    [str, Lying, lambda text: Answering(text, text)],
    ids=["str", "subclass", "answered"],
)
def test_a_path_holding_a_nul_is_refused_before_any_file_is_made(
    held: Ledger, chain: FakeChain, tmp_path: Path, wrap: Callable[[str], Any]
) -> None:
    """Issue #1028: `Path.touch` lets out a ValueError of its own for one.

    The refusal holds nothing of the path, a key's hex in it included.
    """
    text = f"{tmp_path / KEY.hex()}\0.sqlite"
    for name, call in _calls(held, chain, tmp_path, lambda: wrap(text)):
        err_msg = f"^invalid {name}: it holds a NUL character$"
        with raises_alone(BTClibValueError, err_msg) as e:
            call()
        assert_secret_free(e.value, SPELLINGS)
    assert _files(tmp_path) == ["ledger.bak", "ledger.sqlite", "ledger.sqlite-journal"]


@pytest.mark.parametrize(
    "wrap",
    [str, Lying, lambda text: Answering(text, text)],
    ids=["str", "subclass", "answered"],
)
# `os.fsdecode` reads a byte 0x80 that is not UTF-8 as U+DC80. Built by
# `chr`: ruff reads the three literals as one value, and calls them duplicates
@pytest.mark.parametrize("surrogate", [chr(0xD800), chr(0xDC80), chr(0xDFFF)])
def test_a_path_holding_a_surrogate_is_refused_before_any_file_is_made(
    held: Ledger,
    chain: FakeChain,
    tmp_path: Path,
    wrap: Callable[[str], Any],
    surrogate: str,
) -> None:
    """Issue #1048: the URI `store` opens the file through is UTF-8.

    The refusal holds nothing of the path, a key's hex in it included.
    """
    text = f"{tmp_path / KEY.hex()}{surrogate}.sqlite"
    for name, call in _calls(held, chain, tmp_path, lambda: wrap(text)):
        err_msg = f"^invalid {name}: it holds a surrogate$"
        with raises_alone(BTClibValueError, err_msg) as e:
            call()
        assert_secret_free(e.value, SPELLINGS)
    assert _files(tmp_path) == ["ledger.bak", "ledger.sqlite", "ledger.sqlite-journal"]


def test_the_code_points_beside_the_surrogates_name_a_file(
    chain: FakeChain, tmp_path: Path
) -> None:
    """U+D7FB and U+E000 are no surrogates, and UTF-8 encodes them.

    U+D7FB is the last code point assigned below the surrogates: APFS
    refuses a name holding one Unicode has not assigned.
    """
    path = tmp_path / "ퟻ.sqlite"
    Ledger.create(str(path), "regtest", chain).close()
    Ledger.load(str(path), "regtest", chain).close()
    assert _files(tmp_path) == [path.name]


@pytest.mark.parametrize(
    "raised", [ValueError(KEY.hex()), KeyboardInterrupt()], ids=["value", "interrupt"]
)
def test_what_a_pathlikes_fspath_raises_is_raised_as_it_is(
    held: Ledger, chain: FakeChain, tmp_path: Path, raised: BaseException
) -> None:
    """Only the TypeError of `os.fspath` is a refusal of the path's type."""

    class Raising:
        def __fspath__(self) -> str:
            raise raised

    for _, call in _calls(held, chain, tmp_path, Raising):
        with pytest.raises(type(raised)) as e:
            call()
        assert e.value is raised
    assert _files(tmp_path) == ["ledger.bak", "ledger.sqlite", "ledger.sqlite-journal"]
