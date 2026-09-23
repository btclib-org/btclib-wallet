# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The gate for what a public function's name promises about its answer.

btclib's rule that every public function validates its inputs states the
vocabulary: `assert_*` refuses and returns None, `is_*` and `verify*`
answer a bool about a value of a declared type, and `check_*` answers a
bool *and* refuses what cannot be an answer -- the one prefix that warns
a caller it still needs an `except`. A prefix that says several things
says nothing, which is what issue btclib-org/btclib#814 found, and
btclib's own `name_contract_test.py` holds btclib to it.

The rule is read off the annotations rather than off a list of names
somebody keeps in step. What it cannot see is the *contract*: that a
predicate is total over its values is a promise in prose, and only the
return type is here.

`_OTHER_CONTRACT` is what the rule does not cover, one entry per reason.
`test_what_is_excepted_still_needs_to_be` fails on an entry that has come
into line, so a name cannot keep an exemption it has stopped needing.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_LIBRARY = Path(__file__).parents[1] / "src" / "btclib_wallet"

# what each prefix promises the return type is. `verify` is matched
# anywhere in the name and not only at the front: `partial_sig_verify` is
# a verification, and reading the front alone is what left its kind out
# of issue btclib-org/btclib#814's first census
_PROMISED: dict[str, str] = {
    "assert_": "None",
    "check_": "bool",
    "is_": "bool",
    "verify": "bool",
}

_AN_ASSERT_WITH_A_PAYLOAD = (
    "it is the Signer's own question -- five conditions on the psbt, and"
    " the message they prove it commits to -- so refusing and handing back"
    " what was validated are one answer, not two"
)

_OTHER_CONTRACT: dict[str, str] = {
    "btclib_wallet.bip322.assert_signed_message": _AN_ASSERT_WITH_A_PAYLOAD,
}


# A bool need not carry one of the four prefixes: an English predicate is
# the same family and the same contract, and `is_` would cost the reading.
# Each entry carries the reason it keeps the name it has -- and the
# ratchet below is what closes the vocabulary all the same, an entry that
# has gained a prefix being one this list no longer excuses (issue
# btclib-org/btclib#814)
_ITS_STANDARD_SPELLING = (
    "the name is the standard's: BIP379's malleability analysis says a"
    " miniscript mixes timelocks and has duplicate keys, and the three"
    " PSBT_GLOBAL_TX_MODIFIABLE bits are named after the field"
)

_A_PREDICATE_WITH_A_SUBJECT = (
    "`reads_back` is the round trip as a question, and the subject is the"
    " script: `is_read_back` would ask who reads it"
)

_ENGLISH_PREDICATE: dict[str, str] = {
    "btclib_wallet.descriptors.miniscript.has_duplicate_keys": _ITS_STANDARD_SPELLING,
    "btclib_wallet.descriptors.miniscript.mixes_timelocks": _ITS_STANDARD_SPELLING,
    "btclib_wallet.descriptors.miniscript.reads_back": _A_PREDICATE_WITH_A_SUBJECT,
    "btclib_wallet.psbt.psbt.has_sig_hash_single": _ITS_STANDARD_SPELLING,
    "btclib_wallet.psbt.psbt.inputs_modifiable": _ITS_STANDARD_SPELLING,
    "btclib_wallet.psbt.psbt.outputs_modifiable": _ITS_STANDARD_SPELLING,
}


def _promised_by(name: str) -> str | None:
    """Return the type the name promises, or None if it promises nothing."""
    for prefix, promised in _PROMISED.items():
        if name.startswith(prefix) or (prefix == "verify" and prefix in name):
            return promised
    return None


def _named() -> dict[str, str]:
    """Return every public function whose name promises a return type.

    Methods included, a property being one: `BIP32KeyData.is_private`
    promises a bool as much as `bip322.verify` does.

    The dotted name is the file's path and keeps the `__init__` of a
    package module, which is what `input_validation_test.py`'s walk does
    and is importable either way: one spelling across the two gates.
    """
    found: dict[str, str] = {}
    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef) or node.name.startswith("_"):
                continue
            if _promised_by(node.name) is None:
                continue
            # every function of this package is annotated, mypy running
            # strict over it, so an unannotated one is a state the tree
            # does not reach
            assert node.returns is not None
            found[f"{module}.{node.name}"] = ast.unparse(node.returns)
    return found


def _argument_less_bools() -> dict[str, bool]:
    """Return every public argument-less bool, and whether it is a property.

    "No argument" means none besides `self`: a bool about the object it is
    read off, which is the family the question applies to. One that takes
    something is a function of it, and `@property` is not open to it.
    """
    found: dict[str, bool] = {}
    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        # classes and what is in them, not `ast.walk(tree)`: a property is
        # a class thing, which is what `_class_members` below says in as
        # many words, so a module-level function is out of scope however
        # few arguments it takes and cannot be told to become one
        for cls in ast.walk(tree):
            if not isinstance(cls, ast.ClassDef):
                continue
            for node in ast.walk(cls):
                if not isinstance(node, ast.FunctionDef) or node.name.startswith("_"):
                    continue
                if node.returns is None or ast.unparse(node.returns) != "bool":
                    continue
                arguments = [
                    a.arg
                    for a in [
                        *node.args.posonlyargs,
                        *node.args.args,
                        *node.args.kwonlyargs,
                    ]
                    if a.arg != "self"
                ]
                if arguments:
                    continue
                decorated = {ast.unparse(d) for d in node.decorator_list}
                found[f"{module}.{node.name}"] = _is_a_read(decorated)
    return found


# an argument-less member of a public class is a read, and a read is a
# `@property`. These are the shapes that are not a read, by what they do
# rather than by a list of names -- which is what keeps the rule from
# needing one (issue btclib-org/btclib#814):
#
# - `assert_*` refuses, and a property that refuses is a trap: reading
#   `obj.assert_valid` evaluates the method and throws it away
# - `get_*` talks to a node or an explorer, so it costs a round trip and
#   can fail; the prefix is the warning and a property would hide it
# - `to_*` converts, and hands back a new object rather than a read of
#   this one
# - `close` and `clear` are each an action with a side effect
_NOT_A_READ = ("assert_", "get_", "to_")
_AN_ACTION = frozenset({"clear", "close"})


def _is_a_read(decorated: set[str]) -> bool:
    """Return whether the decorators make this a read rather than a call.

    `functools.cached_property` is one as much as `property` is, and this
    function is what keeps the set from being written twice.
    """
    return bool(
        decorated & {"property", "cached_property", "functools.cached_property"}
    )


def _class_members() -> dict[str, bool]:
    """Return every argument-less member of a public class, property or not.

    A property is a class thing, so a module-level function is out of
    scope however few arguments it takes. Methods of a private class are
    out too: they are not API.
    """
    found: dict[str, bool] = {}
    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for cls in ast.walk(tree):
            if not isinstance(cls, ast.ClassDef) or cls.name.startswith("_"):
                continue
            for node in cls.body:
                if not isinstance(node, ast.FunctionDef) or node.name.startswith("_"):
                    continue
                decorated = {ast.unparse(d) for d in node.decorator_list}
                if {"staticmethod", "classmethod"} & decorated:
                    continue
                # no filter for a `@x.setter`: one takes the value it
                # sets, so the argument count below excludes it already
                arguments = [
                    a.arg
                    for a in [
                        *node.args.posonlyargs,
                        *node.args.args,
                        *node.args.kwonlyargs,
                    ]
                    if a.arg != "self"
                ]
                if arguments or node.args.vararg or node.args.kwarg:
                    continue
                key = f"{module}.{cls.name}.{node.name}"
                found[key] = _is_a_read(decorated)
    return found


def _public_bools() -> list[str]:
    """Return every public function that answers a bool, however named.

    The dotted name drops the class, as `_named` above does: a method and
    a module function of one name are one entry, which is the spelling
    `input_validation_test.py` uses too.
    """
    found: list[str] = []
    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef) or node.name.startswith("_"):
                continue
            if node.returns is not None and ast.unparse(node.returns) == "bool":
                found.append(f"{module}.{node.name}")
    return sorted(found)


_NAMED = _named()
_GATED = sorted(set(_NAMED) - _OTHER_CONTRACT.keys())
_PUBLIC_BOOLS = _public_bools()
_ARGUMENT_LESS_BOOLS = _argument_less_bools()
_CLASS_MEMBERS = _class_members()


@pytest.mark.parametrize("dotted", _GATED)
def test_the_name_says_what_the_answer_is(dotted: str) -> None:
    """The rule, over every public name that carries one of the prefixes."""
    promised = _promised_by(dotted.rpartition(".")[2])
    assert _NAMED[dotted] == promised, (
        f"{dotted} returns {_NAMED[dotted]} where its name promises {promised}"
    )


@pytest.mark.parametrize("dotted", sorted(_OTHER_CONTRACT))
def test_what_is_excepted_still_needs_to_be(dotted: str) -> None:
    """An entry of `_OTHER_CONTRACT` cannot outlive the reason for it."""
    promised = _promised_by(dotted.rpartition(".")[2])
    assert _NAMED[dotted] != promised, (
        f"{dotted} now returns {promised}: delete its line from _OTHER_CONTRACT"
    )


def test_the_walk_reaches_what_it_claims() -> None:
    """One name per prefix it must find, and the two kinds it must not.

    A walk that found nothing would pass the test above.
    """
    assert _NAMED["btclib_wallet.hwi.is_usable"] == "bool"
    assert _NAMED["btclib_wallet.bip322.verify"] == "bool"
    assert _NAMED["btclib_wallet.psbt.musig2.partial_sig_verify"] == "bool"
    assert _NAMED["btclib_wallet.bip322.assert_as_valid"] == "None"
    # a method, and a property among them
    assert _NAMED["btclib_wallet.bip32.bip32.is_private"] == "bool"

    # a private name, and a name that promises nothing
    assert "btclib_wallet.psbt.psbt._assert_partial_sigs_verify" not in _NAMED
    assert "btclib_wallet.bip32.bip32.derive" not in _NAMED


def test_check_says_nothing_here() -> None:
    """`check_` names no function of this package.

    The prefix is the one that answers a bool and refuses too, and pinning
    its absence keeps a first `check_` from being added without the
    question being asked: a refusal is an `assert_`, a converter is named
    for what it returns, and a query for what it answers.
    """
    assert {d for d in _NAMED if d.rpartition(".")[2].startswith("check_")} == set()


@pytest.mark.parametrize("dotted", _PUBLIC_BOOLS)
def test_every_public_bool_is_named_by_the_vocabulary(dotted: str) -> None:
    """A bool carries one of the four prefixes, or is named in the list.

    What this closes is the gap the prefixes alone leave: they promise a
    shape to a caller who sees one, and say nothing about a bool that
    carries none. So a bool either carries a prefix or is a decision
    somebody wrote down, with the reason each entry gives.
    """
    name = dotted.rpartition(".")[2]
    assert _promised_by(name) is not None or dotted in _ENGLISH_PREDICATE, (
        f"{dotted} answers a bool and its name promises nothing"
    )


@pytest.mark.parametrize("dotted", sorted(_ENGLISH_PREDICATE))
def test_what_keeps_its_english_name_still_needs_to(dotted: str) -> None:
    """A line of `_ENGLISH_PREDICATE` cannot outlive the name it excuses."""
    assert dotted in _PUBLIC_BOOLS, f"{dotted} is no longer a public bool"
    name = dotted.rpartition(".")[2]
    assert _promised_by(name) is None, (
        f"{dotted} carries a prefix now: delete its line from _ENGLISH_PREDICATE"
    )


@pytest.mark.parametrize("dotted", sorted(_ARGUMENT_LESS_BOOLS))
def test_a_bool_about_the_object_is_a_property(dotted: str) -> None:
    """A bool taking nothing but `self` is read, not called.

    The shape a reader has to remember is one shape (issue
    btclib-org/btclib#814). It also spends the one hazard `truthy-function`
    covers rather than relying on it: `if key.is_private:` with the
    parentheses forgotten would be a bound method, and every bound method
    is true. mypy names that, and mypy is a gate here; a property makes it
    unsayable, which is the stronger of the two.
    """
    assert _ARGUMENT_LESS_BOOLS[dotted], (
        f"{dotted} answers a bool about the object and takes nothing:"
        " it is a @property, not a method"
    )


def test_the_walk_reaches_both_shapes() -> None:
    """One of each shape, so the filter is doing work rather than nothing."""
    assert _ARGUMENT_LESS_BOOLS["btclib_wallet.bip32.bip32.is_private"] is True
    # a bool of an argument is a function of it, and no property can be
    assert "btclib_wallet.psbt.musig2.partial_sig_verify" not in _ARGUMENT_LESS_BOOLS
    assert "btclib_wallet.bip322.verify" not in _ARGUMENT_LESS_BOOLS


@pytest.mark.parametrize("dotted", sorted(_CLASS_MEMBERS))
def test_an_argument_less_member_is_read_not_called(dotted: str) -> None:
    """Whatever it answers, a member that takes nothing is a `@property`.

    The bool rule above, generalised to every return type: two reads of
    one object spelled two ways are two shapes to remember for one.

    What is not a read is here by shape and not by a list of names, which
    is what keeps this rule from needing one.
    """
    name = dotted.rpartition(".")[2]
    if name.startswith(_NOT_A_READ) or name in _AN_ACTION:
        assert not _CLASS_MEMBERS[dotted], (
            f"{dotted} is a @property and its name says it is not a read:"
            " rename it, or drop the decorator"
        )
        return
    assert _CLASS_MEMBERS[dotted], (
        f"{dotted} takes nothing but self: it is a @property, not a method"
    )


def test_the_walk_reaches_every_shape_of_member() -> None:
    """One of each, so neither branch above is running over nothing."""
    assert _CLASS_MEMBERS["btclib_wallet.psbt.psbt_view.PsbtView.prevouts"] is True
    assert (
        _CLASS_MEMBERS["btclib_wallet.psbt_signer.PsbtSigner.master_fingerprint"]
        is True
    )
    # and the shapes that are not a read
    assert _CLASS_MEMBERS["btclib_wallet.psbt.psbt.Psbt.assert_valid"] is False
    assert _CLASS_MEMBERS["btclib_wallet.psbt.psbt.Psbt.to_v2"] is False
    assert _CLASS_MEMBERS["btclib_wallet.hwi.HwiSigner.close"] is False
    assert (
        _CLASS_MEMBERS["btclib_wallet.fetch.fetcher.Fetcher.get_block_count"] is False
    )
