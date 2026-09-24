# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The gate for the two rules about a public function's inputs.

> Every public function guarantees the validation of all its inputs,
> directly or indirectly. A malformed argument leaves as
> `BTClibTypeError` or `BTClibValueError`.

btclib's rule, and which of the two classes comes out is not a coin toss
-- it is the distinction issue btclib-org/btclib#814 settled, so this file
drives the two separately:

- **a value of a type the signature does not declare** is the caller's
  own mistake, and leaves as a `BTClibTypeError`.
- **a value of a declared type that no valid input carries** is a fact
  about the input, and leaves as a `BTClibException`.

btclib's own `input_validation_test.py` walks btclib, and this one walks
this package with the same vocabulary.

## How it calls what it calls

The input types are few and well bounded, most of them named in btclib's
`alias.py` and the rest beside their converters.
`_WRONG_TYPE` and `_WRONG_VALUE` give each of them values of the two
kinds, and the walk finds every public module-level function whose
*required* parameters are all of those types. Those it can call with no
fixture and no knowledge of what the function does.

Every argument is wrong at once, which is not weaker than one wrong
argument among valid ones: whichever the function refuses first, the rule
says how it must refuse it. And it needs no valid values, which is what
makes the walk automatic -- a valid `Octets` is 20 bytes for one
function, 32 for another and any length for a third, so the table of
those is the hand-written thing this avoids.

## What it does not reach

A **parameter with a default** is never driven: to reach it the arguments
before it would have to be valid, which is the table this design is built
to do without. `tests/curve_parameter_test.py` and
`tests/bool_parameter_test.py` carry that table for the two families of
them large enough to be walked.

A **method**, and a function taking a `Tx`, a `Psbt` or a callback, needs
a valid instance the vocabulary cannot build, and
`tests/built_object_contract_test.py` and `tests/bool_contract_test.py`
drive those from fixtures instead. `test_the_walk_reaches_what_it_claims`
pins what the walk does find, so a narrowing of it fails here rather than
quietly running over less.

A function answering a `bool` about a wrong value would answer `False`
rather than refuse it; no function the walk reaches here answers one.

A function whose answer is a reading of any value of its type, rather
than a check of it, answers a wrong value too: `_ANSWERS_A_WRONG_VALUE`
names each the walk reaches, with its reason, and the second rule is
asserted of them the other way round.
"""

from __future__ import annotations

import ast
import importlib
from collections.abc import Callable, Iterator
from functools import partial
from pathlib import Path
from typing import Any

import btclib
import pytest
from btclib.exceptions import BTClibException, BTClibTypeError

_LIBRARY = Path(__file__).parents[1] / "src" / "btclib_wallet"
# where btclib declares the library input types this package takes, the
# rest being declared at module level in this package
_ALIAS_PY = Path(btclib.__file__).parent / "alias.py"

# a value of no type the alias declares: the caller's own mistake, and a
# call mypy refuses. The tuples are read round-robin so that a function
# taking three parameters of one type is called with three different
# wrong values. Constants and not a strategy: what this gate reports has
# to be the same on two runs, the lists below being read as statements
# about the tree
_WRONG_TYPE: dict[str, tuple[Any, ...]] = {
    "BIP32Key": (None, 1.5),
    # bytes, which int(x, 2) reads as the digits they spell
    "BinStr": (None, 1.5, 1, b"0101"),
    "BinaryData": (None, 1.5),
    "DerPath": (None, 1.5),
    # an int is an Entropy
    "Entropy": (None, 1.5),
    "Integer": (None, 1.5),
    # an Octets, beside None and 1.5: every Octets is itself iterable, so
    # a signature reading Sequence[Octets] or Iterable[Octets] accepts
    # one as far as mypy goes, and a function that does not refuse it by
    # name zips through its bytes instead (issue btclib-org/btclib#1405).
    # All four Octets spellings, a guard naming three of the four
    # otherwise passing this walk (issue btclib-org/btclib#1434)
    "Iterable[Octets]": (
        None,
        1.5,
        b"\xaa\xbb\xcc\xdd",
        bytearray(b"\xaa\xbb\xcc\xdd"),
        memoryview(b"\xaa\xbb\xcc\xdd"),
    ),
    "Mnemonic": (None, 1.5, b"abandon"),
    "Octets": (None, 1.5, tuple(range(4))),
    "Point": (None, 1.5, "not a point"),
    "PubKey": (None, 1.5),
    "Sequence[Octets]": (
        None,
        1.5,
        b"\xaa\xbb\xcc\xdd",
        bytearray(b"\xaa\xbb\xcc\xdd"),
        memoryview(b"\xaa\xbb\xcc\xdd"),
    ),
    "String": (None, 1.5, 1),
}

# a value of a declared type that no valid input carries: a fact about
# the input. Every one
# of these type checks -- that is what puts it in this dict rather than
# in the one above -- so a `# type: ignore` is never needed to build the
# call, which is the same line drawn twice
_WRONG_VALUE: dict[str, tuple[Any, ...]] = {
    "BIP32Key": ("not an xkey",),
    "BinStr": ("not binary",),
    "BinaryData": ("not hex at all",),
    # a string no path spelling reads, an index below zero, and one above
    # the four bytes a BIP32 index has
    "DerPath": ("m/x", -1, [2**32]),
    # a string that is not 0/1 digits, and an int below zero
    "Entropy": ("not binary", -1),
    "Integer": ("not hex at all",),
    # a hex string that is not hex, and one of odd length
    "Octets": ("not hex at all", "9"),
    # a tuple of the wrong arity, and a pair of ints that is no point:
    # run time cannot tell tuple[int] from tuple[int, int], so the arity
    # is a value here and not a type
    "Iterable[Octets]": (["not hex at all"],),
    "Mnemonic": ("not a mnemonic",),
    "Point": ((1,), (1, 2)),
    "PubKey": ("not a key",),
    "Sequence[Octets]": (["not hex at all"],),
    "String": ("not an address",),
}


def _alias_of(annotation: ast.expr) -> str | None:
    """Return the input type an annotation names, `X | None` included."""
    name = ast.unparse(annotation).replace(" | None", "").strip()
    return name if name in _WRONG_TYPE else None


def _drivable() -> dict[str, list[str]]:
    """Return every public function the vocabulary can call, by dotted name.

    Required parameters only: what carries a default is what a caller may
    leave out, so a function is driven on the arguments it insists on.
    All of them have to be in the vocabulary -- one `Tx` and the walk has
    nothing to pass.
    """
    found: dict[str, list[str]] = {}
    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        for node in ast.parse(path.read_text(encoding="utf-8")).body:
            if not isinstance(node, ast.FunctionDef) or node.name.startswith("_"):
                continue
            positional = [*node.args.posonlyargs, *node.args.args]
            required = positional[: len(positional) - len(node.args.defaults)]
            # `is not None` narrows for mypy and never filters: mypy runs
            # strict over this package, so a parameter without an
            # annotation is a state the library does not reach
            annotations = [a.annotation for a in required if a.annotation is not None]
            aliases = [_alias_of(a) for a in annotations]
            if required and len(aliases) == len(required) and all(aliases):
                found[f"{module}.{node.name}"] = [a for a in aliases if a]
    return found


_DRIVABLE = _drivable()


def _calls(
    dotted: str, vocabulary: dict[str, tuple[Any, ...]]
) -> Iterator[Callable[[], Any]]:
    """Yield one prepared call per round, every argument wrong at once.

    The vocabulary is the parameter, and it is the whole of what tells the
    two rules apart: the same walk, the same function, two kinds of wrong
    value.
    """
    module_name, _, name = dotted.rpartition(".")
    function = getattr(importlib.import_module(module_name), name)
    aliases = _DRIVABLE[dotted]
    for round_ in range(max(len(vocabulary[a]) for a in aliases)):
        args = [vocabulary[a][round_ % len(vocabulary[a])] for a in aliases]
        # partial and not a lambda, which would close over the loop
        # variables and be read on a later round
        yield partial(function, *args)


_DRIVEN = sorted(_DRIVABLE)

# what answers every wrong value of _WRONG_VALUE instead of refusing it,
# by dotted name, with the reason that is its contract
_ANSWERS_A_WRONG_VALUE = {
    # a sentence no scheme claims: the empty list, and "", are the answers
    # the two docstrings give for it
    "btclib_wallet.mnemonic.dispatch.all_seed_types_from_mnemonic",
    "btclib_wallet.mnemonic.dispatch.seed_type_from_mnemonic",
    # a reading of the sentence that checks nothing of its value, so any
    # str is normalized whether or not it is a mnemonic
    "btclib_wallet.mnemonic.mnemonic.normalize_mnemonic",
}


@pytest.mark.parametrize("dotted", _DRIVEN)
def test_a_wrong_type_leaves_as_a_btclib_type_error(dotted: str) -> None:
    """The first rule, and it has no exceptions.

    `BTClibTypeError` and not `BTClibException`: this is where the class
    is the point. A bare `TypeError` fails here as a `BTClibValueError`
    does -- the first is a leak from underneath the library, the second
    is the library calling a caller's mistake a fact about the input.
    """
    for call in _calls(dotted, _WRONG_TYPE):
        with pytest.raises(BTClibTypeError):
            call()


@pytest.mark.parametrize(
    "dotted", [d for d in _DRIVEN if d not in _ANSWERS_A_WRONG_VALUE]
)
def test_a_wrong_value_leaves_as_a_btclib_exception(dotted: str) -> None:
    """The second rule, over what the walk drives and does not answer.

    `BTClibException` and not one of the three: which of them a malformed
    value deserves is the function's to decide -- a size is a
    `BTClibValueError`, a bool where a number belongs is a
    `BTClibTypeError` -- and the contract a caller is given is the base.
    """
    for call in _calls(dotted, _WRONG_VALUE):
        with pytest.raises(BTClibException):
            call()


@pytest.mark.parametrize("dotted", sorted(_ANSWERS_A_WRONG_VALUE))
def test_what_answers_a_wrong_value_answers_it(dotted: str) -> None:
    """An exemption from the second rule holds, or it is one left behind.

    A function in `_ANSWERS_A_WRONG_VALUE` that starts refusing, or that
    the walk stops reaching, fails here.
    """
    assert dotted in _DRIVABLE
    for call in _calls(dotted, _WRONG_VALUE):
        call()


def test_the_vocabulary_is_the_libraries_input_types() -> None:
    """A renamed type would narrow the walk without failing anything.

    Every name in the two vocabularies is still declared, in this package
    or in btclib, and every type btclib's `alias.py` or a module of this
    package declares and a public parameter of this package is annotated
    with is either in the vocabulary or named below with the reason it is
    not.
    """
    declared: set[str] = set()
    in_alias_py: set[str] = set()
    own: set[str] = set()
    annotated: set[str] = set()
    for path in sorted(
        [*_LIBRARY.rglob("*.py"), *Path(btclib.__file__).parent.rglob("*.py")]
    ):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = {
            node.targets[0].id
            for node in tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id[0].isupper()
        }
        declared |= names
        if not path.is_relative_to(_LIBRARY):
            if path == _ALIAS_PY:
                in_alias_py = names
            continue
        own |= names
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef) or node.name.startswith("_"):
                continue
            arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            annotated |= {
                ast.unparse(a.annotation).replace(" | None", "").strip()
                for a in arguments
                if a.annotation is not None
            }

    # `Sequence[Octets]` and `Iterable[Octets]` are not declarations of
    # their own -- `Octets` is -- so a renamed `Octets` is still caught
    # by unwrapping one level before checking
    def _is_declared(alias: str) -> bool:
        for wrapper in ("Sequence[", "Iterable["):
            if alias.startswith(wrapper) and alias.endswith("]"):
                return alias[len(wrapper) : -1] in declared
        return alias in declared

    assert set(_WRONG_TYPE) == set(_WRONG_VALUE)
    assert all(_is_declared(alias) for alias in _WRONG_TYPE)

    without_a_wrong_value = {
        # a Literal: a value outside it is what mypy refuses, and a test
        # passing one would be testing the type checker
        "BIP44ScriptType",
        # callbacks, which the module docstring's *What it does not reach*
        # leaves to the fixture tests
        "BlockCipherF",
        "InputSolver",
        "SolutionSizer",
        # behind a default wherever a public parameter takes it, and a
        # parameter with a default is never driven
        "OneOrMoreInt",
        "PrvKeys",
    }
    covered = (in_alias_py | own) & annotated
    assert covered <= set(_WRONG_TYPE) | without_a_wrong_value
    # an exemption that matches nothing, or names a type the walk drives,
    # is one left behind
    assert without_a_wrong_value <= covered
    assert not without_a_wrong_value & set(_WRONG_TYPE)


def test_the_walk_reaches_what_it_claims() -> None:
    """The shapes the walk must find, and two it must not.

    A walk that found nothing would pass every test above. One function
    per shape it has to reach -- a single parameter, two of different
    types, one behind a default it must ignore -- and the two kinds it
    must leave alone: a private name, and a function whose required
    parameters are not all in the vocabulary.
    """
    assert _DRIVABLE["btclib_wallet.bip32.der_path.str_from_der_path"] == ["DerPath"]
    assert _DRIVABLE["btclib_wallet.bip32.bip32.derive"] == ["BIP32Key", "DerPath"]
    # `version` carries a default and is not driven
    assert _DRIVABLE["btclib_wallet.bip32.bip32.rootxprv_from_seed"] == ["Octets"]

    assert "btclib_wallet.bip32.bip32._derive" not in _DRIVABLE
    # a required parameter the vocabulary cannot build: a Psbt
    assert "btclib_wallet.psbt.psbt.finalize" not in _DRIVABLE
