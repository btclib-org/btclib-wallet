# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A fuzz/corpus/ seed is still a valid serialization of what it parses.

`fuzz/fuzz_<name>.py` and `fuzz/corpus/fuzz_<name>/` are read from disk;
neither is imported. Every harness imports atheris at module level,
which is CI-only and undeclared in `[dependency-groups]`, so this module
never runs `import fuzz.fuzz_<name>` and never executes a harness's own
code -- it parses the source with `ast` and resolves what a harness
*names* against the installed btclib_wallet instead.

`ENTRY_POINTS`, a module-level tuple of `"module:Qual.name"` string
literals, is what each harness names. `test_entry_points_are_declared`
below finds it with `ast.literal_eval`; `test_entry_points_match_the_calls`
cross-checks it against the `.parse`/`.b64decode`/`.b58decode` calls
`fuzz_target`'s own body makes, walked with `ast` rather than matched
with a regex -- a character class for the callee would still have to
answer which import a bare name resolves to.

`test_every_seed_is_accepted` and `test_accepted_seed_round_trips` are
the corpus half: every seed is tried against every one of its harness's
declared entry points, and passes if at least one accepts it without
raising `BTClibException`. Where the accepting object serializes --
`.serialize()`, or `.b64encode()`/`.b58encode()` behind a `.b64decode()`
or `.b58decode()` entry point -- the reserialization has to reproduce
the seed's own bytes; where it does not (`descriptors.parse` returns a
`Descriptor` with no wire form of its own), the seed is accepted
parse-only and nothing else is asked of it.

`fuzz_bip32.py` calls three entry points against the same `data`, which
is where the price *Trying every declared entry point rather than
picking one by filename convention* below argues about would show if it
applied here: it does not, `BIP32KeyData.parse` requiring exactly 78
octets and `BIP32KeyOrigin.parse` requiring at least 4, so a seed built
for one is never mistaken for a round trip of the other by this gate,
measured by running `_accept` over this corpus.

A seed may legitimately be empty in principle -- no harness here has one
today -- so nothing here asks a seed to be non-empty, only that no seed
ends in the newline a fixer appends.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path
from typing import Any

import pytest
from btclib.exceptions import BTClibException

_FUZZ = Path(__file__).parent.parent / "fuzz"
_CORPUS = _FUZZ / "corpus"

# the one harness whose declared entry point takes text rather than
# bytes: fuzz_descriptor.py decodes with errors="replace" before calling
# btclib_wallet.descriptors.descriptors:parse, and a seed is tried the
# same way
_TEXT_HARNESS = "fuzz_descriptor"


def _harness_paths() -> tuple[Path, ...]:
    """Every fuzz/fuzz_*.py, sorted for a stable parametrize order."""
    return tuple(sorted(_FUZZ.glob("fuzz_*.py")))


def _parse_module(source: str, filename: str) -> ast.Module:
    return ast.parse(source, filename=filename)


def _entry_points(tree: ast.Module) -> tuple[str, ...] | None:
    """Return the module-level ENTRY_POINTS tuple of strings, or None."""
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "ENTRY_POINTS"
        ):
            value = ast.literal_eval(node.value)
            assert isinstance(value, tuple) and all(isinstance(v, str) for v in value)
            return value
    return None


def _fuzz_target(tree: ast.Module) -> ast.FunctionDef | None:
    """Return the module-level `def fuzz_target(...)`, or None."""
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "fuzz_target":
            return node
    return None


def _import_bindings(tree: ast.Module) -> dict[str, tuple[str, str]]:
    """Map a module-level `from X import Y [as Z]` local name to (X, Y)."""
    bindings: dict[str, tuple[str, str]] = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module is not None:
            for alias in node.names:
                bindings[alias.asname or alias.name] = (node.module, alias.name)
    return bindings


def _canonical_spec(module: str, remote: str, attr: str) -> str:
    """Return "module:Qual.name", telling a submodule bind from a class one.

    `from btclib_wallet.bip322 import Sig; Sig.b64decode(...)` binds a
    class, where `b64decode` is a method on it; a binding this corpus has
    none of today, `from X import Y; Y.parse(...)`, would bind a
    submodule instead, `parse` then being that module's own function.
    Trying the submodule import is what tells the two apart, both being
    an ordinary `from X import Y` to the AST alone.
    """
    try:
        importlib.import_module(f"{module}.{remote}")
    except ModuleNotFoundError:
        return f"{module}:{remote}.{attr}"
    return f"{module}.{remote}:{attr}"


def _called_specs(
    func: ast.FunctionDef, bindings: dict[str, tuple[str, str]]
) -> set[str]:
    """Every .parse/.b64decode/.b58decode call `func`'s body makes."""
    specs: set[str] = set()
    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        callee = node.func
        if not isinstance(callee, ast.Attribute):
            continue
        if callee.attr not in ("parse", "b64decode", "b58decode"):
            continue
        if not isinstance(callee.value, ast.Name):
            continue
        name = callee.value.id
        if name not in bindings:
            msg = f"{name!r} is called with .{callee.attr} and imported nowhere"
            raise AssertionError(msg)
        module, remote = bindings[name]
        specs.add(_canonical_spec(module, remote, callee.attr))
    return specs


def _resolve(spec: str) -> Any:
    """Import spec's ("module:Qual.name") callable against what is installed."""
    module_name, _, qualname = spec.partition(":")
    obj: Any = importlib.import_module(module_name)
    for part in qualname.split("."):
        obj = getattr(obj, part)
    return obj


def _round_trip(spec: str, obj: Any, data: bytes) -> bool | None:
    """Return whether `obj` reserializes to `data`, or None if unchecked."""
    attr = spec.rsplit(".", 1)[-1]
    if attr == "b64decode":
        if not hasattr(obj, "b64encode"):
            return None
        return bool(obj.b64encode() == data.decode("ascii"))
    if attr == "b58decode":
        if not hasattr(obj, "b58encode"):
            return None
        return bool(obj.b58encode() == data.decode("ascii"))
    if not hasattr(obj, "serialize"):
        return None
    return bool(obj.serialize() == data)


def _seed_paths(name: str) -> tuple[Path, ...]:
    return tuple(sorted((_CORPUS / name).glob("*.bin")))


def _accept(spec: str, data: bytes, harness: str) -> tuple[bool, bool | None]:
    """Try `spec` against `data`; return (accepted, round_trip)."""
    entry_point = _resolve(spec)
    argument: Any = (
        data.decode("utf-8", errors="replace") if harness == _TEXT_HARNESS else data
    )
    try:
        obj = entry_point(argument)
    except BTClibException:
        return False, None
    return True, _round_trip(spec, obj, data)


# ---- the corpus, read once so every test below parametrizes over it -------

_HARNESSES = _harness_paths()
_SEEDS = tuple(
    (path.stem, seed) for path in _HARNESSES for seed in _seed_paths(path.stem)
)


def test_the_corpus_is_not_empty() -> None:
    """Every assertion below quantifies over _HARNESSES and _SEEDS."""
    assert _HARNESSES, f"{_FUZZ} holds no fuzz_*.py"
    assert _SEEDS, f"{_CORPUS} holds no seed"


@pytest.mark.parametrize("path", _HARNESSES, ids=lambda p: p.stem)
def test_every_harness_has_a_corpus_directory(path: Path) -> None:
    """A harness with no seeds is one no gate here has ever checked."""
    assert (_CORPUS / path.stem).is_dir(), f"fuzz/corpus/{path.stem}/ does not exist"


def test_every_corpus_directory_has_a_harness() -> None:
    """A directory outliving the harness it was named for is dead weight."""
    harness_names = {path.stem for path in _HARNESSES}
    orphans = sorted(
        d.name for d in _CORPUS.iterdir() if d.is_dir() and d.name not in harness_names
    )
    assert not orphans, (
        f"fuzz/corpus/ directories with no fuzz_*.py: {', '.join(orphans)}"
    )


@pytest.mark.parametrize("path", _HARNESSES, ids=lambda p: p.stem)
def test_entry_points_are_declared(path: Path) -> None:
    """ENTRY_POINTS exists and is not the empty tuple."""
    tree = _parse_module(path.read_text(encoding="utf-8"), str(path))
    declared = _entry_points(tree)
    assert declared, f"{path.name} declares no non-empty ENTRY_POINTS"


@pytest.mark.parametrize("path", _HARNESSES, ids=lambda p: p.stem)
def test_entry_points_resolve(path: Path) -> None:
    """Each declared entry point imports against the installed btclib_wallet."""
    tree = _parse_module(path.read_text(encoding="utf-8"), str(path))
    declared = _entry_points(tree)
    assert declared
    for spec in declared:
        assert callable(_resolve(spec)), (
            f"{path.name}'s {spec!r} does not resolve to a callable"
        )


@pytest.mark.parametrize("path", _HARNESSES, ids=lambda p: p.stem)
def test_entry_points_match_the_calls(path: Path) -> None:
    """ENTRY_POINTS is exactly what fuzz_target's own body calls."""
    tree = _parse_module(path.read_text(encoding="utf-8"), str(path))
    declared = _entry_points(tree)
    assert declared
    func = _fuzz_target(tree)
    assert func is not None, f"{path.name} defines no module-level fuzz_target"
    bindings = _import_bindings(tree)
    called = _called_specs(func, bindings)
    assert called == set(declared), (
        f"{path.name}'s ENTRY_POINTS {sorted(declared)} does not match what"
        f" fuzz_target calls: {sorted(called)}"
    )


@pytest.mark.parametrize("path", _HARNESSES, ids=lambda p: p.stem)
def test_corpus_directory_is_not_empty(path: Path) -> None:
    """A harness's own directory holds at least one seed."""
    assert _seed_paths(path.stem), f"fuzz/corpus/{path.stem}/ has no seed"


@pytest.mark.parametrize(
    "seed",
    [seed for _, seed in _SEEDS],
    ids=[str(seed.relative_to(_CORPUS)) for _, seed in _SEEDS],
)
def test_seed_has_no_trailing_newline(seed: Path) -> None:
    """A newline a fixer appended is not a byte the seed's own owner wrote."""
    assert not seed.read_bytes().endswith(b"\n"), f"{seed} ends with a newline"


@pytest.mark.parametrize(
    "harness, seed",
    _SEEDS,
    ids=[str(seed.relative_to(_CORPUS)) for _, seed in _SEEDS],
)
def test_every_seed_is_accepted(harness: str, seed: Path) -> None:
    """At least one of the harness's declared entry points accepts the seed."""
    tree = _parse_module((_FUZZ / f"{harness}.py").read_text(encoding="utf-8"), harness)
    declared = _entry_points(tree)
    assert declared
    data = seed.read_bytes()
    accepted = [spec for spec in declared if _accept(spec, data, harness)[0]]
    assert accepted, f"{seed} is refused by every declared entry point: {declared}"


@pytest.mark.parametrize(
    "harness, seed",
    _SEEDS,
    ids=[str(seed.relative_to(_CORPUS)) for _, seed in _SEEDS],
)
def test_accepted_seed_round_trips(harness: str, seed: Path) -> None:
    """Where a round trip is checkable, it reproduces the seed byte for byte."""
    tree = _parse_module((_FUZZ / f"{harness}.py").read_text(encoding="utf-8"), harness)
    declared = _entry_points(tree)
    assert declared
    data = seed.read_bytes()
    mismatches = [
        spec
        for spec in declared
        for accepted, round_trip in (_accept(spec, data, harness),)
        if accepted and round_trip is False
    ]
    assert not mismatches, f"{seed} does not round-trip under: {mismatches}"


# ---- unit tests of the pure ast helpers, for the branches no harness trips


def _module(source: str) -> ast.Module:
    return ast.parse(source, filename="<synthetic>")


def test_entry_points_returns_none_absent() -> None:
    """A module with no ENTRY_POINTS assignment is not mistaken for one."""
    assert _entry_points(_module("x = 1\n")) is None


def test_fuzz_target_returns_none_absent() -> None:
    """A module with no fuzz_target is not mistaken for one."""
    assert _fuzz_target(_module("def other() -> None:\n    pass\n")) is None


def test_called_specs_rejects_an_unbound_callee() -> None:
    """A callee this test cannot trace to an import is a loud failure.

    Never trips on the harnesses this corpus has, each of whose calls
    resolves directly through an import; this is what a harness calling
    something imported neither way would hit instead of being silently
    skipped.
    """
    source = "def fuzz_target(data):\n    unknown.parse(data)\n"
    func = _fuzz_target(_module(source))
    assert func is not None
    with pytest.raises(AssertionError, match="imported nowhere"):
        _called_specs(func, {})


def test_called_specs_ignores_a_bare_name_call() -> None:
    """A call with no namespace in front, `parse(data)`, is not checked.

    Every entry point in this corpus is reached through an imported name
    or a class, never a bare function in local scope, and no harness
    calls one this way today.
    """
    source = "def fuzz_target(data):\n    parse(data)\n"
    func = _fuzz_target(_module(source))
    assert func is not None
    assert _called_specs(func, {}) == set()


def test_called_specs_ignores_a_two_level_attribute() -> None:
    """`foo.bar.parse(data)` is not one of the calls checked either.

    Every current call is one attribute deep -- `Name.attr(...)` -- which
    is what `_import_bindings` resolves; a chain one level deeper has no
    binding this test can look up, and no harness here writes one.
    """
    source = "def fuzz_target(data):\n    foo.bar.parse(data)\n"
    func = _fuzz_target(_module(source))
    assert func is not None
    assert _called_specs(func, {}) == set()


def test_round_trip_is_unchecked_when_b64decode_has_no_b64encode() -> None:
    """A b64decode entry point whose object cannot re-armor is parse-only.

    No harness's declared b64decode entry point lacks a b64encode
    counterpart today -- Sig and Psbt both carry one -- so this is
    exercised on a bare object rather than on any seed.
    """
    assert _round_trip("btclib_wallet.bip322:Sig.b64decode", object(), b"") is None


def test_round_trip_is_unchecked_when_b58decode_has_no_b58encode() -> None:
    """A b58decode entry point whose object cannot re-armor is parse-only.

    No harness's declared b58decode entry point lacks a b58encode
    counterpart today -- BIP32KeyData carries one -- so this is
    exercised on a bare object rather than on any seed.
    """
    assert (
        _round_trip("btclib_wallet.bip32.bip32:BIP32KeyData.b58decode", object(), b"")
        is None
    )
