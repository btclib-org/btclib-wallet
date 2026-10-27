# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A fuzz/corpus/ seed is still a valid serialization of what it parses.

The entry-point checks read `fuzz/fuzz_<name>.py` with `ast` and resolve
what a harness names against the installed btclib_wallet. Every harness
imports atheris, which is CI-only and undeclared in `[dependency-groups]`.
`test_seed_runs_its_harness` loads a harness with an atheris placeholder,
and runs its pure target on every seed of its corpus without starting the
fuzz engine: the checks a target makes after the read run in the suite
too.

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
parse-only here, and `test_descriptor_seed_prints_back` below asks the
rest.

`fuzz_bip32.py` calls three entry points against the same `data`, which
is where the price *Trying every declared entry point rather than
picking one by filename convention* below argues about would show if it
applied here: it does not, `BIP32KeyData.parse` requiring exactly 78
octets and `BIP32KeyOrigin.parse` requiring at least 4, so a seed built
for one is never mistaken for a round trip of the other by this gate,
measured by running `_accept` over this corpus.

`test_descriptor_seed_prints_back` is the descriptor half: `parse` has no
wire form, so a descriptor seed is held to the normal form that
`fuzz/fuzz_descriptor.py` states, and to a checksum that is valid. A seed
in normal form prints back as written, the checksum aside;
`_REWRITTEN_SEEDS` names the seeds that the normal form rewrites.

`test_psbt_crash_inputs_are_seeds` ties the two rust-bitcoin psbts that
`tests/psbt/psbt_crash_inputs_test.py` reads to their `fuzz_psbt` seeds,
and `test_psbt_vectors_are_seeds` ties the psbt vectors that
`fuzz/fuzz_psbt.py` names as seeds to theirs.

A seed may legitimately be empty in principle -- no harness here has one
today -- so nothing here asks a seed to be non-empty, only that no seed
ends in the newline a fixer appends.
"""

from __future__ import annotations

import ast
import base64
import importlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest
from btclib.exceptions import BTClibException, BTClibValueError

from btclib_wallet.bip32.bip32 import BIP32KeyData
from btclib_wallet.bip32.key_origin import BIP32KeyOrigin
from btclib_wallet.bip322 import Sig
from btclib_wallet.descriptors import descriptors, miniscript
from btclib_wallet.descriptors.key_expression import KeyExpression
from btclib_wallet.psbt.psbt import PSBT_MAGIC_BYTES, Psbt

_TESTS = Path(__file__).parent
_FUZZ = _TESTS.parent / "fuzz"
_CORPUS = _FUZZ / "corpus"
_PSBT_DATA = _TESTS / "psbt" / "_data"

# the one harness whose declared entry point takes text rather than
# bytes: fuzz_descriptor.py decodes with errors="replace" before calling
# btclib_wallet.descriptors.descriptors:parse, and a seed is tried the
# same way
_TEXT_HARNESS = "fuzz_descriptor"

_REWRITTEN_SEEDS = frozenset(
    {
        "bip381_pk_wif",
        "bip386_tr_pkh_leaf",
        "bip386_tr_ranged_private",
        "bip386_tr_tree_private",
        "own_pkh_mixed_hardened_markers",
    }
)


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


_DESCRIPTOR_SEEDS = tuple(seed for harness, seed in _SEEDS if harness == _TEXT_HARNESS)


@pytest.mark.parametrize(
    "seed",
    _DESCRIPTOR_SEEDS,
    ids=[seed.stem for seed in _DESCRIPTOR_SEEDS],
)
def test_descriptor_seed_prints_back(seed: Path) -> None:
    """A descriptor seed's checksum is valid and its normal form is stable."""
    text = seed.read_text(encoding="utf-8")
    printed = str(descriptors.parse(text))
    assert str(descriptors.parse(printed)) == printed
    if seed.stem in _REWRITTEN_SEEDS:
        stripped = descriptors.strip_checksum(text)
        assert descriptors.add_checksum(stripped) == text
        assert printed != stripped
    else:
        assert descriptors.add_checksum(printed) == text


def test_every_rewritten_seed_exists() -> None:
    """A name in _REWRITTEN_SEEDS that is no seed would exempt nothing."""
    assert {seed.stem for seed in _DESCRIPTOR_SEEDS} >= _REWRITTEN_SEEDS


def _load_harness(name: str, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load a target without loading its CI-only fuzz engine."""
    monkeypatch.setitem(sys.modules, "atheris", ModuleType("atheris"))
    spec = importlib.util.spec_from_file_location(name, _FUZZ / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def descriptor_harness(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the descriptor target with an atheris placeholder."""
    return _load_harness(_TEXT_HARNESS, monkeypatch)


@pytest.fixture
def bip32_harness(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the BIP32 target with an atheris placeholder."""
    return _load_harness("fuzz_bip32", monkeypatch)


@pytest.fixture
def bip322_harness(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the BIP322 target with an atheris placeholder."""
    return _load_harness("fuzz_bip322", monkeypatch)


@pytest.mark.parametrize(
    "harness, seed",
    _SEEDS,
    ids=[str(seed.relative_to(_CORPUS)) for _, seed in _SEEDS],
)
def test_seed_runs_its_harness(
    monkeypatch: pytest.MonkeyPatch, harness: str, seed: Path
) -> None:
    """A seed passes every check its target makes after the read."""
    _load_harness(harness, monkeypatch).fuzz_target(seed.read_bytes())


def _bip32_seed(name: str) -> bytes:
    return (_CORPUS / "fuzz_bip32" / f"{name}.bin").read_bytes()


@pytest.mark.parametrize(
    "seed, message",
    [
        ("xpub_binary", "^extended key does not serialize back to its input$"),
        ("xpub", "^extended key does not encode back to its input$"),
    ],
)
def test_bip32_harness_refuses_a_key_that_reads_back_otherwise(
    bip32_harness: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    seed: str,
    message: str,
) -> None:
    """A serializer that writes another depth fails either comparison."""
    original = BIP32KeyData.serialize

    def deeper(key: BIP32KeyData, *, check_validity: bool = True) -> bytes:
        serialized = original(key, check_validity=check_validity)
        return serialized[:4] + bytes([serialized[4] + 1]) + serialized[5:]

    monkeypatch.setattr(BIP32KeyData, "serialize", deeper)
    with pytest.raises(AssertionError, match=message):
        bip32_harness.fuzz_target(_bip32_seed(seed))


def test_bip32_harness_refuses_an_origin_that_reads_back_otherwise(
    bip32_harness: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A key origin that serializes longer than its input is a finding."""
    original = BIP32KeyOrigin.serialize

    def longer(origin: BIP32KeyOrigin, *, check_validity: bool = True) -> bytes:
        return original(origin, check_validity=check_validity) + bytes(4)

    monkeypatch.setattr(BIP32KeyOrigin, "serialize", longer)
    with pytest.raises(
        AssertionError, match="^key origin does not serialize back to its input$"
    ):
        bip32_harness.fuzz_target(_bip32_seed("key_origin"))


@pytest.mark.parametrize(
    "seed, neutered", [("xprv", 1), ("xpub", 0), ("xpub_binary", 0)]
)
def test_bip32_harness_derives_each_key(
    bip32_harness: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    seed: str,
    neutered: int,
) -> None:
    """Each accepted key derives a child, and a private one its xpub."""
    derive = Mock(wraps=bip32_harness.derive_)
    neuter = Mock(wraps=bip32_harness.xpub_from_xprv_)
    monkeypatch.setattr(bip32_harness, "derive_", derive)
    monkeypatch.setattr(bip32_harness, "xpub_from_xprv_", neuter)

    bip32_harness.fuzz_target(_bip32_seed(seed))

    derive.assert_called_once()
    assert neuter.call_count == neutered


def test_bip32_harness_lets_a_refused_derivation_pass(
    bip32_harness: ModuleType,
) -> None:
    """A key at depth 255 has no child, which is a refusal and no finding."""
    data = _bip32_seed("xpub_binary")
    deepest = data[:4] + b"\xff" + b"\x01\x02\x03\x04" + data[9:]
    with pytest.raises(BTClibValueError, match="final depth greater than 255"):
        bip32_harness.derive_(BIP32KeyData.parse(deepest), 0)
    bip32_harness.fuzz_target(deepest)


@pytest.mark.parametrize("operation", ["derive_", "xpub_from_xprv_"])
def test_bip32_harness_propagates_a_derivation_defect(
    bip32_harness: ModuleType, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    """Only the two exception families may leave a derivation quietly."""

    def fail(*_: object) -> None:
        raise IndexError("derivation failed")

    monkeypatch.setattr(bip32_harness, operation, fail)
    with pytest.raises(IndexError, match="^derivation failed$"):
        bip32_harness.fuzz_target(_bip32_seed("xprv"))


def test_bip322_harness_refuses_an_armor_that_reads_back_otherwise(
    bip322_harness: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A signature whose armor decodes to another signature is a finding."""
    smp, ful = (
        (_CORPUS / "fuzz_bip322" / f"{name}.bin").read_text(encoding="ascii")
        for name in ("smp", "ful")
    )
    monkeypatch.setattr(Sig, "b64encode", Mock(side_effect=[smp, ful]))
    with pytest.raises(AssertionError, match="^signature armor is not a fixed point$"):
        bip322_harness.fuzz_target(smp.encode())


def test_bip322_harness_propagates_a_refusal_of_its_own_armor(
    bip322_harness: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the first decode may refuse quietly; the second is a finding."""
    smp = (_CORPUS / "fuzz_bip322" / "smp.bin").read_text(encoding="ascii")
    monkeypatch.setattr(Sig, "b64encode", Mock(return_value=smp + "A"))
    with pytest.raises(BTClibException):
        bip322_harness.fuzz_target(smp.encode())


def test_bip322_harness_reads_an_unprefixed_simple_signature(
    bip322_harness: ModuleType,
) -> None:
    """A simple signature may omit its prefix, so only a fixed point holds."""
    smp = (_CORPUS / "fuzz_bip322" / "smp.bin").read_text(encoding="ascii")
    unprefixed = smp.removeprefix("smp")
    assert unprefixed != smp
    assert Sig.b64decode(unprefixed).b64encode() == smp
    bip322_harness.fuzz_target(unprefixed.encode())


@pytest.mark.parametrize("loss", ["origin", "wildcard", "key"])
def test_descriptor_harness_refuses_a_lossy_print(
    descriptor_harness: ModuleType, monkeypatch: pytest.MonkeyPatch, loss: str
) -> None:
    """A stable printer can still lose an origin, a wildcard or a key."""
    seed = _CORPUS / _TEXT_HARNESS / "bip386_tr_ranged_private.bin"
    xpub = descriptors.parse(seed.read_text(encoding="utf-8")).key_expressions[0].xkey
    key_seed = _CORPUS / _TEXT_HARNESS / "ms_or_b_and_b.bin"
    keys = descriptors.parse(key_seed.read_text(encoding="utf-8")).key_expressions
    key, other = map(str, keys[:2])
    text = f"wpkh([deadbeef]{xpub}/*)" if loss == "wildcard" else f"pk([deadbeef]{key})"
    original = KeyExpression.__str__

    def lossy_print(expression: KeyExpression) -> str:
        printed = original(expression)
        if loss == "origin":
            return printed.replace("[deadbeef]", "")
        if loss == "wildcard":
            return printed.replace("/*", "")
        return printed.replace(key, other)

    monkeypatch.setattr(KeyExpression, "__str__", lossy_print)
    with pytest.raises(
        AssertionError, match="^descriptor print changes the parsed input$"
    ):
        descriptor_harness.fuzz_target(text.encode())


def test_descriptor_harness_refuses_a_changed_miniscript(
    descriptor_harness: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A decoder returning another valid script does not pass the round trip."""
    monkeypatch.setattr(miniscript, "from_script", lambda *_: miniscript.parse("1"))
    seed = _CORPUS / _TEXT_HARNESS / "ms_and_v_older.bin"
    with pytest.raises(
        AssertionError, match="^miniscript script round trip changes the script$"
    ):
        descriptor_harness.fuzz_target(seed.read_bytes())


@pytest.mark.parametrize("operation", ["script", "from_script"])
def test_descriptor_harness_propagates_miniscript_failures(
    descriptor_harness: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    """Only the initial descriptor parse may refuse a fuzz input quietly."""

    def fail(*_: object, **__: object) -> None:
        raise BTClibValueError("round trip failed")

    target = miniscript.Miniscript if operation == "script" else miniscript
    monkeypatch.setattr(target, operation, fail)
    seed = _CORPUS / _TEXT_HARNESS / "ms_and_v_older.bin"
    with pytest.raises(BTClibValueError, match="^round trip failed$"):
        descriptor_harness.fuzz_target(seed.read_bytes())


def test_descriptor_harness_round_trips_a_hardened_private_key(
    descriptor_harness: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Private material read from the input makes hardened keys derivable."""
    seed = _CORPUS / _TEXT_HARNESS / "bip386_tr_ranged_private.bin"
    prv_keys: dict[str, str] = {}
    descriptors.parse(seed.read_text(encoding="utf-8"), prv_keys=prv_keys)
    xprv = next(iter(prv_keys.values()))
    decode = Mock(wraps=miniscript.from_script)
    monkeypatch.setattr(miniscript, "from_script", decode)

    descriptor_harness.fuzz_target(f"wsh(and_v(v:pk({xprv}/0h/*h),older(10)))".encode())

    decode.assert_called_once()


def test_descriptor_harness_skips_only_the_nonderivable_script(
    descriptor_harness: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An xpub's hardened step still gets the input and print comparison."""
    seed = _CORPUS / _TEXT_HARNESS / "bip386_tr_ranged_private.bin"
    xpub = descriptors.parse(seed.read_text(encoding="utf-8")).key_expressions[0].xkey
    decode = Mock(side_effect=AssertionError("a hardened xpub has no script"))
    monkeypatch.setattr(miniscript, "from_script", decode)

    descriptor_harness.fuzz_target(f"wsh(and_v(v:pk({xpub}/0h),older(10)))".encode())

    decode.assert_not_called()


def test_descriptor_harness_derives_every_script_of_a_combo(
    descriptor_harness: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A combo() has several scripts, so only the lists are asked of it."""
    original = descriptors.Descriptor.script_pub_keys
    counts: list[int] = []

    def counted(descriptor: descriptors.Descriptor, *args: Any) -> list[Any]:
        scripts = original(descriptor, *args)
        counts.append(len(scripts))
        return scripts

    single = Mock(side_effect=AssertionError("one script asked of a combo"))
    monkeypatch.setattr(descriptors.Descriptor, "script_pub_keys", counted)
    monkeypatch.setattr(descriptors.Descriptor, "script_pub_key", single)
    seed = _CORPUS / _TEXT_HARNESS / "bip384_combo_origin_xpub.bin"

    descriptor_harness.fuzz_target(seed.read_bytes())

    assert counts
    assert set(counts) == {4}
    single.assert_not_called()


@pytest.mark.parametrize(
    "operation, error",
    [
        ("script_pub_keys", IndexError),
        ("addresses", BTClibValueError),
        ("script_pub_key", BTClibValueError),
        ("address", BTClibValueError),
    ],
)
def test_descriptor_harness_propagates_derivation_failures(
    descriptor_harness: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    error: type[Exception],
) -> None:
    """Once the scripts derive, any later failure is a finding."""

    def fail(*_: object) -> None:
        raise error("derivation failed")

    monkeypatch.setattr(descriptors.Descriptor, operation, fail)
    seed = _CORPUS / _TEXT_HARNESS / "wpkh.bin"
    with pytest.raises(error, match="^derivation failed$"):
        descriptor_harness.fuzz_target(seed.read_bytes())


def test_descriptor_harness_refuses_an_address_off_its_list(
    descriptor_harness: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The one-script accessors must answer what the lists answer."""
    monkeypatch.setattr(descriptors.Descriptor, "address", Mock(return_value=""))
    seed = _CORPUS / _TEXT_HARNESS / "wpkh.bin"
    with pytest.raises(
        AssertionError, match="^script_pub_key or address disagrees with its list$"
    ):
        descriptor_harness.fuzz_target(seed.read_bytes())


def test_descriptor_harness_compares_deep_miniscript_without_recursing(
    descriptor_harness: ModuleType,
) -> None:
    """A valid taproot leaf can nest beyond recursive dataclass equality."""
    seed = _CORPUS / _TEXT_HARNESS / "ms_or_b_and_b.bin"
    keys = descriptors.parse(seed.read_text(encoding="utf-8")).key_expressions
    depth = sys.getrecursionlimit()
    descriptor_harness.fuzz_target(
        f"tr({keys[0]},{'n' * depth}:pk({keys[1]}))".encode()
    )


def test_miniscript_script_round_trip_keeps_bytes_across_associations(
    descriptor_harness: ModuleType,
) -> None:
    """Distinct and_v() trees can mean the same script, so bytes compare."""
    seed = _CORPUS / _TEXT_HARNESS / "ms_or_b_and_b.bin"
    a, b, c = descriptors.parse(seed.read_text(encoding="utf-8")).key_expressions
    left = f"and_v(and_v(v:pk({a}),v:pk({b})),pk({c}))"
    right = f"and_v(v:pk({a}),and_v(v:pk({b}),pk({c})))"
    left_node = miniscript.parse(left)
    right_node = miniscript.parse(right)
    assert left_node != right_node
    assert left_node.script() == right_node.script()
    descriptor_harness.fuzz_target(f"wsh({left})".encode())
    descriptor_harness.fuzz_target(f"wsh({right})".encode())


@pytest.fixture
def psbt_harness(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the psbt target with an atheris placeholder."""
    return _load_harness("fuzz_psbt", monkeypatch)


def test_psbt_harness_refuses_a_moving_serialization(
    psbt_harness: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A serialization that changes on every round trip fails the target."""
    original = Psbt.serialize

    def growing_serialize(psbt: Psbt, *, check_validity: bool = True) -> bytes:
        psbt.unknown = {**psbt.unknown, b"\xee" + bytes([len(psbt.unknown)]): b""}
        return original(psbt, check_validity=check_validity)

    monkeypatch.setattr(Psbt, "serialize", growing_serialize)
    seed = _CORPUS / "fuzz_psbt" / "bip174.bin"
    with pytest.raises(
        AssertionError, match="^psbt serialization is not a fixed point$"
    ):
        psbt_harness.fuzz_target(seed.read_bytes())


@pytest.mark.parametrize("reader", ["to_dict", "finalize"])
def test_psbt_harness_propagates_a_reader_crash(
    psbt_harness: ModuleType, monkeypatch: pytest.MonkeyPatch, reader: str
) -> None:
    """A crash in a reader of an accepted psbt reaches atheris."""

    def crash(*_: object, **__: object) -> None:
        raise IndexError(reader)

    target = Psbt if reader == "to_dict" else psbt_harness
    monkeypatch.setattr(target, reader, crash)
    seed = _CORPUS / "fuzz_psbt" / "bip174.bin"
    with pytest.raises(IndexError, match=f"^{reader}$"):
        psbt_harness.fuzz_target(seed.read_bytes())


def test_psbt_harness_serializes_what_finalize_returns(
    psbt_harness: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The finalized psbt is held to the fixed point too."""
    finalized = Mock(spec=Psbt)
    finalized.serialize.return_value = PSBT_MAGIC_BYTES
    monkeypatch.setattr(psbt_harness, "finalize", lambda _: finalized)
    seed = _CORPUS / "fuzz_psbt" / "bip174.bin"
    with pytest.raises(BTClibValueError, match="^malformed psbt: "):
        psbt_harness.fuzz_target(seed.read_bytes())


@pytest.mark.parametrize("number", [1, 2])
def test_psbt_crash_inputs_are_seeds(number: int) -> None:
    """Each rust-bitcoin psbt vendored under tests/psbt/_data/ is a seed."""
    vendored = _TESTS / "psbt" / "_data" / f"psbt_fuzz{number}.hex"
    seed = _CORPUS / "fuzz_psbt" / f"rust_bitcoin_psbt_fuzz{number}.bin"
    assert seed.read_bytes() == bytes.fromhex(vendored.read_text(encoding="ascii"))


def _psbt_vectors() -> tuple[tuple[str, bytes], ...]:
    """Every valid BIP174 and BIP371 psbt, and one with a final witness."""
    psbts: list[tuple[str, bytes]] = []
    for name in ("bip174_test_vectors.json", "bip371_test_vectors.json"):
        vectors = json.loads((_PSBT_DATA / name).read_text(encoding="utf-8"))
        psbts.extend(
            (f"{name}[{i}]", base64.b64decode(vector["encoded psbt"]))
            for i, vector in enumerate(vectors["valid psbts"])
        )
    rust_psbt = _PSBT_DATA / "rust-psbt" / "bip174.json"
    cases = json.loads(rust_psbt.read_text(encoding="utf-8"))["cases"]
    (case,) = (c for c in cases if c["description"].startswith("Workflow A (step 7)"))
    psbts.append(("Workflow A (step 7)", bytes.fromhex(case["expected"]["hex"])))
    return tuple(psbts)


_PSBT_VECTORS = _psbt_vectors()


@pytest.mark.parametrize(
    "psbt", [psbt for _, psbt in _PSBT_VECTORS], ids=[name for name, _ in _PSBT_VECTORS]
)
def test_psbt_vectors_are_seeds(psbt: bytes) -> None:
    """Each psbt `fuzz/fuzz_psbt.py` names as a seed is one, as octets."""
    assert psbt in {seed.read_bytes() for seed in _seed_paths("fuzz_psbt")}


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
