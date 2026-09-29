# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for what the package exports.

Every module and package of btclib_wallet declares an `__all__`, at every
depth: a name is public here because a list says so, not because it
happens to lack a leading underscore. A list per module is a list per
module to keep true, and the policy tests below are what keeps it, rather
than a reviewer noticing.

`btclib_wallet.__all__` is the root of that tree, and one of those tests
walks it from the root, into every module-valued export, down to a node
that has none.

These tests are written against the names rather than the counts, so that a
deliberate addition is one line here and an accidental one is a failure.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable, Iterator
from importlib import import_module
from pathlib import Path
from pkgutil import iter_modules
from types import ModuleType

import bitcoin_core_rpc
import btclib_mnemonics
import btclib_mnemonics.bip39
import btclib_mnemonics.exceptions
import btclib_mnemonics.mnemonic
import pytest

import btclib_wallet
import btclib_wallet.mnemonic
import btclib_wallet.psbt
from btclib_wallet.psbt import psbt_utils
from tests import module_names

# what a module defines without a leading underscore and deliberately does
# not export, with the reason beside the list in each module's docstring.
# A name added here is a decision; a name that has to be added here to make
# the suite pass is one that was about to become public by accident
UNEXPORTED = {
    "btclib_wallet": ["name"],
    "btclib_wallet.descriptors.descriptors": [
        "CHECKSUM_CHARSET",
        "GENERATOR",
        "INPUT_CHARSET",
    ],
}


def _reexports(*groups: tuple[ModuleType, list[str]]) -> dict[str, ModuleType]:
    """Turn a module's own re-export groups into one name-to-canonical map.

    A re-exporting module can alias more than one canonical, each for its
    own reason, and a plain `{**a, **b}` merge of one `{name: module}` dict per
    group would drop a name both groups declare rather than say so. This raises
    instead, so a name recorded against two canonicals fails here rather than
    resolving to whichever group happened to come last.
    """
    merged: dict[str, ModuleType] = {}
    for canonical, names in groups:
        for name in names:
            assert name not in merged, (
                f"{name} is reexported from both {merged[name].__name__} and"
                f" {canonical.__name__}"
            )
            merged[name] = canonical
    return merged


# what a module exports without defining it, which for a module rather than a
# package is a leak -- and REEXPORTED below is the exception, one entry per
# re-exporting module, mapping each re-exported name to its canonical
# module: a module recorded there is not leaking, it is aliasing the
# canonical object under the name a caller already had.
#
# The `bitcoin-core-rpc` package is the canonical source of the rpc client
# and of the transport under it, and this package depends on it rather than
# carrying a copy; each module aliasing it states its reasoning in its own
# docstring -- a transport has one bounded-read policy, and an import path
# published here stays valid.
#
# `btclib_wallet.psbt.psbt_utils` is the other: the two psbt versions decide
# what an input and an output map write and read, and neither `psbt_in` nor
# `psbt_out` can import `psbt`, so the pair is defined below all three.
# `btclib_wallet.psbt.psbt` names them still, being where the rest of the
# format's constants are.
REEXPORTED = {
    "btclib_wallet.fetch.bitcoin_core": _reexports(
        (
            bitcoin_core_rpc,
            [
                "COOKIE_USER",
                "DEFAULT_DATADIR",
                "BitcoinCoreRpcClient",
                "chain_from_network",
                "cookie_auth",
            ],
        ),
    ),
    "btclib_wallet.fetch.bitcoin_core_rest": _reexports(
        (bitcoin_core_rpc, ["BitcoinCoreRestClient"]),
    ),
    "btclib_wallet.fetch.transport": _reexports(
        (
            bitcoin_core_rpc,
            [
                "DEFAULT_MAX_BODY_SIZE",
                "DEFAULT_TIMEOUT",
                "MAX_ERROR_BODY_SIZE",
                "HttpTransport",
                "SessionTransport",
                "http_request",
                "urlopen_transport",
            ],
        ),
    ),
    "btclib_wallet.psbt.psbt": _reexports(
        (psbt_utils, ["PSBT_V0", "PSBT_V2"]),
    ),
}

# every direct child module of every package, on the side of the decision
# its parent made about it: `groups` is what the parent publishes, and
# `unpublished` is what it deliberately does not -- a module holding names
# the parent re-exports flat, or an implementation nothing outside the
# package calls.
#
# The two together are asserted to be the package's whole directory, which
# is the half a table of the published edges alone cannot check: a child
# module added and left out of its parent's `__all__` changes neither the
# list nor the edges. Both sides are recorded, so a module added to a
# package fails the suite until somebody says which of the two it is.
#
# btclib_wallet itself is not here: its children are the top-level modules,
# and test_the_root_publishes_every_top_level_module asserts the same
# partition against the directory with nothing on the unpublished side
CHILD_MODULES = {
    "btclib_wallet.bip32": {
        "groups": [],
        "unpublished": ["bip32", "der_path", "key_origin"],
    },
    "btclib_wallet.descriptors": {
        "groups": ["miniscript"],
        "unpublished": ["descriptors", "key_expression"],
    },
    "btclib_wallet.fetch": {
        "groups": [],
        "unpublished": [
            "bitcoin_core",
            "bitcoin_core_rest",
            "broadcaster",
            "decorators",
            "electrum",
            "esplora",
            "fee_estimator",
            "fetcher",
            "transport",
        ],
    },
    "btclib_wallet.mnemonic": {
        "groups": ["bip39", "electrum", "slip39"],
        "unpublished": [],
    },
    "btclib_wallet.psbt": {
        "groups": ["frost", "musig2", "silent_payments"],
        "unpublished": [
            "psbt",
            "psbt_in",
            "psbt_out",
            "psbt_size",
            "psbt_utils",
            "psbt_view",
        ],
    },
    "btclib_wallet.wallet": {
        "groups": [],
        "unpublished": [
            "descriptor_wallet",
            "key_wallet",
            "script_wallet",
            "wallet",
        ],
    },
}


def public_name(dotted: str) -> bool:
    """Whether every component of a dotted module name is public."""
    return not any(part.startswith("_") for part in dotted.split("."))


def library_modules() -> list[ModuleType]:
    """Return every module and package of the library, private ones out.

    Found rather than listed: one added to btclib_wallet is one these
    tests ask about, and the walk is the whole tree rather than the top
    level, the packages having submodules a caller reaches by name --
    `btclib_wallet.psbt.musig2`, `btclib_wallet.mnemonic.bip39`.

    Anything under a private name is out: a module whose name opens with
    an underscore is not part of the surface, so what is public *in* it is
    not reachable by any spelling a caller is offered.

    The walk is `tests/__init__.py`'s, which is where the sites asking a
    question of every module take it from; what is this file's own is the
    filter and the import.
    """
    return [import_module(name) for name in module_names() if public_name(name)]


def module_scope(body: Iterable[ast.stmt]) -> Iterator[ast.stmt]:
    """Yield the statements a module executes in its own namespace.

    Every statement of the body, and then inside each compound one, which
    runs at module scope too: an import in a module-level `try`, `if`,
    `with`, `for`, `while` or `match` binds a global exactly as a
    top-level one does, and `try: from dependency import PublicType` is
    how an optional import is written. A function or a class opens a scope
    of its own, so an import in either binds nothing here, and neither is
    descended into.
    """
    for node in body:
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        nested: list[ast.stmt] = []
        for field in ("body", "orelse", "finalbody"):
            statements = getattr(node, field, None)
            if isinstance(statements, list):
                nested += statements
        for clause in (*getattr(node, "handlers", ()), *getattr(node, "cases", ())):
            nested += clause.body
        yield from module_scope(nested)


def imported_names_in(source: str) -> set[str]:
    """Return the names the import statements of one module source bind."""
    return {
        alias.asname or alias.name.split(".")[0]
        for node in module_scope(ast.parse(source).body)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }


def imported_names(module: ModuleType) -> set[str]:
    """Return the names a module's own import statements bind.

    Read off the source rather than the module object, there being nothing
    in a module's namespace to say how a name got there.
    """
    return imported_names_in(Path(str(module.__file__)).read_text(encoding="utf-8"))


def defined_public_names(module: ModuleType) -> set[str]:
    """Return the public names a module defines itself.

    Everything in its namespace, minus the underscored, minus what it
    imported, minus the modules: a submodule becomes an attribute of its
    package as soon as anything imports it, so `btclib_wallet.bip32` is in
    `vars(btclib_wallet)` by the time any test runs.
    """
    imported = imported_names(module)
    return {
        name
        for name, value in vars(module).items()
        if not name.startswith("_")
        and name not in imported
        and not isinstance(value, ModuleType)
    }


def test_mnemonic_exports_its_three_schemes() -> None:
    """Verify bip39, electrum and slip39 are exported and importable."""
    for name in ("bip39", "electrum", "slip39"):
        assert name in btclib_wallet.mnemonic.__all__
        module = getattr(btclib_wallet.mnemonic, name)
        assert module.__name__ == f"btclib_wallet.mnemonic.{name}"


def test_psbt_exports_the_format_not_its_plumbing() -> None:
    """The maps and the roles, not how one field of one map is written.

    The list it replaces held more names from psbt_utils than names for the
    psbt itself, `encode_dict_bytes_bytes` twice among them, so a caller
    reading `btclib_wallet.psbt` was offered the plumbing of a file format ahead
    of the format.
    """
    assert sorted(btclib_wallet.psbt.__all__) == [
        "InputSolver",
        "KeyManager",
        "Psbt",
        "PsbtIn",
        "PsbtOut",
        "PsbtView",
        "SolutionSizer",
        "assert_signatures_only",
        "assert_signed",
        "combine",
        "ecdsa_sig_hash",
        "estimated_input_sizes",
        "extract_tx",
        "finalize",
        "frost",
        "join",
        "musig2",
        "new_signers",
        "prevouts",
        "sign",
        "silent_payments",
        "taproot_sig_hash",
    ]

    # BIP373 is a role, so the module is the name, as btclib_ecc.ecc.musig2 is
    assert btclib_wallet.psbt.musig2.__name__ == "btclib_wallet.psbt.musig2"
    # and the same for the roles over a BIP445 session, whose fields are
    # btclib's own proprietary records rather than assigned type bytes
    assert btclib_wallet.psbt.frost.__name__ == "btclib_wallet.psbt.frost"

    # the plumbing is still there, in the module that defines it
    for name in (
        "assert_valid_unknown",
        "decode_dict_bytes_bytes",
        "deserialize_map",
        "deserialize_tx",
        "encode_dict_bytes_bytes",
        "serialize_bytes",
        "serialize_dict_bytes_bytes",
        "serialize_hd_key_paths",
    ):
        assert hasattr(psbt_utils, name), f"psbt_utils.{name} went missing"
        assert name not in btclib_wallet.psbt.__all__


def test_every_exported_name_exists() -> None:
    """An `__all__` entry that names nothing is a broken `import *`.

    Every module and package of the library, found rather than listed: one
    added to btclib_wallet is one this checks, where a list here would be one
    more thing to keep true, and a module missing `__all__` is what this catches
    that a fixed list cannot. The whole tree is walked, which imports every
    module of the library; tests/imports_test.py does that deliberately and one
    module at a time, for the cycle a bulk import hides, and this one asks a
    question that needs them all loaded.

    An empty list is a legitimate answer, and the assertion says when: a
    module with nothing public of its own -- a package `__init__` that only
    re-exports, or a module that is all private helpers -- declares `[]`
    rather than nothing, so that the declaration is there to read.
    """
    modules = library_modules()
    assert len(modules) > 40, f"only {len(modules)} modules found"
    for module in modules:
        names = getattr(module, "__all__", None)
        assert names is not None, f"{module.__name__} declares no __all__"
        assert names or not defined_public_names(module), (
            f"{module.__name__} declares an empty __all__ and defines"
            f" {sorted(defined_public_names(module))}"
        )
        for name in names:
            assert hasattr(module, name), f"{module.__name__}.{name} is not there"


def test_no_module_exports_a_name_it_imported() -> None:
    """A module exports what it defines, which is what packages do not.

    A package's `__all__` is re-export by design -- `btclib_wallet.psbt`
    names `Psbt`, defined a module away -- and for a module the same thing
    is a leak: `Octets` reached through `btclib_wallet.bip21` is that
    module's import section, where `btclib.alias.Octets` is the name a
    caller wants. A
    module with a reason to re-export something is a conversation to have
    with this test, not around it.

    `REEXPORTED` is that conversation, one name-to-canonical mapping per
    re-exporting module: every module aliasing an object the
    `bitcoin-core-rpc` package canonically holds keeps the name a caller
    already had, a transport having one bounded-read policy to keep; and
    `btclib_wallet.psbt.psbt` names the two psbt
    versions that `psbt_utils` defines below the maps taking one as an
    argument.

    Asserted both ways, because a skip list is only half a table: it says
    which names may be re-exported and nothing about whether they still are,
    so dropping one of these aliases from an `__all__` would have been
    invisible to every test in this file. The recorded names and the
    re-exported ones must be the same set, and each must be the canonical
    object its own entry names, not merely a same-named one -- which is
    the property the whole arrangement exists for.
    """
    for module in library_modules():
        if hasattr(module, "__path__"):  # a package re-exports for a living
            continue
        imported = imported_names(module)
        leaked = {name for name in module.__all__ if name in imported}
        recorded = REEXPORTED.get(module.__name__)
        if recorded is None:
            assert not leaked, f"{module.__name__} re-exports {sorted(leaked)}"
            continue
        assert leaked == set(recorded), (
            f"{module.__name__} re-exports {sorted(leaked)}, where REEXPORTED"
            f" records {sorted(recorded)}"
        )
        for name, canonical in recorded.items():
            assert getattr(module, name) is getattr(canonical, name), (
                f"{module.__name__}.{name} is not the canonical"
                f" {canonical.__name__}.{name}"
            )


def test_reexports_refuses_a_name_recorded_against_two_canonicals() -> None:
    """`REEXPORTED`'s own building block, exercised where no real entry does.

    Every entry above is collision-free today, so `_reexports`'s guard
    never fires under the suite: a regression back toward a `{**a, **b}`
    merge, which drops a repeated key rather than refusing it, would
    pass every test in this file and still resolve a name to whichever
    group happened to come last. This is the control on the guard
    itself, two synthetic modules sharing a name, and the message is
    checked to name that name rather than merely to have raised.
    """
    mod_a = ModuleType("modA")
    mod_b = ModuleType("modB")
    with pytest.raises(
        AssertionError, match=r"^FOO is reexported from both modA and modB"
    ):
        _reexports((mod_a, ["FOO"]), (mod_b, ["FOO", "BAR"]))


def test_the_export_tree_is_walkable_to_its_leaves() -> None:
    """Every module reachable through `__all__` declares one of its own.

    A module named in a parent's list and declaring nothing is a node a
    walker arrives at and cannot descend from -- which is what this asks
    about, transitively from `btclib_wallet` down, following exports
    rather than the file tree.

    A module-valued export is also checked to be a submodule of the module
    exporting it: `btclib_wallet.psbt.musig2` is `btclib_wallet.psbt`'s to
    publish, and a module from somewhere else in the tree would make the
    path a caller reads off the walk name something the import does not.
    """
    seen = {btclib_wallet.__name__}
    frontier: list[ModuleType] = [btclib_wallet]
    while frontier:
        module = frontier.pop()
        names = getattr(module, "__all__", None)
        assert names is not None, f"{module.__name__} declares no __all__"
        for name in names:
            value = getattr(module, name)
            if not isinstance(value, ModuleType):
                continue
            assert value.__name__ == f"{module.__name__}.{name}", (
                f"{module.__name__} exports {name}, which is {value.__name__}"
            )
            # the set is the frontier's filter rather than a check on the
            # way out: one module reachable from two parents would be
            # walked twice, and nothing here is -- which is what the
            # `no branch` says, the tree being one and the filter being
            # what would keep a future re-export from doubling the walk
            if value.__name__ not in seen:  # pragma: no branch -- the tree is one
                seen.add(value.__name__)
                frontier.append(value)
    # the root, the packages and the modules they publish: a walk that
    # stopped at the root would satisfy the loop above
    assert len(seen) > 30, f"the export tree walk reached {len(seen)} modules"


def test_every_child_module_is_a_group_or_deliberately_not() -> None:
    """Each package's children are partitioned, and the parts are recorded.

    Two directions, and the second is the one nothing else here can see.
    The published side is the exact module-valued exports, so a submodule
    imported into an `__init__` for one name and left in `__all__` by habit
    is a command group nobody decided on. The union of the two sides is the
    package's whole directory, so a child module added and left out of the
    list -- which changes neither the list nor the edges -- fails until
    somebody writes down which side it is on.

    The empty published sides are as deliberate as the rest: `bip32`,
    `fetch` and `wallet` offer a flat surface and no group. Every package has to
    be in the table, so a new one is a decision rather than a silent pair of
    empty lists.
    """
    packages = [module for module in library_modules() if hasattr(module, "__path__")]
    assert len(packages) == len(CHILD_MODULES) + 1, (
        "btclib_wallet itself plus every package CHILD_MODULES records"
    )
    for package in packages:
        if package.__name__ == "btclib_wallet":  # the directory is its assertion
            continue
        assert package.__name__ in CHILD_MODULES, f"{package.__name__} is not recorded"
        recorded = CHILD_MODULES[package.__name__]
        edges = sorted(
            name
            for name in package.__all__
            if isinstance(getattr(package, name), ModuleType)
        )
        assert edges == recorded["groups"], f"{package.__name__} publishes {edges}"
        children = sorted(
            child
            for _, child, _ in iter_modules(package.__path__)
            if public_name(child)
        )
        assert sorted([*recorded["groups"], *recorded["unpublished"]]) == children, (
            f"{package.__name__}'s children are {children}"
        )


def test_the_root_publishes_every_top_level_module() -> None:
    """`btclib_wallet.__all__` is the tree's root: nothing top-level is missing.

    The list is written out rather than discovered -- a declaration is a
    list somebody edited -- and this is the other half of that: a module
    added to `src/btclib_wallet/` and not published here would be a name
    `getattr(btclib_wallet, ...)` cannot answer, where a discovered list
    would have published it without anybody deciding to.
    """
    top_level = sorted(
        name for _, name, _ in iter_modules(btclib_wallet.__path__) if public_name(name)
    )
    assert sorted(btclib_wallet.__all__) == top_level
    # and each answers on a package that imported none of them, which is
    # what the module __getattr__ is for
    for name in top_level:
        assert getattr(btclib_wallet, name).__name__ == f"btclib_wallet.{name}"


def test_the_root_answers_only_for_what_it_publishes() -> None:
    """A name outside the list raises, as an attribute of anything does.

    What the list decides is what this package imports *for* a caller: a
    submodule is an attribute of its package once anything imports it,
    whatever the list says.
    """
    with pytest.raises(AttributeError, match="has no attribute 'bip33'"):
        _ = btclib_wallet.bip33
    # dir() answers the published tree, not only what has been imported
    assert set(btclib_wallet.__all__) <= set(dir(btclib_wallet))


def test_the_import_scan_reaches_a_nested_import() -> None:
    """A module-level `try` binds a global, and a function body does not.

    The check above is only as good as this scan: an optional dependency
    imported in a `try` and named in `__all__` is exactly the re-export it
    refuses, and reading `tree.body` alone would have let it through.
    """
    source = (
        "try:\n"
        "    from dependency import PublicType\n"
        "except ImportError:\n"
        "    from fallback import PublicType\n"
        "if TYPE_CHECKING:\n"
        "    from typing import Never\n"
        "for _name in ():\n"
        "    import late\n"
        "def f():\n"
        "    import local\n"
        "class C:\n"
        "    import attribute\n"
    )
    assert imported_names_in(source) == {"PublicType", "Never", "late"}


def test_nothing_becomes_public_by_accident() -> None:
    """Every public name is exported or recorded as kept out.

    This is the check the underscore convention cannot make: a helper that
    grows into a name callers depend on does so silently, where a package
    takes an edit to a list. `UNEXPORTED` is that edit for modules, and
    `sorted` is what the failure reads as -- the names not accounted for,
    against the ones that are.
    """
    for module in library_modules():
        kept_out = sorted(defined_public_names(module) - set(module.__all__))
        assert kept_out == UNEXPORTED.get(module.__name__, []), (
            f"{module.__name__} defines public names that are neither"
            f" exported nor recorded in UNEXPORTED: {kept_out}"
        )


def _owned_by_btclib_mnemonics(value: object) -> bool:
    """Answer whether an object is one of btclib_mnemonics' own.

    A module of that package, a function or a class it defines, or an
    instance of a class it defines -- a word-list registry, say. The
    package itself is not: `import btclib_mnemonics.bip39` binds it, and
    the name it is bound by is the one a caller already has.
    """
    if isinstance(value, ModuleType):
        return value.__name__.startswith("btclib_mnemonics.")
    owner = getattr(value, "__module__", None)
    if not isinstance(owner, str):
        owner = type(value).__module__
    return owner == "btclib_mnemonics" or owner.startswith("btclib_mnemonics.")


def test_no_module_binds_a_name_btclib_mnemonics_owns() -> None:
    """What moved to btclib_mnemonics is reached there and nowhere here.

    The narrower `test_no_module_exports_a_name_it_imported` reads
    `__all__`; this reads the namespace, where an imported name is bound
    whether or not a list publishes it -- so a moved path such as
    `btclib_wallet.mnemonic.bip39.seed_from_mnemonic` would still resolve
    for a caller. A module of this package reaches that package's names
    through the package, `btclib_mnemonics.bip39.seed_from_mnemonic`, and
    binds none of them.
    """
    for module in library_modules():
        bound = sorted(
            name
            for name, value in vars(module).items()
            if not name.startswith("__") and _owned_by_btclib_mnemonics(value)
        )
        assert bound == [], f"{module.__name__} binds {bound} of btclib_mnemonics"


def test_the_ownership_check_sees_each_kind_of_name() -> None:
    """Each kind of name btclib_mnemonics owns is seen, and nothing else.

    A module, a function, a class and an instance of one are; the package
    itself, a module of ours, a built-in type and an integer are not. The
    real tree binds none of them -- that is what the test above
    measures -- so this is the only green run that crosses the branch
    answering yes.
    """
    for owned in (
        btclib_mnemonics.bip39,
        btclib_mnemonics.bip39.seed_from_mnemonic,
        btclib_mnemonics.exceptions.BTClibMnemonicsValueError,
        btclib_mnemonics.mnemonic.WORDLISTS,
    ):
        assert _owned_by_btclib_mnemonics(owned)
    for not_owned in (btclib_mnemonics, btclib_wallet.mnemonic.bip39, str, 1):
        assert not _owned_by_btclib_mnemonics(not_owned)


def _private_btclib_mnemonics_names_in(source: str) -> set[str]:
    """Return every `_`-prefixed name of btclib_mnemonics a source reaches.

    An import naming one -- `from btclib_mnemonics.electrum import
    _normalize`, or a private module in the dotted path -- and an attribute
    read off the package by its dotted name,
    `btclib_mnemonics.electrum._normalize`.
    """
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if (
            isinstance(node, ast.ImportFrom)
            and (node.module or "").split(".")[0] == "btclib_mnemonics"
        ):
            module = str(node.module)
            found |= {part for part in module.split(".") if part.startswith("_")}
            found |= {a.name for a in node.names if a.name.startswith("_")}
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] == "btclib_mnemonics":
                    found |= {p for p in alias.name.split(".") if p.startswith("_")}
        elif isinstance(node, ast.Attribute) and node.attr.startswith("_"):
            root: ast.expr = node.value
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name) and root.id == "btclib_mnemonics":
                found.add(node.attr)
    return found


def test_the_private_name_scan_finds_each_spelling() -> None:
    """Each way of reaching a private name is reported, and a public one is not.

    The real tree has none -- that is what the test below measures -- so
    this is the only green run that crosses the branch reporting one.
    """
    source = (
        "from btclib_mnemonics.electrum import _normalize, version_from_mnemonic\n"
        "from btclib_mnemonics._utils import assert_type\n"
        "import btclib_mnemonics._data\n"
        "import btclib_mnemonics.bip39\n"
        "btclib_mnemonics.slip39._feistel\n"
        "btclib_mnemonics.bip39.seed_from_mnemonic\n"
        "from btclib_wallet.bip32.der_path import _HARDENED_OFFSET\n"
    )
    assert _private_btclib_mnemonics_names_in(source) == {
        "_normalize",
        "_utils",
        "_data",
        "_feistel",
    }


def test_no_module_imports_a_private_name_of_btclib_mnemonics() -> None:
    """A private name of btclib_mnemonics is that package's to change.

    Every module of this package, private ones included: what a private
    module of ours reached would break at a btclib_mnemonics release as
    surely as a public one.
    """
    for path in sorted(Path(str(btclib_wallet.__file__)).parent.rglob("*.py")):
        found = _private_btclib_mnemonics_names_in(path.read_text(encoding="utf-8"))
        assert not found, f"{path.name} reaches {sorted(found)} of btclib_mnemonics"
