# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The gate for what `parse`, `serialize`, `to_dict` and `from_dict` take.

btclib's rule that every public function validates its inputs, at the
boundary where an object meets octets, text or json: a value of a type
the signature does not declare leaves as a `BTClibTypeError`, a value of
a declared type that no valid input carries as a `BTClibValueError`.
Issue btclib-org/btclib#867 is where the family was measured, and btclib's
own `serialization_boundary_test.py` holds its half of it.

**Not the contract `parse_contract_test.py` holds.** That file asks where
the bytes end -- a field is as long as its encoding says, a complete octet
string is one whole object, a caller's stream is the caller's -- and this
one asks what type the argument is. The two are different questions about
the same methods, which is why the walk that finds every one of them is
`tests/__init__.py`'s and neither file's.

**`from_dict` is where the hazard is sharpest**: it is the json boundary,
so its input is whatever a schema mistake produced. A mapping missing a
field must not leave as a `KeyError`, which is neither a
`BTClibException` nor a `ValueError`; `btclib.utils.fields_from_json_object`
is the one line that answers both, and `btclib.utils.list_from_json_array`
the arrays it walks: `Sequence[Any]` accepts a `str` and a `Mapping`, so
an input handed where the list of them was meant would be as many inputs
as it had characters.

**`to_dict`, `serialize` and `b64encode` mostly have nothing to drive**:
their input is the object, which `built_object_contract_test.py` owns.
The exceptions are the arguments `_EXTRA_ARGUMENTS` records, and the last
test is what keeps that record honest -- one more added to this family
fails here until it is driven.

**Parametric above the byte boundary, mono-format at it.** `ec` and `hf`
are nowhere in this family: an encoding does not name its curve or its
hash function, so `parse(data, ec=...)` would not be parsing -- it would
be decoding under instruction, accepting in silence a caller who names
the wrong one (issue btclib-org/btclib#1084).
`test_the_family_takes_no_ec_or_hf` is what turns that from an agreement
into a gate.

`check_validity` is not driven anywhere in this file: it is a flag that
decides whether a check runs rather than what is computed, so it is read
for its truth.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from importlib import import_module
from inspect import signature
from typing import Any

import pytest
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.key import PrvKeyData

from btclib_wallet import bip322
from btclib_wallet.bip21 import Bip21
from btclib_wallet.bip32.bip32 import BIP32KeyData
from btclib_wallet.bip32.key_origin import BIP32KeyOrigin
from btclib_wallet.descriptors import descriptors, miniscript
from btclib_wallet.psbt import Psbt, PsbtIn, PsbtOut
from btclib_wallet.psbt.psbt_utils import PSBT_V0, PSBT_V2
from tests import module_names, public_classes_with
from tests.psbt import psbt_cases

# a value of no type any of these positions declares. `Any`, because
# every position they are handed to declares something narrower: what
# these tests are about is the caller who has not run mypy
_WRONG_TYPES: tuple[Any, ...] = (None, 1.5, [1, 2])

# and the two iterables that are not a json array: each is walked element
# by element unless it is asked about whole, so what fails is the element
# rather than the argument
_NOT_AN_ARRAY: tuple[Any, ...] = (*_WRONG_TYPES, "ab", {"a": 1})

# and the same list where `None` is a type the position declares, which is
# a statement about the signature rather than an exemption from the rule
_NOT_NONE: tuple[Any, ...] = tuple(w for w in _WRONG_TYPES if w is not None)

# a published psbt rather than one built here: what makes the json cases
# worth running is a mapping with something in it, and the BIP174 vectors
# are where a psbt carrying derivations, scripts and signatures comes from
_PSBT = next(
    psbt
    for psbt in (
        Psbt.b64decode(case["encoded psbt"])
        for case in psbt_cases("bip174_test_vectors.json", "valid psbts")
    )
    if any(psbt_in.hd_key_paths for psbt_in in psbt.inputs)
)


@dataclass(frozen=True)
class _JsonCase:
    """A class with a `to_dict`/`from_dict` pair, and one valid object."""

    label: str
    cls: type[Any]
    obj: Any


# every public class with a json boundary, which the last test is what
# makes a promise: one of these per `from_dict` in the package
_JSON_CASES = (
    _JsonCase("Psbt", Psbt, _PSBT),
    _JsonCase("PsbtIn", PsbtIn, _PSBT.inputs[0]),
    _JsonCase("PsbtOut", PsbtOut, _PSBT.outputs[0]),
    _JsonCase("BIP32KeyOrigin", BIP32KeyOrigin, BIP32KeyOrigin("deadbeef", "m/44h/0h")),
)

_JSON_IDS = tuple(case.label for case in _JSON_CASES)

# the arrays a `from_dict` walks, one per key: the class, the key, and
# nothing else -- what a wrong value there costs is stated in the test
_JSON_ARRAYS = (
    ("Psbt", Psbt, _PSBT, "inputs"),
    ("Psbt", Psbt, _PSBT, "outputs"),
    ("Psbt", Psbt, _PSBT, "bip32_derivs"),
    ("PsbtIn", PsbtIn, _PSBT.inputs[0], "bip32_derivs"),
    ("PsbtOut", PsbtOut, _PSBT.outputs[0], "taproot_hd_key_paths"),
)

_ARRAY_IDS = tuple(f"{label}-{key}" for label, _, _, key in _JSON_ARRAYS)

# what reads octets: every `parse` but Bip21's, a URI being text. The
# class and the method name, so that the walk at the end can say which
# decoders are covered
_OCTETS_DECODERS = (
    ("Psbt.parse", Psbt, "parse"),
    ("PsbtIn.parse", PsbtIn, "parse"),
    ("PsbtOut.parse", PsbtOut, "parse"),
    ("BIP32KeyData.parse", BIP32KeyData, "parse"),
    ("BIP32KeyOrigin.parse", BIP32KeyOrigin, "parse"),
)

_OCTETS_IDS = tuple(label for label, _, _ in _OCTETS_DECODERS)

# and what reads text: the base64 and base58 decoders, and the one
# `parse` whose argument is a string
_TEXT_DECODERS = (
    ("Bip21.parse", Bip21, "parse"),
    ("BIP32KeyData.b58decode", BIP32KeyData, "b58decode"),
    ("Psbt.b64decode", Psbt, "b64decode"),
    ("bip322.Sig.b64decode", bip322.Sig, "b64decode"),
)

_TEXT_IDS = tuple(label for label, _, _ in _TEXT_DECODERS)

# what any of these methods takes beyond the object it is about, the
# octets or the mapping it reads, and `check_validity`: everything else a
# caller can get wrong, each driven below
_EXTRA_ARGUMENTS = {
    ("btclib_wallet.psbt.psbt_in.PsbtIn", "serialize"): "psbt_version",
    ("btclib_wallet.psbt.psbt_in.PsbtIn", "parse"): "psbt_version",
    ("btclib_wallet.psbt.psbt_out.PsbtOut", "serialize"): "psbt_version",
    ("btclib_wallet.psbt.psbt_out.PsbtOut", "parse"): "psbt_version",
}

# the eight names issue btclib-org/btclib#867 measured, which is what the
# walk runs over, split by which of them is handed an encoding: a reader
# takes one as its first argument, a writer starts from the object and
# takes none
_READERS = ("parse", "from_dict", "b64decode", "b58decode")
_WRITERS = ("serialize", "to_dict", "b64encode", "b58encode")
_FAMILY = (*_READERS, *_WRITERS)

# and the same family where it is a module function rather than a method:
# the two text parsers with no class between them and the encoding, each
# driven on what it converts, which is its first argument
_MODULE_READERS = (
    ("descriptors.parse", descriptors.parse, "invalid descriptor type"),
    ("miniscript.parse", miniscript.parse, "invalid miniscript type"),
)

_MODULE_READER_IDS = tuple(label for label, _, _ in _MODULE_READERS)

# what those two take besides the text they convert, each driven by a
# test of its own below
_MODULE_EXTRA_ARGUMENTS = {
    ("btclib_wallet.descriptors.descriptors", "parse"): ["network", "prv_keys"],
    ("btclib_wallet.descriptors.miniscript", "parse"): ["context", "prv_keys"],
}


def _as_json(obj: Any) -> dict[str, Any]:
    """Return what `to_dict` wrote, round-tripped through json itself.

    Through `json` and not straight from `to_dict`: what these tests
    drive is the boundary a stored file arrives at, and a dict that
    never went through a serializer is one whose tuples are still tuples
    and whose ints are still ints of Python's making.
    """
    dict_: dict[str, Any] = json.loads(json.dumps(obj.to_dict()))
    return dict_


@pytest.mark.parametrize("case", _JSON_CASES, ids=_JSON_IDS)
def test_the_json_round_trip_is_exact(case: _JsonCase) -> None:
    """The fixture is valid, which is what makes a refusal below a finding.

    Without this a case whose object had gone stale would pass every test
    in this file by refusing everything it is handed.
    """
    assert case.cls.from_dict(_as_json(case.obj)) == case.obj


@pytest.mark.parametrize("case", _JSON_CASES, ids=_JSON_IDS)
def test_from_dict_refuses_what_is_no_json_object(case: _JsonCase) -> None:
    """The first rule at the json boundary: a `Mapping` or nothing.

    A `str` is the one worth naming: it is not a mapping and is
    subscriptable, so it reached `dict_["version"]` and left as "string
    indices must be integers" -- a complaint about a builtin, and about
    the key rather than about the argument.
    """
    for wrong in (*_WRONG_TYPES, "a string"):
        with pytest.raises(BTClibTypeError, match="dict type"):
            case.cls.from_dict(wrong)


@pytest.mark.parametrize("case", _JSON_CASES, ids=_JSON_IDS)
def test_from_dict_names_the_field_it_has_not_got(case: _JsonCase) -> None:
    """The second rule: a mapping without the field is a wrong value.

    Every key in turn, and a key `from_dict` ignores -- a transaction's
    txid, a header's difficulty, the psbt's derived "tx" -- is one whose
    absence is no error at all, which is why the assertion is on what a
    failure may be rather than on which keys fail. What must never happen
    is a bare `KeyError` reaching the caller: `exceptions.py`'s guarantee
    is that no public function lets a native exception through, and this
    is the family the guarantee has to hold for.

    The count is asserted too, or a `from_dict` that stopped reading its
    mapping would pass this by never failing.
    """
    dict_ = _as_json(case.obj)
    refused = []
    for key in dict_:
        without = {k: v for k, v in dict_.items() if k != key}
        try:
            case.cls.from_dict(without)
        except BTClibValueError as e:
            refused.append((key, str(e)))
    assert refused, f"{case.label}.from_dict requires none of its fields"
    for key, err_msg in refused:
        assert key in err_msg


@pytest.mark.parametrize("label, cls, obj, key", _JSON_ARRAYS, ids=_ARRAY_IDS)
def test_a_json_array_is_asked_before_it_is_walked(
    label: str, cls: type[Any], obj: Any, key: str
) -> None:
    """A list field, driven with what a schema mistake puts there.

    The two iterables are the point: a `str` is a list of its characters
    and a `Mapping` a list of its keys, so one input handed where the
    array of them was meant was as many inputs as it had characters --
    each refused for what it is not, which reports the wrong mistake.
    `Witness`'s stack is worse than that and was the finding here: its
    constructor reads `stack or []`, so a `None` was a witness of no
    elements rather than an error.
    """
    dict_ = _as_json(obj)
    for wrong in _NOT_AN_ARRAY:
        broken = deepcopy(dict_)
        broken[key] = wrong
        with pytest.raises(BTClibTypeError):
            cls.from_dict(broken)


def test_a_json_null_is_no_amount_and_is_an_absent_one() -> None:
    """A psbt output's `null` amount is the field being absent.

    btclib's `TxOut.from_dict` refuses a `null` value, a transaction
    output always carrying one; a psbt output carries an amount only in
    version 2, so there `None` stays a value the boundary takes.
    """
    psbt_out = _as_json(_PSBT.outputs[0])
    assert PsbtOut.from_dict({**psbt_out, "amount": None}).amount is None


@pytest.mark.parametrize("label, cls, method", _OCTETS_DECODERS, ids=_OCTETS_IDS)
def test_the_octets_boundary_refuses_what_is_no_octets(
    label: str, cls: type[Any], method: str
) -> None:
    """`bytes_from_octets` is the one coercion, and it is the one refusal."""
    for wrong in _WRONG_TYPES:
        with pytest.raises(BTClibTypeError, match="invalid octets type"):
            getattr(cls, method)(wrong)


@pytest.mark.parametrize("label, cls, method", _TEXT_DECODERS, ids=_TEXT_IDS)
def test_the_text_boundary_refuses_what_is_no_text(
    label: str, cls: type[Any], method: str
) -> None:
    """The same rule where the encoding is text rather than octets.

    Three of these left a native exception: the base64 decoders handed
    what is neither `str` nor `bytes` to `base64` -- "argument should be
    a bytes-like object or ASCII string" -- or to `.strip`, and
    `b58decode` to the cache in front of `base58.decode`, which keys on
    the argument and so refused an unhashable one for being unhashable.
    """
    for wrong in _WRONG_TYPES:
        with pytest.raises(BTClibTypeError, match="type"):
            getattr(cls, method)(wrong)


@pytest.mark.parametrize(
    "label, function, err_msg", _MODULE_READERS, ids=_MODULE_READER_IDS
)
def test_a_codec_that_is_a_function_refuses_a_wrong_type_too(
    label: str, function: Callable[..., Any], err_msg: str
) -> None:
    """The same rule where there is no class between the two sides.

    A text parser that went through nothing would leave "'NoneType' object
    has no attribute 'partition'" or "object of type 'float' has no
    len()".
    """
    for wrong in _WRONG_TYPES:
        with pytest.raises(BTClibTypeError, match=err_msg):
            function(wrong)


@pytest.mark.parametrize("cls", [PsbtIn, PsbtOut], ids=["PsbtIn", "PsbtOut"])
def test_a_map_is_written_and_read_as_a_version_that_exists(cls: type[Any]) -> None:
    """`psbt_version` decides which fields a map carries, so it is asked.

    Every version that is not 0 wrote and read the BIP370 fields, so a
    `None`, a 3 or a string was a version 2 map and said nothing -- and
    the psbt they belong to holds its own version to `PSBT_V0` or
    `PSBT_V2` already, which is the same question one layer up.
    """
    map_ = _PSBT.inputs[0] if cls is PsbtIn else _PSBT.outputs[0]
    for version in (PSBT_V0, PSBT_V2):
        assert cls.parse(map_.serialize(psbt_version=version), psbt_version=version)

    for wrong in _WRONG_TYPES:
        with pytest.raises(BTClibTypeError, match="invalid version type"):
            map_.serialize(psbt_version=wrong)
        with pytest.raises(BTClibTypeError, match="invalid version type"):
            cls.parse(map_.serialize(), psbt_version=wrong)

    for wrong_value in (1, 3):
        with pytest.raises(BTClibValueError, match="invalid psbt version"):
            map_.serialize(psbt_version=wrong_value)
        with pytest.raises(BTClibValueError, match="invalid psbt version"):
            cls.parse(map_.serialize(), psbt_version=wrong_value)


def test_a_descriptor_is_parsed_for_a_network_that_exists() -> None:
    """The two arguments `descriptors.parse` takes besides the text.

    A name no network has was carried into the `Descriptor` and refused
    by whichever encoder came to use it, one call later than the argument
    that was wrong; `prv_keys` was walked with `in` and `[]`, so a list
    of pairs answered "not found" for every key rather than saying it is
    not a mapping. `None` is a type it declares, so it is asserted to
    work rather than driven -- a statement about the signature, and the
    one `built_object_contract_test.py` records as `optional`.
    """
    descriptor = f"pk({PrvKeyData(1).pub.sec.hex()})"
    assert descriptors.parse(descriptor, "testnet").network == "testnet"
    assert descriptors.parse(descriptor, prv_keys={}).network == "mainnet"
    assert descriptors.parse(descriptor, prv_keys=None).network == "mainnet"
    # and normalized, which is what going through the library's own
    # question buys beyond refusing what is not one
    assert descriptors.parse(descriptor, " TestNet ").network == "testnet"

    for wrong in _WRONG_TYPES:
        with pytest.raises(BTClibTypeError, match="not a network name"):
            descriptors.parse(descriptor, wrong)
    for wrong in _NOT_NONE:
        with pytest.raises(BTClibTypeError, match="invalid prv_keys type"):
            descriptors.parse(descriptor, prv_keys=wrong)
    with pytest.raises(BTClibValueError, match="unknown network"):
        descriptors.parse(descriptor, "mainet")


def test_a_miniscript_is_parsed_in_a_context_that_exists() -> None:
    """The same pair for the miniscript parser, its own first argument.

    Every rule reads the context by asking whether it is `TAPSCRIPT`, so
    a third value was the p2wsh one silently: the expression was
    type-checked and sized under rules it was not offered to.
    """
    expression = f"pk({PrvKeyData(1).pub.sec.hex()})"
    for context in (miniscript.P2WSH, miniscript.TAPSCRIPT):
        assert miniscript.parse(expression, context).context == context
    assert miniscript.parse(expression, prv_keys=None).context == miniscript.P2WSH

    for wrong in _WRONG_TYPES:
        with pytest.raises(BTClibTypeError, match="invalid context type"):
            miniscript.parse(expression, wrong)
    for wrong in _NOT_NONE:
        with pytest.raises(BTClibTypeError, match="invalid prv_keys type"):
            miniscript.parse(expression, prv_keys=wrong)
    with pytest.raises(BTClibValueError, match="unknown spend context"):
        miniscript.parse(expression, "P2SH")


def test_every_json_boundary_is_covered() -> None:
    """The inventory is a promise only if omission is what fails.

    A `to_dict`/`from_dict` pair added here and forgotten in the table is
    the failure this catches: the tests above would go on passing on the
    classes they were given. The pair is asserted as a pair, a class that
    writes json and does not read it back being a finding of its own.
    """
    covered = {f"{case.cls.__module__}.{case.cls.__qualname__}" for case in _JSON_CASES}
    assert public_classes_with("from_dict") == covered
    assert public_classes_with("to_dict") == covered


def test_every_decoder_is_covered() -> None:
    """The same promise for what reads octets and what reads text.

    No exclusion list, which is the state to keep: every decoder in the
    library takes an argument of a declared type, and refusing what is
    not of it is a rule with no exception to state.
    """
    covered = {
        f"{cls.__module__}.{cls.__qualname__}.{method}"
        for _, cls, method in (*_OCTETS_DECODERS, *_TEXT_DECODERS)
    }
    found = {
        f"{name}.{method}"
        for method in ("parse", "b64decode", "b58decode")
        for name in public_classes_with(method)
    }
    assert found == covered


def test_every_codec_that_is_a_function_is_covered() -> None:
    """And the same promise where the family is a module function.

    The walk that finds the methods finds classes, so these would be
    invisible to it: a `parse` or a `serialize` added to a module of this
    package is held to nothing until it appears in a table above.

    What each takes besides the encoding is recorded rather than driven,
    every one of them being a parameter behind a default -- which is
    issue btclib-org/btclib#868's census and the line this file stops at.
    """
    covered = {
        f"{function.__module__}.{function.__name__}"
        for _, function, _ in _MODULE_READERS
    }
    found = {}
    for module_name in module_names():
        module = import_module(module_name)
        for method in _FAMILY:
            function = getattr(module, method, None)
            if not callable(function) or isinstance(function, type):
                continue
            if getattr(function, "__module__", "") != module_name:
                continue
            parameters = list(signature(function).parameters)
            found[f"{module_name}.{method}"] = parameters[1:]

    assert set(found) == covered
    assert {
        (name.rsplit(".", 1)[0], name.rsplit(".", 1)[1]): extra
        for name, extra in found.items()
        if extra
    } == _MODULE_EXTRA_ARGUMENTS


def test_the_family_takes_no_argument_this_file_does_not_drive() -> None:
    """What the eight methods take, beyond the object and `check_validity`.

    Read off the signatures rather than listed, which is what makes
    `_EXTRA_ARGUMENTS` a record instead of a wish: an argument added to
    any `parse`, `serialize`, `to_dict` or `from_dict` in the library
    fails here until it is driven above or given a reason of its own.

    The argument this walk does not count is the object's own: the
    encoding a reader is handed -- `data`, `dict_`, `uri`, `address` --
    which the tests above drive for every class carrying one, and which a
    writer does not have at all, the object being what it writes.
    """
    found: dict[tuple[str, str], str] = {}
    for method in _FAMILY:
        for name in public_classes_with(method):
            module_name, _, class_name = name.rpartition(".")
            cls = getattr(import_module(module_name), class_name)
            parameters = [
                parameter
                for parameter in signature(getattr(cls, method)).parameters
                # `cls` is gone already, a classmethod read off the class
                # being bound to it; `self` is not, an instance method read
                # off the class being the plain function
                if parameter not in ("self", "cls", "check_validity")
            ]
            # then the encoding, which is the first argument of a reader
            # and is not an argument at all for a writer: what a writer
            # converts is the object it is called on
            extra = parameters[1:] if method in _READERS else parameters
            assert len(extra) <= 1, f"{name}.{method} takes {extra}"
            for parameter in extra:
                found[name, method] = parameter

    assert found == _EXTRA_ARGUMENTS


def test_the_family_takes_no_ec_or_hf() -> None:
    """No member of the family takes a curve or a hash function.

    Parametric above the byte boundary, mono-format at it: `parse`
    reads the curve and the hash function the format is defined over,
    not ones a caller names, so neither is ever a parameter here --
    the module docstring is the reason. No exclusion list, the same
    state `test_every_decoder_is_covered` keeps: an `ec` or an `hf`
    added to any member of this family, class method or module
    function, fails here rather than waiting for a reader to notice.
    """
    # unconditional, so that every line here runs whether or not a name
    # is ever found offending: the branch this test is for is the one
    # below, and a codebase with nothing to catch must not leave a line
    # of its own catcher uncovered
    found: dict[str, set[str]] = {}
    for method in _FAMILY:
        for name in public_classes_with(method):
            module_name, _, class_name = name.rpartition(".")
            cls = getattr(import_module(module_name), class_name)
            found[f"{name}.{method}"] = set(signature(getattr(cls, method)).parameters)

    for module_name in module_names():
        module = import_module(module_name)
        for method in _FAMILY:
            function = getattr(module, method, None)
            if not callable(function) or isinstance(function, type):
                continue
            if getattr(function, "__module__", "") != module_name:
                continue
            found[f"{module_name}.{method}"] = set(signature(function).parameters)

    offenders = {name for name, params in found.items() if params & {"ec", "hf"}}
    assert not offenders
