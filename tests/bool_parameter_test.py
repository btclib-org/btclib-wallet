# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every `bool` parameter of the package, classified and held to its class.

btclib's census of the same name, over this package: a kind written down
and read back -- json, a configuration file, a coordinator's message --
arrives as whatever it was written as, and `"false"` is true
(issue btclib-org/btclib#868).

## The line, and the shape that makes it decidable

A **truth** only decides whether the call refuses: `verify_checksum=False`
says do not check, and the answer is the same one. So a value read for its
truth runs a check or skips one and changes no answer, which is why
nothing is refused there.

A **kind** decides what a non-refusing call computes, returns or writes.
`"no"` is true, so a kind read for its truth quietly computes the other
answer -- the other key, the other signature, the other script -- and that
is what the refusal is for.

## The polarity a truth has to have

`"no"` is true, and so is every other wrong value, so the misreading is
never "the flag was off": it is always the one the flag's `True` stands
for. That is what makes a truth safe rather than the fact that it changes
no answer: the wrong value falls on the side that refuses more.

So a truth's `True` has to be its conservative value, and a flag whose
`True` is the permissive one is a kind however little it computes:
`allow_partial` is one, in `_KINDS` with its reason beside it
(issue btclib-org/btclib#884).

The two tests below are that line, one each:

- a kind refuses `"no"`, `0`, `1` and (where the annotation does not
  declare it) `None`, with a `BTClibTypeError`
- a truth **accepts** them, on a fixture the flag's `True` accepts: a
  truth that starts refusing fails here, and the entry has to move rather
  than the test being edited

## The walk, and the one name it subtracts

`_bool_parameters` reads every public function of the package and every
`bool`-annotated parameter of one, so a flag added anywhere is either in a
table here or the run is red -- there is no third table, and that is the
state to keep.

`check_validity` is subtracted by name: it is a convention rather than a
parameter, held by btclib's own `check_validity_test.py` to one rule over
every class.

## Where a fixture is not what it looks like

`hwi.enumerate_devices` runs a command line, so its stand-in is `python -c
"print('[]')"` -- a device list of none, which is what an `emulators` of
the wrong type must be refused in front of.
"""

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from btclib.b58 import p2pkh
from btclib.curves import bytes_from_point, bytes_from_prv_key_int, mult
from btclib.exceptions import BTClibTypeError
from btclib.key import PrvKeyData, PubKeyData
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx
from btclib.tx.tx_in import TxIn
from btclib.tx.tx_out import TxOut

from btclib_wallet import bip38, bip322, core_import, slip132
from btclib_wallet.bip32.bip32 import (
    _PythonPubKeyTweakChain,
    derive,
    derive_from_account,
    derive_from_account_,
    derive_from_account_range,
    derive_from_account_range_,
    prv_keyinfo_from_xprv,
    pub_keyinfo_from_xpub,
    rootxprv_from_seed,
    xpub_from_xprv,
)
from btclib_wallet.bip32.der_path import (
    hardenings_from_der_path,
    indexes_from_der_path,
    int_from_index_str,
)
from btclib_wallet.descriptors.descriptors import parse as descriptor_from_string
from btclib_wallet.fetch.bitcoin_core import BitcoinCoreFetcher
from btclib_wallet.fetch.bitcoin_core_rest import (
    BitcoinCoreRestClient,
    BitcoinCoreRestFetcher,
)
from btclib_wallet.fetch.electrum import ElectrumFetcher
from btclib_wallet.fetch.esplora import EsploraFetcher
from btclib_wallet.hwi import HwiSigner, enumerate_devices
from btclib_wallet.mnemonic import bip39, slip39
from btclib_wallet.mnemonic.entropy import (
    bin_str_entropy_from_random,
    bin_str_entropy_from_rolls,
)
from btclib_wallet.mnemonic.mnemonic import WordLists
from btclib_wallet.psbt import musig2 as psbt_musig2
from btclib_wallet.psbt.psbt import Psbt, assert_signed
from btclib_wallet.psbt.psbt import join as psbt_join
from btclib_wallet.psbt.psbt_in import PsbtIn
from btclib_wallet.psbt.psbt_utils import (
    deserialize_sized_int,
    deserialize_tx,
    serialize_sized_int,
)
from btclib_wallet.psbt_signer import SoftwareSigner
from btclib_wallet.wallet.script_wallet import KeyGroup
from tests.fetch import Recorded
from tests.fetch.bitcoin_core_test import client
from tests.fetch.electrum_test import LineRecorded
from tests.psbt import psbt_cases


def _is_signed(psbt: Psbt) -> bool:
    """Return whether every input of the psbt is signed through."""
    try:
        assert_signed(psbt)
    except Exception:  # noqa: BLE001
        return False
    return True


_LIBRARY = Path(__file__).parents[1] / "src" / "btclib_wallet"

# `check_validity` is the one name the walk subtracts, and this is the
# reason it may: it is a convention over many signatures rather than a
# parameter of one
_OWNED_BY_ITS_OWN_FILE = "check_validity"

# a value of no bool type: a truthy string, and the two integers `bool`
# inherits from. Every one of them is a call mypy refuses
_WRONG_TYPES: tuple[Any, ...] = ("no", 0, 1)

_PRV_KEY = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
_SEC = bytes_from_point(mult(_PRV_KEY))
_SEC_2 = bytes_from_prv_key_int(_PRV_KEY + 1)
_MSG = b"Satoshi Nakamoto"

_ROOT_XPRV = rootxprv_from_seed("00" * 32)
_ACCOUNT_XPRV = derive(_ROOT_XPRV, "m/44h/0h/0h")


# a block cipher this file never has to get right: `bip38.encrypt` and
# `new_key_pair` need one to reach `compressed` at all, and what happens
# to the plaintext is not this file's question, only whether the flag it
# is refusing was read for its type. A 16-byte block in, the same 16
# bytes out, is a cipher no BIP38 record could be decrypted with and a
# perfectly good fixture
def _block_cipher(key: bytes, block: bytes) -> bytes:
    return block


_INT_CODE = bip38.intermediate_code("test password")

_XPUB = xpub_from_xprv(_ROOT_XPRV)
_DESCRIPTOR = descriptor_from_string(f"wpkh({_XPUB}/0/*)")
_ADDRESS = p2pkh(PubKeyData(_SEC))
_BIP322_SIG = bip322.sign(_MSG, PrvKeyData(_PRV_KEY), _ADDRESS)

# a transaction with an input, which is what the psbt boundary refuses to
# work without
_TX = Tx(vin=[TxIn(OutPoint(b"\x00" * 32, 0))], vout=[TxOut(1000, b"\x51")])
# a second one spending another outpoint: what `join` refuses is two
# transactions with an input in common, so one twice is no fixture
_TX_2 = Tx(vin=[TxIn(OutPoint(b"\x11" * 32, 1))], vout=[TxOut(900, b"\x51")])
_PSBTS = [Psbt.from_tx(_TX), Psbt.from_tx(_TX_2)]
_TX_BYTES = _TX.serialize(include_witness=False, check_validity=False)

# the first BIP174 vector that is signed through, which is what makes
# `allow_partial` a flag both of whose values accept it
_SIGNED_PSBT = next(
    psbt
    for psbt in (
        Psbt.b64decode(case["encoded psbt"])
        for case in psbt_cases("bip174_test_vectors.json", "valid psbts")
    )
    if _is_signed(psbt)
)

# a device that answers HWI's own shape and needs no device: the flag is
# read in front of the command line, which is where it has to be
_STAND_IN = [sys.executable, "-c", "print('[]')"]


@dataclass(frozen=True)
class _Case:
    """One `bool` parameter, and a call of its function that works."""

    dotted: str
    flag: str
    function: Any
    # every argument but the flag, by keyword
    args: dict[str, Any] = field(default_factory=dict)
    # the flag value the working call is made with: `True` unless the
    # fixture is one only `False` accepts
    valid: bool = True
    # `bool | None` declares None, so it is not a wrong value there. Read
    # off the annotation, not an exemption from anything
    optional: bool = False
    # the classification, which is prose because it is a judgement: for a
    # truth what the flag turns on and what it therefore cannot change,
    # and for a kind only where the kind is the polarity rather than the
    # answer -- the flags carrying one below are those
    reason: str = ""


_KINDS = (
    # `compressed` chooses which public key is computed, and therefore
    # which address
    _Case(
        "btclib_wallet.bip38.encrypt",
        "compressed",
        bip38.encrypt,
        {
            "prv_key": _PRV_KEY,
            "password": "pw",  # pragma: allowlist secret
            "encrypt_block": _block_cipher,
        },
    ),
    _Case(
        "btclib_wallet.bip38.new_key_pair",
        "compressed",
        bip38.new_key_pair,
        {"int_code": _INT_CODE, "encrypt_block": _block_cipher},
    ),
    # the one that is a bound method: a chain holds the point it steps,
    # so the instance is built here and btclib's `bytes_from_point` is
    # the check this one reaches. A refused call must not step it, which
    # is why the serialization happens before the step rather than after
    _Case(
        "btclib_wallet.bip32.bip32._PythonPubKeyTweakChain.tweak_add",
        "compressed",
        _PythonPubKeyTweakChain(_SEC).tweak_add,
        {"tweak": _PRV_KEY.to_bytes(32, byteorder="big", signed=False)},
    ),
    # the psbt boundary: which integer encoding, and which transaction
    _Case(
        "btclib_wallet.psbt.psbt_utils.deserialize_sized_int",
        "signed",
        deserialize_sized_int,
        {"k": b"\x00", "v": b"\x01\x00\x00\x00", "type_": "field", "size": 4},
        valid=False,
    ),
    _Case(
        "btclib_wallet.psbt.psbt_utils.serialize_sized_int",
        "signed",
        serialize_sized_int,
        {"type_": b"\x00", "value": 1, "size": 4},
        valid=False,
    ),
    _Case(
        "btclib_wallet.psbt.psbt_utils.deserialize_tx",
        "include_witness",
        deserialize_tx,
        {"k": b"\x00", "v": _TX_BYTES, "type_": "field"},
        valid=False,
    ),
    _Case(
        "btclib_wallet.psbt.psbt_utils.deserialize_tx",
        "unsigned_template",
        deserialize_tx,
        {"k": b"\x00", "v": _TX_BYTES, "type_": "field", "include_witness": False},
        valid=False,
    ),
    _Case(
        "btclib_wallet.psbt.musig2.add_participant_pub_keys",
        "sort",
        psbt_musig2.add_participant_pub_keys,
        {"psbt_map": PsbtIn(), "participant_pub_keys": [_SEC, _SEC_2]},
        valid=False,
    ),
    _Case(
        "btclib_wallet.mnemonic.entropy.bin_str_entropy_from_rolls",
        "shuffle",
        bin_str_entropy_from_rolls,
        {"bits": 8, "dice_sides": 6, "rolls": [1, 2, 3, 4, 5, 6, 1, 2]},
    ),
    _Case(
        "btclib_wallet.mnemonic.entropy.bin_str_entropy_from_random",
        "to_be_hashed",
        bin_str_entropy_from_random,
        {"bits": 128},
    ),
    _Case(
        "btclib_wallet.psbt.psbt.join",
        "shuffle_inp",
        psbt_join,
        {
            "psbts": _PSBTS,
            "enforce_same_tx_version": True,
            "enforce_same_tx_lock_time": True,
            "shuffle_out": False,
        },
        valid=False,
    ),
    _Case(
        "btclib_wallet.psbt.psbt.join",
        "shuffle_out",
        psbt_join,
        {
            "psbts": _PSBTS,
            "enforce_same_tx_version": True,
            "enforce_same_tx_lock_time": True,
            "shuffle_inp": False,
        },
        valid=False,
    ),
    # which verification runs: a BMS signature over the message, or
    # BIP322's own
    _Case(
        "btclib_wallet.bip322.assert_as_valid",
        "legacy",
        bip322.assert_as_valid,
        {"msg": _MSG, "addr": _ADDRESS, "sig": _BIP322_SIG},
    ),
    _Case(
        "btclib_wallet.bip322.verify",
        "legacy",
        bip322.verify,
        {"msg": _MSG, "addr": _ADDRESS, "sig": _BIP322_SIG},
    ),
    _Case(
        "btclib_wallet.hwi.enumerate_devices",
        "emulators",
        enumerate_devices,
        {"executable": _STAND_IN},
        valid=False,
    ),
    _Case(
        "btclib_wallet.hwi.HwiSigner.__init__",
        "emulators",
        HwiSigner,
        {"fingerprint": "00" * 4, "executable": _STAND_IN},
        valid=False,
    ),
    _Case(
        "btclib_wallet.psbt_signer.SoftwareSigner.__init__",
        "musig2",
        SoftwareSigner,
        {"xkey": _ROOT_XPRV},
        valid=False,
    ),
    _Case(
        "btclib_wallet.psbt_signer.SoftwareSigner.from_accounts",
        "musig2",
        SoftwareSigner.from_accounts,
        {"master_fingerprint": "00" * 4, "accounts": {"m/0h": _XPUB}},
        valid=False,
    ),
    _Case(
        "btclib_wallet.core_import.import_request",
        "internal",
        core_import.import_request,
        {"descriptor": _DESCRIPTOR, "timestamp": 0},
        valid=False,
    ),
    _Case(
        "btclib_wallet.core_import.import_request",
        "active",
        core_import.import_request,
        {"descriptor": _DESCRIPTOR, "timestamp": 0},
    ),
    _Case(
        "btclib_wallet.core_import.account_import_requests",
        "active",
        core_import.account_import_requests,
        {"receive": _DESCRIPTOR, "change": _DESCRIPTOR, "timestamp": 0},
    ),
    _Case(
        "btclib_wallet.mnemonic.slip39.mnemonics_from_master_secret",
        "extendable",
        slip39.mnemonics_from_master_secret,
        {"master_secret": "00" * 16},
    ),
    _Case(
        "btclib_wallet.wallet.script_wallet.KeyGroup.__init__",
        "verify",
        KeyGroup,
        {"threshold": 2, "keys": [_XPUB, _XPUB]},
        valid=False,
    ),
    _Case(
        "btclib_wallet.psbt.psbt.assert_signed",
        "allow_partial",
        assert_signed,
        {"psbt": _SIGNED_PSBT},
        reason="`True` accepts an input still unsigned, so a non-bool"
        " stores as complete a psbt nobody finished signing",
    ),
    # the two extended-key parses. Their `compressed` computes nothing --
    # a BIP32 key is compressed, so the flag is a check on a key that has
    # already answered the question -- and it is the polarity that makes
    # each a kind
    _Case(
        "btclib_wallet.bip32.bip32.prv_keyinfo_from_xprv",
        "compressed",
        prv_keyinfo_from_xprv,
        {"xprv": _ROOT_XPRV},
        optional=True,
        reason="`True` is the value an extended key already has, so a"
        " non-bool passes the check a False was written down to fail and"
        " an uncompressed key is reported as this compressed one",
    ),
    _Case(
        "btclib_wallet.bip32.bip32.pub_keyinfo_from_xpub",
        "compressed",
        pub_keyinfo_from_xpub,
        {"xpub": _XPUB},
        optional=True,
        reason="`prv_keyinfo_from_xprv`'s above, on the public half",
    ),
)

_TRUTHS = (
    _Case(
        "btclib_wallet.slip132.p2pkh_xkey",
        "check_root_xkey",
        slip132.p2pkh_xkey,
        {"xkey": _ROOT_XPRV},
        reason="whether the xkey is required to be a root one",
    ),
    _Case(
        "btclib_wallet.slip132.p2wpkh_xkey",
        "check_root_xkey",
        slip132.p2wpkh_xkey,
        {"xkey": _ROOT_XPRV},
        reason="whether the xkey is required to be a root one",
    ),
    _Case(
        "btclib_wallet.slip132.p2wpkh_p2sh_xkey",
        "check_root_xkey",
        slip132.p2wpkh_p2sh_xkey,
        {"xkey": _ROOT_XPRV},
        reason="whether the xkey is required to be a root one",
    ),
    _Case(
        "btclib_wallet.mnemonic.bip39.seed_from_mnemonic",
        "verify_checksum",
        bip39.seed_from_mnemonic,
        {"mnemonic": "abandon " * 11 + "about", "passphrase": ""},
        reason="whether the mnemonic's checksum is checked; the seed is the"
        " same either way, being a PBKDF2 of the words",
    ),
    _Case(
        "btclib_wallet.mnemonic.bip39.mxprv_from_mnemonic",
        "verify_checksum",
        bip39.mxprv_from_mnemonic,
        {"mnemonic": "abandon " * 11 + "about"},
        reason="whether the mnemonic's checksum is checked",
    ),
    _Case(
        "btclib_wallet.bip32.der_path.int_from_index_str",
        "bip380_enforced",
        int_from_index_str,
        {"s": "0"},
        reason="whether BIP380's spelling rules are enforced; an index both"
        " accept is the same integer",
    ),
    _Case(
        "btclib_wallet.bip32.der_path.indexes_from_der_path",
        "bip380_enforced",
        indexes_from_der_path,
        {"der_path": "0/1"},
        reason="whether BIP380's spelling rules are enforced",
    ),
    _Case(
        "btclib_wallet.bip32.der_path.hardenings_from_der_path",
        "bip380_enforced",
        hardenings_from_der_path,
        {"der_path": "0/1"},
        reason="whether BIP380's spelling rules are enforced",
    ),
    _Case(
        "btclib_wallet.psbt.psbt.join",
        "enforce_same_tx_version",
        psbt_join,
        {
            "psbts": _PSBTS,
            "enforce_same_tx_lock_time": True,
            "shuffle_inp": False,
            "shuffle_out": False,
        },
        reason="whether a transaction version the others do not share is refused",
    ),
    _Case(
        "btclib_wallet.psbt.psbt.join",
        "enforce_same_tx_lock_time",
        psbt_join,
        {
            "psbts": _PSBTS,
            "enforce_same_tx_version": True,
            "shuffle_inp": False,
            "shuffle_out": False,
        },
        reason="whether a lock time the others do not share is refused",
    ),
    # the declaration the four below forward to, and the one that gives
    # them the same name, the same keyword-only argument and the same
    # default. Driven through a backend because the class it belongs to
    # is abstract: `assert_network` is what a backend answers for itself,
    # so there is no instance of the base to construct
    _Case(
        "btclib_wallet.fetch.fetcher.NetworkVerifyingFetcher.__init__",
        "verify_network",
        ElectrumFetcher,
        {"transport": LineRecorded()},
        reason="whether the host is asked which chain it serves before"
        " the first answer leaves; a check, and the fetch is the same"
        " fetch either way",
    ),
    _Case(
        "btclib_wallet.fetch.bitcoin_core.BitcoinCoreFetcher.__init__",
        "verify_network",
        BitcoinCoreFetcher,
        {"client": client()},
        reason="whether the node is asked which chain it serves; a check,"
        " and the one the fetcher makes before its first fetch",
    ),
    _Case(
        "btclib_wallet.fetch.bitcoin_core_rest.BitcoinCoreRestFetcher.__init__",
        "verify_network",
        BitcoinCoreRestFetcher,
        {
            "client": BitcoinCoreRestClient(
                "http://127.0.0.1:8332", transport=Recorded()
            )
        },
        reason="whether the node is asked which chain it serves, the same"
        " check over -rest, `/chaininfo.json` carrying the same `chain`",
    ),
    _Case(
        "btclib_wallet.fetch.esplora.EsploraFetcher.__init__",
        "verify_network",
        EsploraFetcher,
        {"base_url": "https://esplora.example/api", "transport": Recorded()},
        reason="whether the explorer is asked which chain it serves; the"
        " same check under the same name, made before its first fetch",
    ),
    _Case(
        "btclib_wallet.fetch.electrum.ElectrumFetcher.__init__",
        "verify_network",
        ElectrumFetcher,
        {"transport": LineRecorded()},
        reason="whether the server is asked which chain it serves; the"
        " same check again, over the header at height 0 this backend"
        " hashes rather than a chain name it would be told",
    ),
    _Case(
        "btclib_wallet.bip32.bip32.derive_from_account",
        "branches_0_1_only",
        derive_from_account,
        {"mxkey": _ACCOUNT_XPRV, "branch": 0, "address_index": 0},
        reason="whether a branch other than 0 and 1 is refused; the key"
        " derived at a branch both accept is the same key",
    ),
    _Case(
        "btclib_wallet.bip32.bip32.derive_from_account_",
        "branches_0_1_only",
        derive_from_account_,
        {"mxkey": _ACCOUNT_XPRV, "branch": 0, "address_index": 0},
        reason="the flag of `derive_from_account` above, in the spelling"
        " that answers the key rather than its Base58Check text",
    ),
    _Case(
        "btclib_wallet.bip32.bip32.derive_from_account_range",
        "branches_0_1_only",
        derive_from_account_range,
        {"mxkey": _ACCOUNT_XPRV, "branch": 0, "address_indexes": [0]},
        reason="the flag of `derive_from_account` above, over many"
        " addresses of one branch rather than over one",
    ),
    _Case(
        "btclib_wallet.bip32.bip32.derive_from_account_range_",
        "branches_0_1_only",
        derive_from_account_range_,
        {"mxkey": _ACCOUNT_XPRV, "branch": 0, "address_indexes": [0]},
        reason="the flag of `derive_from_account_range` above, in the"
        " spelling that answers the keys rather than their text",
    ),
    _Case(
        "btclib_wallet.mnemonic.mnemonic.WordLists.__init__",
        "power_of_two",
        WordLists,
        {},
        reason="whether a word list whose length is not a power of two is"
        " refused, which is what Electrum's 1626 words need off",
    ),
)

_KIND_IDS = tuple(f"{case.dotted}({case.flag})" for case in _KINDS)
_TRUTH_IDS = tuple(f"{case.dotted}({case.flag})" for case in _TRUTHS)


def _flags_of(function: ast.FunctionDef) -> set[str]:
    """Return the `bool`-annotated parameters of one public function."""
    if function.name.startswith("_") and not function.name.startswith("__"):
        return set()
    arguments = [
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    ]
    return {
        argument.arg
        for argument in arguments
        if argument.annotation is not None
        and ast.unparse(argument.annotation) in {"bool", "bool | None"}
        and argument.arg != _OWNED_BY_ITS_OWN_FILE
    }


def _bool_parameters() -> set[tuple[str, str]]:
    """Return every (function, `bool` parameter) pair of the public API.

    Keyed on the annotation, `bool` and `bool | None`: what a flag is
    called says nothing, and `include_witness` is spelled both ways.

    A method counts and a private function does not, as in
    `curve_parameter_test.py`; and a function nested in another is a
    closure rather than API -- `Miniscript.to_script`'s `up` takes a
    `verify` that no caller can pass.
    """
    found: set[tuple[str, str]] = set()

    def walk(node: ast.Module | ast.ClassDef, module: str, prefix: str) -> None:
        for child in node.body:
            if isinstance(child, ast.ClassDef):
                walk(child, module, f"{prefix}{child.name}.")
            elif isinstance(child, ast.FunctionDef):
                dotted = f"{module}.{prefix}{child.name}"
                found.update((dotted, flag) for flag in _flags_of(child))

    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        walk(ast.parse(path.read_text(encoding="utf-8")), module, "")
    return found


@pytest.mark.parametrize("case", [*_KINDS, *_TRUTHS], ids=[*_KIND_IDS, *_TRUTH_IDS])
def test_the_call_works(case: _Case) -> None:
    """The fixture is valid, which is what makes a refusal below a finding.

    Without this a case whose arguments had gone stale would pass every
    test in the file by refusing everything it is handed.
    """
    case.function(**case.args, **{case.flag: case.valid})


@pytest.mark.parametrize("case", _KINDS, ids=_KIND_IDS)
def test_a_kind_refuses_a_non_bool(case: _Case) -> None:
    """A kind decides what is computed, so it is not read for its truth.

    `"no"` is the value that makes the point -- it is true, so the flag
    would be on -- and `0` and `1` are the two `bool` inherits from, which
    is what makes `isinstance(value, int)` no check at all here.
    """
    wrong = _WRONG_TYPES if case.optional else (*_WRONG_TYPES, None)
    for value in wrong:
        with pytest.raises(BTClibTypeError, match=f"invalid {case.flag} type"):
            case.function(**case.args, **{case.flag: value})


@pytest.mark.parametrize("case", _TRUTHS, ids=_TRUTH_IDS)
def test_a_truth_is_read_for_its_truth(case: _Case) -> None:
    """The other half of the line, and the ratchet under this file.

    A truth turns a check on or off and changes no answer, so a value of
    another type is read for whether it is true and refused by nothing.
    An entry that starts refusing fails here rather than passing quietly:
    the fix is to move it to `_KINDS`, which is a decision about the
    parameter and not about this test.
    """
    for value in _WRONG_TYPES:
        case.function(**case.args, **{case.flag: value})


def test_every_bool_parameter_is_classified() -> None:
    """No third table: a flag is a kind or a truth, and the walk says so.

    A parameter added anywhere under `src/btclib_wallet/` fails here until
    somebody decides which of the two it is -- which is the decision this file
    exists to keep from being made by default.
    """
    classified = {(case.dotted, case.flag) for case in (*_KINDS, *_TRUTHS)}
    found = _bool_parameters()
    assert classified == found, (
        f"unclassified: {sorted(found - classified)};"
        f" gone from the tree: {sorted(classified - found)}"
    )


def test_the_walk_reaches_what_it_claims() -> None:
    """The shapes it must find, and the four it must not.

    A walk that found nothing would pass the test above.
    """
    found = _bool_parameters()
    # a defaulted flag, a required one, an optional annotation, a method
    assert ("btclib_wallet.bip38.encrypt", "compressed") in found
    assert ("btclib_wallet.psbt.psbt.join", "shuffle_inp") in found
    assert ("btclib_wallet.bip32.bip32.prv_keyinfo_from_xprv", "compressed") in found
    assert ("btclib_wallet.hwi.HwiSigner.__init__", "emulators") in found

    # the convention with a file of its own
    assert not [pair for pair in found if pair[1] == "check_validity"]
    # a private function, a closure, and a parameter of another type
    assert ("btclib_wallet.psbt.psbt._tx_in", "zeroed_sequence") not in found
    assert ("btclib_wallet.descriptors.miniscript.up", "verify") not in found
    assert ("btclib_wallet.bip32.bip32.derive", "der_path") not in found
