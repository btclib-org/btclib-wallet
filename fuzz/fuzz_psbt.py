# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib_wallet.psbt.psbt.Psbt`'s two decoders.

A psbt travels between wallets that do not trust each other -- that is
what it is for -- and every one of them parses what the last one wrote
before any signature in it has been looked at. Its own maps are
length-prefixed keys and values whose types decide how the value is read,
which is a deserializer taking a stranger's own numbers, and BIP174's
file form wraps the whole of it in base64 that anybody can paste.

`parse` is the octets and `b64decode` is the armor in front of them, so
this harness runs both against the same input: neither is reachable from
the other, `b64decode` refusing what is not canonical base64 before
`parse` ever sees it. `Psbt.parse` dispatches to `PsbtIn.parse`,
`PsbtOut.parse` and the map and Taproot-tree readers of
`psbt_utils.py` for every record a psbt carries, so a corpus of real
psbts drives those readers too; each also has its own direct entry point
in the Hypothesis property suite, `tests/fuzz_test.py`.

A psbt that parses is then used. It is serialized, and the
serialization has to be a fixed point: `serialize(parse(serialize(p)))
== serialize(p)`. The bytes need not come back as they arrived, because
`PsbtIn.serialize` drops the signing fields of a finalized input
(`_DROPPED_ONCE_FINALIZED` in `psbt_in.py`). The psbt is then read the
way a wallet reads it next: `to_dict`, `prevouts`, `assert_signable`
and `finalize`, whose result has to serialize to a fixed point too.

A crash here on hostile bytes is a defect in the parser, in `serialize`
or in one of those readers, never in this harness: `data` is
unconstrained bytes handed straight to each entry point, `b64decode`
taking bytes as the ascii it decodes them from. `BTClibException` and
`EccException` are what the entry points and the readers answer input
they refuse with, so that family is caught below as the expected
outcome. `parse` has already validated the psbt, so nothing is caught
around `serialize`, the second `parse` and `to_dict`: a refusal from
any of them is a finding. An `IndexError`, a `RecursionError` or a
failed check of this harness propagates to atheris as the finding it
is.

The seed corpus holds, as octets, every valid psbt of
`tests/psbt/_data/bip174_test_vectors.json` and
`bip371_test_vectors.json`, and the first BIP174 one also as the base64
it is published as. The fuzzer thus starts from witness utxos, partial
signatures, scripts, BIP32 derivations and the Taproot records, rather
than having to build each by mutation. It also holds the psbt with a
final script witness that `tests/psbt/_data/rust-psbt/bip174.json`
expects from "Workflow A (step 7)", and the two psbts that crashed
rust-bitcoin's combiner, `tests/psbt/_data/psbt_fuzz1.hex` and
`psbt_fuzz2.hex`.

Byte mutation keeps a seed's records and seldom writes a new one that
parses. `custom_mutator` below mutates the records instead: it splits
the octets into maps, changes, deletes, duplicates or adds records and
maps, and joins them again.
"""

from __future__ import annotations

import contextlib
import io
import random
import sys
from collections.abc import Callable

import atheris
from btclib import var_bytes, var_int
from btclib.exceptions import BTClibException
from ecc.exceptions import EccException

from btclib_wallet.psbt.psbt import (
    PSBT_GLOBAL_FALLBACK_LOCKTIME,
    PSBT_GLOBAL_INPUT_COUNT,
    PSBT_GLOBAL_OUTPUT_COUNT,
    PSBT_GLOBAL_TX_MODIFIABLE,
    PSBT_GLOBAL_TX_VERSION,
    PSBT_GLOBAL_UNSIGNED_TX,
    PSBT_GLOBAL_VERSION,
    PSBT_GLOBAL_XPUB,
    PSBT_MAGIC_BYTES,
    Psbt,
    finalize,
    prevouts,
)
from btclib_wallet.psbt.psbt_in import (
    PSBT_IN_BIP32_DERIVATION,
    PSBT_IN_FINAL_SCRIPTSIG,
    PSBT_IN_FINAL_SCRIPTWITNESS,
    PSBT_IN_HASH160,
    PSBT_IN_HASH256,
    PSBT_IN_MUSIG2_PARTIAL_SIG,
    PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS,
    PSBT_IN_MUSIG2_PUB_NONCE,
    PSBT_IN_NON_WITNESS_UTXO,
    PSBT_IN_OUTPUT_INDEX,
    PSBT_IN_PARTIAL_SIG,
    PSBT_IN_PREVIOUS_TXID,
    PSBT_IN_REDEEM_SCRIPT,
    PSBT_IN_REQUIRED_HEIGHT_LOCKTIME,
    PSBT_IN_REQUIRED_TIME_LOCKTIME,
    PSBT_IN_RIPEMD160,
    PSBT_IN_SEQUENCE,
    PSBT_IN_SHA256,
    PSBT_IN_SIG_HASH_TYPE,
    PSBT_IN_TAP_BIP32_DERIVATION,
    PSBT_IN_TAP_INTERNAL_KEY,
    PSBT_IN_TAP_KEY_SIG,
    PSBT_IN_TAP_LEAF_SCRIPT,
    PSBT_IN_TAP_MERKLE_ROOT,
    PSBT_IN_TAP_SCRIPT_SIG,
    PSBT_IN_WITNESS_SCRIPT,
    PSBT_IN_WITNESS_UTXO,
)
from btclib_wallet.psbt.psbt_out import (
    PSBT_OUT_AMOUNT,
    PSBT_OUT_BIP32_DERIVATION,
    PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS,
    PSBT_OUT_REDEEM_SCRIPT,
    PSBT_OUT_SCRIPT,
    PSBT_OUT_TAP_BIP32_DERIVATION,
    PSBT_OUT_TAP_INTERNAL_KEY,
    PSBT_OUT_TAP_TREE,
    PSBT_OUT_WITNESS_SCRIPT,
)
from btclib_wallet.psbt.psbt_utils import (
    MUSIG2_PARTIAL_SIG_SIZE,
    MUSIG2_PUB_NONCE_SIZE,
    PSBT_SEPARATOR,
    PSBT_V0,
    PSBT_V2,
)

# tests/fuzz_corpus_test.py reads this by ast.literal_eval. It also loads
# this module with a placeholder for the CI-only atheris, and runs
# fuzz_target on every seed. Its mutator tests give that placeholder a
# Mutate stub, so atheris may be called only from main() and through
# atheris.Mutate.
ENTRY_POINTS = (
    "btclib_wallet.psbt.psbt:Psbt.parse",
    "btclib_wallet.psbt.psbt:Psbt.b64decode",
)


def _assert_fixed_point(psbt: Psbt) -> None:
    """Serialize `psbt`, parse that, and serialize it again unchanged."""
    serialized = psbt.serialize()
    if Psbt.parse(serialized).serialize() != serialized:
        raise AssertionError("psbt serialization is not a fixed point")


def _use(psbt: Psbt) -> None:
    """Serialize an accepted psbt, then read it as a wallet would."""
    _assert_fixed_point(psbt)
    psbt.to_dict()
    with contextlib.suppress(BTClibException, EccException):
        prevouts(psbt)
    with contextlib.suppress(BTClibException, EccException):
        psbt.assert_signable()
    try:
        finalized = finalize(psbt)
    except (BTClibException, EccException):
        return
    _assert_fixed_point(finalized)


def fuzz_target(data: bytes) -> None:
    """Parse `data` as psbt octets, then as the base64 armor of some.

    Each psbt either one accepts is used; the module docstring says what
    is caught and what propagates.
    """
    try:
        psbt = Psbt.parse(data)
    except (BTClibException, EccException):
        pass
    else:
        _use(psbt)
    try:
        psbt = Psbt.b64decode(data)
    except (BTClibException, EccException):
        pass
    else:
        _use(psbt)


# ---- the structure-aware mutator --------------------------------------
#
# Bitcoin Core's PSBT mutator, PR bitcoin/bitcoin#36631's
# src/test/fuzz/util/psbt.cpp, in Python. Where Core replaces an input
# that does not split into maps with a minimal psbt, this hands it to
# atheris.Mutate: the same bytes also feed Psbt.b64decode, and a
# template would replace the base64 seed.

_Map = list[tuple[bytes, bytes]]
_Bytes = Callable[[random.Random], bytes]

_V0 = 1
_V2 = 2
_ANY_VERSION = _V0 | _V2
_PROPRIETARY = b"\xfc"
# G and 2G: key data is checked, and random bytes are almost never a point
_G = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"  # pragma: allowlist secret
_2G = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"  # pragma: allowlist secret
_PUB_KEYS = (bytes.fromhex(_G), bytes.fromhex(_2G))
_X_ONLY = _PUB_KEYS[0][1:]
_XPUB_VERSION = bytes.fromhex("0488b21e")
_TAPSCRIPT = 0xC0


def _random_bytes(size: int) -> _Bytes:
    """Return a maker of `size` random bytes."""
    return lambda rng: rng.randbytes(size)


def _any_bytes(rng: random.Random) -> bytes:
    return rng.randbytes(rng.randrange(64))


def _no_key_data(_: random.Random) -> bytes:
    return b""


def _pub_key(rng: random.Random) -> bytes:
    return rng.choice(_PUB_KEYS)


def _x_only(_: random.Random) -> bytes:
    return _X_ONLY


def _x_only_leaf(rng: random.Random) -> bytes:
    return _X_ONLY + rng.randbytes(32)


def _control_block(rng: random.Random) -> bytes:
    leaf_version = bytes([_TAPSCRIPT | rng.getrandbits(1)])
    return leaf_version + _X_ONLY + rng.randbytes(32 * rng.randrange(3))


def _xpub(rng: random.Random) -> bytes:
    # a depth above zero, so that the random fingerprint and child number
    # are allowed
    depth = bytes([rng.randrange(1, 256)])
    return _XPUB_VERSION + depth + rng.randbytes(4 + 4 + 32) + _pub_key(rng)


def _musig2_ids(rng: random.Random) -> bytes:
    leaf_hash = rng.randbytes(32) if rng.getrandbits(1) else b""
    return _pub_key(rng) + _pub_key(rng) + leaf_hash


def _proprietary(rng: random.Random) -> bytes:
    identifier = var_bytes.serialize(rng.randbytes(rng.randrange(8)))
    subtype = var_int.serialize(rng.randrange(4))
    return identifier + subtype + rng.randbytes(rng.randrange(8))


def _tx(rng: random.Random) -> bytes:
    """Return an unsigned transaction of one to three inputs and outputs."""
    script_size = rng.randrange(64)
    tx_ins = [
        rng.randbytes(32 + 4) + var_bytes.serialize(b"") + b"\xff" * 4
        for _ in range(rng.randrange(1, 4))
    ]
    tx_outs = [
        rng.randbytes(8) + var_bytes.serialize(rng.randbytes(script_size))
        for _ in range(rng.randrange(1, 4))
    ]
    return b"".join(
        [
            (2).to_bytes(4, "little"),
            var_int.serialize(len(tx_ins)),
            *tx_ins,
            var_int.serialize(len(tx_outs)),
            *tx_outs,
            bytes(4),
        ]
    )


def _tx_out(rng: random.Random) -> bytes:
    return rng.randbytes(8) + var_bytes.serialize(_any_bytes(rng))


def _der_sig(rng: random.Random) -> bytes:
    """Return a strict DER signature of SIGHASH_ALL."""
    r = bytes([rng.randrange(1, 0x80)]) + rng.randbytes(31)
    s = bytes([rng.randrange(1, 0x80)]) + rng.randbytes(31)
    return b"\x30\x44\x02\x20" + r + b"\x02\x20" + s + b"\x01"


def _key_origin(rng: random.Random) -> bytes:
    return rng.randbytes(4 * rng.randrange(1, 5))


def _tap_key_origin(rng: random.Random) -> bytes:
    leaf_hashes = rng.randrange(3)
    return (
        var_int.serialize(leaf_hashes)
        + rng.randbytes(32 * leaf_hashes)
        + _key_origin(rng)
    )


def _pub_keys(rng: random.Random) -> bytes:
    return b"".join(_pub_key(rng) for _ in range(rng.randrange(1, 4)))


def _tap_tree(rng: random.Random) -> bytes:
    """Return a complete tree: one leaf at depth 0, or two at depth 1."""
    depth = rng.getrandbits(1)
    return b"".join(
        bytes([depth, _TAPSCRIPT])
        + var_bytes.serialize(rng.randbytes(rng.randrange(16)))
        for _ in range(1 + depth)
    )


def _psbt_version(rng: random.Random) -> bytes:
    return rng.choice((PSBT_V0, PSBT_V2)).to_bytes(4, "little")


# (key type, the versions allowing it, key data, value) of each record a
# BIP174, BIP370, BIP371 or BIP373 map may carry
_Known = tuple[bytes, int, _Bytes, _Bytes]
_GLOBAL_RECORDS: tuple[_Known, ...] = (
    (PSBT_GLOBAL_UNSIGNED_TX, _V0, _no_key_data, _tx),
    (PSBT_GLOBAL_XPUB, _ANY_VERSION, _xpub, _key_origin),
    (PSBT_GLOBAL_TX_VERSION, _V2, _no_key_data, _random_bytes(4)),
    (PSBT_GLOBAL_FALLBACK_LOCKTIME, _V2, _no_key_data, _random_bytes(4)),
    (PSBT_GLOBAL_INPUT_COUNT, _V2, _no_key_data, _random_bytes(1)),
    (PSBT_GLOBAL_OUTPUT_COUNT, _V2, _no_key_data, _random_bytes(1)),
    (PSBT_GLOBAL_TX_MODIFIABLE, _V2, _no_key_data, _random_bytes(1)),
    (PSBT_GLOBAL_VERSION, _ANY_VERSION, _no_key_data, _psbt_version),
    (_PROPRIETARY, _ANY_VERSION, _proprietary, _any_bytes),
)
_INPUT_RECORDS: tuple[_Known, ...] = (
    (PSBT_IN_NON_WITNESS_UTXO, _ANY_VERSION, _no_key_data, _tx),
    (PSBT_IN_WITNESS_UTXO, _ANY_VERSION, _no_key_data, _tx_out),
    (PSBT_IN_PARTIAL_SIG, _ANY_VERSION, _pub_key, _der_sig),
    (PSBT_IN_SIG_HASH_TYPE, _ANY_VERSION, _no_key_data, _random_bytes(4)),
    (PSBT_IN_REDEEM_SCRIPT, _ANY_VERSION, _no_key_data, _any_bytes),
    (PSBT_IN_WITNESS_SCRIPT, _ANY_VERSION, _no_key_data, _any_bytes),
    (PSBT_IN_BIP32_DERIVATION, _ANY_VERSION, _pub_key, _key_origin),
    (PSBT_IN_FINAL_SCRIPTSIG, _ANY_VERSION, _no_key_data, _any_bytes),
    (PSBT_IN_FINAL_SCRIPTWITNESS, _ANY_VERSION, _no_key_data, _any_bytes),
    (PSBT_IN_RIPEMD160, _ANY_VERSION, _random_bytes(20), _any_bytes),
    (PSBT_IN_SHA256, _ANY_VERSION, _random_bytes(32), _any_bytes),
    (PSBT_IN_HASH160, _ANY_VERSION, _random_bytes(20), _any_bytes),
    (PSBT_IN_HASH256, _ANY_VERSION, _random_bytes(32), _any_bytes),
    (PSBT_IN_PREVIOUS_TXID, _V2, _no_key_data, _random_bytes(32)),
    (PSBT_IN_OUTPUT_INDEX, _V2, _no_key_data, _random_bytes(4)),
    (PSBT_IN_SEQUENCE, _V2, _no_key_data, _random_bytes(4)),
    (PSBT_IN_REQUIRED_TIME_LOCKTIME, _V2, _no_key_data, _random_bytes(4)),
    (PSBT_IN_REQUIRED_HEIGHT_LOCKTIME, _V2, _no_key_data, _random_bytes(4)),
    (PSBT_IN_TAP_KEY_SIG, _ANY_VERSION, _no_key_data, _random_bytes(64)),
    (PSBT_IN_TAP_SCRIPT_SIG, _ANY_VERSION, _x_only_leaf, _random_bytes(64)),
    (PSBT_IN_TAP_LEAF_SCRIPT, _ANY_VERSION, _control_block, _any_bytes),
    (PSBT_IN_TAP_BIP32_DERIVATION, _ANY_VERSION, _x_only, _tap_key_origin),
    (PSBT_IN_TAP_INTERNAL_KEY, _ANY_VERSION, _no_key_data, _random_bytes(32)),
    (PSBT_IN_TAP_MERKLE_ROOT, _ANY_VERSION, _no_key_data, _random_bytes(32)),
    (PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS, _ANY_VERSION, _pub_key, _pub_keys),
    (
        PSBT_IN_MUSIG2_PUB_NONCE,
        _ANY_VERSION,
        _musig2_ids,
        _random_bytes(MUSIG2_PUB_NONCE_SIZE),
    ),
    (
        PSBT_IN_MUSIG2_PARTIAL_SIG,
        _ANY_VERSION,
        _musig2_ids,
        _random_bytes(MUSIG2_PARTIAL_SIG_SIZE),
    ),
    (_PROPRIETARY, _ANY_VERSION, _proprietary, _any_bytes),
)
_OUTPUT_RECORDS: tuple[_Known, ...] = (
    (PSBT_OUT_REDEEM_SCRIPT, _ANY_VERSION, _no_key_data, _any_bytes),
    (PSBT_OUT_WITNESS_SCRIPT, _ANY_VERSION, _no_key_data, _any_bytes),
    (PSBT_OUT_BIP32_DERIVATION, _ANY_VERSION, _pub_key, _key_origin),
    (PSBT_OUT_AMOUNT, _V2, _no_key_data, _random_bytes(8)),
    (PSBT_OUT_SCRIPT, _V2, _no_key_data, _any_bytes),
    (PSBT_OUT_TAP_INTERNAL_KEY, _ANY_VERSION, _no_key_data, _random_bytes(32)),
    (PSBT_OUT_TAP_TREE, _ANY_VERSION, _no_key_data, _tap_tree),
    (PSBT_OUT_TAP_BIP32_DERIVATION, _ANY_VERSION, _x_only, _tap_key_origin),
    (PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS, _ANY_VERSION, _pub_key, _pub_keys),
    (_PROPRIETARY, _ANY_VERSION, _proprietary, _any_bytes),
)


def _split(data: bytes) -> list[_Map]:
    """Return psbt octets as maps of records, a duplicated key kept.

    A map cut short is dropped, and the maps before it kept. There is no
    map where the magic bytes are missing.
    """
    if not data.startswith(PSBT_MAGIC_BYTES):
        return []
    stream = io.BytesIO(data[len(PSBT_MAGIC_BYTES) :])
    maps: list[_Map] = []
    with contextlib.suppress(BTClibException):
        while stream.tell() < len(stream.getbuffer()):
            records: _Map = []
            while key := var_bytes.parse(stream):
                records.append((key, var_bytes.parse(stream)))
            maps.append(records)
    return maps


def _join(maps: list[_Map]) -> bytes:
    """Return the maps as psbt octets, each record and separator in place."""
    return PSBT_MAGIC_BYTES + b"".join(
        b"".join(
            var_bytes.serialize(key) + var_bytes.serialize(value)
            for key, value in records
        )
        + PSBT_SEPARATOR
        for records in maps
    )


def _value_of(records: _Map, key: bytes) -> bytes | None:
    """Return the value of the first record whose whole key is `key`."""
    return next((value for k, value in records if k == key), None)


def _input_count(global_map: _Map, version: int) -> int | None:
    """Return how many input maps the global map declares, if it says."""
    if version == _V2:
        value = _value_of(global_map, PSBT_GLOBAL_INPUT_COUNT)
    else:
        tx = _value_of(global_map, PSBT_GLOBAL_UNSIGNED_TX)
        # the input count follows the version of an unsigned transaction
        value = None if tx is None else tx[4:]
    try:
        return None if value is None else var_int.parse(value)
    except BTClibException:
        return None


def _known_record(
    maps: list[_Map], index: int, rng: random.Random
) -> tuple[bytes, bytes]:
    """Return a record of a type the map at `index` may carry.

    The global map comes first, then the inputs, then the outputs. A
    type of the version the global map declares is preferred, one call in
    eight taking a type of either version.
    """
    v2 = PSBT_V2.to_bytes(4, "little")
    version = _V2 if _value_of(maps[0], PSBT_GLOBAL_VERSION) == v2 else _V0
    if index == 0:
        pool = _GLOBAL_RECORDS
    else:
        input_count = _input_count(maps[0], version)
        is_input = rng.getrandbits(1) if input_count is None else index <= input_count
        pool = _INPUT_RECORDS if is_input else _OUTPUT_RECORDS
    allowed = _ANY_VERSION if rng.randrange(8) == 0 else version
    key_type, _, key_data, value = rng.choice(
        [record for record in pool if record[1] & allowed]
    )
    return key_type + key_data(rng), value(rng)


def _mutate_maps(maps: list[_Map], rng: random.Random) -> None:
    """Apply one record or map mutation to `maps`, in place."""
    index = rng.randrange(len(maps))
    records = maps[index]
    mutation = rng.randrange(6)
    if mutation == 5:
        # a map added or removed shifts the input and output counts the
        # maps imply
        if len(maps) == 1 or rng.getrandbits(1):
            maps.append([])
        else:
            del maps[index]
    elif mutation == 4:
        records.append(_known_record(maps, index, rng))
    elif records:
        i = rng.randrange(len(records))
        key, value = records[i]
        # room to grow, so that a field of another length can be reached
        if mutation == 0:
            records[i] = (key, atheris.Mutate(value, len(value) + 16))
        elif mutation == 1:
            if key:
                records[i] = (atheris.Mutate(key, len(key) + 16), value)
        elif mutation == 2:
            del records[i]
        else:
            # a duplicated key, for the parser to refuse
            records.append(records[i])


def custom_mutator(data: bytes, max_size: int, seed: int) -> bytes:
    """Mutate psbt octets record by record, else as bytes.

    One call in eight, and every call whose input does not split into
    maps, mutates the raw bytes through `atheris.Mutate`. Every other
    call applies one to three record or map mutations and joins the maps
    again.
    """
    rng = random.Random(seed)  # noqa: S311 -- seeded by libFuzzer, no secret
    if rng.randrange(8) == 0:
        return atheris.Mutate(data, max_size)
    maps = _split(data)
    if not maps:
        return atheris.Mutate(data, max_size)
    for _ in range(rng.randrange(1, 4)):
        _mutate_maps(maps, rng)
    return _join(maps)[:max_size]


def main() -> None:
    """Wire `fuzz_target` and `custom_mutator` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(
        sys.argv,
        fuzz_target,
        custom_mutator=custom_mutator,
        enable_python_coverage=True,
    )
    atheris.Fuzz()


if __name__ == "__main__":
    main()
