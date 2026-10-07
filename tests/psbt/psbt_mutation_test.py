# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A corrupted psbt is refused or read as given, by `Psbt` and `PsbtView`.

A signer reads untrusted bytes, so the property is: a psbt with flipped
or missing bytes is either refused, or parsed as exactly the bytes it
is, with no repair and no difference between the two readers.

The cases are those of embit's `tests/tests/test_parsing.py`, at commit
2b375a33bd8926caec7e53d7cfd41b165d196566
(https://github.com/diybitcoinhardware/embit): the bit-flip corpus, the
scriptSig length flips, the global transaction's empty scriptSigs, the
truncated global transaction and the global transaction boundaries, with the
non-witness utxo boundaries of its `test_non_witness_boundary`.
"""

from __future__ import annotations

import base64
from collections.abc import Iterator
from typing import Any

import pytest
from btclib import var_int
from btclib.exceptions import BTClibValueError
from btclib.tx import OutPoint, Tx, TxIn, TxOut

from btclib_wallet.psbt import Psbt, PsbtView

_P2PKH = b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"


def _base() -> bytes:
    """Return embit's psbt, the one whose bits are flipped."""
    tx = Tx(
        2,
        0x0701,
        [TxIn(OutPoint(bytes(range(32)).hex(), 0), b"", 0xFFFFFFFE)],
        [
            TxOut(value, b"\x76\xa9\x14" + bytes(range(n, n + 20)) + b"\x88\xac")
            for n, value in ((0, 99999699), (20, 402653184))
        ],
    )
    return Psbt.from_tx(tx).serialize()


def _flips(size: int) -> Iterator[list[int]]:
    """Yield every single bit position, then sets of two and of three bits.

    A fixed LCG rather than `random`, so the corpus does not depend on the
    interpreter or its version.
    """
    for position in range(size * 8):
        yield [position]
    state = 0x9E3779B9
    for count in (2, 3):
        for _ in range(500):
            positions = []
            for _ in range(count):
                state = (state * 1103515245 + 12345) & 0x7FFFFFFF
                positions.append(state % (size * 8))
            yield positions


def _walk(raw: bytes) -> tuple[Any, ...]:
    """Return what a signer sees through a view."""
    view = PsbtView(raw)
    return (
        view.version,
        view.tx_version,
        view.lock_time,
        view.tx,
        [view.input(i) for i in range(view.input_count)],
        [view.output(i) for i in range(view.output_count)],
    )


def _read_by_both(raw: bytes, mutant: object = None) -> Psbt | None:
    """Return the psbt both readers accept, None where both refuse.

    One refusing and the other not fails; so does an accepted psbt that
    does not serialize to its own bytes, or that the readers see differently.
    `mutant` names the case in the failure message.
    """
    where = "" if mutant is None else f": {mutant}"
    try:
        psbt: Psbt | None = Psbt.parse(raw)
    except BTClibValueError:
        psbt = None
    try:
        seen: tuple[Any, ...] | None = _walk(raw)
    except BTClibValueError:
        seen = None

    if psbt is None:
        assert seen is None, f"only the view accepts it{where}"
        return None
    assert psbt.serialize() == raw, f"repaired{where}"
    assert seen == (
        psbt.version,
        psbt.tx_version,
        psbt.lock_time,
        psbt.tx,
        psbt.inputs,
        psbt.outputs,
    ), f"the readers disagree{where}"
    return psbt


def _global_psbt(tx_octets: bytes) -> bytes:
    """Return a psbt whose global map declares this as its transaction."""
    return (
        b"psbt\xff\x01\x00" + var_int.serialize(len(tx_octets)) + tx_octets + bytes(3)
    )


def test_the_base_psbt_is_read_by_both() -> None:
    """The control: what is flipped below is itself accepted."""
    base = _base()
    assert _read_by_both(base) is not None


def test_a_bit_flipped_psbt_is_refused_or_read_as_given() -> None:
    """Every mutant is refused by both, or read by both as its own bytes."""
    base = _base()
    accepted = refused = 0
    for positions in _flips(len(base)):
        mutant = bytearray(base)
        for position in positions:
            mutant[position // 8] ^= 1 << (position % 8)
        if _read_by_both(bytes(mutant), positions) is None:
            refused += 1
        else:
            accepted += 1
    # a flip in an id, an amount or a script can give another valid psbt;
    # a flip in a length, a count or the framing is refused
    assert accepted > 0
    assert refused > 0


@pytest.mark.parametrize("bit", range(8))
def test_a_flipped_script_sig_length_is_refused(bit: int) -> None:
    """The global transaction's scriptSig length is 0; no flip of it is read."""
    tx = Tx(
        2,
        7,
        [TxIn(OutPoint(bytes(range(32)).hex(), 1), b"", 0xFFFFFFFF)],
        [TxOut(i, _P2PKH) for i in range(2)],
    )
    payload = Psbt.from_tx(tx).serialize()
    offset = payload.index(tx.serialize(include_witness=True)) + 4 + 1 + 36
    assert payload[offset] == 0
    assert _read_by_both(payload) is not None

    mutant = bytearray(payload)
    mutant[offset] ^= 1 << bit
    assert _read_by_both(bytes(mutant)) is None


def test_a_truncated_global_transaction_is_refused() -> None:
    """A transaction declared 117 octets long that needs 119.

    Its lock time runs two octets past the value, into the separators after
    it, which embit before ff98e0f read as the lock time.
    """
    payload = base64.b64decode(
        "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+"  # pragma: allowlist secret
        "////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UvKwIAAAAYAAAAABl2qRQ5"
        "RIJtUF/J8tJ37TUDq/eSSI9aJ8GAAQcAAAAA"
    )
    assert payload[7] == 117
    assert _read_by_both(payload) is None


def test_the_global_transaction_boundaries() -> None:
    """A global transaction of the wrong length, or a cut psbt, is refused.

    The transaction is one or four octets short or one long; the psbt is cut
    at 20 octets.
    """
    raw = Tx(
        2,
        0,
        [TxIn(OutPoint(bytes(range(32)).hex(), 1), b"", 0xFFFFFFFF)],
        [TxOut(42, b"")],
    ).serialize(include_witness=True)
    assert _read_by_both(_global_psbt(raw)) is not None

    for declared in (raw[:-1], raw[:-4], raw + b"x"):
        assert _read_by_both(_global_psbt(declared)) is None
    assert _read_by_both(_global_psbt(raw)[:20]) is None


@pytest.mark.parametrize("signed", [[0], [1], [0, 1, 2]])
def test_a_global_transaction_with_a_script_sig_is_refused(
    signed: list[int],
) -> None:
    """BIP174 has the global transaction unsigned: every scriptSig is empty."""

    def payload(signed: list[int]) -> bytes:
        vin = [
            TxIn(
                OutPoint(bytes(range(32)).hex(), i),
                b"\x51\x51" if i in signed else b"",
                0xFFFFFFFF,
            )
            for i in range(3)
        ]
        raw = Tx(2, 7, vin, [TxOut(42, b"")]).serialize(include_witness=True)
        # the global map's end, then a map for each of 3 inputs and 1 output
        return _global_psbt(raw)[:-3] + bytes(5)

    assert _read_by_both(payload([])) is not None
    assert _read_by_both(payload(signed)) is None


def _psbt_with_a_utxo() -> tuple[bytes, int, bytes]:
    """Return a psbt, where its non-witness utxo value starts, and the value."""
    # a lock time ending in a non-zero octet: a value one octet short is
    # completed by the 0x00 after it, which must not give back this transaction
    prev_tx = Tx(
        1,
        0x01000000,
        [TxIn(OutPoint("22" * 32, 0), b"\x51", 0)],
        [TxOut(9, b"\x51")],
    )
    tx = Tx(2, 0, [TxIn(OutPoint(prev_tx.id, 0), b"", 0)], [TxOut(1, b"\x51")])
    psbt = Psbt.from_tx(tx)
    psbt.inputs[0].non_witness_utxo = prev_tx
    value = prev_tx.serialize(include_witness=False)
    raw = psbt.serialize()
    return raw, raw.index(var_int.serialize(len(value)) + value), value


@pytest.mark.parametrize(
    "length_delta, value_delta",
    [(-1, 0), (1, 1), (0, -1)],
    ids=["length one short", "one octet past the transaction", "value one short"],
)
def test_a_non_witness_utxo_whose_length_is_not_its_value_is_refused(
    length_delta: int, value_delta: int
) -> None:
    """The declared length and the transaction it holds must agree."""
    raw, start, value = _psbt_with_a_utxo()
    assert _read_by_both(raw) is not None

    new_value = (value + b"x")[: len(value) + value_delta]
    field = var_int.serialize(len(value) + length_delta) + new_value
    mutant = raw[:start] + field + raw[start + 1 + len(value) :]
    assert _read_by_both(mutant) is None
