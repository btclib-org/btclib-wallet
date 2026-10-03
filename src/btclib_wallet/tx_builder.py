# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Compose the psbt spending a set of outputs, at a fee rate, with change.

Every part of this is elsewhere and nothing composes them, so every
caller composes them again: `Psbt` holds what is being built,
`psbt.prevouts` says what its inputs are worth, `Psbt.vsize_estimate`
says how large the signed transaction will be, `fee.fee_from_vsize`
prices that size and `fee.dust_threshold` says whether the change is
worth creating. `build_psbt` is that composition, and the three
decisions it makes are the ones a hand-written builder gets wrong.

**The fee comes from the rate and the size, and the size comes from the
psbt.** A transaction that is not signed has no size to be priced by --
`Tx.vsize` is read off a serialization, and the signatures are not
written yet -- so the object built here is a psbt: `Psbt.vsize_estimate`
sizes the missing signatures from each input's utxo and scripts, which
is the one thing in the tree that answers before there is anything to
sign. The unsigned transaction is `built.psbt.tx`, a property away, so a
second entry point answering with a `Tx` would be a second spelling of
one answer rather than a second answer.

**Change is an output or it is fee.** Below `dust_threshold` for its own
script an output cannot be relayed, so it is not created and its value
is left to the fee; and the transaction is then smaller than the one
that was priced, so the fee it owes is computed again rather than
reused. `change_index` is which output it is, or None for the branch
that dropped it.

**An input is a `PsbtIn`**: the outpoint it spends, the output that
outpoint names -- `non_witness_utxo`, with `witness_utxo` beside it for
a segwit input, or `witness_utxo` alone where every input is taproot and
none asks for ANYONECANPAY -- and whatever else says how it will be
unlocked, a redeem script or a witness script included. Two things
follow from taking the psbt's own map rather than a pair of an outpoint
and a `TxOut`. Nothing here fetches anything, an outpoint alone saying
neither what it is worth nor what it spends, and a builder that fetches
is a builder with a node in it; and an input whose script is wrapped or
multisig is estimated exactly, its redeem or witness script being a
field of the map that arrives rather than an argument this function
would have to grow. The outputs are `TxOut` and not `PsbtOut` because
the asymmetry is real: the input map is *read*, every byte a signature
will take being computed from it, where nothing computed here reads an
output map -- what a wallet writes into one, `descriptors`'
`update_psbt_output` on the change output at `change_index` included, is
written after this returns and changes no size.

Explicitly not here, both of them boundaries this library draws
elsewhere too:

- **coin selection**. Which utxos to spend is policy with a literature
  behind it, and keeping it out is what lets a caller bring its own;
  this spends the ones it is given, all of them. `tx.input_weight` is
  the number that caller prices a candidate with -- one input, before
  there is a psbt to put it in -- where what a fee is bought by here is
  the whole transaction, which `Psbt.vsize_estimate` is the one arithmetic
  for.
- **a node, an rpc, or wallet state**. The same arguments give the same
  answer forever, which is `fee`'s own boundary: what is downstream of a
  network -- a fee estimate for a confirmation target, which utxos are
  confirmed, the block height that would make an anti-fee-sniping lock
  time -- is fed in rather than fetched.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from math import ceil

from btclib import var_int
from btclib.alias import Octets
from btclib.consensus import WITNESS_SCALE_FACTOR
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.fee import DUST_RELAY_FEE_RATE, FeeRate, dust_threshold, fee_from_vsize
from btclib.tx import TxOut
from btclib.tx.limits import SEQUENCE_FINAL
from btclib.tx.tx import SEGWIT_MARKER
from btclib.utils import assert_type, bytes_from_octets, is_integer

from btclib_wallet.psbt.psbt import Psbt, prevouts
from btclib_wallet.psbt.psbt_in import PsbtIn
from btclib_wallet.psbt.psbt_out import PsbtOut
from btclib_wallet.psbt.psbt_size import SolutionSizer
from btclib_wallet.psbt.psbt_utils import PSBT_V0

__all__ = [
    "DEFAULT_MAX_FEE",
    "DEFAULT_MAX_FEE_RATE",
    "FundedPsbt",
    "build_psbt",
]

# Core's wallet.h DEFAULT_TRANSACTION_MAXFEE, the -maxtxfee default: 0.10
# BTC, the largest fee `build_psbt` pays unless its caller raises it
DEFAULT_MAX_FEE = 10_000_000

# Core's wallet.h DEFAULT_MAX_TRANSACTION_FEERATE, the -maxfeerate
# default: 0.10 BTC per kvB, the highest rate `build_psbt` pays unless its
# caller raises it
DEFAULT_MAX_FEE_RATE = FeeRate(sats_per_kvbyte=10_000_000)


@dataclass(frozen=True)
class FundedPsbt:
    """A psbt whose fee is paid, and what paying it decided.

    The three answers Bitcoin Core's `fundrawtransaction` gives, which
    is the same triple under its own names: the transaction, `fee`, and
    `changepos` -- spelled here as an index into the psbt's outputs, and
    None where Core writes -1 for the transaction that has no change
    output.

    `fee` is what the inputs are worth less what the outputs hold. It is
    at least what `fee_rate` asked of the estimated size and can exceed
    it, by exactly the change that was too small to create.
    """

    psbt: Psbt
    fee: int
    change_index: int | None

    @property
    def change(self) -> int:
        """Return the satoshi the change output holds, 0 where there is none."""
        if self.change_index is None:
            return 0
        return self.psbt.outputs[self.change_index].amount or 0


def _target_overhead_vsize(outputs: Sequence[TxOut], candidate_count: int) -> int:
    """Return what a transaction's own bytes cost, no input counted.

    Version, lock time, the output count and the outputs themselves,
    read off `Psbt.vsize_estimate` over a psbt of these outputs and no
    inputs at all -- this function is that estimate, not a second copy
    of its arithmetic, so a change to one reaches the other. Version and
    lock time cost four bytes each whatever value they hold, so the
    placeholder's own 2 and 0 answer for a caller who will pass
    `build_psbt` something else too.

    Padded by one virtual byte for the segwit marker `build_psbt` writes
    once any selected input carries a witness, which this function --
    given only the outputs, before a single input is chosen -- cannot
    know either way. The pad rounds up rather than down: left off, a
    selection built entirely of witness inputs would ask `build_psbt`
    for a few satoshi it does not have; left on, a selection of
    non-witness inputs alone asks for one virtual byte more than
    `build_psbt` will actually charge, an overshoot rather than a
    shortfall.

    `candidate_count` bounds the other unknown, the input count's own
    var_int: the placeholder above prices it at zero inputs, one byte,
    but the true count is whatever the selection this overhead feeds
    ends up choosing, which is not yet decided when this is asked and
    can be as large as the whole pool it is choosing from. Read from
    `candidate_count` -- the pool's own size, always at least the
    selected count -- rather than the placeholder's zero, so the
    estimate never charges for fewer input-count bytes than the real
    selection can turn out to need; below 253 candidates the two
    var_ints are one byte either way and this adds nothing.

    `coin_selection` is the caller this exists for: what one input costs
    is `tx.input_weight`'s answer, supplied per candidate; what the rest
    of the transaction costs is this one, and a selection's own target is
    the two added together, so that a match to it is a match `build_psbt`
    can fund.
    """
    psbt_outputs = [
        PsbtOut(amount=tx_out.value, script_pub_key=tx_out.script_pub_key.script)
        for tx_out in outputs
    ]
    placeholder = Psbt(
        2, [], psbt_outputs, PSBT_V0, {}, fallback_lock_time=0, check_validity=False
    )
    marker_pad = ceil(len(SEGWIT_MARKER) / WITNESS_SCALE_FACTOR)
    # the placeholder above already prices a zero-input var_int, one byte;
    # this is only the extra width a pool of 253 or more candidates can add
    input_count_pad = len(var_int.serialize(candidate_count)) - len(
        var_int.serialize(0)
    )
    return placeholder.vsize_estimate() + marker_pad + input_count_pad


def _assert_arguments(
    inputs: Sequence[PsbtIn],
    outputs: Sequence[TxOut],
    fee_rate: FeeRate,
    dust_fee_rate: FeeRate,
    max_fee: int,
    max_fee_rate: FeeRate,
) -> None:
    """Refuse an argument of the wrong type before a field is read off it.

    The two sequences are checked as sequences and then element by
    element, which is the shape `tests/built_object_contract_test.py`
    calls a sequence walked before it is checked: `None` is not iterable
    from underneath this library, and a `str` is a sequence of one-character
    strings that would each be read for fields it has not got.
    """
    assert_type(inputs, Sequence, "inputs")
    for psbt_in in inputs:
        assert_type(psbt_in, PsbtIn, "psbt input")
    assert_type(outputs, Sequence, "outputs")
    for tx_out in outputs:
        assert_type(tx_out, TxOut, "output")
    assert_type(fee_rate, FeeRate, "fee rate")
    assert_type(dust_fee_rate, FeeRate, "dust fee rate")
    assert_type(max_fee_rate, FeeRate, "max fee rate")
    if not is_integer(max_fee):
        raise BTClibTypeError(f"invalid max_fee type: {type(max_fee).__name__}")
    if max_fee < 0:
        raise BTClibValueError(f"negative max_fee: {max_fee}")


def _assert_fee_within(
    fee: int, vsize: int, max_fee: int, max_fee_rate: FeeRate
) -> None:
    """Refuse a fee above either ceiling, Core's `-maxtxfee` and `-maxfeerate`.

    `CreateTransactionInternal` compares the fee of the transaction it
    has built, change decided, first with the absolute ceiling and then
    with what the rate ceiling asks of that transaction's virtual size,
    rounded up as `CFeeRate::GetFee` rounds it -- `fee_from_vsize`'s own
    rounding. So this runs on each of `build_psbt`'s exits rather than on
    what coin selection expected, and `vsize` is the estimate the fee was
    priced on: Core's size is that of the transaction it built, signed
    where it signs, and this estimate bounds the signed one from above.
    """
    if fee > max_fee:
        err_msg = f"a fee of {fee} satoshi exceeds max_fee, {max_fee} satoshi"
        raise BTClibValueError(err_msg)
    ceiling = fee_from_vsize(vsize, max_fee_rate)
    if fee > ceiling:
        err_msg = f"a fee of {fee} satoshi on {vsize} vbytes exceeds "
        err_msg += f"max_fee_rate, which allows {ceiling} satoshi"
        raise BTClibValueError(err_msg)


def build_psbt(
    inputs: Sequence[PsbtIn],
    outputs: Sequence[TxOut],
    fee_rate: FeeRate,
    change_script_pub_key: Octets | None,
    *,
    tx_version: int = 2,
    lock_time: int = 0,
    dust_fee_rate: FeeRate = DUST_RELAY_FEE_RATE,
    max_fee: int = DEFAULT_MAX_FEE,
    max_fee_rate: FeeRate = DEFAULT_MAX_FEE_RATE,
    sizer: SolutionSizer | None = None,
) -> FundedPsbt:
    """Return the psbt spending these inputs at this rate, and its change.

    `inputs` are the psbt's own input maps, each carrying the outpoint it
    spends and the output that outpoint names; `outputs` are what is
    being paid. What is left over pays the fee, and `change_script_pub_key`
    is where the rest of it goes -- to an output of that script when it
    would be worth more than `dust_threshold` asks, and to the fee when
    it would not. None is every leftover satoshi to the fee, which is
    what a caller sweeping an address means and what a caller who forgot
    the argument would get, so it is spelled rather than defaulted.

    Raised, all as `BTClibValueError`: no inputs, no outputs left to pay,
    an outpoint spent twice, an input carrying no utxo, an input whose
    type the psbt does not determine -- `psbt_size`'s rule, and `sizer`
    is where a caller answers for one -- an output worth less than
    `dust_threshold` for its script, a `lock_time` that every input's
    sequence voids, a negative `max_fee`, inputs that do not cover the
    outputs and the fee, and a fee above `max_fee` or above what
    `max_fee_rate` asks of the estimated size.

    `tx_version` and `lock_time` are the transaction's, defaulting to
    Core's own 2 and to no lock time: the block height that would make a
    lock time worth setting is a node's answer, and this function has no
    node. Each input's sequence is its own `PsbtIn.sequence`, and an
    input naming none spends with the final sequence -- no lock time and
    no BIP125 replacement, which a caller wanting either sets on the
    input rather than having overwritten here. Consensus ignores the lock
    time of a transaction whose every input is final, so a non-zero
    `lock_time` there is refused rather than built into a transaction it
    does not constrain.

    `dust_fee_rate` is the rate the dust threshold is computed at, for
    the outputs being paid and for the change, Core's `-dustrelayfee`
    default; it is not `fee_rate`, an output being dust by what the
    network will relay rather than by what this transaction chose to pay.

    `max_fee` is the largest fee paid, in satoshi, `DEFAULT_MAX_FEE` being
    Core's `-maxtxfee` default of 0.10 BTC, and `max_fee_rate` the
    highest rate, `DEFAULT_MAX_FEE_RATE` being Core's `-maxfeerate`
    default of 0.10 BTC per kvB: a fee that a mistyped `fee_rate`, or a
    sweep of inputs worth far more than its outputs, runs past either is
    refused rather than paid. The fee compared is the one returned,
    change that was too small to create included, and the size the rate
    is applied to is `Psbt.vsize_estimate`'s.

    The psbt is version 0, which every Signer reads; `Psbt.to_v2` is the
    other one.
    """
    _assert_arguments(inputs, outputs, fee_rate, dust_fee_rate, max_fee, max_fee_rate)
    if not inputs:
        raise BTClibValueError("no inputs")
    change_script = (
        None
        if change_script_pub_key is None
        else bytes_from_octets(change_script_pub_key)
    )

    psbt_outputs = [
        PsbtOut(amount=tx_out.value, script_pub_key=tx_out.script_pub_key.script)
        for tx_out in outputs
    ]
    change_index: int | None = None
    if change_script is not None:
        change_index = len(psbt_outputs)
        # the amount is what the fee leaves and the fee is what this
        # psbt's size costs, so the output has to be in it before there
        # is an amount to put in the output. A value is eight bytes
        # whatever it holds, so the estimate does not move when the
        # placeholder below is replaced by the answer computed from it
        psbt_outputs.append(PsbtOut(amount=0, script_pub_key=change_script))

    # not validated here: `prevouts` below validates, and it is the first
    # thing that reads the psbt
    psbt = Psbt(
        tx_version,
        inputs,
        psbt_outputs,
        PSBT_V0,
        {},
        fallback_lock_time=lock_time,
        check_validity=False,
    )
    # `prevouts` validates, and the psbt's transaction with it, so the
    # outpoint spent twice this sum would double count is refused before
    # the sum is made -- `Tx.assert_valid`'s rule, Core's
    # `bad-txns-inputs-duplicate`, rather than one this function repeats
    total_in = sum(prev_out.value for prev_out in prevouts(psbt))
    total_out = sum(tx_out.value for tx_out in outputs)
    remainder = total_in - total_out

    # what the caller asked for, refused before any fee is priced: Core's
    # `CreateTransactionInternal` refuses a dust recipient before it
    # selects a coin
    for i, tx_out in enumerate(outputs):
        threshold = dust_threshold(tx_out.script_pub_key.script, dust_fee_rate)
        if tx_out.value < threshold:
            err_msg = f"output {i} of {tx_out.value} satoshi is dust: "
            err_msg += f"its script's threshold is {threshold} satoshi"
            raise BTClibValueError(err_msg)
    if lock_time != 0 and all(
        tx_in.sequence == SEQUENCE_FINAL for tx_in in psbt.tx.vin
    ):
        err_msg = f"lock_time {lock_time} is void: every input's sequence is "
        err_msg += "final, and one input needs a non-final PsbtIn.sequence"
        raise BTClibValueError(err_msg)

    if change_script is not None:
        vsize = psbt.vsize_estimate(sizer)
        fee = fee_from_vsize(vsize, fee_rate)
        change = remainder - fee
        if change >= dust_threshold(change_script, dust_fee_rate):
            _assert_fee_within(fee, vsize, max_fee, max_fee_rate)
            # the last output, this having appended it
            psbt.outputs[-1].amount = change
            # the one state nothing else has judged: every other exit
            # returns what `vsize_estimate` last validated
            psbt.assert_valid()
            return FundedPsbt(psbt, fee, change_index)
        # dust cannot be created, so what would have been change is fee
        psbt.outputs.pop()
        change_index = None

    if not psbt.outputs:
        err_msg = "no outputs: nothing is paid, and there is no change to create"
        raise BTClibValueError(err_msg)
    # the whole leftover, which is at least what the rate asks: the
    # transaction is smaller than the one priced above, so what it owes
    # is computed again rather than the larger figure reused
    vsize = psbt.vsize_estimate(sizer)
    owed = fee_from_vsize(vsize, fee_rate)
    if remainder < owed:
        err_msg = f"the inputs are worth {total_in} satoshi, "
        err_msg += f"where the outputs and the fee need {total_out + owed}"
        raise BTClibValueError(err_msg)
    _assert_fee_within(remainder, vsize, max_fee, max_fee_rate)
    return FundedPsbt(psbt, remainder, change_index)
