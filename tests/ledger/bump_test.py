# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A `Ledger`'s fee bumps, over a chain in memory.

Each case of Core's test/functional/wallet_bumpfee.py at
bitcoin/bitcoin@f0de87f040 (the v32.1 tag) that the ledger answers is
named by its lines; `tests/integration/ledger_test.py` asks bitcoind.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.fee import FeeRate, fee_from_vsize
from btclib.script.witness import Witness
from btclib.tx import OutPoint, Tx, TxIn, TxOut

from btclib_wallet.descriptors import parse
from btclib_wallet.exceptions import FetchError
from btclib_wallet.fetch.relay_fees import RelayFees
from btclib_wallet.ledger import Ledger, TxState, WalletTx
from btclib_wallet.ledger.ledger import _assert_replaces
from btclib_wallet.psbt.psbt import Psbt, extract_tx, finalize
from btclib_wallet.psbt.psbt_size import miniscript_sizer
from btclib_wallet.psbt_signer import SoftwareSigner
from btclib_wallet.wallet import DescriptorWallet
from tests.ledger.conftest import (
    ONE_SAT,
    XPRV,
    FakeChain,
    script_of,
    source,
    tampered,
)

RBF = 0xFFFFFFFD
NON_RBF = 0xFFFFFFFE


def _rate(sats_per_vbyte: float) -> FeeRate:
    return FeeRate.from_sats_per_vbyte(sats_per_vbyte)


def _funded(ledger: Ledger, chain: FakeChain, value: int = 100_000) -> Tx:
    """Pay the ledger from outside and confirm it."""
    payment = chain.pay([TxOut(value, script_of(ledger.new_address()))])
    chain.mine([payment])
    ledger.sync()
    return payment


def _outside(value: int = 30_000) -> TxOut:
    """Return an output paying somebody else."""
    other = source("wpkh({}/84h/1h/9h/{}/*)", (0,))
    return TxOut(value, other.script_pub_key(0, 0))


def _wtx(ledger: Ledger, tx: Tx) -> WalletTx:
    return ledger.transaction(tx.id).wallet_tx


def _fee(ledger: Ledger, tx: Tx) -> int:
    fee = ledger.transaction(tx.id).fee
    assert fee is not None
    return fee


def _assert_fee_amount(fee: int, vsize: int, rate: FeeRate) -> None:
    """Core's `assert_fee_amount` (test/functional/test_framework/util.py).

    The fee is what the rate asks of the size, up to two virtual bytes
    more, for a signature shorter than the one priced.
    """
    assert fee_from_vsize(vsize, rate) <= fee <= fee_from_vsize(vsize + 2, rate)


def _sent(ledger: Ledger, chain: FakeChain, vin: list[TxIn], vout: list[TxOut]) -> Tx:
    """Return a transaction the ledger signs, broadcast and synced."""
    unsigned = Tx(vin=vin, vout=vout)
    tx = extract_tx(finalize(ledger.sign(Psbt.from_tx(unsigned))))
    chain.broadcast(tx)
    ledger.sync()
    return tx


def test_a_spend_signals_replaceability_unless_asked_not_to(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Core's DEFAULT_WALLET_RBF, and its sequence for an input not signalling.

    src/wallet/wallet.h:132 and src/wallet/spend.cpp:1303-1311.
    """
    _funded(ledger, chain)
    assert {tx_in.sequence for tx_in in ledger.spend([_outside()]).vin} == {RBF}
    spent = ledger.spend([_outside()], replaceable=False)
    assert {tx_in.sequence for tx_in in spent.vin} == {NON_RBF}
    funded = ledger.fund([_outside(1_000)], replaceable=False)
    assert {psbt_in.sequence for psbt_in in funded.psbt.inputs} == {NON_RBF}


def test_comments_are_kept_with_a_spend_and_in_the_file(
    ledger: Ledger, chain: FakeChain, path: Path
) -> None:
    """`sendtoaddress`'s comment and comment_to, as `gettransaction` reads."""
    _funded(ledger, chain)
    spent = ledger.spend([_outside()], comment="2 pizzas", comment_to="jeremy")
    ledger.sync()
    assert (_wtx(ledger, spent).comment, _wtx(ledger, spent).comment_to) == (
        "2 pizzas",
        "jeremy",
    )
    ledger.close()
    with Ledger.load(path, "regtest", chain) as loaded:
        held = _wtx(loaded, spent)
        assert (held.comment, held.comment_to) == ("2 pizzas", "jeremy")
    with pytest.raises(BTClibTypeError, match="invalid comment type"):
        ledger.spend([_outside()], comment=1)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid comment_to type"):
        ledger.spend([_outside()], comment_to=1)  # type: ignore[arg-type]


def test_a_bump_replaces_the_spend_and_links_the_two(
    ledger: Ledger, chain: FakeChain, path: Path
) -> None:
    """Lines 307-347, 721-731 and 743-756: links, comments, the same change."""
    _funded(ledger, chain)
    spent = ledger.spend([_outside()], comment="c", comment_to="t")
    bumped = ledger.bump(spent.id)
    assert [i.prev_out for i in bumped.vin] == [i.prev_out for i in spent.vin]
    assert {i.sequence for i in bumped.vin} == {RBF}
    # the payment is the same, the change paid to the same script
    assert bumped.vout[0] == spent.vout[0]
    assert bumped.vout[1].script_pub_key == spent.vout[1].script_pub_key
    assert _fee(ledger, bumped) > _fee(ledger, spent)
    assert bumped.vout[1].value == spent.vout[1].value - (
        _fee(ledger, bumped) - _fee(ledger, spent)
    )
    # the change address was reused, none handed out
    assert ledger.new_change_address() == ledger.sources[0].address(1, 1)
    assert spent.id not in chain.mempool

    def linked(held: Ledger) -> None:
        old, new = _wtx(held, spent), _wtx(held, bumped)
        assert (old.state, old.replaced_by, old.replaces) == (
            TxState.INACTIVE,
            bumped.id,
            None,
        )
        assert (new.state, new.replaced_by, new.replaces) == (
            TxState.MEMPOOL,
            None,
            spent.id,
        )
        assert (new.comment, new.comment_to) == ("c", "t")
        assert held.transaction(spent.id).wallet_conflicts == {bumped.id}

    linked(ledger)
    ledger.sync()
    linked(ledger)
    ledger.close()
    with Ledger.load(path, "regtest", chain) as loaded:
        linked(loaded)


def test_the_rate_none_names_is_the_replaced_one_raised(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Core's `EstimateFeeRate`, then the estimate for a target where higher."""
    _funded(ledger, chain)
    spent = ledger.spend([_outside()])
    old_fee = _fee(ledger, spent)
    bumped = ledger.bump_psbt(spent.id)
    assert (bumped.replaces, bumped.old_fee) == (spent.id, old_fee)
    vsize = bumped.psbt.vsize_estimate(miniscript_sizer)
    # the node's incremental rate, 1 sat/vB here, is below the wallet's
    rate = FeeRate(sats_per_kvbyte=old_fee * 1000 // spent.vsize + 1 + 5_000)
    assert bumped.fee == fee_from_vsize(vsize, rate)
    chain.estimate = _rate(20)
    bumped = ledger.bump_psbt(spent.id, conf_target=2)
    assert bumped.fee == fee_from_vsize(vsize, _rate(20))
    chain.relay = RelayFees(ONE_SAT, ONE_SAT, _rate(30))
    chain.estimate = None
    bumped = ledger.bump_psbt(spent.id)
    rate = FeeRate(sats_per_kvbyte=old_fee * 1000 // spent.vsize + 1 + 30_000)
    assert bumped.fee == fee_from_vsize(vsize, rate)


def test_a_named_rate_pays_the_incremental_rate_over_the_replacement(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Lines 120-130 and 813-832: the replaced rate is refused, one more not."""
    _funded(ledger, chain)
    # the spend paid 2 sat/vB, and the node's incremental rate is 1
    spent = ledger.spend([_outside()])
    with pytest.raises(BTClibValueError, match="insufficient total fee"):
        ledger.bump_psbt(spent.id, _rate(2))
    bumped = ledger.bump_psbt(spent.id, _rate(3))
    vsize = bumped.psbt.vsize_estimate(miniscript_sizer)
    assert bumped.fee == bumped.old_fee + vsize
    chain.relay = RelayFees(ONE_SAT, _rate(5), ONE_SAT)
    with pytest.raises(BTClibValueError, match="below the mempool's minimum 5000"):
        ledger.bump_psbt(spent.id, _rate(4))


def test_the_replacement_rule_is_cores_pays_for_rbf() -> None:
    """src/policy/rbf.cpp:100-125: at the threshold, and one satoshi under."""
    _assert_replaces(1_000, 1_141, 141, ONE_SAT)
    with pytest.raises(BTClibValueError, match="at least 1141"):
        _assert_replaces(1_000, 1_140, 141, ONE_SAT)
    # Core's default incremental rate, 0.1 sat/vB, rounded up
    _assert_replaces(1_000, 1_015, 141, FeeRate(sats_per_kvbyte=100))
    with pytest.raises(BTClibValueError, match="incremental fee 15"):
        _assert_replaces(1_000, 1_014, 141, FeeRate(sats_per_kvbyte=100))


def test_a_ledger_with_no_relay_fee_reader_takes_cores_incremental_rate(
    chain: FakeChain, path: Path
) -> None:
    """Lines 826-831: 2.1 sat/vB over 2 pays 0.1 sat/vB over the replacement."""
    with Ledger.create(
        path, "regtest", chain, broadcaster=chain, fallback_fee_rate=_rate(2)
    ) as ledger:
        ledger.add_source(source(), lookahead=3)
        _funded(ledger, chain)
        spent = ledger.spend([_outside()])
        with pytest.raises(BTClibValueError, match="insufficient total fee"):
            ledger.bump_psbt(spent.id, _rate(2))
        bumped = ledger.bump(spent.id, _rate(2.1))
        assert _fee(ledger, bumped) > _fee(ledger, spent)
        # with no rate named: the wallet's 5 sat/vB over the replaced rate
        again = ledger.bump_psbt(bumped.id)
        vsize = again.psbt.vsize_estimate(miniscript_sizer)
        rate = again.old_fee * 1000 // bumped.vsize + 1 + 5_000
        assert again.fee == fee_from_vsize(vsize, FeeRate(sats_per_kvbyte=rate))


def test_new_outputs_take_a_new_change_address(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Lines 316-319 and 343-346: the outputs named replace the old ones."""
    _funded(ledger, chain)
    spent = ledger.spend([_outside()])
    bumped = ledger.bump(spent.id, outputs=[_outside(20_000)])
    assert bumped.vout[0] == _outside(20_000)
    assert ledger.position_of(bumped.vout[1].script_pub_key) == (0, 1, 1)
    assert ledger.new_change_address() == ledger.sources[0].address(1, 2)


def test_the_change_index_names_the_output_taking_the_change(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Lines 183-188 and 241-268: a receiving output recycled as change."""
    _funded(ledger, chain)
    receive = TxOut(20_000, script_of(ledger.new_address()))
    spent = ledger.spend([_outside(), receive])
    assert ledger.position_of(receive.script_pub_key) == (0, 0, 1)
    bumped = ledger.bump_psbt(spent.id, original_change_index=1)
    assert bumped.change_index == 2
    (output,) = [
        o
        for o in bumped.psbt.outputs
        if o.script_pub_key == receive.script_pub_key.script
    ]
    assert output.amount == 20_000 - (bumped.fee - bumped.old_fee)
    assert output.hd_key_paths
    # an output not the ledger's can take it too, as Core's can
    foreign = ledger.bump_psbt(spent.id, original_change_index=0)
    assert foreign.psbt.outputs[2].amount == 30_000 - (foreign.fee - foreign.old_fee)
    assert not foreign.psbt.outputs[2].hd_key_paths
    with pytest.raises(BTClibValueError, match="change index 3 is out of range"):
        ledger.bump_psbt(spent.id, original_change_index=3)
    with pytest.raises(BTClibValueError, match="incompatible"):
        ledger.bump_psbt(spent.id, outputs=[_outside()], original_change_index=0)


def test_a_change_address_given_a_label_is_paid_whole(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Core's `OutputIsChange` (src/wallet/feebumper.cpp:258), not the branch.

    A label makes the change address a receiving one, as *Labels* in the
    ledger's docstring says: the bump pays it whole and opens new change.
    """
    _funded(ledger, chain)
    _funded(ledger, chain)
    spent = ledger.spend([_outside()])
    assert ledger.position_of(spent.vout[1].script_pub_key) == (0, 1, 0)
    ledger.set_label(ledger.sources[0].address(1, 0), "savings")
    bumped = ledger.bump(spent.id)
    assert bumped.vout[:2] == spent.vout
    assert ledger.position_of(bumped.vout[2].script_pub_key) == (0, 1, 1)
    assert len(bumped.vin) == 2


def test_dust_change_goes_to_the_fee(ledger: Ledger, chain: FakeChain) -> None:
    """Lines 512-533: change below the dust threshold is not created."""
    _funded(ledger, chain)
    spent = ledger.spend([_outside(99_368)])
    assert len(spent.vout) == 2
    assert 294 <= spent.vout[1].value < 400
    bumped = ledger.bump(spent.id, _rate(3))
    assert bumped.vout == [_outside(99_368)]
    assert _fee(ledger, bumped) == 100_000 - 99_368


def test_a_bump_adds_a_confirmed_coin_where_the_change_falls_short(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Lines 470-509 and 773-781: confirmed coins only, and none left."""
    _funded(ledger, chain)
    spent = ledger.spend([_outside()])
    # a coin in the mempool is not added, however large
    chain.pay([TxOut(1_000_000, script_of(ledger.new_address()))])
    coin = _funded(ledger, chain, 200_000)
    # without the change, still short: a change dropped would do
    bumped = ledger.bump(spent.id, _rate(700))
    assert [i.prev_out for i in bumped.vin] == [
        *(i.prev_out for i in spent.vin),
        OutPoint(coin.id, 0),
    ]
    with pytest.raises(BTClibValueError, match="the confirmed coins cannot fund"):
        ledger.bump(bumped.id, _rate(2_000))


def test_a_fee_above_the_ceiling_is_refused(ledger: Ledger, chain: FakeChain) -> None:
    """Lines 535-548: Core's -maxtxfee, and -maxfeerate, defaults."""
    _funded(ledger, chain, 10_000_000)
    spent = ledger.spend([_outside()])
    with pytest.raises(BTClibValueError, match="exceeds"):
        ledger.bump_psbt(spent.id, _rate(11_000))


@pytest.mark.parametrize("coin", [None, 20_000_000])
def test_change_paid_to_itself_above_the_ceiling_is_refused(
    ledger: Ledger, chain: FakeChain, coin: int | None
) -> None:
    """Lines 535-548 where every output is change, a coin added or not.

    The fee is checked once the surplus is change: Core's -maxtxfee and
    -maxfeerate defaults.
    """
    _funded(ledger, chain, 50_000_000 if coin is None else 100_000)
    spent = ledger.spend([_outside()])
    change = spent.vout[1].script_pub_key
    value = 40_000_000
    if coin is not None:
        _funded(ledger, chain, coin)
        value = 5_000_000
    with pytest.raises(BTClibValueError, match="exceeds max_fee_rate"):
        ledger.bump_psbt(spent.id, _rate(11_000), outputs=[TxOut(value, change)])


def test_a_sweep_to_change_above_the_fee_ceiling_is_refused(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Lines 535-548: every output change, the fee above -maxtxfee."""
    coins = [_funded(ledger, chain, 100_000_000) for _ in range(20)]
    change = ledger.sources[0].script_pub_key(1, 0)
    vin = [TxIn(OutPoint(c.id, 0), sequence=RBF) for c in coins]
    swept = _sent(ledger, chain, vin, [TxOut(20 * 100_000_000 - 20_000, change)])
    with pytest.raises(BTClibValueError, match="exceeds max_fee,"):
        ledger.bump_psbt(swept.id, _rate(9_000))


def test_every_output_change_pays_the_fee(ledger: Ledger, chain: FakeChain) -> None:
    """Lines 192-239 and 270-305: the fee is taken from the change."""
    first, second = _funded(ledger, chain), _funded(ledger, chain)
    receive = script_of(ledger.new_address())
    # one output, not signalling: lines 374-378 replace it all the same
    single = _sent(
        ledger,
        chain,
        [TxIn(OutPoint(first.id, 0), sequence=0xFFFFFFFF)],
        [TxOut(99_800, receive)],
    )
    assert single.vin[0].sequence == 0xFFFFFFFF
    with pytest.raises(BTClibValueError, match="too small to pay the fee"):
        ledger.bump_psbt(single.id, _rate(1_100), original_change_index=0)
    bumped = ledger.bump(single.id, _rate(10), original_change_index=0)
    assert len(bumped.vin) == len(bumped.vout) == 1
    assert bumped.vout[0].value + _fee(ledger, bumped) == 100_000
    _assert_fee_amount(_fee(ledger, bumped), bumped.vsize, _rate(10))
    # not named as change, it is paid whole: a coin is added, and change
    again = ledger.bump(bumped.id, _rate(20))
    assert [i.prev_out for i in again.vin] == [
        OutPoint(first.id, 0),
        OutPoint(second.id, 0),
    ]
    assert again.vout[0] == bumped.vout[0]
    assert ledger.position_of(again.vout[1].script_pub_key) == (0, 1, 0)


@pytest.mark.parametrize(
    "old_fee, amounts, fee",
    [
        (200, [98_900], 1_100),
        (500, [98_900], 1_100),
        (979, [98_900], 1_100),
        (980, [97_610, 980], 1_410),
        (1_000, [97_590, 1_000], 1_410),
    ],
)
def test_what_the_inputs_hold_over_the_change_is_fee_or_change(
    ledger: Ledger, chain: FakeChain, old_fee: int, amounts: list[int], fee: int
) -> None:
    """As Core's `CreateTransactionInternal` counts it, measured on v32.1.

    What is left over is change of at least `min_viable_change`, 980
    satoshi for this script at Core's discard rate, and fee otherwise, the
    output paying only the rest of what 10 sat/vB asks.
    """
    payment = _funded(ledger, chain)
    single = _sent(
        ledger,
        chain,
        [TxIn(OutPoint(payment.id, 0))],
        [TxOut(100_000 - old_fee, script_of(ledger.new_address()))],
    )
    bumped = ledger.bump_psbt(single.id, _rate(10), original_change_index=0)
    assert [o.amount for o in bumped.psbt.outputs] == amounts
    assert bumped.fee == fee


def test_the_only_output_named_change_need_not_be_the_ledgers(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Lines 270-296, the output paying somebody else: it pays the fee."""
    payment = _funded(ledger, chain)
    single = _sent(ledger, chain, [TxIn(OutPoint(payment.id, 0))], [_outside(99_800)])
    bumped = ledger.bump_psbt(single.id, _rate(10), original_change_index=0)
    (output,) = bumped.psbt.outputs
    assert (output.amount or 0) + bumped.fee == 100_000
    assert not output.hd_key_paths


def test_change_paid_back_to_itself_keeps_what_is_left_as_change(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Lines 192-239: less than the inputs, then more, back to the change."""
    first, second = _funded(ledger, chain), _funded(ledger, chain)
    spent = ledger.spend([_outside()])
    assert [i.prev_out for i in spent.vin] in (
        [OutPoint(first.id, 0)],
        [OutPoint(second.id, 0)],
    )
    change = spent.vout[1].script_pub_key
    bumped = ledger.bump(spent.id, _rate(20), outputs=[TxOut(60_000, change)])
    assert bumped.vout[0].script_pub_key == change
    assert bumped.vout[0].value + _fee(ledger, bumped) == 60_000
    assert bumped.vout[1].value == 40_000
    assert ledger.position_of(bumped.vout[1].script_pub_key) == (0, 1, 1)
    again = ledger.bump(bumped.id, _rate(40), outputs=[TxOut(150_000, change)])
    assert len(again.vin) == 2
    assert again.vout[0].value + _fee(ledger, again) == 150_000
    assert again.vout[1].value == 50_000


def test_a_coin_added_to_change_paid_to_itself_comes_back_as_change(
    ledger: Ledger, chain: FakeChain
) -> None:
    """What the coin holds over the change is change, not a fee too high.

    Measured before the fee is, so `build_psbt`'s ceilings, Core's
    -maxtxfee and -maxfeerate defaults, are not asked of it.
    """
    _funded(ledger, chain)
    spent = ledger.spend([_outside()])
    change = spent.vout[1].script_pub_key
    _funded(ledger, chain, 20_000_000)
    bumped = ledger.bump(spent.id, _rate(20), outputs=[TxOut(150_000, change)])
    assert len(bumped.vin) == 2
    assert bumped.vout[0].value + _fee(ledger, bumped) == 150_000
    assert bumped.vout[1].value == 100_000 + 20_000_000 - 150_000
    _assert_fee_amount(_fee(ledger, bumped), bumped.vsize, _rate(20))


def test_a_bump_keeps_its_links_in_a_file_no_other_ledger_holds(
    ledger: Ledger, chain: FakeChain, path: Path
) -> None:
    """A ledger loaded before the bump is refused.

    At its next sync it would write both transactions back without the
    links and the comments (ISS btclib-org/btclib-wallet#800). Loaded once
    the first is closed, it reads and keeps them.
    """
    _funded(ledger, chain)
    spent = ledger.spend([_outside()], comment="c", comment_to="t")
    with pytest.raises(BTClibValueError, match="is open in another ledger"):
        Ledger.load(path, "regtest", chain)
    bumped = ledger.bump(spent.id)
    ledger.close()
    with Ledger.load(path, "regtest", chain) as loaded:
        loaded.sync()
        assert _wtx(loaded, spent).replaced_by == bumped.id
        held = _wtx(loaded, bumped)
        assert (held.replaces, held.comment, held.comment_to) == (spent.id, "c", "t")


def test_a_bump_made_is_seen_by_the_next_ledger_on_the_file(
    ledger: Ledger, chain: FakeChain, path: Path
) -> None:
    """A ledger loaded before the bump is refused, so it bumps nothing again.

    It would bump the original a second time, and a broadcast refused
    would leave the original linked to that replacement (ISS
    btclib-org/btclib-wallet#800). Loaded once the first is closed, it
    refuses the second bump and keeps the link.
    """
    _funded(ledger, chain)
    spent = ledger.spend([_outside()])
    with pytest.raises(BTClibValueError, match="is open in another ledger"):
        Ledger.load(path, "regtest", chain)
    bumped = ledger.bump(spent.id)
    ledger.close()
    with Ledger.load(path, "regtest", chain, broadcaster=chain) as loaded:
        chain.refuse = "insufficient fee"
        with pytest.raises(BTClibValueError, match="already bumped"):
            loaded.bump(spent.id)
        assert _wtx(loaded, spent).replaced_by == bumped.id


def test_a_descendant_is_refused_and_an_abandoned_one_is_not(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Lines 422-467: a descendant in the ledger, then abandoned."""
    _funded(ledger, chain)
    parent = ledger.spend([TxOut(50_000, script_of(ledger.new_address()))])
    child = ledger.spend([_outside(40_000)])
    assert child.vin[0].prev_out.tx_id == parent.id
    with pytest.raises(BTClibValueError, match="descendants in the ledger"):
        ledger.bump(parent.id)
    # out of the mempool, the child still counts
    del chain.mempool[child.id]
    ledger.sync()
    assert _wtx(ledger, child).state is TxState.INACTIVE
    with pytest.raises(BTClibValueError, match="descendants in the ledger"):
        ledger.bump(parent.id)
    # nor is a spend of a coin in no block and no mempool bumped
    del chain.mempool[parent.id]
    ledger.sync()
    with pytest.raises(
        BTClibValueError,
        match="^an outpoint of the transaction is already spent$",
    ):
        ledger.bump(child.id)
    ledger.abandon(child.id)
    bumped = ledger.bump(parent.id, _rate(5))
    assert _wtx(ledger, parent).state is TxState.INACTIVE
    assert _wtx(ledger, bumped).state is TxState.MEMPOOL


def test_an_abandoned_transaction_is_bumped(ledger: Ledger, chain: FakeChain) -> None:
    """As Core's `bumpfee` bumps one: no precondition refuses it."""
    payment = _funded(ledger, chain)
    spent = ledger.spend([_outside()])
    del chain.mempool[spent.id]
    ledger.sync()
    ledger.abandon(spent.id)
    # its coin is free again, and is not added a second time
    assert [u.outpoint for u in ledger.utxos()] == [OutPoint(payment.id, 0)]
    bumped = ledger.bump(spent.id, _rate(5))
    assert [i.prev_out for i in bumped.vin] == [OutPoint(payment.id, 0)]
    assert _wtx(ledger, spent).state is TxState.ABANDONED
    assert _wtx(ledger, spent).replaced_by == bumped.id


def test_the_replaced_one_is_refused_and_its_replacement_bumped(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Lines 639-647."""
    _funded(ledger, chain)
    spent = ledger.spend([_outside()])
    bumped = ledger.bump(spent.id, _rate(50))
    with pytest.raises(
        BTClibValueError,
        match="^cannot bump a transaction that was already bumped$",
    ):
        ledger.bump(spent.id, _rate(100))
    ledger.bump(bumped.id, _rate(100))


def test_a_replacement_not_signalling_can_be_bumped(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Lines 649-664."""
    _funded(ledger, chain)
    spent = ledger.spend([_outside()])
    bumped = ledger.bump(spent.id, _rate(50), replaceable=False)
    assert {i.sequence for i in bumped.vin} == {NON_RBF}
    again = ledger.bump(bumped.id, _rate(100))
    assert {i.sequence for i in again.vin} == {RBF}


def test_a_confirmed_or_conflicted_transaction_spends_a_coin_spent(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Lines 667-674: the coin is spent in a block, whichever spends it."""
    _funded(ledger, chain)
    spent = ledger.spend([_outside()])
    chain.mine([spent])
    ledger.sync()
    with pytest.raises(
        BTClibValueError,
        match="^an outpoint of the transaction is already spent$",
    ):
        ledger.bump(spent.id)
    _funded(ledger, chain)
    pending = ledger.spend([_outside()])
    coins = [TxIn(tx_in.prev_out) for tx_in in pending.vin]
    double = _sent(ledger, chain, coins, [_outside(10_000)])
    chain.mine([double])
    ledger.sync()
    assert _wtx(ledger, pending).state is TxState.CONFLICTED
    with pytest.raises(
        BTClibValueError,
        match="^an outpoint of the transaction is already spent$",
    ):
        ledger.bump(pending.id)


def test_outputs_of_a_bump_and_of_what_it_replaced_are_not_safe(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Lines 676-719: until confirmed, neither one's coins are spent."""
    _funded(ledger, chain)
    spent = ledger.spend([TxOut(50_000, script_of(ledger.new_address()))])
    bumped = ledger.bump(spent.id)
    ledger.sync()
    assert {(u.outpoint.tx_id, u.safe) for u in ledger.utxos(0)} == {(bumped.id, False)}
    assert ledger.utxos(0, include_unsafe=False) == ()
    with pytest.raises(BTClibValueError, match="no selection"):
        ledger.fund([_outside(1_000)])
    # the replaced one back in the mempool, its replacement out
    del chain.mempool[bumped.id]
    chain.mempool[spent.id] = spent
    ledger.sync()
    assert {(u.outpoint.tx_id, u.safe) for u in ledger.utxos(0)} == {(spent.id, False)}
    chain.mine([spent])
    ledger.sync()
    assert {(u.outpoint.tx_id, u.safe) for u in ledger.utxos(0)} == {(spent.id, True)}


def test_a_refused_replacement_stays_linked_and_inactive(
    ledger: Ledger, chain: FakeChain
) -> None:
    """As Core's `CommitTransaction` marks the original, whatever the node says.

    src/wallet/feebumper.cpp:352-381.
    """
    _funded(ledger, chain)
    spent = ledger.spend([_outside()])
    chain.refuse = "insufficient fee"
    with pytest.raises(FetchError, match="insufficient fee"):
        ledger.bump(spent.id)
    (refused,) = [
        info.wallet_tx
        for info in ledger.transactions
        if info.wallet_tx.replaces == spent.id
    ]
    assert refused.state is TxState.INACTIVE
    assert _wtx(ledger, spent).state is TxState.MEMPOOL
    assert _wtx(ledger, spent).replaced_by == refused.tx.id


def test_a_refused_replacement_resubmitted_takes_the_replaced_ones_place(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Accepted by `resubmit`, the bump leaves what it replaced inactive.

    As `bump` leaves it once the broadcaster takes the replacement; an
    abandoned one stays abandoned.
    """
    _funded(ledger, chain)
    _funded(ledger, chain)
    spent = ledger.spend([_outside()])
    chain.refuse = "insufficient fee"
    with pytest.raises(FetchError, match="insufficient fee"):
        ledger.bump(spent.id)
    refused = _wtx(ledger, spent).replaced_by
    assert refused is not None
    chain.refuse = ""
    assert ledger.resubmit() == {}
    assert set(chain.mempool) == {refused}
    assert ledger.transaction(refused).wallet_tx.state is TxState.MEMPOOL
    assert _wtx(ledger, spent).state is TxState.INACTIVE
    ledger.sync()
    assert _wtx(ledger, spent).state is TxState.INACTIVE
    # one abandoned, bumped, refused, then resubmitted
    abandoned = ledger.spend([_outside()])
    del chain.mempool[abandoned.id]
    ledger.sync()
    ledger.abandon(abandoned.id)
    chain.refuse = "insufficient fee"
    with pytest.raises(FetchError, match="insufficient fee"):
        ledger.bump(abandoned.id, _rate(5))
    again = _wtx(ledger, abandoned).replaced_by
    assert again is not None
    chain.refuse = ""
    assert ledger.resubmit() == {}
    assert ledger.transaction(again).wallet_tx.state is TxState.MEMPOOL
    assert _wtx(ledger, abandoned).state is TxState.ABANDONED


def test_a_resubmitted_original_refused_is_left_by_its_replacement(
    ledger: Ledger, chain: FakeChain
) -> None:
    """The original refused, its replacement taken: the original is inactive.

    Its refusal is still returned.
    """
    _funded(ledger, chain)
    _funded(ledger, chain)
    spent = ledger.spend([_outside()])
    chain.refuse = "insufficient fee"
    with pytest.raises(FetchError, match="insufficient fee"):
        ledger.bump(spent.id)
    replacement = _wtx(ledger, spent).replaced_by
    assert replacement is not None
    chain.refuse = ""
    taken = chain.broadcast

    def picky(tx: Tx) -> bytes:
        if tx.id == spent.id:
            raise FetchError("mempool min fee not met")
        return taken(tx)

    chain.broadcast = picky  # type: ignore[method-assign]
    refused = ledger.resubmit()
    assert list(refused) == [spent.id]
    assert _wtx(ledger, spent).state is TxState.INACTIVE
    assert ledger.transaction(replacement).wallet_tx.state is TxState.MEMPOOL


def test_a_refusal_hands_out_the_change_and_nothing_else(
    ledger: Ledger, chain: FakeChain
) -> None:
    """As Core keeps its change address once it creates the transaction.

    src/wallet/spend.cpp:1432-1434; what else is paid is handed out only
    once the broadcaster accepts it.
    """
    for _ in range(3):
        _funded(ledger, chain)
    receive = ledger.sources[0].script_pub_key(0, 3)
    chain.refuse = "refused"
    with pytest.raises(FetchError, match="refused"):
        ledger.spend([_outside(), TxOut(20_000, receive)])
    assert ledger.new_change_address() == ledger.sources[0].address(1, 1)
    assert ledger.new_address() == ledger.sources[0].address(0, 3)
    chain.refuse = ""
    spent = ledger.spend([_outside()])
    chain.refuse = "refused"
    with pytest.raises(FetchError, match="refused"):
        ledger.bump(spent.id, outputs=[_outside(20_000)])
    assert ledger.new_change_address() == ledger.sources[0].address(1, 4)


def test_a_locked_ledger_bumps_nothing(ledger: Ledger, chain: FakeChain) -> None:
    """Lines 733-741, and Core's `psbtbumpfee` refused too.

    src/wallet/rpc/spend.cpp:1109, which both reach.
    """
    # an install on Windows arm64 leaves `cryptography` out
    pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    _funded(ledger, chain)
    ledger.encrypt("passphrase")
    ledger.unlock_keys("passphrase", 60)
    spent = ledger.spend([_outside()])
    ledger.lock_keys()
    for bump in (ledger.bump, ledger.bump_psbt):
        with pytest.raises(BTClibValueError, match="the ledger is locked"):
            bump(spent.id)
    ledger.unlock_keys("passphrase", 60)
    bumped = ledger.bump(spent.id)
    assert _wtx(ledger, bumped).replaces == spent.id


def test_a_watch_only_ledger_gets_the_bump_as_a_psbt(
    chain: FakeChain, path: Path
) -> None:
    """Lines 550-637: bumpfee is refused, psbtbumpfee answers a psbt to sign."""
    signer = SoftwareSigner(XPRV)
    account = "m/84h/1h/5h"
    origin = f"[{signer.master_fingerprint.hex()}/84h/1h/5h]"
    watched = DescriptorWallet(
        [
            parse(f"wpkh({origin}{signer.xpub(account)}/{branch}/*)", "regtest")
            for branch in (0, 1)
        ]
    )
    with Ledger.create(
        path,
        "regtest",
        chain,
        broadcaster=chain,
        relay_fee_reader=chain,
        fallback_fee_rate=_rate(1),
    ) as ledger:
        ledger.add_source(watched, lookahead=3)
        _funded(ledger, chain)
        _funded(ledger, chain)
        funded = ledger.fund([_outside(50_000)])
        original = extract_tx(finalize(signer.sign_psbt(funded.psbt)))
        chain.broadcast(original)
        ledger.sync()
        with pytest.raises(BTClibValueError, match="bump_psbt returns"):
            ledger.bump(original.id)
        bumped = ledger.bump_psbt(original.id, _rate(500))
        assert len(bumped.psbt.inputs) > 1
        assert all(psbt_in.hd_key_paths for psbt_in in bumped.psbt.inputs)
        assert bumped.old_fee == ledger.transaction(original.id).fee
        replacement = extract_tx(finalize(signer.sign_psbt(bumped.psbt)))
        chain.broadcast(replacement)
        ledger.sync()
        assert _wtx(ledger, original).state is TxState.INACTIVE
        assert _wtx(ledger, replacement).state is TxState.MEMPOOL


def test_an_input_the_ledger_does_not_hold_is_refused(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Lines 381-420: Core values it from the chain, which the ledger cannot."""
    payment = _funded(ledger, chain)
    elsewhere = chain.pay([_outside(100_000)])
    chain.mine([elsewhere])
    ledger.sync()
    unsigned = Tx(
        vin=[TxIn(OutPoint(payment.id, 0)), TxIn(OutPoint(elsewhere.id, 0))],
        vout=[_outside(150_000)],
    )
    psbt = Psbt.from_tx(unsigned)
    psbt.inputs[1].non_witness_utxo = elsewhere
    ((pub_key, sig),) = ledger.sign(psbt).inputs[0].partial_sigs.items()
    mixed = Tx(
        vin=[
            TxIn(OutPoint(payment.id, 0), script_witness=Witness([sig, pub_key])),
            TxIn(OutPoint(elsewhere.id, 0)),
        ],
        vout=unsigned.vout,
    )
    chain.broadcast(mixed)
    ledger.sync()
    with pytest.raises(BTClibValueError, match="input 1 spends an output"):
        ledger.bump_psbt(mixed.id)


def test_a_forged_spend_of_the_ledgers_coin_is_not_bumped(
    ledger: Ledger, chain: FakeChain
) -> None:
    """ISS btclib-org/btclib-wallet#642: the sync keeps it out of the ledger.

    The backend reports a spend of the ledger's coin whose signature does
    not verify; neither `bump` nor `bump_psbt` finds it. The honest one,
    reported instead, is bumped.
    """
    payment = _funded(ledger, chain)
    change = TxOut(69_000, ledger.sources[0].script_pub_key(1, 0))
    unsigned = Tx(vin=[TxIn(OutPoint(payment.id, 0))], vout=[_outside(), change])
    honest = extract_tx(finalize(ledger.sign(Psbt.from_tx(unsigned))))
    forged = tampered(honest)
    assert forged.id == honest.id
    chain.mempool[forged.id] = chain.known[forged.id] = forged
    ledger.sync()
    for bump in (ledger.bump, ledger.bump_psbt):
        with pytest.raises(BTClibValueError, match="not a ledger transaction"):
            bump(forged.id)
    chain.mempool[honest.id] = chain.known[honest.id] = honest
    ledger.sync()
    assert ledger.bump_psbt(honest.id).replaces == honest.id


def test_bump_arguments_are_checked(ledger: Ledger, chain: FakeChain) -> None:
    """Lines 132-188, as far as a typed call can get them wrong."""
    _funded(ledger, chain)
    spent = ledger.spend([_outside()])
    txid = spent.id
    with pytest.raises(BTClibTypeError, match="invalid fee_rate type"):
        ledger.bump_psbt(txid, 1)  # type: ignore[arg-type]
    # Core's `ParseConfirmTarget` (src/rpc/util.cpp:374-382)
    for target in (-1, 0):
        with pytest.raises(BTClibValueError, match="invalid confirmation target"):
            ledger.bump_psbt(txid, conf_target=target)
    with pytest.raises(BTClibTypeError, match="invalid confirmation target type"):
        ledger.bump_psbt(txid, conf_target="2")  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid outputs type"):
        ledger.bump_psbt(txid, outputs=[1])  # type: ignore[list-item]
    with pytest.raises(BTClibTypeError, match="invalid outputs type"):
        ledger.bump_psbt(txid, outputs=1)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid original_change_index"):
        ledger.bump_psbt(txid, original_change_index="0")  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid replaceable type"):
        ledger.bump_psbt(txid, replaceable=1)  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError, match="not both"):
        ledger.bump_psbt(txid, _rate(5), conf_target=2)
    with pytest.raises(BTClibValueError, match="no outputs"):
        ledger.bump_psbt(txid, outputs=[])
    with pytest.raises(BTClibValueError, match="not a ledger transaction"):
        ledger.bump_psbt(bytes(32))


def test_a_ledger_with_no_broadcaster_bumps_nothing(
    chain: FakeChain, path: Path
) -> None:
    """As it spends nothing; `bump_psbt` still answers."""
    with Ledger.create(path, "regtest", chain, fallback_fee_rate=_rate(2)) as ledger:
        ledger.add_source(source(), lookahead=3)
        _funded(ledger, chain)
        funded = ledger.fund([_outside()])
        tx = extract_tx(finalize(ledger.sign(funded.psbt)))
        chain.broadcast(tx)
        ledger.sync()
        with pytest.raises(BTClibValueError, match="no broadcaster"):
            ledger.bump(tx.id)
        assert ledger.bump_psbt(tx.id).replaces == tx.id
