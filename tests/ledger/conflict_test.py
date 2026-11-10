# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Conflicts with a block, abandon and resubmission, over a chain in memory.

The cases are Bitcoin Core's test/functional/wallet_abandonconflict.py
and wallet_txn_doublespend.py at bitcoin/bitcoin@f0de87f040, the v32.1
tag, each named by its lines; `tests/integration/ledger_test.py` asks
the same of bitcoind's wallet.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.tx import OutPoint, Tx, TxIn, TxOut

from btclib_wallet.exceptions import FetchError
from btclib_wallet.fetch.fetcher import tx_for_network
from btclib_wallet.fetch.history import BlockRef
from btclib_wallet.ledger import Balances, Ledger, TxState
from tests.ledger.conftest import FakeChain, script_of
from tests.ledger.ledger_test import _funded, _outside, _signed


def _state(ledger: Ledger, tx: Tx) -> TxState:
    return ledger.transaction(tx.id).wallet_tx.state


def _two_coins(ledger: Ledger, chain: FakeChain) -> tuple[OutPoint, OutPoint]:
    """Return a coin of 100_000 confirmed at height 1, one of 50_000 at 2."""
    first = _funded(ledger, chain, 100_000)
    second = _funded(ledger, chain, 50_000)
    return OutPoint(first.id, 0), OutPoint(second.id, 0)


def _in_mempool(
    ledger: Ledger, chain: FakeChain, vin: list[TxIn], vout: list[TxOut]
) -> Tx:
    """Return a transaction the ledger signs, put in the mempool and synced.

    Its outputs are labelled regtest, as a backend's answer labels them.
    """
    tx = tx_for_network(_signed(ledger, vin, vout), "regtest")
    chain.mempool[tx.id] = chain.known[tx.id] = tx
    ledger.sync()
    return tx


def _spend_and_child(
    ledger: Ledger, chain: FakeChain, x: OutPoint, y: OutPoint
) -> tuple[Tx, Tx]:
    """Return a spend of both coins, with change, and a spend of its change.

    wallet_abandonconflict.py lines 69-95: txAB1 and txABC2.
    """
    change = script_of(ledger.new_change_address())
    spend = _in_mempool(
        ledger, chain, [TxIn(x), TxIn(y)], [_outside(), TxOut(110_000, change)]
    )
    child = _in_mempool(
        ledger,
        chain,
        [TxIn(OutPoint(spend.id, 1))],
        [TxOut(100_000, script_of(ledger.new_address()))],
    )
    return spend, child


def _double_spend(ledger: Ledger, coin: OutPoint) -> Tx:
    """Return a spend of `coin` alone, paying elsewhere, labelled regtest."""
    tx = _signed(ledger, [TxIn(coin)], [TxOut(10_000, _outside().script_pub_key)])
    return tx_for_network(tx, "regtest")


def _conflicted(ledger: Ledger, chain: FakeChain) -> tuple[Tx, Tx, Tx, OutPoint]:
    """Return a spend and its child that a block at height 3 conflicts with.

    The block holds a double spend of the first coin; one more block is
    built on it. The spend, its child and the double spend are returned,
    and the second coin, which only the spend spends.
    """
    x, y = _two_coins(ledger, chain)
    spend, child = _spend_and_child(ledger, chain, x, y)
    double = _double_spend(ledger, x)
    chain.mempool.clear()
    chain.mine([double])
    chain.mine()
    result = ledger.sync()
    assert result.changed == {spend.id, child.id, double.id}
    return spend, child, double, y


def test_a_block_conflicts_with_a_spend_and_its_child(
    ledger: Ledger, chain: FakeChain, path: Path
) -> None:
    """wallet_abandonconflict.py lines 186-230; doublespend lines 120-126."""
    spend, child, double, y = _conflicted(ledger, chain)
    block = BlockRef(3, chain.blocks[3][0])
    for tx in (spend, child):
        info = ledger.transaction(tx.id)
        assert info.wallet_tx.state is TxState.CONFLICTED
        assert info.wallet_tx.block == block
        # minus the depth of the conflicting block, as the --mineblock
        # variant reads -2
        assert (info.confirmations, info.trusted) == (-2, False)
    # both sides of the double spend name each other
    assert ledger.transaction(spend.id).wallet_conflicts == {double.id}
    assert ledger.transaction(double.id).wallet_conflicts == {spend.id}
    assert ledger.transaction(child.id).wallet_conflicts == frozenset()
    # the second coin, spent only by the conflicted spend, is spendable again
    assert ledger.balances() == Balances(50_000, 0, 0, 0)
    assert [utxo.outpoint for utxo in ledger.utxos()] == [y]
    with pytest.raises(BTClibValueError, match="a conflicted transaction cannot"):
        ledger.abandon(spend.id)
    # a later sync changes nothing, and a load answers the same
    assert ledger.sync().changed == frozenset()
    answers = (ledger.transactions, ledger.balances())
    ledger.close()
    with Ledger.load(path, "regtest", chain) as loaded:
        assert (loaded.transactions, loaded.balances()) == answers


def test_a_reorganization_that_disconnects_the_block_undoes_the_conflict(
    ledger: Ledger, chain: FakeChain
) -> None:
    """wallet_abandonconflict.py lines 231-240: confirmations back to 0."""
    spend, child, double, _ = _conflicted(ledger, chain)
    chain.invalidate(3)
    chain.mine(count=2)
    result = ledger.sync()
    assert result.fork_height == 2
    assert {spend.id, child.id, double.id} <= result.changed
    for tx in (spend, child, double):
        info = ledger.transaction(tx.id)
        assert info.wallet_tx.state is TxState.INACTIVE
        assert (info.wallet_tx.block, info.confirmations) == (None, 0)
    assert ledger.transaction(spend.id).wallet_conflicts == {double.id}
    # both coins are spent again, by transactions outside the mempool
    assert ledger.balances() == Balances(150_000, 0, 0, -150_000)
    assert ledger.balances(include_nonmempool=False) == Balances(0, 0, 0, 0)
    # the double spend in a block of the new chain conflicts with them again
    chain.mine([double])
    ledger.sync()
    info = ledger.transaction(spend.id)
    assert info.wallet_tx.state is TxState.CONFLICTED
    assert (info.wallet_tx.block, info.confirmations) == (chain.tip, -1)
    assert _state(ledger, child) is TxState.CONFLICTED


def test_the_lowest_conflicting_block_is_kept(ledger: Ledger, chain: FakeChain) -> None:
    """A higher block found later, or a parent's lower one, does not move it."""
    x, y = _two_coins(ledger, chain)
    z = OutPoint(_funded(ledger, chain, 20_000).id, 0)
    change = script_of(ledger.new_change_address())
    spend = _in_mempool(
        ledger, chain, [TxIn(x), TxIn(y)], [_outside(), TxOut(110_000, change)]
    )
    # the child spends a third coin too, which the highest block spends
    child = _in_mempool(
        ledger,
        chain,
        [TxIn(OutPoint(spend.id, 1)), TxIn(z)],
        [TxOut(120_000, script_of(ledger.new_address()))],
    )
    first, second, third = (_double_spend(ledger, coin) for coin in (x, y, z))
    chain.mempool.clear()
    chain.mine([first])
    ledger.sync()
    low = chain.tip
    chain.mine([second])
    chain.mine([third])
    ledger.sync()
    for tx in (spend, child):
        info = ledger.transaction(tx.id)
        assert info.wallet_tx.state is TxState.CONFLICTED
        assert info.wallet_tx.block == low
    assert ledger.transaction(spend.id).wallet_conflicts == {first.id, second.id}
    assert ledger.transaction(child.id).wallet_conflicts == {third.id}


def test_a_receiver_sees_a_double_spend_that_pays_it(
    ledger: Ledger, chain: FakeChain
) -> None:
    """wallet_abandonconflict.py lines 213-223: the receiver's side."""
    coin = chain.foreign_input()
    payment = Tx(vin=[coin], vout=[TxOut(50_000, script_of(ledger.new_address()))])
    chain.mempool[payment.id] = chain.known[payment.id] = payment
    ledger.sync()
    double = Tx(vin=[coin], vout=[TxOut(40_000, script_of(ledger.new_address()))])
    chain.mempool.clear()
    chain.mine([double])
    ledger.sync()
    info = ledger.transaction(payment.id)
    assert info.wallet_tx.state is TxState.CONFLICTED
    assert (info.confirmations, info.wallet_conflicts) == (-1, frozenset({double.id}))
    # below depth 0 no output is listed as received, as Core lists none
    assert info.details == ()
    assert ledger.transaction(double.id).wallet_conflicts == {payment.id}
    assert ledger.balances() == Balances(40_000, 0, 0, 0)


def test_a_double_spend_paying_elsewhere_leaves_a_payment_inactive(
    ledger: Ledger, chain: FakeChain
) -> None:
    """The reader does not answer it, so it is no conflict the ledger sees."""
    coin = chain.foreign_input()
    payment = Tx(vin=[coin], vout=[TxOut(50_000, script_of(ledger.new_address()))])
    chain.mempool[payment.id] = chain.known[payment.id] = payment
    ledger.sync()
    chain.mempool.clear()
    chain.mine([Tx(vin=[coin], vout=[_outside()])])
    ledger.sync()
    info = ledger.transaction(payment.id)
    assert info.wallet_tx.state is TxState.INACTIVE
    assert (info.confirmations, info.wallet_conflicts) == (0, frozenset())


def test_abandon_refuses_what_is_not_inactive(ledger: Ledger, chain: FakeChain) -> None:
    """wallet_abandonconflict.py lines 41-56: Core's -5 cases."""
    payment = _funded(ledger, chain)
    with pytest.raises(BTClibValueError, match="a confirmed transaction cannot"):
        ledger.abandon(payment.id)
    pending = chain.pay([TxOut(1_000, script_of(ledger.new_address()))])
    ledger.sync()
    with pytest.raises(BTClibValueError, match="a mempool transaction cannot"):
        ledger.abandon(pending.id)
    with pytest.raises(BTClibValueError, match="not a ledger transaction"):
        ledger.abandon(b"\xff" * 32)
    with pytest.raises(BTClibTypeError, match="invalid txid type"):
        ledger.abandon("ff" * 32)  # type: ignore[arg-type]
    assert _state(ledger, payment) is TxState.CONFIRMED
    assert _state(ledger, pending) is TxState.MEMPOOL


def test_abandon_frees_the_coins_and_survives_a_load(
    ledger: Ledger, chain: FakeChain, path: Path
) -> None:
    """wallet_abandonconflict.py lines 97-160."""
    x, y = _two_coins(ledger, chain)
    spend, child = _spend_and_child(ledger, chain, x, y)
    # out of the mempool: the coins stay spent, outside it
    chain.mempool.clear()
    ledger.sync()
    assert ledger.balances() == Balances(150_000, 0, 0, -150_000)
    assert ledger.utxos(0) == ()
    # the child alone: its parent stays as it is
    ledger.abandon(child.id)
    assert (_state(ledger, spend), _state(ledger, child)) == (
        TxState.INACTIVE,
        TxState.ABANDONED,
    )
    ledger.abandon(spend.id)
    assert _state(ledger, spend) is TxState.ABANDONED
    assert ledger.balances() == Balances(150_000, 0, 0, 0)
    assert {utxo.outpoint for utxo in ledger.utxos()} == {x, y}
    info = ledger.transaction(spend.id)
    assert (info.confirmations, info.trusted) == (0, False)
    # abandoned again: nothing changes
    answers = ledger.transactions
    ledger.abandon(spend.id)
    assert ledger.transactions == answers
    ledger.close()
    with Ledger.load(path, "regtest", chain) as loaded:
        assert loaded.transactions == answers
        # seen in the mempool again: its own mark goes, its child's stays
        chain.mempool[spend.id] = spend
        assert loaded.sync().changed == {spend.id}
        assert _state(loaded, spend) is TxState.MEMPOOL
        assert _state(loaded, child) is TxState.ABANDONED
        assert loaded.balances() == Balances(110_000, 0, 0, 0)
        chain.mempool[child.id] = child
        loaded.sync()
        assert _state(loaded, child) is TxState.MEMPOOL
        assert loaded.balances() == Balances(100_000, 0, 0, 0)


def test_an_abandoned_spend_a_block_conflicts_with_is_conflicted(
    ledger: Ledger, chain: FakeChain
) -> None:
    """The conflict replaces the mark, and a reorganization leaves neither."""
    x, y = _two_coins(ledger, chain)
    spend, child = _spend_and_child(ledger, chain, x, y)
    chain.mempool.clear()
    ledger.sync()
    ledger.abandon(spend.id)
    chain.mine([_double_spend(ledger, x)])
    ledger.sync()
    assert _state(ledger, spend) is TxState.CONFLICTED
    assert _state(ledger, child) is TxState.CONFLICTED
    chain.invalidate(3)
    chain.mine(count=2)
    ledger.sync()
    assert _state(ledger, spend) is TxState.INACTIVE
    assert _state(ledger, child) is TxState.INACTIVE


def test_resubmit_broadcasts_again_what_is_neither_abandoned_nor_in_a_block(
    ledger: Ledger, chain: FakeChain, path: Path
) -> None:
    """Only when called; a refusal is returned, and the rest still go."""
    payment = _funded(ledger, chain)
    first = ledger.spend([_outside()])
    chain.mempool.clear()
    ledger.sync()
    ledger.abandon(first.id)
    # the coin `first` spent is free again, and spent a second time
    second = ledger.spend([_outside()])
    assert {tx_in.prev_out for tx_in in second.vin} == {OutPoint(payment.id, 0)}
    chain.mempool.clear()
    ledger.sync()
    assert _state(ledger, second) is TxState.INACTIVE
    chain.refuse = "mempool full"
    refused = ledger.resubmit()
    assert list(refused) == [second.id]
    assert isinstance(refused[second.id], FetchError)
    assert str(refused[second.id]) == "mempool full"
    assert _state(ledger, second) is TxState.INACTIVE
    chain.refuse = ""
    assert ledger.resubmit() == {}
    assert set(chain.mempool) == {second.id}
    assert _state(ledger, second) is TxState.MEMPOOL
    assert _state(ledger, first) is TxState.ABANDONED
    # in the mempool already: broadcast again, and no state changes
    assert ledger.resubmit() == {}
    ledger.close()
    with Ledger.load(path, "regtest", chain) as loaded:
        assert _state(loaded, second) is TxState.MEMPOOL


def test_a_ledger_with_no_broadcaster_does_not_resubmit(
    chain: FakeChain, path: Path
) -> None:
    """Refused, as `spend` is, with nothing to broadcast through."""
    with (
        Ledger.create(path, "regtest", chain) as bare,
        pytest.raises(BTClibValueError, match="no broadcaster"),
    ):
        bare.resubmit()
