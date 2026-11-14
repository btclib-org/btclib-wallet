# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Which coins `Ledger.fund` tries first, over a chain in memory.

The passes of Core's `AutomaticCoinSelection`, src/wallet/spend.cpp:895-925
at bitcoin/bitcoin@f0de87f040, the v32.1 tag. Each test pays what one
coin alone pays with no change, at a rate above Core's long-term rate,
so that a selection of that coin alone is the one of least waste: a pass
that leaves the coin out is what keeps it from being spent.
"""

from __future__ import annotations

import pytest
from btclib.exceptions import BTClibValueError
from btclib.fee import FeeRate
from btclib.tx import OutPoint, Tx, TxOut

from btclib_wallet.ledger import Ledger
from btclib_wallet.tx_builder import FundedPsbt
from tests.ledger.conftest import FakeChain, script_of, source

_RATE = FeeRate.from_sats_per_vbyte(20)
# what is left over a coin's value once the payment is made: more than
# the fee of a spend of one input and one output at `_RATE`, and less
# than that plus the cost of change
_LEFT_OVER = 2_600


def _received(ledger: Ledger, chain: FakeChain, value: int) -> OutPoint:
    """Pay the ledger from outside, confirm it, and return the coin."""
    payment = chain.pay([TxOut(value, script_of(ledger.new_address()))])
    chain.mine([payment])
    ledger.sync()
    return OutPoint(payment.id, 0)


def _outside(value: int = 30_000) -> TxOut:
    """Return an output paying somebody else."""
    other = source("wpkh({}/84h/1h/9h/{}/*)", (0,))
    return TxOut(value, other.script_pub_key(0, 0))


def _coins(ledger: Ledger, tx: Tx) -> list[OutPoint]:
    """Return the ledger's unspent coins of `tx`."""
    return [u.outpoint for u in ledger.utxos(0) if u.outpoint.tx_id == tx.id]


def _value(ledger: Ledger, coin: OutPoint) -> int:
    (value,) = [u.tx_out.value for u in ledger.utxos(0) if u.outpoint == coin]
    return value


def _matching(ledger: Ledger, coin: OutPoint) -> FundedPsbt:
    """Fund a payment of what `coin` alone pays with no change."""
    return ledger.fund([_outside(_value(ledger, coin) - _LEFT_OVER)], _RATE)


def _spent(funded: FundedPsbt) -> set[OutPoint]:
    return {tx_in.prev_out for tx_in in funded.psbt.tx.vin}


def test_a_confirmed_coin_funds_before_unconfirmed_change(
    ledger: Ledger, chain: FakeChain
) -> None:
    """ISS btclib-org/btclib-wallet#895: change waits for its block."""
    _received(ledger, chain, 100_000)
    confirmed = _received(ledger, chain, 100_000)
    ledger.lock(confirmed)
    (change,) = _coins(ledger, ledger.spend([_outside()]))
    ledger.unlock(confirmed)
    assert _spent(_matching(ledger, change)) == {confirmed}
    # with no confirmed coin left, the change funds the payment
    ledger.lock(confirmed)
    assert _spent(_matching(ledger, change)) == {change}


def test_the_first_pass_asks_more_confirmations_of_a_coin_received(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Six for a coin whose transaction spends no output of the ledger."""
    old = _received(ledger, chain, 100_000)
    chain.mine(count=5)
    ledger.sync()
    recent = _received(ledger, chain, 50_000)
    assert _spent(_matching(ledger, recent)) == {old}
    # one for a coin whose transaction spends one
    ledger.lock(old)
    own_address = script_of(ledger.new_address())
    spend = ledger.spend([TxOut(20_000, own_address)])
    chain.mine([spend])
    ledger.sync()
    ledger.unlock(old)
    (own,) = [c for c in _coins(ledger, spend) if _value(ledger, c) == 20_000]
    assert _spent(_matching(ledger, own)) == {own}


def test_unconfirmed_coins_with_fewer_ancestors_fund_first(
    ledger: Ledger, chain: FakeChain
) -> None:
    """A coin three unconfirmed transactions deep waits for a shallower one."""
    _received(ledger, chain, 100_000)
    other = _received(ledger, chain, 100_000)
    ledger.lock(other)
    ledger.spend([_outside()])
    ledger.spend([_outside()])
    (deep,) = _coins(ledger, ledger.spend([_outside()]))
    ledger.unlock(other)
    (shallow,) = _coins(ledger, ledger.spend([_outside()]))
    assert _spent(_matching(ledger, deep)) == {shallow}


def test_unconfirmed_coins_in_a_smaller_cluster_fund_first(
    ledger: Ledger, chain: FakeChain
) -> None:
    """A coin of one ancestor whose cluster is three waits too."""
    _received(ledger, chain, 100_000)
    other = _received(ledger, chain, 100_000)
    ledger.lock(other)
    first = ledger.spend([TxOut(20_000, script_of(ledger.new_address()))])
    (own,) = [c for c in _coins(ledger, first) if _value(ledger, c) == 20_000]
    ledger.lock(own)
    ledger.spend([_outside()])
    ledger.spend([_outside()])
    ledger.unlock(own)
    ledger.unlock(other)
    (small,) = _coins(ledger, ledger.spend([_outside()]))
    assert _spent(_matching(ledger, own)) == {small}


def test_a_chain_past_the_package_limits_is_not_spent(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Core's `-walletrejectlongchains`, and the refusal it gives."""
    _received(ledger, chain, 1_000_000)
    # the last coin spent has as many unconfirmed ancestors as the last
    # pass admits, and its change one more
    for _ in range(25):
        ledger.spend([_outside()])
    with pytest.raises(BTClibValueError, match="unconfirmed coins are available"):
        ledger.spend([_outside()])
    # a payment the coin could not fund either is refused as such
    (coin,) = ledger.utxos(0)
    with pytest.raises(BTClibValueError, match="no selection"):
        ledger.fund([_outside(coin.tx_out.value * 2)])
    # once confirmed, it is spent
    chain.mine(list(chain.mempool.values()))
    ledger.sync()
    ledger.spend([_outside()])
