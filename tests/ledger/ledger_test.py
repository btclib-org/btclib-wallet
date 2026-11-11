# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What a `Ledger` holds and answers, over a chain in memory.

Each state transition of a transaction -- into the mempool, into a
block, out of the mempool by a replacement or a refusal, out of a block
by a reorganization -- and each balance bucket are asked of a
`FakeChain`; `tests/integration/ledger_test.py` asks the same of
bitcoind's wallet.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import pytest
from btclib.alias import Octets
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.fee import FeeRate
from btclib.script import ScriptPubKey
from btclib.script.sig_hash import ALL, segwit_v0
from btclib.script.witness import Witness
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from btclib.tx.limits import COINBASE_MATURITY
from ecc import dsa

from btclib_wallet.bip32 import BIP32KeyData
from btclib_wallet.bip32.bip32 import derive, prv_keyinfo_from_xprv, xpub_from_xprv
from btclib_wallet.descriptors import parse
from btclib_wallet.exceptions import FetchError
from btclib_wallet.fetch.history import BlockRef, ScriptHistory
from btclib_wallet.ledger import (
    LOOKAHEAD,
    Balances,
    Ledger,
    TxDetail,
    TxState,
)
from btclib_wallet.ledger.ledger import _SYNC_ATTEMPTS, _parents_first
from btclib_wallet.psbt.psbt import Psbt, extract_tx, finalize
from btclib_wallet.psbt_signer import SoftwareSigner
from btclib_wallet.wallet import DescriptorWallet
from tests.ledger.conftest import LOOKAHEAD as SMALL_LOOKAHEAD
from tests.ledger.conftest import XPRV, FakeChain, script_of, source, tampered


def _state(ledger: Ledger, tx: Tx) -> TxState:
    return ledger.transaction(tx.id).wallet_tx.state


def _funded(ledger: Ledger, chain: FakeChain, value: int = 100_000) -> Tx:
    """Pay the ledger from outside and confirm it."""
    payment = chain.pay([TxOut(value, script_of(ledger.new_address()))])
    chain.mine([payment])
    ledger.sync()
    return payment


def _outside() -> TxOut:
    """Return an output paying somebody else."""
    other = source("wpkh({}/84h/1h/9h/{}/*)", (0,))
    return TxOut(30_000, other.script_pub_key(0, 0))


def _signed(ledger: Ledger, vin: list[TxIn], vout: list[TxOut]) -> Tx:
    """Return a transaction the ledger signs, spending what `vin` names."""
    unsigned = Tx(vin=vin, vout=vout)
    return extract_tx(finalize(ledger.sign(Psbt.from_tx(unsigned))))


def test_lookahead_is_cores_keypool() -> None:
    """`DEFAULT_KEYPOOL_SIZE`, src/wallet/scriptpubkeyman.h."""
    assert LOOKAHEAD == 1000


def test_a_payment_enters_the_mempool_and_then_a_block(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Untrusted while pending, trusted once confirmed."""
    payment = chain.pay([TxOut(50_000, script_of(ledger.new_address()))])
    result = ledger.sync()
    assert result.changed == {payment.id}
    assert result.fork_height is None
    assert result.tip == chain.tip == ledger.tip
    assert _state(ledger, payment) is TxState.MEMPOOL
    assert ledger.balances() == Balances(0, 50_000, 0, 0)
    assert ledger.utxos() == ()
    (utxo,) = ledger.utxos(0)
    assert (utxo.confirmations, utxo.safe) == (0, False)

    chain.mine([payment])
    result = ledger.sync()
    assert result.changed == {payment.id}
    info = ledger.transaction(payment.id)
    assert info.wallet_tx.block == BlockRef(1, chain.tip.block_id)
    assert (info.confirmations, info.trusted, info.amount, info.fee) == (
        1,
        True,
        50_000,
        None,
    )
    assert info.details == (TxDetail("receive", 0, 50_000),)
    assert ledger.balances() == Balances(50_000, 0, 0, 0)
    assert ledger.balances(2).trusted == 0
    assert ledger.sync().changed == frozenset()


def test_the_window_moves_on_with_each_position_paid(
    ledger: Ledger, chain: FakeChain
) -> None:
    """A payment past the first window is found once an earlier one is.

    The window is `lookahead` indexes past the last position handed out
    or paid, so index 4 is watched from the start and index 8 only once
    index 4 is paid: one sync reads both.
    """
    wallet = ledger.sources[0]
    far = chain.pay([TxOut(1_000, wallet.script_pub_key(0, 8))])
    near = chain.pay([TxOut(2_000, wallet.script_pub_key(0, 4))])
    result = ledger.sync()
    assert result.changed == {near.id, far.id}
    assert ledger.position_of(wallet.script_pub_key(0, 8)) == (0, 0, 8)
    assert ledger.position_of(wallet.script_pub_key(0, 8 + SMALL_LOOKAHEAD)) == (
        0,
        0,
        8 + SMALL_LOOKAHEAD,
    )
    assert ledger.position_of(wallet.script_pub_key(0, 9 + SMALL_LOOKAHEAD)) is None
    # paid positions are not handed out again
    assert ledger.new_address() == wallet.address(0, 9)


def test_addresses_are_handed_out_in_order(ledger: Ledger) -> None:
    """Each branch counts on its own; a source and a branch are checked."""
    wallet = ledger.sources[0]
    assert ledger.new_address() == wallet.address(0, 0)
    assert ledger.new_address() == wallet.address(0, 1)
    assert ledger.new_change_address() == wallet.address(1, 0)
    with pytest.raises(BTClibValueError, match="no source 1"):
        ledger.new_address(1)
    with pytest.raises(BTClibTypeError, match="invalid source type"):
        ledger.new_address("0")  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError, match="invalid branch: 2"):
        ledger.new_address(0, 2)
    with pytest.raises(BTClibTypeError, match="invalid script_pub_key type"):
        ledger.position_of(b"")  # type: ignore[arg-type]


def test_a_branch_that_is_not_ranged_has_one_address(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Handed out every time, and watched at index 0 alone."""
    fixed = source("wpkh({}/84h/1h/5h/{}/0)", (0,))
    source_id = ledger.add_source(fixed, lookahead=SMALL_LOOKAHEAD)
    payment = chain.pay([TxOut(3_000, fixed.script_pub_key(0, 0))])
    ledger.sync()
    assert ledger.transaction(payment.id).amount == 3_000
    address = ledger.new_address(source_id)
    assert address == fixed.address(0, 0)
    assert ledger.new_address(source_id) == address


def test_a_source_added_later_owns_what_is_held(
    ledger: Ledger, chain: FakeChain
) -> None:
    """No rescan: wallet_balance.py lines 291-307 at v32.1.

    One transaction pays both sources. Before the second is added, only
    the first output is the ledger's; after it, both are, with no read of
    the chain.
    """
    other = source("wpkh({}/84h/1h/7h/{}/*)", (0,))
    both = chain.pay(
        [
            TxOut(10_000, script_of(ledger.new_address())),
            TxOut(20_000, other.script_pub_key(0, 0)),
        ]
    )
    chain.mine([both])
    ledger.sync()
    assert ledger.balances().trusted == 10_000
    reads = len(chain.reads)
    ledger.add_source(other, None, lookahead=SMALL_LOOKAHEAD)
    assert ledger.balances().trusted == 30_000
    assert len(chain.reads) == reads
    # born "now", so the next sync reads it from the tip alone
    ledger.sync()
    assert set(chain.reads[reads:]) == {chain.tip.height}


def test_a_source_added_with_a_birth_height_reads_its_history(
    ledger: Ledger, chain: FakeChain
) -> None:
    """The next sync reads the new source's scripts from its birth."""
    other = source("wpkh({}/84h/1h/7h/{}/*)", (0,))
    payment = chain.pay([TxOut(20_000, other.script_pub_key(0, 0))])
    chain.mine([payment])
    chain.mine(count=3)
    ledger.sync()
    with pytest.raises(BTClibValueError):
        ledger.transaction(payment.id)
    ledger.add_source(other, 1, lookahead=SMALL_LOOKAHEAD)
    assert payment.id in ledger.sync().changed
    assert ledger.balances().trusted == 20_000


def test_a_new_source_paid_at_the_tip_still_reads_its_history(
    ledger: Ledger, chain: FakeChain
) -> None:
    """A payment the main read finds grows the window, not replaces it.

    The new source's whole window is still read from its birth.
    """
    other = source("wpkh({}/84h/1h/7h/{}/*)", (0,))
    early = chain.pay([TxOut(20_000, other.script_pub_key(0, 0))])
    chain.mine([early])
    chain.mine(count=3)
    ledger.sync()
    ledger.add_source(other, 1, lookahead=SMALL_LOOKAHEAD)
    late = chain.pay([TxOut(30_000, other.script_pub_key(0, 1))])
    changed = ledger.sync().changed
    assert {early.id, late.id} <= changed
    assert ledger.balances().trusted == 20_000
    assert ledger.balances().untrusted_pending == 30_000


def test_a_source_is_checked(ledger: Ledger) -> None:
    """A wallet of descriptors, of the ledger's network."""
    with pytest.raises(BTClibTypeError, match="invalid wallet type"):
        ledger.add_source("wpkh()")  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid birth_height type"):
        ledger.add_source(source(), "0")  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError, match="negative lookahead"):
        ledger.add_source(source(), lookahead=-1)
    xpub = SoftwareSigner(XPRV).xpub("m/84h/1h/0h")
    wallet = DescriptorWallet(parse(f"wpkh({xpub}/0/*)", "testnet"))
    with pytest.raises(BTClibValueError, match="a testnet wallet in a regtest ledger"):
        ledger.add_source(wallet)
    with pytest.raises(BTClibTypeError, match="invalid branch type: str"):
        ledger.new_address(0, "0")  # type: ignore[arg-type]


def test_a_ledger_with_no_source_does_not_sync(chain: FakeChain, path: Path) -> None:
    """Refused before any read, whatever the reader."""
    with (
        Ledger.create(path, "regtest", chain) as empty,
        pytest.raises(BTClibValueError, match="no source"),
    ):
        empty.sync()
    assert chain.reads == []


def test_a_replaced_transaction_is_kept_inactive(
    ledger: Ledger, chain: FakeChain
) -> None:
    """wallet_balance.py lines 174-180: the replaced one stays, marked."""
    payment = _funded(ledger, chain)
    coin = TxIn(OutPoint(payment.id, 0))
    first = _signed(
        ledger, [coin], [_outside(), TxOut(60_000, _outside().script_pub_key)]
    )
    chain.mempool[first.id] = chain.known[first.id] = first
    ledger.sync()
    assert _state(ledger, first) is TxState.MEMPOOL
    second = _signed(
        ledger, [coin], [_outside(), TxOut(59_000, _outside().script_pub_key)]
    )
    del chain.mempool[first.id]
    chain.mempool[second.id] = chain.known[second.id] = second
    result = ledger.sync()
    assert result.changed == {first.id, second.id}
    assert _state(ledger, first) is TxState.INACTIVE
    assert _state(ledger, second) is TxState.MEMPOOL
    # spent in the mempool, so in no bucket
    assert ledger.balances() == Balances(0, 0, 0, 0)
    info = ledger.transaction(second.id)
    assert info.fee == 100_000 - 30_000 - 59_000
    assert info.amount == -30_000 - 59_000
    assert [d.category for d in info.details] == ["send", "send"]


def test_a_refused_broadcast_stays_as_nonmempool(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Recorded first, so a refusal keeps it: wallet_balance.py 214-225."""
    _funded(ledger, chain)
    chain.refuse = "min relay fee not met"
    with pytest.raises(FetchError, match="min relay fee not met"):
        ledger.spend([_outside()])
    (refused,) = [
        info for info in ledger.transactions if info.wallet_tx.state is TxState.INACTIVE
    ]
    assert ledger.balances() == Balances(100_000, 0, 0, -100_000)
    assert ledger.balances(include_nonmempool=False) == Balances(0, 0, 0, 0)
    assert not refused.trusted
    # the coin it spends is spent
    assert ledger.utxos() == ()
    ledger.sync()
    assert ledger.transaction(refused.wallet_tx.tx.id).wallet_tx.state is (
        TxState.INACTIVE
    )
    # the mempool takes it after all
    chain.refuse = ""
    chain.broadcast(refused.wallet_tx.tx)
    ledger.sync()
    assert _state(ledger, refused.wallet_tx.tx) is TxState.MEMPOOL


def test_a_spend_pays_change_that_is_trusted(ledger: Ledger, chain: FakeChain) -> None:
    """Change from a trusted parent is trusted, in the mempool already."""
    _funded(ledger, chain)
    spent = ledger.spend([_outside()])
    assert _state(ledger, spent) is TxState.MEMPOOL
    info = ledger.transaction(spent.id)
    change = 100_000 - 30_000 - (info.fee or 0)
    # the fee is left out, as Core's `amount` leaves it
    assert info.amount == -30_000
    # the change is no detail of its own, as Core leaves it out
    assert info.details == (TxDetail("send", 0, -30_000),)
    assert ledger.balances() == Balances(change, 0, 0, 0)
    (utxo,) = ledger.utxos(0)
    assert (utxo.branch, utxo.index, utxo.safe) == (1, 0, True)
    # a spend of the trusted change, unconfirmed, is trusted too
    again = ledger.spend([_outside()])
    assert ledger.transaction(again.id).trusted
    ledger.sync()
    assert _state(ledger, again) is TxState.MEMPOOL


def test_an_unconfirmed_receipt_is_not_spent(ledger: Ledger, chain: FakeChain) -> None:
    """Only trusted coins are selected, and a spend of none is refused."""
    chain.pay([TxOut(100_000, script_of(ledger.new_address()))])
    ledger.sync()
    with pytest.raises(BTClibValueError, match="no selection"):
        ledger.spend([_outside()])
    assert len(ledger.utxos(0, include_unsafe=False)) == 0
    assert len(ledger.utxos(0)) == 1


def test_the_change_of_a_spend_of_an_untrusted_coin_is_untrusted(
    ledger: Ledger, chain: FakeChain
) -> None:
    """A parent from outside, unconfirmed, makes its children untrusted."""
    payment = chain.pay([TxOut(100_000, script_of(ledger.new_address()))])
    ledger.sync()
    child = _signed(
        ledger,
        [TxIn(OutPoint(payment.id, 0))],
        [TxOut(90_000, script_of(ledger.new_address()))],
    )
    chain.mempool[child.id] = chain.known[child.id] = child
    ledger.sync()
    assert not ledger.transaction(child.id).trusted
    assert ledger.balances() == Balances(0, 90_000, 0, 0)


def _beside(ledger: Ledger, ours: OutPoint, parent: Tx, vout: int) -> Tx:
    """Return a spend of `ours` and of an output of `parent`, ours signed.

    The ledger signs its own input; the other is left unsigned.
    """
    unsigned = Tx(
        vin=[TxIn(ours), TxIn(OutPoint(parent.id, vout))],
        vout=[TxOut(1_000, script_of(ledger.new_address()))],
    )
    psbt = Psbt.from_tx(unsigned)
    psbt.inputs[1].non_witness_utxo = parent
    ((pub_key, sig),) = ledger.sign(psbt).inputs[0].partial_sigs.items()
    vin = [
        TxIn(ours, script_witness=Witness([sig, pub_key])),
        TxIn(OutPoint(parent.id, vout)),
    ]
    return Tx(vin=vin, vout=unsigned.vout)


def test_a_spend_beside_an_input_of_somebody_else_is_not_trusted(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Core's `CachedTxIsTrusted`: every input has to be a trusted coin.

    The other input spends an output the ledger does not own, of a
    transaction it holds, or of one it does not hold.
    """
    payment = chain.pay(
        [
            TxOut(100_000, script_of(ledger.new_address())),
            TxOut(100_000, _outside().script_pub_key),
        ]
    )
    elsewhere = chain.pay([TxOut(100_000, _outside().script_pub_key)])
    chain.mine([payment, elsewhere])
    ledger.sync()
    ours = OutPoint(payment.id, 0)
    for parent, vout in ((payment, 1), (elsewhere, 0)):
        mixed = _beside(ledger, ours, parent, vout)
        chain.mempool = {mixed.id: mixed}
        chain.known[mixed.id] = mixed
        ledger.sync()
        info = ledger.transaction(mixed.id)
        assert info.wallet_tx.state is TxState.MEMPOOL
        assert not info.trusted


def test_a_spend_naming_an_output_its_parent_lacks_is_not_trusted(
    ledger: Ledger, chain: FakeChain
) -> None:
    """The other input names an index past the last output of a parent held.

    The ledger's own input is signed as a signer holding the same key signs
    one input at a time: a wpkh signature commits to no other input's output.
    """
    script = ledger.sources[0].script_pub_key(0, 0).script
    payment = chain.pay([TxOut(100_000, script)])
    chain.mine([payment])
    ledger.sync()
    vin = [TxIn(OutPoint(payment.id, 0)), TxIn(OutPoint(payment.id, 1))]
    vout = [TxOut(1_000, _outside().script_pub_key)]
    xprv = derive(XPRV, "m/84h/1h/0h/0/0")
    pub_key = BIP32KeyData.b58decode(xpub_from_xprv(xprv)).key
    # the p2pkh script of the key hash the wpkh script holds
    script_code = b"\x76\xa9\x14" + script[2:] + b"\x88\xac"
    msg_hash = segwit_v0(script_code, Tx(vin=vin, vout=vout), 0, ALL, 100_000)
    sig = dsa.sign_(msg_hash, prv_keyinfo_from_xprv(xprv)[0]).serialize()
    vin[0] = TxIn(vin[0].prev_out, script_witness=Witness([sig + b"\x01", pub_key]))
    spend = Tx(vin=vin, vout=vout)
    chain.mempool[spend.id] = chain.known[spend.id] = spend
    ledger.sync()
    info = ledger.transaction(spend.id)
    assert info.wallet_tx.state is TxState.MEMPOOL
    assert not info.trusted
    assert ledger.balances() == Balances(0, 0, 0, 0)


def test_a_reorganization_returns_a_confirmed_payment_to_the_mempool(
    ledger: Ledger, chain: FakeChain
) -> None:
    """The fork is the highest block held still on the chain."""
    early = _funded(ledger, chain, 1_000)
    payment = chain.pay([TxOut(70_000, script_of(ledger.new_address()))])
    chain.mine()
    ledger.sync()
    chain.mine([payment])
    ledger.sync()
    assert ledger.transaction(payment.id).confirmations == 1
    chain.invalidate(3)
    chain.mempool[payment.id] = payment
    chain.mine(count=2)
    result = ledger.sync()
    assert result.fork_height == 2
    assert payment.id in result.changed
    assert _state(ledger, payment) is TxState.MEMPOOL
    assert _state(ledger, early) is TxState.CONFIRMED
    assert ledger.balances() == Balances(1_000, 70_000, 0, 0)
    # then confirmed in another block
    chain.mine([payment])
    ledger.sync()
    assert ledger.transaction(payment.id).wallet_tx.block == chain.tip


def test_a_transaction_a_reorganization_drops_is_inactive(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Out of every block and out of the mempool: kept, not dropped."""
    ledger.sync()
    payment = _funded(ledger, chain)
    chain.invalidate(1)
    chain.mine(count=2)
    result = ledger.sync()
    # height 0 is the one block held below the old tip
    assert result.fork_height == 0
    assert _state(ledger, payment) is TxState.INACTIVE
    assert ledger.balances() == Balances(0, 0, 0, 0)
    assert ledger.utxos(0) == ()


def test_a_reorganization_below_every_block_held(
    ledger: Ledger, chain: FakeChain
) -> None:
    """No block held is on the chain: the fork height is -1."""
    chain.mine(count=2)
    ledger.sync()
    chain.blocks = [(b"\x07" * 32, [])]
    chain.mine(count=3)
    result = ledger.sync()
    assert result.fork_height == -1
    assert result.tip == chain.tip


def test_a_coinbase_matures_after_100_blocks(ledger: Ledger, chain: FakeChain) -> None:
    """Immature until COINBASE_MATURITY blocks are built on it."""
    coinbase = chain.coinbase(script_of(ledger.new_address()), 5_000_000)
    chain.mine([coinbase])
    chain.mine(count=COINBASE_MATURITY - 1)
    ledger.sync()
    assert ledger.balances() == Balances(0, 0, 5_000_000, 0)
    assert ledger.utxos(0) == ()
    assert len(ledger.utxos(0, include_immature_coinbase=True)) == 1
    info = ledger.transaction(coinbase.id)
    assert info.details == (TxDetail("immature", 0, 5_000_000),)
    assert info.amount == 0
    chain.mine()
    ledger.sync()
    assert ledger.balances() == Balances(5_000_000, 0, 0, 0)
    info = ledger.transaction(coinbase.id)
    assert info.details == (TxDetail("generate", 0, 5_000_000),)
    assert info.amount == 5_000_000
    # a reorganization takes it out of the chain: at depth 0 it is
    # immature, so it adds nothing, as bitcoind v32.1 reports it, and
    # abandoned, as Core's `blockDisconnected` leaves it
    chain.invalidate(1)
    chain.mine(count=101)
    ledger.sync()
    info = ledger.transaction(coinbase.id)
    assert info.wallet_tx.state is TxState.ABANDONED
    assert info.details == (TxDetail("orphan", 0, 5_000_000),)
    assert info.amount == 0
    assert ledger.balances() == Balances(0, 0, 0, 0)


def test_utxos_filters_as_core_does(ledger: Ledger, chain: FakeChain) -> None:
    """Locked, below the depth, unsafe: each left out on its own."""
    payment = _funded(ledger, chain)
    coin = OutPoint(payment.id, 0)
    ledger.lock(coin)
    assert ledger.locked == {coin}
    assert ledger.utxos() == ()
    assert len(ledger.utxos(include_locked=True)) == 1
    with pytest.raises(BTClibValueError, match="no selection"):
        ledger.spend([_outside()])
    ledger.unlock(coin)
    assert ledger.locked == frozenset()
    assert ledger.utxos(2) == ()
    with pytest.raises(BTClibTypeError, match="invalid outpoint type"):
        ledger.lock("00" * 32)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid outpoint type"):
        ledger.unlock(None)  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError, match="negative min_depth"):
        ledger.utxos(-1)
    with pytest.raises(BTClibTypeError, match="invalid include_unsafe type"):
        ledger.utxos(include_unsafe=1)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid include_nonmempool type"):
        ledger.balances(include_nonmempool=1)  # type: ignore[arg-type]


def test_a_transaction_is_asked_for_by_its_id(ledger: Ledger) -> None:
    """An id of no ledger transaction is refused, and so is a string."""
    with pytest.raises(BTClibValueError, match="not a ledger transaction"):
        ledger.transaction(b"\x00" * 32)
    with pytest.raises(BTClibTypeError, match="invalid txid type"):
        ledger.transaction("00" * 32)  # type: ignore[arg-type]


def test_an_invalid_spend_of_the_ledgers_coin_never_enters(
    ledger: Ledger, chain: FakeChain
) -> None:
    """ISS btclib-org/btclib-wallet#642: the signature is checked first.

    A backend reports a mempool transaction spending the ledger's coin
    with a signature that does not verify. It enters no history, the coin
    stays unspent, and the ledger spends it.
    """
    payment = _funded(ledger, chain)
    honest = _signed(ledger, [TxIn(OutPoint(payment.id, 0))], [_outside()])
    forged = tampered(honest)
    assert forged.id == honest.id
    chain.mempool[forged.id] = chain.known[forged.id] = forged
    assert ledger.sync().changed == frozenset()
    with pytest.raises(BTClibValueError, match="not a ledger transaction"):
        ledger.transaction(forged.id)
    assert len(ledger.utxos()) == 1
    del chain.mempool[forged.id]
    assert _state(ledger, ledger.spend([_outside()])) is TxState.MEMPOOL


def test_a_spender_seen_before_its_parent_is_checked_when_it_arrives(
    ledger: Ledger, chain: FakeChain, path: Path
) -> None:
    """Admitted unchecked, then gone with its child once the parent shows."""
    payment = chain.pay([TxOut(100_000, script_of(ledger.new_address()))])
    chain.mine([payment])
    honest = _signed_after_seeing(path, chain, payment)
    forged = tampered(honest)
    # a child of its output to somebody else, which nothing checks
    child = Tx(
        vin=[TxIn(OutPoint(forged.id, 0))],
        vout=[TxOut(1_000, script_of(ledger.new_address()))],
    )
    chain.hidden.add(payment.id)
    for tx in (forged, child):
        chain.mempool[tx.id] = chain.known[tx.id] = tx
    ledger.sync()
    assert _state(ledger, forged) is TxState.MEMPOOL
    assert _state(ledger, child) is TxState.MEMPOOL
    chain.hidden.clear()
    result = ledger.sync()
    assert {forged.id, child.id, payment.id} <= result.changed
    for gone in (forged, child):
        with pytest.raises(BTClibValueError, match="not a ledger transaction"):
            ledger.transaction(gone.id)


def _signed_after_seeing(path: Path, chain: FakeChain, payment: Tx) -> Tx:
    """Sign a spend of the payment with a ledger that holds it, elsewhere."""
    helper_path = path.with_name("helper.sqlite")
    with Ledger.create(helper_path, "regtest", chain) as helper:
        helper.add_source(source(), lookahead=SMALL_LOOKAHEAD)
        helper.sync()
        return _signed(
            helper,
            [TxIn(OutPoint(payment.id, 0))],
            [_outside(), TxOut(60_000, script_of(helper.new_change_address()))],
        )


def test_a_valid_spender_seen_before_its_parent_stays(
    ledger: Ledger, chain: FakeChain, path: Path
) -> None:
    """The check passes once the parent arrives, and nothing leaves."""
    payment = chain.pay([TxOut(100_000, script_of(ledger.new_address()))])
    chain.mine([payment])
    honest = _signed_after_seeing(path, chain, payment)
    chain.hidden.add(payment.id)
    chain.mempool[honest.id] = chain.known[honest.id] = honest
    ledger.sync()
    chain.hidden.clear()
    ledger.sync()
    assert _state(ledger, honest) is TxState.MEMPOOL


def _signed_by_twin(
    path: Path,
    chain: FakeChain,
    wallet: DescriptorWallet,
    vin: list[TxIn],
    vout: list[TxOut],
) -> Tx:
    """Sign with another ledger of `wallet`, over the same chain."""
    with Ledger.create(path.with_name("twin.sqlite"), "regtest", chain) as twin:
        twin.add_source(wallet, lookahead=SMALL_LOOKAHEAD)
        twin.sync()
        return _signed(twin, vin, vout)


def test_a_forged_spend_of_a_coin_the_same_sync_brings_into_view(
    ledger: Ledger, chain: FakeChain, path: Path
) -> None:
    """Checked against the windows as the sync leaves them.

    Index 5 is past the first window, 0 to 4. A payment to index 2 moves
    the window to 7, so the sync that reads it also finds a payment to
    index 5, and a forged spend of that coin: the spend is kept out.
    """
    wallet = ledger.sources[0]
    near = chain.pay([TxOut(10_000, wallet.script_pub_key(0, 2))])
    far = chain.pay([TxOut(500_000, wallet.script_pub_key(0, 5))])
    chain.mine([near, far])
    honest = _signed_by_twin(
        path, chain, source(), [TxIn(OutPoint(far.id, 0))], [_outside()]
    )
    forged = tampered(honest)
    chain.mempool[forged.id] = chain.known[forged.id] = forged
    result = ledger.sync()
    assert result.changed == {near.id, far.id}
    with pytest.raises(BTClibValueError, match="not a ledger transaction"):
        ledger.transaction(forged.id)
    assert ledger.balances().trusted == 510_000
    # the window as it stands now holds it out at the next sync too
    assert ledger.sync().changed == frozenset()


def test_a_forged_spend_of_a_coin_a_new_source_owns_leaves(
    ledger: Ledger, chain: FakeChain, path: Path
) -> None:
    """Checked again once `add_source` makes the coin it spends the ledger's.

    A held transaction pays the ledger and a wallet not yet added. A
    forged spend of the second output pays the ledger too, so it enters
    as a receipt with nothing of the ledger's to check. Adding the wallet
    makes its input the ledger's: it leaves the ledger and the file.
    """
    other = source("wpkh({}/84h/1h/7h/{}/*)", (0,))
    parent = chain.pay(
        [
            TxOut(10_000, script_of(ledger.new_address())),
            TxOut(20_000, other.script_pub_key(0, 0)),
        ]
    )
    chain.mine([parent])
    ledger.sync()
    honest = _signed_by_twin(
        path,
        chain,
        other,
        [TxIn(OutPoint(parent.id, 1))],
        [TxOut(5_000, script_of(ledger.new_address())), TxOut(10_000, b"\x51")],
    )
    forged = tampered(honest)
    chain.mempool[forged.id] = chain.known[forged.id] = forged
    assert ledger.sync().changed == {forged.id}
    ledger.add_source(other, None, lookahead=SMALL_LOOKAHEAD)
    with pytest.raises(BTClibValueError, match="not a ledger transaction"):
        ledger.transaction(forged.id)
    assert ledger.balances().trusted == 30_000
    with Ledger.load(path, "regtest", chain) as loaded:
        assert [info.wallet_tx.tx.id for info in loaded.transactions] == [parent.id]


def test_a_payment_to_its_own_address_is_sent_and_received(
    ledger: Ledger, chain: FakeChain
) -> None:
    """receive.cpp:165-191: an output that is not change is sent too.

    bitcoind v32.1 gives a payment to its own receiving address a `send`
    line and a `receive` line of the same output, and none of the change.
    """
    _funded(ledger, chain)
    to_self = ledger.new_address()
    tx = ledger.spend([TxOut(30_000, script_of(to_self))])
    vout = next(
        i
        for i, tx_out in enumerate(tx.vout)
        if tx_out.script_pub_key.address == to_self
    )
    assert ledger.transaction(tx.id).details == (
        TxDetail("send", vout, -30_000),
        TxDetail("receive", vout, 30_000),
    )


def test_an_input_naming_no_output_of_a_held_parent(
    ledger: Ledger, chain: FakeChain
) -> None:
    """An output index past the parent's outputs spends nothing held."""
    payment = _funded(ledger, chain)
    odd = Tx(
        vin=[TxIn(OutPoint(payment.id, 7)), chain.foreign_input()],
        vout=[TxOut(1_000, script_of(ledger.new_address()))],
    )
    chain.mempool[odd.id] = chain.known[odd.id] = odd
    ledger.sync()
    assert ledger.transaction(odd.id).fee is None


def test_the_fee_rate_is_the_callers_the_estimate_or_the_fallback(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Decision 5 of ISS btclib-org/btclib-wallet#712, and the relay floors."""
    _funded(ledger, chain, 1_000_000)
    two = FeeRate.from_sats_per_vbyte(2)
    # the fallback, there being no estimate
    funded = ledger.fund([_outside()])
    assert funded.fee == funded.psbt.vsize_estimate() * 2
    # the estimate
    chain.estimate = FeeRate.from_sats_per_vbyte(3)
    funded = ledger.fund([_outside()])
    assert funded.fee == funded.psbt.vsize_estimate() * 3
    # raised to the mempool's minimum
    chain.relay = chain.relay.__class__(two, FeeRate.from_sats_per_vbyte(4), two)
    funded = ledger.fund([_outside()])
    assert funded.fee == funded.psbt.vsize_estimate() * 4
    # the caller's, refused below the relay minimum
    funded = ledger.fund([_outside()], FeeRate.from_sats_per_vbyte(2))
    assert funded.fee == funded.psbt.vsize_estimate() * 2
    with pytest.raises(BTClibValueError, match="below the minimum relay rate"):
        ledger.fund([_outside()], FeeRate.from_sats_per_vbyte(1))
    with pytest.raises(BTClibTypeError, match="invalid fee_rate type"):
        ledger.fund([_outside()], 2)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid outputs type"):
        ledger.fund([b"\x00"])  # type: ignore[list-item]
    with pytest.raises(BTClibTypeError, match="invalid outputs type"):
        ledger.fund(_outside())  # type: ignore[arg-type]


def test_no_estimate_and_no_fallback_refuses_a_spend(
    chain: FakeChain, path: Path
) -> None:
    """As Core does with `-fallbackfee=0`."""
    with Ledger.create(path, "regtest", chain, broadcaster=chain) as ledger:
        ledger.add_source(source(), lookahead=SMALL_LOOKAHEAD)
        _funded(ledger, chain)
        with pytest.raises(BTClibValueError, match="no fee estimate"):
            ledger.spend([_outside()])
        # with no relay reader, the caller's rate is taken as it is, and
        # the fallback too
        funded = ledger.fund([_outside()], FeeRate(sats_per_kvbyte=0))
        assert funded.fee == 0
        ledger.fallback_fee_rate = FeeRate.from_sats_per_vbyte(3)
        funded = ledger.fund([_outside()])
        assert funded.fee == funded.psbt.vsize_estimate() * 3


def test_a_ledger_with_no_broadcaster_does_not_send(
    chain: FakeChain, path: Path
) -> None:
    """Refused before anything is funded."""
    with Ledger.create(path, "regtest", chain) as ledger:
        with pytest.raises(BTClibValueError, match="no broadcaster"):
            ledger.spend([_outside()])
        with pytest.raises(BTClibTypeError, match="invalid fallback_fee_rate type"):
            Ledger.load(path, "regtest", chain, fallback_fee_rate=2)  # type: ignore[arg-type]


def test_a_spend_with_no_change_hands_out_no_change_address(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Change below dust goes to the fee, and its address stays unused."""
    _funded(ledger, chain, 30_400)
    spent = ledger.spend([_outside()], FeeRate.from_sats_per_vbyte(1))
    assert len(spent.vout) == 1
    assert ledger.new_change_address() == ledger.sources[0].address(1, 0)


def test_a_source_of_one_branch_takes_its_change_there(
    chain: FakeChain, path: Path
) -> None:
    """Branch 0, where there is no branch 1."""
    with Ledger.create(path, "regtest", chain, broadcaster=chain) as ledger:
        ledger.add_source(source(branches=(0,)), lookahead=SMALL_LOOKAHEAD)
        _funded(ledger, chain)
        spent = ledger.spend([_outside()], FeeRate.from_sats_per_vbyte(1))
        assert ledger.position_of(spent.vout[1].script_pub_key) == (0, 0, 1)
        with pytest.raises(BTClibValueError, match="invalid branch: 1"):
            ledger.new_change_address()


def test_keys_with_an_origin_and_a_watch_only_source_sign(
    chain: FakeChain, path: Path
) -> None:
    """A key origin names the master; a source with no keys signs nothing."""
    signer = SoftwareSigner(XPRV)
    account = "84h/1h/3h"
    xprv = signer._at(f"m/{account}")
    origin = f"[{signer.master_fingerprint.hex()}/{account}]"
    prv_keys: dict[str, str] = {}
    descriptors = [
        parse(f"wpkh({origin}{xprv}/{branch}/*)", "regtest", prv_keys)
        for branch in (0, 1)
    ]
    watch_only = DescriptorWallet(
        parse(f"wpkh({signer.xpub('m/84h/1h/4h')}/0/*)", "regtest")
    )
    with Ledger.create(path, "regtest", chain, broadcaster=chain) as ledger:
        ledger.add_source(DescriptorWallet(descriptors, prv_keys), lookahead=3)
        ledger.add_source(watch_only, lookahead=3)
        _funded(ledger, chain)
        spent = ledger.spend([_outside()], FeeRate.from_sats_per_vbyte(1))
        assert _state(ledger, spent) is TxState.MEMPOOL


def test_sign_leaves_an_input_it_does_not_hold(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Only the inputs spending the ledger's outputs are updated."""
    payment = _funded(ledger, chain)
    elsewhere = chain.pay([_outside()])
    psbt = Psbt.from_tx(
        Tx(
            vin=[TxIn(OutPoint(payment.id, 0)), TxIn(OutPoint(elsewhere.id, 0))],
            vout=[_outside()],
        )
    )
    psbt.inputs[1].non_witness_utxo = elsewhere
    psbt = ledger.sign(psbt)
    assert psbt.inputs[0].partial_sigs
    assert not psbt.inputs[1].partial_sigs
    with pytest.raises(BTClibTypeError, match="invalid psbt type"):
        ledger.sign(b"")  # type: ignore[arg-type]


def test_a_load_answers_what_the_ledger_held(
    ledger: Ledger, chain: FakeChain, path: Path
) -> None:
    """Every answer, with no read of the backend; the keys still sign."""
    _funded(ledger, chain)
    ledger.spend([_outside()])
    ledger.sync()
    answers = (
        ledger.balances(),
        ledger.utxos(0),
        ledger.transactions,
        ledger.tip,
        _texts(ledger),
    )
    ledger.close()
    reads = len(chain.reads)
    with Ledger.load(path, "regtest", chain, broadcaster=chain) as loaded:
        assert (
            loaded.balances(),
            loaded.utxos(0),
            loaded.transactions,
            loaded.tip,
            _texts(loaded),
        ) == answers
        assert len(chain.reads) == reads
        spent = loaded.spend([_outside()], FeeRate.from_sats_per_vbyte(1))
        assert _state(loaded, spent) is TxState.MEMPOOL


def _texts(ledger: Ledger) -> list[tuple[list[str], dict[str, str]]]:
    """Return each source's descriptors and keys, which a load reads back."""
    return [
        (
            [str(wallet.descriptor(branch)) for branch in wallet.branches],
            dict(wallet.prv_keys or {}),
        )
        for wallet in ledger.sources
    ]


def test_a_sync_reads_again_where_the_tip_moved(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Between two reads of one sync, at most `_SYNC_ATTEMPTS` times in all.

    A source added with a birth height is read on its own after the main
    read, so its read can answer for another tip.
    """
    ledger.sync()
    ledger.add_source(source("wpkh({}/84h/1h/7h/{}/*)", (0,)), 0, lookahead=3)
    # the tip moves before the second read of the first attempt
    chain.on_read.extend([lambda: None, chain.mine])
    ledger.sync()
    assert ledger.tip == chain.tip
    assert ledger.tip.height == 1
    ledger.add_source(source("wpkh({}/84h/1h/8h/{}/*)", (0,)), 0, lookahead=3)
    original = chain.get_history
    calls = 0

    def moving(
        scripts: Iterable[Octets | ScriptPubKey], start_height: int = 0
    ) -> ScriptHistory:
        nonlocal calls
        calls += 1
        if calls % 2 == 0:
            chain.mine()
        return original(scripts, start_height)

    chain.get_history = moving  # type: ignore[method-assign]
    with pytest.raises(FetchError, match="the chain tip moved"):
        ledger.sync()
    # the main read and the new source's read, at every attempt
    assert calls == 2 * _SYNC_ATTEMPTS


def test_a_taproot_spend_beside_an_output_not_held_is_kept_out(
    chain: FakeChain, path: Path
) -> None:
    """A taproot signature commits to every output spent.

    The ledger signs its taproot input of a spend beside another taproot
    input. Where the ledger holds the transaction paying that other
    input, the check passes; where it does not, the check cannot run
    over the right outputs, and fails.
    """
    with Ledger.create(path, "regtest", chain) as ledger:
        ledger.add_source(source("tr({}/86h/1h/0h/{}/*)"), lookahead=SMALL_LOOKAHEAD)
        foreign_script = source("tr({}/86h/1h/9h/{}/*)", (0,)).script_pub_key(0, 0)
        # one transaction pays both, so the ledger holds the other's parent
        held = chain.pay(
            [
                TxOut(50_000, script_of(ledger.new_address())),
                TxOut(50_000, foreign_script),
            ]
        )
        not_held = chain.pay([TxOut(50_000, foreign_script)])
        chain.mine([held, not_held])
        ledger.sync()
        for parent, admitted in ((held, True), (not_held, False)):
            other = OutPoint(parent.id, 1 if parent is held else 0)
            unsigned = Tx(
                vin=[TxIn(OutPoint(held.id, 0)), TxIn(other)],
                vout=[TxOut(90_000, script_of(ledger.new_address()))],
            )
            psbt = Psbt.from_tx(unsigned)
            psbt.inputs[1].witness_utxo = TxOut(50_000, foreign_script)
            signature = ledger.sign(psbt).inputs[0].taproot_key_spend_signature
            spend = Tx(
                vin=[
                    TxIn(OutPoint(held.id, 0), script_witness=Witness([signature])),
                    TxIn(other),
                ],
                vout=unsigned.vout,
            )
            chain.mempool = {spend.id: spend}
            chain.known[spend.id] = spend
            ledger.sync()
            found = [info.wallet_tx.tx.id for info in ledger.transactions]
            assert (spend.id in found) is admitted


def test_a_long_unconfirmed_chain_is_ordered_with_no_recursion() -> None:
    """Parents first over a chain far deeper than Python's recursion limit."""
    chain = [Tx(vin=[TxIn(OutPoint(b"\xee" * 32, 0))], vout=[TxOut(1_000, b"\x51")])]
    for _ in range(1, 2_000):
        spend = TxIn(OutPoint(chain[-1].id, 0))
        chain.append(Tx(vin=[spend], vout=[TxOut(1_000, b"\x51")]))
    newest_first = {tx.id: tx for tx in reversed(chain)}
    assert [tx.id for tx in _parents_first(newest_first)] == [tx.id for tx in chain]
