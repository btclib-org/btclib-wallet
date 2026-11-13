# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The labels a `Ledger` keeps, and what it answers by address and label.

`tests/integration/ledger_labels_test.py` asks the same of bitcoind's
wallet.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.script import ScriptPubKey
from btclib.tx import TxIn, TxOut
from btclib.tx.limits import COINBASE_MATURITY

from btclib_wallet.descriptors import parse
from btclib_wallet.exceptions import FetchError
from btclib_wallet.ledger import GroupedAddress, Ledger, TxDetail
from btclib_wallet.wallet import DescriptorWallet
from tests.ledger.conflict_test import _conflicted, _spend_and_child, _two_coins
from tests.ledger.conftest import LOOKAHEAD, XPRV, FakeChain, script_of, source
from tests.ledger.ledger_test import _funded

# an address of somebody else, on the ledger's network
FOREIGN = source("wpkh({}/84h/1h/9h/{}/*)", (0,)).address(0, 0)


def test_a_label_is_set_changed_and_listed_by_purpose(ledger: Ledger) -> None:
    """Core's `setlabel`, `listlabels` and `getaddressesbylabel`."""
    own = ledger.new_address(label="a")
    ledger.set_label(FOREIGN, "f")
    assert ledger.labels() == ("a", "f")
    assert ledger.labels("receive") == ("a",)
    assert ledger.labels("send") == ("f",)
    # Core's `listlabels` reads "" as no purpose, and "refund" as one
    # nothing here sets
    assert ledger.labels("") == ledger.labels()
    assert ledger.labels("refund") == ()
    assert ledger.addresses_by_label("a") == {own: "receive"}
    assert ledger.addresses_by_label("f") == {FOREIGN: "send"}
    ledger.set_label(own, "b")
    assert ledger.labels() == ("b", "f")
    assert (ledger.label_of(own), ledger.label_of(FOREIGN)) == ("b", "f")
    with pytest.raises(BTClibValueError, match="no address has the label 'a'"):
        ledger.addresses_by_label("a")


def test_a_receiving_address_has_the_empty_label(ledger: Ledger) -> None:
    """Handed out, it has "", as Core gives it; change has none."""
    assert ledger.labels() == ()
    wallet = ledger.sources[0]
    assert ledger.label_of(wallet.address(0, 0)) is None
    own = ledger.new_address()
    change = ledger.new_change_address()
    assert ledger.label_of(own) == ""
    assert ledger.label_of(change) is None
    assert ledger.label_of(FOREIGN) is None
    assert ledger.labels() == ("",)
    assert ledger.addresses_by_label("") == {own: "receive"}
    # a label makes a change address a receiving one, as Core's
    # `setlabel` does
    ledger.set_label(change, "c")
    assert ledger.addresses_by_label("c") == {change: "receive"}


def test_a_new_address_replaces_the_label_it_had(ledger: Ledger) -> None:
    """Core's `getnewaddress` sets its label, "" by default, over any."""
    first = ledger.sources[0].address(0, 0)
    ledger.set_label(first, "pre")
    assert ledger.new_address() == first
    assert ledger.label_of(first) == ""
    assert ledger.labels() == ("",)
    # a send label on an address of a source added later
    later = source("wpkh({}/84h/1h/2h/{}/*)", (0, 1))
    ledger.set_label(later.address(0, 0), "f")
    later_id = ledger.add_source(later, lookahead=LOOKAHEAD)
    assert ledger.addresses_by_label("f") == {later.address(0, 0): "send"}
    assert ledger.new_address(later_id) == later.address(0, 0)
    assert ledger.addresses_by_label("") == {
        first: "receive",
        later.address(0, 0): "receive",
    }
    # a change address, and the one address of a branch not ranged, keep it
    ledger.set_label(later.address(1, 0), "c")
    assert ledger.new_change_address(later_id) == later.address(1, 0)
    fixed = _fixed()
    ledger.set_label(fixed.address(0, 0), "x")
    fixed_id = ledger.add_source(fixed, lookahead=LOOKAHEAD)
    assert ledger.new_address(fixed_id) == fixed.address(0, 0)
    assert (
        ledger.label_of(later.address(1, 0)),
        ledger.label_of(fixed.address(0, 0)),
    ) == ("c", "x")


def test_labels_are_read_back_after_a_load(
    ledger: Ledger, chain: FakeChain, path: Path
) -> None:
    """The file holds each label and its purpose."""
    own = ledger.new_address(label="a")
    ledger.set_label(FOREIGN, "f")
    ledger.close()
    with Ledger.load(path, "regtest", chain) as loaded:
        assert loaded.labels("receive") == ("a",)
        assert loaded.labels("send") == ("f",)
        assert loaded.addresses_by_label("a") == {own: "receive"}


def test_the_name_star_and_what_is_no_label_are_refused(ledger: Ledger) -> None:
    """Core's -11 "Invalid label name", wherever a label goes in."""
    with pytest.raises(BTClibValueError, match="invalid label name"):
        ledger.new_address(label="*")
    # nothing was handed out
    assert ledger.new_address() == ledger.sources[0].address(0, 0)
    for call in (
        lambda: ledger.set_label(FOREIGN, "*"),
        lambda: ledger.addresses_by_label("*"),
        lambda: ledger.received_by_label("*"),
        lambda: ledger.add_source(_fixed(), label="*"),
    ):
        with pytest.raises(BTClibValueError, match="invalid label name"):
            call()
    with pytest.raises(BTClibTypeError, match="invalid label type"):
        ledger.set_label(FOREIGN, 1)  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError, match="invalid purpose: 'unknown'"):
        ledger.labels("unknown")
    with pytest.raises(BTClibTypeError, match="invalid purpose type"):
        ledger.labels(1)  # type: ignore[arg-type]
    script = source("wpkh({}/84h/1h/9h/{}/*)", (0,)).script_pub_key(0, 0).script
    with pytest.raises(BTClibValueError, match="not an address of regtest"):
        ledger.set_label(ScriptPubKey(script, "mainnet").address, "m")
    assert ledger.labels() == ("",)


def _fixed() -> DescriptorWallet:
    """Return a source whose branch 0 is one address."""
    return source("wpkh({}/84h/1h/5h/{}/0)", (0,))


def test_a_source_not_ranged_takes_a_label(ledger: Ledger) -> None:
    """Core's `importdescriptors` label, refused on a ranged descriptor."""
    fixed = _fixed()
    ledger.add_source(fixed, lookahead=LOOKAHEAD, label="fixed")
    assert ledger.addresses_by_label("fixed") == {fixed.address(0, 0): "receive"}
    with pytest.raises(BTClibValueError, match="a label needs one address on branch 0"):
        ledger.add_source(source(), label="ranged")
    prv_keys: dict[str, str] = {}
    change_only = DescriptorWallet(
        {1: parse(f"wpkh({XPRV}/84h/1h/6h/1/0)", "regtest", prv_keys)}, prv_keys
    )
    with pytest.raises(BTClibValueError, match="a label needs one address on branch 0"):
        ledger.add_source(change_only, label="change")
    assert len(ledger.sources) == 2
    # without a label, its address has the empty one, as Core gives it
    other = source("wpkh({}/84h/1h/7h/{}/0)", (0,))
    ledger.add_source(other, lookahead=LOOKAHEAD)
    assert ledger.label_of(other.address(0, 0)) == ""


def test_received_by_address_counts_what_is_deep_enough(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Core's `getreceivedbyaddress`, change included."""
    own = ledger.new_address()
    payment = chain.pay([TxOut(100_000, script_of(own))])
    ledger.sync()
    assert ledger.received_by_address(own) == 0
    assert ledger.received_by_address(own, 0) == 100_000
    chain.mine([payment])
    ledger.sync()
    assert ledger.received_by_address(own) == 100_000
    assert ledger.received_by_address(own, 2) == 0
    outside = source("wpkh({}/84h/1h/9h/{}/*)", (0,)).script_pub_key(0, 1)
    spend = ledger.spend([TxOut(30_000, outside)])
    change = next(
        tx_out for tx_out in spend.vout if ledger.position_of(tx_out.script_pub_key)
    )
    assert ledger.received_by_address(change.script_pub_key.address, 0) == (
        change.value
    )
    # what is spent stays received
    assert ledger.received_by_address(own, 0) == 100_000
    with pytest.raises(BTClibValueError, match="not an address of the ledger"):
        ledger.received_by_address(FOREIGN)
    with pytest.raises(BTClibValueError, match="negative min_depth"):
        ledger.received_by_address(own, -1)


def test_a_coinbase_is_received_once_mature(ledger: Ledger, chain: FakeChain) -> None:
    """Unless asked for immature; one in no block never."""
    own = ledger.new_address()
    chain.mine([chain.coinbase(script_of(own), 5_000_000)])
    ledger.sync()
    assert ledger.received_by_address(own) == 0
    assert ledger.received_by_address(own, include_immature_coinbase=True) == 5_000_000
    chain.mine(count=COINBASE_MATURITY)
    ledger.sync()
    assert ledger.received_by_address(own) == 5_000_000
    chain.invalidate(1)
    chain.mine(count=COINBASE_MATURITY + 1)
    ledger.sync()
    assert ledger.received_by_address(own, 0, include_immature_coinbase=True) == 0


def test_received_by_label_sums_the_ledgers_addresses(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Core's `getreceivedbylabel`, over the ledger's addresses alone."""
    first = ledger.new_address(label="a")
    second = ledger.new_address(label="a")
    chain.mine(
        [
            chain.pay([TxOut(10_000, script_of(first))]),
            chain.pay([TxOut(20_000, script_of(second))]),
        ]
    )
    ledger.sync()
    assert ledger.received_by_label("a") == 30_000
    ledger.set_label(FOREIGN, "f")
    with pytest.raises(BTClibValueError, match="no address of the ledger has the"):
        ledger.received_by_label("f")
    with pytest.raises(BTClibValueError, match="no address has the label 'g'"):
        ledger.received_by_label("g")


def test_addresses_spent_together_are_grouped(ledger: Ledger, chain: FakeChain) -> None:
    """Core's `listaddressgroupings`, with the change of the spend."""
    first = ledger.new_address(label="a")
    second = ledger.new_address()
    chain.mine(
        [
            chain.pay([TxOut(40_000, script_of(first))]),
            chain.pay([TxOut(50_000, script_of(second))]),
        ]
    )
    ledger.sync()
    assert ledger.address_groupings == tuple(
        sorted(
            [
                (GroupedAddress(first, 40_000, "a"),),
                (GroupedAddress(second, 50_000, ""),),
            ],
            key=lambda group: group[0].address,
        )
    )
    outside = source("wpkh({}/84h/1h/9h/{}/*)", (0,)).script_pub_key(0, 1)
    spend = ledger.spend([TxOut(85_000, outside)])
    change = next(
        tx_out for tx_out in spend.vout if ledger.position_of(tx_out.script_pub_key)
    )
    # the change is the ledger's own, and trusted in the mempool; a
    # payment from outside in the mempool holds nothing yet
    third = ledger.new_address()
    chain.pay([TxOut(60_000, script_of(third))])
    ledger.sync()
    group, alone = sorted(ledger.address_groupings, key=len, reverse=True)
    assert alone == (GroupedAddress(third, 0, ""),)
    assert group == tuple(
        sorted(
            [
                GroupedAddress(first, 0, "a"),
                GroupedAddress(second, 0, ""),
                GroupedAddress(change.script_pub_key.address, change.value, None),
            ],
            key=lambda entry: entry.address,
        )
    )


def test_a_conflicted_payment_is_not_received_and_an_abandoned_one_is(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Core's `GetReceived` reads the depth alone, and an abandoned one is 0.

    A conflicted transaction is below depth 0. Each transaction joins the
    addresses it spends, whatever its state, as `GetAddressGroupings`
    reads every transaction of the wallet.
    """
    spend, _, _, _ = _conflicted(ledger, chain)
    change = spend.vout[1].script_pub_key.address
    assert ledger.received_by_address(change, 0) == 0
    spent = {_address(ledger, tx_in) for tx_in in spend.vin}
    groups = [{e.address for e in group} for group in ledger.address_groupings]
    assert spent | {change} in groups

    x, y = _two_coins(ledger, chain)
    spend, _ = _spend_and_child(ledger, chain, x, y)
    chain.mempool.clear()
    ledger.sync()
    ledger.abandon(spend.id)
    change = spend.vout[1].script_pub_key.address
    assert ledger.received_by_address(change, 0) == spend.vout[1].value
    assert ledger.received_by_address(change) == 0


def _address(ledger: Ledger, tx_in: TxIn) -> str:
    """Return the address of the ledger's output an input spends."""
    parent = ledger.transaction(tx_in.prev_out.tx_id).wallet_tx.tx
    return parent.vout[tx_in.prev_out.vout].script_pub_key.address


def test_a_labelled_change_address_receives(ledger: Ledger, chain: FakeChain) -> None:
    """Core's `ScriptIsChange`: change is an output of the ledger with no label.

    bitcoind, given a label on its change index 0 and then a spend
    of two coins, groups the two coins alone and lists the labelled
    output as a detail of its own.
    """
    first = ledger.new_address()
    second = ledger.new_address()
    chain.mine(
        [
            chain.pay([TxOut(40_000, script_of(first))]),
            chain.pay([TxOut(50_000, script_of(second))]),
        ]
    )
    ledger.sync()
    change = ledger.sources[0].address(1, 0)
    ledger.set_label(change, "c")
    outside = source("wpkh({}/84h/1h/9h/{}/*)", (0,)).script_pub_key(0, 1)
    spend = ledger.spend([TxOut(60_000, outside)])
    (vout, tx_out) = next(
        (i, o) for i, o in enumerate(spend.vout) if o.script_pub_key.address == change
    )
    assert sorted(ledger.address_groupings, key=len) == [
        (GroupedAddress(change, tx_out.value, "c"),),
        tuple(
            sorted(
                [GroupedAddress(first, 0, ""), GroupedAddress(second, 0, "")],
                key=lambda entry: entry.address,
            )
        ),
    ]
    details = ledger.transaction(spend.id).details
    assert TxDetail("send", vout, -tx_out.value) in details
    assert TxDetail("receive", vout, tx_out.value) in details


def test_a_script_with_no_address_has_no_label_and_no_group(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Core skips what `ExtractDestination` refuses, as `pk()` pays to."""
    prv_keys: dict[str, str] = {}
    bare = DescriptorWallet(
        [parse(f"pk({XPRV}/1h/{branch}/0)", "regtest", prv_keys) for branch in (0, 1)],
        prv_keys,
    )
    ledger.add_source(bare, lookahead=LOOKAHEAD, label="bare")
    chain.mine([chain.pay([TxOut(9_000, bare.script_pub_key(0, 0))])])
    ledger.sync()
    assert ledger.labels() == ()
    assert ledger.address_groupings == ()
    assert ledger.balances().trusted == 9_000


def test_a_spend_to_its_own_address_labels_it_at_once(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Accepted, a spend hands out what it pays, as Core marks it used.

    bitcoind, right after `sendtoaddress` to its own address 1, lists the
    payment as sent and received.
    """
    _funded(ledger, chain, 100_000)
    own = ledger.sources[0].script_pub_key(0, 1)
    spend = ledger.spend([TxOut(30_000, own)])
    assert ledger.label_of(own.address) == ""
    details = ledger.transaction(spend.id).details
    assert TxDetail("send", 0, -30_000) in details
    assert TxDetail("receive", 0, 30_000) in details


def test_the_indexes_below_one_paid_are_labelled(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Core's `MarkUnusedAddresses` marks every index up to the one paid."""
    wallet = ledger.sources[0]
    ledger.new_address()
    chain.mine([chain.pay([TxOut(10_000, wallet.script_pub_key(0, 3))])])
    ledger.sync()
    assert ledger.addresses_by_label("") == {
        wallet.address(0, index): "receive" for index in range(4)
    }
    assert ledger.label_of(wallet.address(0, 4)) is None


def test_a_refused_spend_to_its_own_address_hands_out_nothing(
    ledger: Ledger, chain: FakeChain, path: Path
) -> None:
    """Core marks what a transaction pays only once the mempool reports it.

    bitcoind's `CommitTransaction` adds the transaction with `AddToWallet`,
    which marks no script used; a resubmission the node accepts does.
    """
    _funded(ledger, chain, 100_000)
    wallet = ledger.sources[0]
    chain.refuse = "refused"
    with pytest.raises(FetchError, match="refused"):
        ledger.spend([TxOut(30_000, wallet.script_pub_key(0, 2))])
    for index in (1, 2):
        assert ledger.label_of(wallet.address(0, index)) is None
    ledger.close()
    with Ledger.load(path, "regtest", chain, broadcaster=chain) as loaded:
        assert loaded.label_of(wallet.address(0, 2)) is None
        chain.refuse = ""
        assert loaded.resubmit() == {}
        assert loaded.label_of(wallet.address(0, 2)) == ""
        assert loaded.new_address() == wallet.address(0, 3)


def _bare(ledger: Ledger) -> DescriptorWallet:
    """Add a source paying to `pk()`, which has no address, and return it."""
    prv_keys: dict[str, str] = {}
    bare = DescriptorWallet(
        [parse(f"pk({XPRV}/1h/0/*)", "regtest", prv_keys)], prv_keys
    )
    ledger.add_source(bare, lookahead=LOOKAHEAD)
    return bare


def test_a_spend_to_a_script_with_no_address_is_handed_out(
    ledger: Ledger, chain: FakeChain, path: Path
) -> None:
    """Its position is handed out, in memory and in the file alike.

    Handed out, index 0 moves the window on to index `LOOKAHEAD`.
    """
    _funded(ledger, chain, 100_000_000)
    bare = _bare(ledger)
    last = bare.script_pub_key(0, LOOKAHEAD)
    assert ledger.position_of(last) is None
    spend = ledger.spend([TxOut(10_000_000, bare.script_pub_key(0, 0))])
    assert spend.id in chain.mempool
    assert ledger.position_of(last) == (1, 0, LOOKAHEAD)
    ledger.close()
    with Ledger.load(path, "regtest", chain) as loaded:
        assert loaded.position_of(last) == (1, 0, LOOKAHEAD)


def test_a_resubmission_to_a_script_with_no_address_is_accepted(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Two refused spends to it, then a resubmission the node accepts."""
    _funded(ledger, chain, 100_000_000)
    _funded(ledger, chain, 100_000_000)
    script = _bare(ledger).script_pub_key(0, 0)
    chain.refuse = "refused"
    for _ in range(2):
        with pytest.raises(FetchError, match="refused"):
            ledger.spend([TxOut(10_000_000, script)])
    chain.refuse = ""
    assert ledger.resubmit() == {}
