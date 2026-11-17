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
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from btclib.tx.limits import COINBASE_MATURITY

from btclib_wallet.descriptors import parse
from btclib_wallet.exceptions import FetchError
from btclib_wallet.ledger import GroupedAddress, Ledger, TxDetail
from btclib_wallet.wallet import DescriptorWallet
from tests.ledger import (
    ClaimsInt,
    ObjectClaimingStr,
    Star,
    StrWithNoClass,
    TwinStr,
)
from tests.ledger.conflict_test import _conflicted, _spend_and_child, _two_coins
from tests.ledger.conftest import (
    LOOKAHEAD,
    REFUSED_BROADCAST,
    XPRV,
    FakeChain,
    script_of,
    source,
)
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


def test_a_label_is_the_str_it_holds(ledger: Ledger) -> None:
    """Checked, kept and looked up as the str held, whatever `==` claims.

    The empty label is the exact "" too, and a str whose `__class__`
    claims int is copied as a str.
    """
    assert (Star("a") == "*", Star("") == "*", TwinStr("*") == "*") == (
        True,
        True,
        False,
    )
    for call in (
        lambda: ledger.new_address(label=TwinStr("*")),
        lambda: ledger.set_label(FOREIGN, TwinStr("*")),
        lambda: ledger.add_source(_fixed(), label=TwinStr("*")),
    ):
        with pytest.raises(BTClibValueError, match="invalid label name"):
            call()
    own = ledger.new_address(label=Star("a"))
    assert own == ledger.sources[0].address(0, 0)
    ledger.set_label(FOREIGN, Star("f"))
    fixed = _fixed()
    ledger.add_source(fixed, lookahead=LOOKAHEAD, label=Star("x"))
    blank = ledger.new_address(label=Star(""))
    claiming = ledger.new_address(label=ClaimsInt("i"))
    addresses = (own, FOREIGN, fixed.address(0, 0), blank, claiming)
    held = [ledger.label_of(address) for address in addresses]
    assert [(type(label), label) for label in held] == [
        (str, "a"),
        (str, "f"),
        (str, "x"),
        (str, ""),
        (str, "i"),
    ]
    assert ledger.addresses_by_label(TwinStr("a")) == {own: "receive"}
    assert ledger.received_by_label(TwinStr("a")) == 0


def test_a_label_is_a_str_by_its_type_whatever_its_class_claims(
    ledger: Ledger,
) -> None:
    """An object that claims str is refused, a str whose class raises is not.

    `isinstance` reads `__class__`, at each place a label goes in.
    """
    claimant = ObjectClaimingStr()
    for call in (
        lambda: ledger.new_address(label=claimant),  # type: ignore[arg-type]
        lambda: ledger.set_label(FOREIGN, claimant),  # type: ignore[arg-type]
        lambda: ledger.add_source(_fixed(), label=claimant),  # type: ignore[arg-type]
        lambda: ledger.addresses_by_label(claimant),  # type: ignore[arg-type]
        lambda: ledger.received_by_label(claimant),  # type: ignore[arg-type]
    ):
        with pytest.raises(BTClibTypeError, match="^invalid label type: Object"):
            call()
    own = ledger.new_address(label=StrWithNoClass("s"))
    ledger.set_label(FOREIGN, StrWithNoClass("f"))
    fixed = _fixed()
    ledger.add_source(fixed, lookahead=LOOKAHEAD, label=StrWithNoClass("x"))
    held = [ledger.label_of(a) for a in (own, FOREIGN, fixed.address(0, 0))]
    assert [(type(label), label) for label in held] == [
        (str, "s"),
        (str, "f"),
        (str, "x"),
    ]
    assert ledger.addresses_by_label(StrWithNoClass("s")) == {own: "receive"}
    assert ledger.received_by_label(StrWithNoClass("s")) == 0
    # what isinstance reads of each, which the ledger must not ask
    with pytest.raises(RuntimeError, match="no __class__"):
        isinstance(StrWithNoClass("s"), bool)
    assert isinstance(claimant, str)


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


def _sharing(
    chain: FakeChain, path: Path, lookahead: int, branch: int, shared_first: bool
) -> tuple[Ledger, int, DescriptorWallet]:
    """Return a ledger of `source()` and a source sharing its scripts.

    The second source's branch 0 is the first's `branch`, watched with
    `LOOKAHEAD`, and `lookahead` is the first's. `shared_first` adds the
    second source before the first. The second source's id and wallet
    are returned beside the ledger.
    """
    ledger = Ledger.create(path, "regtest", chain)
    shared = source(f"wpkh({{}}/84h/1h/0h/{branch}/*)", (0,))
    if shared_first:
        shared_id = ledger.add_source(shared, lookahead=LOOKAHEAD)
        ledger.add_source(source(), lookahead=lookahead)
    else:
        ledger.add_source(source(), lookahead=lookahead)
        shared_id = ledger.add_source(shared, lookahead=LOOKAHEAD)
    return ledger, shared_id, shared


@pytest.mark.parametrize(
    "lookahead, branch, shared_first, hand_out, paid",
    [
        pytest.param(LOOKAHEAD, 0, False, True, 5, id="branch 0"),
        pytest.param(20, 0, False, False, 5, id="branch 0, the first source labels"),
        pytest.param(LOOKAHEAD, 1, False, True, 5, id="branch 1"),
        pytest.param(20, 1, False, True, 5, id="branch 1 reached first"),
        pytest.param(20, 1, True, True, 5, id="branch 1, the shared source first"),
        pytest.param(20, 1, False, False, 3, id="branch 1, nothing handed out"),
    ],
)
def test_a_script_two_sources_share_is_labelled_by_either(
    chain: FakeChain,
    tmp_path: Path,
    lookahead: int,
    branch: int,
    shared_first: bool,
    hand_out: bool,
    paid: int,
) -> None:
    """Indexes up to the one paid have "", whatever the lookaheads.

    `_sharing` says what each parameter makes of the two sources. The
    shared source hands out index 0 where `hand_out` says so, and is
    paid at `paid`. A restore watching 20 indexes, once synced, answers
    the same.
    """
    ledger, shared_id, shared = _sharing(
        chain, tmp_path / "l.sqlite", lookahead, branch, shared_first
    )
    with ledger:
        if hand_out:
            ledger.new_address(shared_id)
        chain.mine([chain.pay([TxOut(10_000, shared.script_pub_key(0, paid))])])
        ledger.sync()
        addresses = [shared.address(0, index) for index in range(8)]
        labels = [""] * (paid + 1) + [None] * (7 - paid)
        assert [ledger.label_of(address) for address in addresses] == labels
        assert ledger.addresses_by_label("") == dict.fromkeys(
            addresses[: paid + 1], "receive"
        )
        text = ledger.export_policy()
    restored, _ = Ledger.restore_policy(
        text, tmp_path / "r.sqlite", "regtest", chain, lookahead=20
    )
    with restored:
        restored.sync()
        assert [restored.label_of(address) for address in addresses] == labels


@pytest.mark.parametrize("shared_first", [False, True])
@pytest.mark.parametrize("lookahead", [LOOKAHEAD, 20])
def test_a_payment_to_a_shared_script_moves_each_source_on(
    chain: FakeChain, tmp_path: Path, lookahead: int, shared_first: bool
) -> None:
    """Neither source hands out the paid address again, as Core does.

    Core marks a paid script in each ScriptPubKeyMan that holds it.
    """
    ledger, shared_id, shared = _sharing(
        chain, tmp_path / "l.sqlite", lookahead, 0, shared_first
    )
    with ledger:
        chain.mine([chain.pay([TxOut(10_000, shared.script_pub_key(0, 3))])])
        ledger.sync()
        assert [ledger.new_address(shared_id) for _ in range(4)] == [
            shared.address(0, index) for index in range(4, 8)
        ]
        assert ledger.new_address(1 - shared_id) == shared.address(0, 4)


def test_a_window_grown_by_a_payment_marks_what_it_reaches(
    chain: FakeChain, tmp_path: Path
) -> None:
    """A position a sync's read brings into a window is marked too.

    One payment pays the shared source's indexes 1 and 3, and its window
    of 2 reaches index 3 only once index 1 is marked. `source()` watches
    index 3 from the start.
    """
    shared = source("wpkh({}/84h/1h/0h/{}/*)", (0,))
    paid = [TxOut(10_000, shared.script_pub_key(0, index)) for index in (1, 3)]
    chain.mine([chain.pay(paid)])
    chain.mine(count=3)
    with Ledger.create(tmp_path / "l.sqlite", "regtest", chain) as ledger:
        ledger.add_source(source(), lookahead=20)
        shared_id = ledger.add_source(shared, lookahead=2)
        ledger.sync()
        assert [ledger.new_address(shared_id) for _ in range(2)] == [
            shared.address(0, index) for index in (4, 5)
        ]


def test_a_spend_to_a_shared_script_moves_each_source_on(
    ledger: Ledger, chain: FakeChain
) -> None:
    """A spend hands out the position of each source it pays."""
    shared = source("wpkh({}/84h/1h/0h/{}/*)", (0,))
    shared_id = ledger.add_source(shared, lookahead=LOOKAHEAD)
    _funded(ledger, chain, 100_000)
    ledger.spend([TxOut(30_000, shared.script_pub_key(0, 2))])
    assert ledger.new_address(shared_id) == shared.address(0, 3)
    assert ledger.new_address(0) == shared.address(0, 3)


def test_the_ledgers_own_change_stays_change(
    ledger: Ledger, chain: FakeChain, tmp_path: Path
) -> None:
    """A spend's change has no label, though a source receives at it.

    Source 1's branch 0 is source 0's change branch. The spend's change
    stays change through a bump, a payment from outside, a sync and a
    restore, as *Labels* in the ledger's docstring says.
    """
    shared = source("wpkh({}/84h/1h/0h/1/*)", (0,))
    ledger.add_source(shared, lookahead=LOOKAHEAD)
    _funded(ledger, chain)
    spent = ledger.spend([TxOut(30_000, script_of(FOREIGN))])
    change = shared.address(0, 0)
    assert spent.vout[1].script_pub_key.address == change
    assert ledger.label_of(change) is None
    # the fee comes from the change, with no coin added
    bumped = ledger.bump(spent.id)
    assert bumped.vout[1].script_pub_key.address == change
    assert len(bumped.vin) == 1
    chain.mine([bumped, chain.pay([TxOut(10_000, script_of(change))])])
    ledger.sync()
    assert ledger.label_of(change) is None
    assert ledger.label_of(shared.address(0, 1)) is None
    restored, _ = Ledger.restore_policy(
        ledger.export_policy(), tmp_path / "r.sqlite", "regtest", chain
    )
    with restored:
        restored.sync()
        assert restored.label_of(change) is None


def test_a_payment_from_outside_to_a_change_script_is_received(
    ledger: Ledger, chain: FakeChain
) -> None:
    """With no spend paying it, a source receiving at it labels it "".

    Source 1's branch 0 is source 0's change branch.
    """
    shared = source("wpkh({}/84h/1h/0h/1/*)", (0,))
    ledger.add_source(shared, lookahead=LOOKAHEAD)
    _funded(ledger, chain)
    chain.mine([chain.pay([TxOut(10_000, shared.script_pub_key(0, 0))])])
    ledger.sync()
    assert ledger.label_of(shared.address(0, 0)) == ""


def test_a_spend_makes_change_only_of_the_script_it_pays(
    ledger: Ledger, chain: FakeChain
) -> None:
    """An outside payment beside the spend, to another change script.

    Source 1's branch 0 is source 0's change branch. The spend's change
    is index 0, and a payment from outside in the same block pays index
    1: only index 0 is the ledger's own change.
    """
    shared = source("wpkh({}/84h/1h/0h/1/*)", (0,))
    ledger.add_source(shared, lookahead=LOOKAHEAD)
    _funded(ledger, chain)
    spent = ledger.spend([TxOut(30_000, script_of(FOREIGN))])
    chain.mine([spent, chain.pay([TxOut(10_000, shared.script_pub_key(0, 1))])])
    ledger.sync()
    assert ledger.label_of(shared.address(0, 1)) == ""
    assert ledger.label_of(shared.address(0, 0)) is None
    labelled = ledger.addresses_by_label("")
    assert shared.address(0, 1) in labelled
    assert shared.address(0, 0) not in labelled


def test_a_spend_whose_only_output_is_change_keeps_it_change(
    ledger: Ledger, chain: FakeChain
) -> None:
    """Output 0 is read as any other, as in a bump where all is change.

    Source 1's branch 0 is source 0's change branch. The transaction
    spends the ledger's coin and pays source 0's change index 0 alone.
    """
    shared = source("wpkh({}/84h/1h/0h/1/*)", (0,))
    ledger.add_source(shared, lookahead=LOOKAHEAD)
    funding = _funded(ledger, chain)
    change = ledger.sources[0].script_pub_key(1, 0)
    vin = [TxIn(OutPoint(funding.id, 0))]
    chain.mine([Tx(vin=vin, vout=[TxOut(funding.vout[0].value - 1_000, change)])])
    ledger.sync()
    assert ledger.label_of(change.address) is None
    assert change.address not in ledger.addresses_by_label("")


def test_a_spend_to_an_address_two_sources_receive_at_labels_it(
    ledger: Ledger, chain: FakeChain
) -> None:
    """No source watches it on a branch other than 0, so it is no change.

    Source 1's branch 0 is source 0's branch 0.
    """
    shared = source("wpkh({}/84h/1h/0h/{}/*)", (0,))
    ledger.add_source(shared, lookahead=LOOKAHEAD)
    _funded(ledger, chain)
    ledger.spend([TxOut(30_000, shared.script_pub_key(0, 3))])
    assert ledger.label_of(shared.address(0, 3)) == ""


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
    with pytest.raises(FetchError, match=f"^{REFUSED_BROADCAST}$"):
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
        with pytest.raises(FetchError, match=f"^{REFUSED_BROADCAST}$"):
            ledger.spend([TxOut(10_000_000, script)])
    chain.refuse = ""
    assert ledger.resubmit() == {}
