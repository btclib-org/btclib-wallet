# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A `Ledger`'s labels read against bitcoind's own wallet on one chain.

`tests/integration/ledger_test.py` says what the node and its wallets
`miner` and `twin` are. Each label is set on the ledger and on `twin`
alike, and after each step -- payments to labelled addresses, a label
on an address of somebody else, a spend joining two coins, a spend
paying a labelled change address, a payment past an index never handed
out, a spend to the ledger's own address, a label changed, an immature
coinbase, a label on an address before it is handed out, an unload and
a load -- the ledger is compared with `twin` as `ledger_test._compare`
compares them.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from btclib.amount import btc_from_sats
from btclib.script import ScriptPubKey
from btclib.tx import TxOut

from btclib_wallet.fetch.bitcoin_core import BitcoinCoreFetcher
from btclib_wallet.ledger import Ledger
from tests.integration import ledger_test
from tests.integration.ledger_test import (
    FALLBACK,
    Node,
    _compare,
    _mine,
    _miner_output,
    _sats,
    _source,
)

pytestmark = pytest.mark.integration

# the module's own node, started as `ledger_test`'s is: the labels set
# here are in `twin`'s address book, which that module's ledger lacks
node = ledger_test.node


def _labelled(node: Node, ledger: Ledger, label: str) -> str:
    """Hand out an address with a label, set on `twin` too."""
    address = ledger.new_address(label=label)
    node.wallet("twin").call("setlabel", [address, label])
    return address


def _pay(node: Node, address: str) -> None:
    """Pay a quarter of the miner's matured balance to `address`."""
    miner = node.wallet("miner")
    paid = _sats(miner.call("getbalance")) // 4
    miner.call("sendtoaddress", [address, f"{btc_from_sats(paid):.8f}"])


def test_the_labels_answer_what_cores_wallet_answers(
    node: Node, tmp_path: Path
) -> None:
    """Each step of the module docstring, compared after a sync."""
    path = tmp_path / "ledger.sqlite"
    fetcher = BitcoinCoreFetcher(node.client, "regtest")
    ledger = Ledger.create(
        path,
        "regtest",
        fetcher,
        broadcaster=fetcher,
        fee_estimator=fetcher,
        fallback_fee_rate=FALLBACK,
    )
    ledger.add_source(_source())
    ledger.sync()
    _compare(node, ledger)

    # payments to two labelled addresses, in the mempool and then a block
    first = _labelled(node, ledger, "a")
    _pay(node, first)
    _pay(node, _labelled(node, ledger, "b"))
    ledger.sync()
    _compare(node, ledger)
    _mine(node)
    ledger.sync()
    _compare(node, ledger)

    # a label on an address of somebody else
    foreign = node.wallet("miner").call("getnewaddress")
    ledger.set_label(foreign, "foreign")
    node.wallet("twin").call("setlabel", [foreign, "foreign"])
    _compare(node, ledger)

    # a spend that needs both coins, which joins them and its change
    spend = ledger.spend([_miner_output(node, ledger.balances().trusted - 100_000)])
    ledger.sync()
    _compare(node, ledger)
    # Core counts change as received, and so does the ledger
    (change,) = (o for o in spend.vout if ledger.position_of(o.script_pub_key))
    address = change.script_pub_key.address
    assert ledger.received_by_address(address, 0) == change.value
    assert len(ledger.address_groupings) == 1
    _mine(node)
    ledger.sync()
    _compare(node, ledger)

    # a label on the next change address makes it a receiving one, which
    # no spend joins
    labelled = ledger.sources[0].address(1, 1)
    ledger.set_label(labelled, "c")
    node.wallet("twin").call("setlabel", [labelled, "c"])
    ledger.spend([_miner_output(node, ledger.balances().trusted // 2)])
    ledger.sync()
    _compare(node, ledger)
    groups = [{entry.address for entry in group} for group in ledger.address_groupings]
    assert {labelled} in groups
    _mine(node)
    ledger.sync()
    _compare(node, ledger)

    # a payment two indexes past one handed out, which labels the index
    # between too, then a spend to the next address, labelled at once
    wallet = ledger.sources[0]
    position = ledger.position_of(ScriptPubKey.from_address(ledger.new_address()))
    assert position is not None
    index = position[2]
    _pay(node, wallet.address(0, index + 2))
    ledger.sync()
    _compare(node, ledger)
    _mine(node)
    ledger.sync()
    _compare(node, ledger)
    ledger.spend([TxOut(100_000, wallet.script_pub_key(0, index + 3))])
    _compare(node, ledger)
    _mine(node)
    ledger.sync()
    _compare(node, ledger)

    # a label changed
    ledger.set_label(first, "b")
    node.wallet("twin").call("setlabel", [first, "b"])
    _compare(node, ledger)

    # an immature coinbase to a labelled address
    coinbase = _labelled(node, ledger, "coinbase")
    node.client.call("generatetoaddress", [1, coinbase])
    ledger.sync()
    _compare(node, ledger)

    # a label on the next address, which handing it out replaces with "",
    # as `getnewaddress` does
    position = ledger.position_of(ScriptPubKey.from_address(coinbase))
    assert position is not None
    upcoming = wallet.address(0, position[2] + 1)
    ledger.set_label(upcoming, "pre")
    node.wallet("twin").call("setlabel", [upcoming, "pre"])
    _compare(node, ledger)
    assert ledger.new_address() == upcoming
    assert node.wallet("twin").call("getnewaddress") == upcoming
    assert ledger.label_of(upcoming) == ""
    _compare(node, ledger)

    # an unload and a load: the same labels
    labels = {label: ledger.addresses_by_label(label) for label in ledger.labels()}
    ledger.close()
    with Ledger.load(path, "regtest", fetcher) as loaded:
        assert {
            label: loaded.addresses_by_label(label) for label in loaded.labels()
        } == labels
        _compare(node, loaded)
