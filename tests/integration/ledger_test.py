# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A `Ledger` read against bitcoind's own wallet on the same regtest chain.

Core's wallet is the oracle. The node's wallet `twin` holds the very
descriptors the ledger holds, keys included, so both watch the same
scripts. After each step -- a mempool arrival, a confirmation, a coinbase,
a spend and its replacement, a broadcast the node refuses, a reorganization, a
double spend taken through a reorganization, an unload and load, and a
node restart -- the ledger is synced and its answers are compared with
what `twin` answers: its balances, coins and transactions, and its
labels, what each address and label received, and its address groupings.
A ledger restored from a backup, and an encrypted one, are compared the
same way.

The node is this module's own, so that it can be restarted; it refuses
a transaction paying under 2 sat/vB. A second wallet, `miner`, pays the
ledger from its matured balance, never a fixed amount.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from bitcoin_core_rpc import BitcoinCoreRpcClient
from bitcoin_core_rpc import RpcError as CoreRpcError
from btclib.amount import btc_from_sats, sats_from_btc
from btclib.exceptions import BTClibValueError
from btclib.fee import FeeRate
from btclib.script import ScriptPubKey
from btclib.tx import Tx, TxIn, TxOut

from btclib_wallet.descriptors import add_checksum, parse
from btclib_wallet.exceptions import RpcError
from btclib_wallet.fetch.bitcoin_core import BitcoinCoreFetcher
from btclib_wallet.ledger import Ledger, TxState
from btclib_wallet.psbt.psbt import Psbt, extract_tx, finalize
from btclib_wallet.wallet import DescriptorWallet
from tests.integration.conftest import _start_node, _stop, start_on_free_ports

pytestmark = pytest.mark.integration

XPRV = (
    "tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARb"
    "tRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK"
)
RECEIVE = f"wpkh({XPRV}/84h/1h/0h/0/*)"
CHANGE = f"wpkh({XPRV}/84h/1h/0h/1/*)"
# another account, for the backup's test: a ledger synced from scratch
# shows none of the conflicts the first test's ledger saw happen
BACKUP_RECEIVE = f"wpkh({XPRV}/84h/1h/1h/0/*)"
BACKUP_CHANGE = f"wpkh({XPRV}/84h/1h/1h/1/*)"
# and another, for the encrypted ledger's test
ENCRYPTED_RECEIVE = f"wpkh({XPRV}/84h/1h/2h/0/*)"
ENCRYPTED_CHANGE = f"wpkh({XPRV}/84h/1h/2h/1/*)"
# the node's own floor, 2 sat/vB, and the fallback the ledger pays above it
MIN_RELAY = "0.00002"
FALLBACK = FeeRate.from_sats_per_vbyte(5)


@dataclass
class Node:
    """The module's node, which a test may restart on the same data."""

    bitcoind: str
    datadir: Path
    process: Any = None
    client: Any = None

    def start(self) -> None:
        """Start the node, and load the wallets it held when it stopped."""
        self.process, self.client, _ = start_on_free_ports(
            lambda: _start_node(
                [self.bitcoind], self.datadir, None, (f"-minrelaytxfee={MIN_RELAY}",)
            )
        )
        loaded = set(self.client.call("listwallets"))
        for name in self.client.call("listwalletdir")["wallets"]:
            if name["name"] not in loaded:
                self.client.call("loadwallet", [name["name"]])

    def stop(self) -> None:
        """Stop the node."""
        _stop(self.process)

    def wallet(self, name: str) -> BitcoinCoreRpcClient:
        """Return a client of one of the node's wallets."""
        return self.client.for_wallet(name)  # type: ignore[no-any-return]


@pytest.fixture(scope="module")
def node(
    bitcoind_path: str, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[Node]:
    """Yield the module's node, with `miner` funded and `twin` the ledger's."""
    started = Node(bitcoind_path, tmp_path_factory.mktemp("ledger-node"))
    started.start()
    try:
        started.client.call("createwallet", ["miner"])
        miner = started.wallet("miner")
        miner.call("generatetoaddress", [101, miner.call("getnewaddress")])
        _create_twin(started, "twin", RECEIVE, CHANGE)
        yield started
    finally:
        started.stop()


def _create_twin(node: Node, name: str, receive: str, change: str) -> None:
    """Create a wallet of the node holding a ledger's two descriptors."""
    node.client.call("createwallet", [name, False, True])
    node.wallet(name).call(
        "importdescriptors",
        [
            [
                {
                    "desc": add_checksum(desc),
                    "active": True,
                    "internal": internal,
                    "timestamp": 0,
                    "range": [0, 999],
                }
                for desc, internal in ((receive, False), (change, True))
            ]
        ],
    )


def _source(receive: str = RECEIVE, change: str = CHANGE) -> DescriptorWallet:
    prv_keys: dict[str, str] = {}
    branches = [parse(text, "regtest", prv_keys) for text in (receive, change)]
    return DescriptorWallet(branches, prv_keys)


def _sats(value: Any) -> int:
    """Return a BTC amount of Core's in satoshi, a negative one included."""
    amount = Decimal(str(value))
    return -sats_from_btc(-amount) if amount < 0 else sats_from_btc(amount)


def _settle(node: Node) -> None:
    """Let the node's wallets take in what its mempool and chain did."""
    node.client.call("syncwithvalidationinterfacequeue")


def _compare(node: Node, ledger: Ledger, twin_name: str = "twin") -> None:
    """Assert the ledger answers what its twin answers, after a sync."""
    _settle(node)
    twin = node.wallet(twin_name)
    mine = twin.call("getbalances")["mine"]
    balances = ledger.balances()
    assert balances.trusted == _sats(mine["trusted"])
    assert balances.untrusted_pending == _sats(mine["untrusted_pending"])
    assert balances.immature == _sats(mine["immature"])
    assert balances.nonmempool == _sats(mine["nonmempool"])
    for minconf in (0, 1):
        trusted = ledger.balances(minconf, include_nonmempool=False).trusted
        assert trusted == _sats(twin.call("getbalance", ["*", minconf]))
    expected = {
        (u["txid"], u["vout"], _sats(u["amount"]), u["confirmations"], u["safe"])
        for u in twin.call("listunspent", [0])
    }
    found = {
        (
            u.outpoint.tx_id.hex(),
            u.outpoint.vout,
            u.tx_out.value,
            u.confirmations,
            u.safe,
        )
        for u in ledger.utxos(0)
    }
    assert found == expected
    for info in ledger.transactions:
        if info.wallet_tx.state is TxState.INACTIVE:
            continue
        core = twin.call("gettransaction", [info.wallet_tx.tx.id.hex()])
        assert info.amount == _sats(core["amount"])
        assert info.fee == (-_sats(core["fee"]) if "fee" in core else None)
        assert info.confirmations == core["confirmations"]
        if core["confirmations"] <= 0:
            assert info.trusted == core["trusted"]
        conflicts = {bytes.fromhex(txid) for txid in core["walletconflicts"]}
        assert info.wallet_conflicts == conflicts
        abandoned = {d["abandoned"] for d in core["details"]}
        assert abandoned <= {info.wallet_tx.state is TxState.ABANDONED}
    last = twin.call("getwalletinfo")["lastprocessedblock"]
    assert ledger.tip is not None
    assert ledger.tip.block_id.hex() == last["hash"]
    assert ledger.tip.height == last["height"]
    _compare_labels(twin, ledger)


def _answer(call: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Return what a call answers, None where it refuses."""
    try:
        return call(*args, **kwargs)
    except (BTClibValueError, CoreRpcError):
        return None


def _compare_labels(twin: BitcoinCoreRpcClient, ledger: Ledger) -> None:
    """Assert the ledger's labels, totals and groupings are `twin`'s."""
    for purpose in (None, "receive", "send"):
        args = [] if purpose is None else [purpose]
        assert ledger.labels(purpose) == tuple(twin.call("listlabels", args))
    asked = [(minconf, immature) for minconf in (0, 1) for immature in (False, True)]
    for label in ledger.labels():
        core = twin.call("getaddressesbylabel", [label])
        expected = {address: entry["purpose"] for address, entry in core.items()}
        assert ledger.addresses_by_label(label) == expected
        for minconf, immature in asked:
            received = _answer(
                ledger.received_by_label,
                label,
                minconf,
                include_immature_coinbase=immature,
            )
            core = _answer(twin.call, "getreceivedbylabel", [label, minconf, immature])
            assert received == (None if core is None else _sats(core))
    addresses = {
        tx_out.script_pub_key.address
        for info in ledger.transactions
        for tx_out in info.wallet_tx.tx.vout
        if ledger.position_of(tx_out.script_pub_key) is not None
    }
    for address in addresses:
        labels = twin.call("getaddressinfo", [address])["labels"]
        assert ledger.label_of(address) == (labels[0] if labels else None)
        for minconf, immature in asked:
            received = ledger.received_by_address(
                address, minconf, include_immature_coinbase=immature
            )
            core = twin.call("getreceivedbyaddress", [address, minconf, immature])
            assert received == _sats(core)
    expected_groups = {
        frozenset(
            (entry[0], _sats(entry[1]), entry[2] if len(entry) > 2 else None)
            for entry in group
        )
        for group in twin.call("listaddressgroupings")
    }
    found_groups = {
        frozenset((entry.address, entry.amount, entry.label) for entry in group)
        for group in ledger.address_groupings
    }
    assert found_groups == expected_groups


def _pay_ledger(node: Node, ledger: Ledger) -> str:
    """Pay a quarter of the miner's matured balance to a new address."""
    miner = node.wallet("miner")
    paid = _sats(miner.call("getbalance")) // 4
    return str(
        miner.call(
            "sendtoaddress", [ledger.new_address(), f"{btc_from_sats(paid):.8f}"]
        )
    )


def _mine(node: Node, blocks: int = 1) -> list[str]:
    miner = node.wallet("miner")
    return list(miner.call("generatetoaddress", [blocks, miner.call("getnewaddress")]))


def _miner_output(node: Node, value: int) -> TxOut:
    address = node.wallet("miner").call("getnewaddress")
    return TxOut(value, ScriptPubKey.from_address(address))


def test_the_ledger_answers_what_cores_wallet_answers(
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

    # a mempool arrival, then its confirmation
    _pay_ledger(node, ledger)
    ledger.sync()
    _compare(node, ledger)
    assert ledger.balances().untrusted_pending > 0
    _mine(node)
    ledger.sync()
    _compare(node, ledger)

    # a coinbase paid to the ledger, immature
    node.client.call("generatetoaddress", [1, ledger.new_address()])
    ledger.sync()
    _compare(node, ledger)
    assert ledger.balances().immature > 0

    # a spend, then a replacement paying one more satoshi a vbyte
    spend = ledger.spend([_miner_output(node, ledger.balances().trusted // 3)])
    ledger.sync()
    _compare(node, ledger)
    replacement = _replacement(ledger, spend)
    node.client.call(
        "sendrawtransaction", [replacement.serialize(include_witness=True).hex()]
    )
    result = ledger.sync()
    assert {spend.id, replacement.id} <= result.changed
    assert ledger.transaction(spend.id).wallet_tx.state is TxState.INACTIVE
    assert ledger.transaction(replacement.id).wallet_tx.state is TxState.MEMPOOL
    _compare(node, ledger)
    _mine(node)
    ledger.sync()
    _compare(node, ledger)

    # a broadcast the node refuses, under its relay floor: made from a
    # copy of the file, so that Core's wallet, which never sees the
    # transaction, stays comparable with the ledger after it
    copy = tmp_path / "refusing.sqlite"
    shutil.copyfile(path, copy)
    refusing = Ledger.load(copy, "regtest", fetcher, broadcaster=fetcher)
    with pytest.raises(RpcError, match="min relay fee not met"):
        refusing.spend(
            [_miner_output(node, refusing.balances().trusted // 4)],
            FeeRate.from_sats_per_vbyte(1),
        )
    refusing.sync()
    # the last transaction recorded
    last = refusing.transactions[-1].wallet_tx
    assert last.state is TxState.INACTIVE
    refused = last.tx
    spent = sum(_value_spent(refusing, tx_in) for tx_in in refused.vin)
    _settle(node)
    mine = node.wallet("twin").call("getbalances")["mine"]
    # the coins it spends are trusted in Core's wallet, which never saw
    # it, and here too, with `nonmempool` taking them back
    assert refusing.balances().trusted == _sats(mine["trusted"])
    assert refusing.balances().nonmempool == -spent
    assert (
        refusing.balances(include_nonmempool=False).trusted
        == _sats(mine["trusted"]) - spent
    )
    refusing.close()

    # a reorganization: the block confirming a payment is invalidated and
    # an empty block takes its height
    payment = _pay_ledger(node, ledger)
    (block,) = _mine(node)
    ledger.sync()
    node.client.call("invalidateblock", [block])
    node.client.call("generateblock", [node.wallet("miner").call("getnewaddress"), []])
    result = ledger.sync()
    assert result.fork_height is not None
    assert bytes.fromhex(payment) in result.changed
    assert ledger.transaction(bytes.fromhex(payment)).wallet_tx.state is TxState.MEMPOOL
    _compare(node, ledger)
    _mine(node)
    ledger.sync()
    _compare(node, ledger)

    # a double spend: the ledger's spend is in the mempool when a block
    # holding another spend of all its coins is mined, and one block on
    # top, as wallet_txn_doublespend's --mineblock variant reads -2
    pending = ledger.spend([_miner_output(node, ledger.balances().trusted // 3)])
    ledger.sync()
    _compare(node, ledger)
    double = _double_spend(node, ledger, pending)
    address = node.wallet("miner").call("getnewaddress")
    block = node.client.call(
        "generateblock", [address, [double.serialize(include_witness=True).hex()]]
    )["hash"]
    _mine(node)
    ledger.sync()
    info = ledger.transaction(pending.id)
    assert info.wallet_tx.state is TxState.CONFLICTED
    assert (info.confirmations, info.wallet_conflicts) == (-2, frozenset({double.id}))
    _compare(node, ledger)
    # a reorganization takes the double spend's block out: it goes back to
    # the mempool, and the spend is no longer conflicted
    node.client.call("invalidateblock", [block])
    node.client.call("generateblock", [address, []])
    ledger.sync()
    assert ledger.transaction(pending.id).wallet_tx.state is TxState.INACTIVE
    assert ledger.transaction(double.id).wallet_tx.state is TxState.MEMPOOL
    _compare(node, ledger)
    # abandoned in both wallets, then conflicted again by the double
    # spend's next block, which replaces the mark
    ledger.abandon(pending.id)
    node.wallet("twin").call("abandontransaction", [pending.id.hex()])
    assert ledger.transaction(pending.id).wallet_tx.state is TxState.ABANDONED
    _compare(node, ledger)
    _mine(node)
    ledger.sync()
    assert ledger.transaction(pending.id).confirmations == -1
    _compare(node, ledger)

    # an unload and a load: the same answers, and no read of the node
    answers = (ledger.balances(), ledger.utxos(0), ledger.transactions, ledger.tip)
    ledger.close()
    ledger = Ledger.load(path, "regtest", _NoReader(), fallback_fee_rate=FALLBACK)
    assert (
        ledger.balances(),
        ledger.utxos(0),
        ledger.transactions,
        ledger.tip,
    ) == answers
    ledger.close()

    # a node restart
    node.stop()
    node.start()
    fetcher = BitcoinCoreFetcher(node.client, "regtest")
    ledger = Ledger.load(
        path, "regtest", fetcher, broadcaster=fetcher, fallback_fee_rate=FALLBACK
    )
    assert (
        ledger.balances(),
        ledger.utxos(0),
        ledger.transactions,
        ledger.tip,
    ) == answers
    ledger.sync()
    _compare(node, ledger)
    ledger.close()


def test_a_restored_backup_answers_what_cores_wallet_answers(
    node: Node, tmp_path: Path
) -> None:
    """Five rounds after the backup, the original gone, then a restore.

    Core's wallet_backup.py at bitcoin/bitcoin@f0de87f040 (lines
    209-257): each round pays the ledger at a new address and spends
    from it, with change.
    """
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
    ledger.add_source(_source(BACKUP_RECEIVE, BACKUP_CHANGE))
    _create_twin(node, "backup-twin", BACKUP_RECEIVE, BACKUP_CHANGE)

    def one_round() -> None:
        _pay_ledger(node, ledger)
        _mine(node)
        ledger.sync()
        ledger.spend([_miner_output(node, ledger.balances().trusted // 3)])
        _mine(node)
        ledger.sync()

    one_round()
    backup = tmp_path / "ledger.bak"
    ledger.backup(backup)
    for _ in range(5):
        one_round()
    _compare(node, ledger, "backup-twin")
    ledger.close()
    path.unlink()

    restored = Ledger.restore(
        backup,
        tmp_path / "restored.sqlite",
        "regtest",
        fetcher,
        fallback_fee_rate=FALLBACK,
    )
    with restored:
        restored.sync()
        _compare(node, restored, "backup-twin")


def test_an_encrypted_ledger_answers_locked_and_spends_unlocked(
    node: Node, tmp_path: Path
) -> None:
    """Locked, it answers as its twin does; unlocked, the node takes its spend.

    Core's wallet_encryption.py at bitcoin/bitcoin@f0de87f040 (lines
    40-58): encrypted, the wallet refuses to sign until unlocked.
    """
    # an install on Windows arm64 leaves `cryptography` out, as
    # `tests/ledger/encryption_test.py` says
    pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    path = tmp_path / "ledger.sqlite"
    fetcher = BitcoinCoreFetcher(node.client, "regtest")
    _create_twin(node, "encrypted-twin", ENCRYPTED_RECEIVE, ENCRYPTED_CHANGE)
    with Ledger.create(path, "regtest", fetcher) as ledger:
        ledger.add_source(_source(ENCRYPTED_RECEIVE, ENCRYPTED_CHANGE))
        _pay_ledger(node, ledger)
        _mine(node)
        ledger.sync()
        ledger.encrypt("passphrase")
    assert XPRV.encode() not in path.read_bytes()
    with Ledger.load(
        path,
        "regtest",
        fetcher,
        broadcaster=fetcher,
        fee_estimator=fetcher,
        fallback_fee_rate=FALLBACK,
    ) as ledger:
        _pay_ledger(node, ledger)
        _mine(node)
        ledger.sync()
        _compare(node, ledger, "encrypted-twin")
        payment = _miner_output(node, ledger.balances().trusted // 3)
        with pytest.raises(ValueError, match="the ledger is locked"):
            ledger.spend([payment])
        ledger.unlock_keys("passphrase", 60)
        ledger.spend([payment])
        _mine(node)
        ledger.sync()
        _compare(node, ledger, "encrypted-twin")


def _value_spent(ledger: Ledger, tx_in: TxIn) -> int:
    """Return the value of the ledger's output an input spends."""
    parent = ledger.transaction(tx_in.prev_out.tx_id).wallet_tx.tx
    return parent.vout[tx_in.prev_out.vout].value


def _double_spend(node: Node, ledger: Ledger, spend: Tx) -> Tx:
    """Return a spend of every coin `spend` spends, paying the miner.

    Taking every coin, it leaves none that `spend` alone spends: Core's
    wallet stops counting a transaction the mempool conflicts with as a
    spender (`isMempoolConflicted`), which the ledger does not track.
    """
    value = sum(_value_spent(ledger, tx_in) for tx_in in spend.vin) - 10_000
    unsigned = Tx(
        vin=[TxIn(tx_in.prev_out) for tx_in in spend.vin],
        vout=[_miner_output(node, value)],
    )
    return extract_tx(finalize(ledger.sign(Psbt.from_tx(unsigned))))


def _replacement(ledger: Ledger, spend: Tx) -> Tx:
    """Return the spend paying 1000 satoshi less change, signed again."""
    change = next(
        i
        for i, tx_out in enumerate(spend.vout)
        if ledger.position_of(tx_out.script_pub_key) is not None
    )
    vout = list(spend.vout)
    vout[change] = TxOut(vout[change].value - 1_000, vout[change].script_pub_key)
    unsigned = Tx(
        version=spend.version,
        lock_time=spend.lock_time,
        vin=[TxIn(tx_in.prev_out, sequence=tx_in.sequence) for tx_in in spend.vin],
        vout=vout,
    )
    return extract_tx(finalize(ledger.sign(Psbt.from_tx(unsigned))))


class _NoReader:
    """A reader that fails every call: a load reads nothing."""

    def get_history(self, scripts: Any, start_height: int = 0) -> Any:
        pytest.fail("the load read the backend")
