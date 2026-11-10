# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A chain in memory that answers what a `Ledger` asks of a backend.

`FakeChain` is a `HistoryReader`, a `Broadcaster`, a `FeeEstimator` and a
`RelayFeeReader` at once, as `BitcoinCoreFetcher` is. Its blocks are
lists of transactions under made-up ids, and its mempool a mapping; a
test mines, pays, reorganizes and refuses by hand.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterable, Iterator, Sequence
from pathlib import Path

import pytest
from btclib.alias import Octets
from btclib.fee import FeeRate
from btclib.script import ScriptPubKey
from btclib.script.witness import Witness
from btclib.tx import OutPoint, Tx, TxIn, TxOut

from btclib_wallet.descriptors import parse
from btclib_wallet.exceptions import FetchError
from btclib_wallet.fetch.fee_estimator import FeeQuote
from btclib_wallet.fetch.history import (
    BlockRef,
    HistoryTx,
    ScriptHistory,
    history_scripts,
)
from btclib_wallet.fetch.relay_fees import RelayFees
from btclib_wallet.ledger import Ledger
from btclib_wallet.wallet import DescriptorWallet

XPRV = (
    "tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARb"
    "tRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK"
)
# a small window, so that a test reaches past it in a few payments
LOOKAHEAD = 5
ONE_SAT = FeeRate.from_sats_per_vbyte(1)


def without_cryptography(monkeypatch: pytest.MonkeyPatch) -> None:
    """Put `cryptography` out of reach, as an install on Windows arm64 has it.

    A module named None in `sys.modules` fails its import, and
    `ledger.crypto` imports these at each call that needs them.
    """
    for name in (
        "cryptography.exceptions",
        "cryptography.hazmat.primitives.ciphers.aead",
    ):
        monkeypatch.setitem(sys.modules, name, None)


def source(
    template: str = "wpkh({}/84h/1h/0h/{}/*)", branches: Sequence[int] = (0, 1)
) -> DescriptorWallet:
    """Return a wallet of one descriptor per branch, keys included."""
    prv_keys: dict[str, str] = {}
    descriptors = [
        parse(template.format(XPRV, branch), "regtest", prv_keys) for branch in branches
    ]
    return DescriptorWallet(descriptors, prv_keys)


def script_of(address: str) -> ScriptPubKey:
    """Return the script an address pays to, labelled regtest."""
    return ScriptPubKey.from_address(address)


class FakeChain:
    """Blocks, a mempool, and the backend questions over them."""

    def __init__(self) -> None:
        self.blocks: list[tuple[bytes, list[Tx]]] = [(bytes(32), [])]
        self.mempool: dict[bytes, Tx] = {}
        # every transaction ever seen, which is how an input finds the
        # script it spends
        self.known: dict[bytes, Tx] = {}
        # transactions `get_history` does not list, as a backend that has
        # not seen them yet
        self.hidden: set[bytes] = set()
        self.refuse = ""
        self.estimate: FeeRate | None = None
        self.relay = RelayFees(ONE_SAT, ONE_SAT, ONE_SAT)
        # called before each answer, so that a test can move the chain
        # between two reads of one sync
        self.on_read: list[Callable[[], object]] = []
        self.reads: list[int] = []
        self._ids = 0
        self._foreign = 0

    @property
    def tip(self) -> BlockRef:
        """The last block."""
        height = len(self.blocks) - 1
        return BlockRef(height, self.blocks[height][0])

    def _new_id(self) -> bytes:
        self._ids += 1
        return self._ids.to_bytes(32, "big")

    def foreign_input(self) -> TxIn:
        """Return an input spending an output nobody here holds."""
        self._foreign += 1
        return TxIn(OutPoint(b"\xff" * 28 + self._foreign.to_bytes(4, "big"), 0))

    def pay(self, outputs: Iterable[TxOut]) -> Tx:
        """Return a payment from outside, put in the mempool."""
        tx = Tx(vin=[self.foreign_input()], vout=list(outputs))
        self.known[tx.id] = tx
        self.mempool[tx.id] = tx
        return tx

    def coinbase(self, script: ScriptPubKey, value: int) -> Tx:
        """Return a coinbase paying `value` to `script`, height-unique."""
        script_sig = len(self.blocks).to_bytes(4, "little")
        vin = [TxIn(OutPoint(), script_sig=script_sig)]
        return Tx(vin=vin, vout=[TxOut(value, script)])

    def mine(self, txs: Iterable[Tx] = (), *, count: int = 1) -> list[bytes]:
        """Add `count` blocks, the first holding `txs`, and return their ids."""
        ids = []
        held = list(txs)
        for _ in range(count):
            for tx in held:
                self.mempool.pop(tx.id, None)
                self.known[tx.id] = tx
            ids.append(self._new_id())
            self.blocks.append((ids[-1], held))
            held = []
        return ids

    def invalidate(self, height: int) -> list[Tx]:
        """Drop the blocks from `height` up, and return their transactions."""
        dropped = [tx for _, txs in self.blocks[height:] for tx in txs]
        del self.blocks[height:]
        return dropped

    def _spent_script(self, tx_in: TxIn) -> bytes:
        parent = self.known.get(tx_in.prev_out.tx_id)
        if parent is None or tx_in.prev_out.vout >= len(parent.vout):
            return b""
        return parent.vout[tx_in.prev_out.vout].script_pub_key.script

    def _touches(self, tx: Tx, scripts: set[bytes]) -> bool:
        if tx.id in self.hidden:
            return False
        if any(tx_out.script_pub_key.script in scripts for tx_out in tx.vout):
            return True
        return any(self._spent_script(tx_in) in scripts for tx_in in tx.vin)

    def get_history(
        self, scripts: Iterable[Octets | ScriptPubKey], start_height: int = 0
    ) -> ScriptHistory:
        """Answer as `HistoryReader` says, from blocks and mempool."""
        for call in list(self.on_read):
            self.on_read.remove(call)
            call()
        wanted = set(history_scripts(scripts))
        self.reads.append(start_height)
        tip = self.tip
        start = min(start_height, tip.height)
        txs = [
            HistoryTx(tx, BlockRef(height, self.blocks[height][0]))
            for height in range(start, tip.height + 1)
            for tx in self.blocks[height][1]
            if self._touches(tx, wanted)
        ]
        txs += [
            HistoryTx(tx, None)
            for tx in self.mempool.values()
            if self._touches(tx, wanted)
        ]
        return ScriptHistory(BlockRef(start, self.blocks[start][0]), tip, tuple(txs))

    def broadcast(self, tx: Tx) -> bytes:
        """Take the transaction into the mempool, or refuse it.

        A transaction taken replaces each one in the mempool spending one
        of its inputs, as a node's full RBF does; their descendants stay,
        a test removing them where it needs to.
        """
        if self.refuse:
            raise FetchError(self.refuse)
        spent = {tx_in.prev_out for tx_in in tx.vin}
        for other in list(self.mempool.values()):
            if any(tx_in.prev_out in spent for tx_in in other.vin):
                del self.mempool[other.id]
        self.known[tx.id] = tx
        self.mempool[tx.id] = tx
        return tx.id

    def estimate_fee(self, target: int) -> FeeQuote:
        """Quote `estimate`, or decline as a backend with no data does."""
        if self.estimate is None:
            raise FetchError("insufficient data")
        return FeeQuote(self.estimate, target)

    def get_relay_fees(self) -> RelayFees:
        """Return `relay`."""
        return self.relay


def tampered(tx: Tx) -> Tx:
    """Return the transaction with a byte of each input's signature flipped.

    Every input carries a witness whose first element is a signature.
    """
    vin = []
    for tx_in in tx.vin:
        stack = list(tx_in.script_witness.stack)
        stack[0] = stack[0][:-2] + bytes([stack[0][-2] ^ 1]) + stack[0][-1:]
        vin.append(
            TxIn(
                tx_in.prev_out,
                script_sig=tx_in.script_sig,
                sequence=tx_in.sequence,
                script_witness=Witness(stack),
            )
        )
    return Tx(version=tx.version, lock_time=tx.lock_time, vin=vin, vout=tx.vout)


@pytest.fixture
def chain() -> FakeChain:
    """Return an empty chain: the genesis block and nothing else."""
    return FakeChain()


@pytest.fixture
def path(tmp_path: Path) -> Path:
    """Return where the ledger's file goes."""
    return tmp_path / "ledger.sqlite"


@pytest.fixture
def ledger(chain: FakeChain, path: Path) -> Iterator[Ledger]:
    """Yield a ledger of one source over the chain, every capability on."""
    created = Ledger.create(
        path,
        "regtest",
        chain,
        broadcaster=chain,
        fee_estimator=chain,
        relay_fee_reader=chain,
        fallback_fee_rate=FeeRate.from_sats_per_vbyte(2),
    )
    created.add_source(source(), lookahead=LOOKAHEAD)
    with created:
        yield created
