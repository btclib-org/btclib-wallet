# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A `Ledger`'s encryption at rest, and the key bytes its files keep.

The cases follow Core's test/functional/wallet_encryption.py at
bitcoin/bitcoin@f0de87f040, the v32.1 tag: the refusals before and after
encryption (lines 36-47), a timed unlock (lines 49-56), a wrong
passphrase (line 59), a lock (lines 61-65), a new passphrase (lines
67-72), the timeout's bounds (lines 74-91), passphrases holding NUL
characters (lines 93-104) and a wallet without private keys (lines
106-109).

The files are searched as the measurement on ISS
btclib-org/btclib-wallet#623 searched Core's: every file in the
ledger's directory, for every spelling of every key, after a clean
encryption, after a process killed mid-encryption, after a failed one,
and in a backup.
"""

from __future__ import annotations

import contextlib
import sqlite3
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import ClassVar

import pytest
from btclib.exceptions import BTClibRuntimeError, BTClibTypeError, BTClibValueError
from btclib.fee import FeeRate
from btclib.network import NETWORKS
from btclib.tx import TxOut

from btclib_wallet.bip32 import rootxprv_from_seed
from btclib_wallet.bip32.bip32 import BIP32KeyData
from btclib_wallet.descriptors import parse
from btclib_wallet.ledger import MAX_UNLOCK_TIME, Ledger, TxState, crypto
from btclib_wallet.ledger import ledger as ledger_module
from btclib_wallet.psbt.psbt import Psbt
from btclib_wallet.wallet import DescriptorWallet
from tests.ledger.conftest import (
    LOOKAHEAD,
    XPRV,
    FakeChain,
    script_of,
    source,
    without_cryptography,
)
from tests.secret_free import assert_secret_free, chained, windows

# an install on Windows arm64 leaves `cryptography` out;
# `no_cryptography_test.py` asks what a ledger does without it
pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")

# Core's test passphrase; not a credential of anything
PASSPHRASE = "WalletPassphrase"  # noqa: S105  # pragma: allowlist secret
# a second master key, of a seed of this file's
XPRV2 = rootxprv_from_seed(bytes(range(32)), NETWORKS["testnet"].bip32_prv)
NOW = 1_800_000_000
FALLBACK = FeeRate.from_sats_per_vbyte(2)


class Clock:
    """The two clocks the ledger reads, moved by hand.

    `now` is the wall clock `unlocked_until` reports, and `elapsed` the
    monotonic one the timeout is kept on. `tick` moves both.
    """

    def __init__(self) -> None:
        self.now = NOW
        self.elapsed = 0.0

    def tick(self, seconds: int) -> None:
        """Let `seconds` pass."""
        self.now += seconds
        self.elapsed += seconds


@pytest.fixture(autouse=True)
def cheap_scrypt(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run scrypt at its lowest cost: the cost is not what is tested here."""
    monkeypatch.setattr(crypto, "_SCRYPT_N", 2**4)


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    """Return the clock the ledger reads."""
    fake = Clock()
    monkeypatch.setattr(ledger_module, "_now", lambda: fake.now)
    monkeypatch.setattr(ledger_module, "_monotonic", lambda: fake.elapsed)
    return fake


def _wallet(xprv: str, account: int = 0) -> DescriptorWallet:
    """Return a wallet of a receive and a change branch under `xprv`."""
    prv_keys: dict[str, str] = {}
    descriptors = [
        parse(f"wpkh({xprv}/84h/1h/{account}h/{branch}/*)", "regtest", prv_keys)
        for branch in (0, 1)
    ]
    return DescriptorWallet(descriptors, prv_keys)


def _watch_only() -> DescriptorWallet:
    """Return a wallet with no private key: an account xpub of `XPRV`."""
    wallet = _wallet(XPRV, 3)
    return DescriptorWallet(
        [parse(text, "regtest") for text in _normalized(wallet).values()]
    )


def _normalized(wallet: DescriptorWallet) -> dict[int, str]:
    return ledger_module._watched(wallet)


def _created(path: Path, chain: FakeChain, *wallets: DescriptorWallet) -> Ledger:
    """Return a new ledger over `chain` holding `wallets`."""
    ledger = Ledger.create(
        path,
        "regtest",
        chain,
        broadcaster=chain,
        fee_estimator=chain,
        relay_fee_reader=chain,
        fallback_fee_rate=FALLBACK,
    )
    for wallet in wallets:
        ledger.add_source(wallet, lookahead=LOOKAHEAD)
    return ledger


def _loaded(path: Path, chain: FakeChain) -> Ledger:
    return Ledger.load(
        path,
        "regtest",
        chain,
        broadcaster=chain,
        fee_estimator=chain,
        relay_fee_reader=chain,
        fallback_fee_rate=FALLBACK,
    )


def _three(path: Path, chain: FakeChain) -> Ledger:
    """Return a ledger of three sources holding keys, of two master keys.

    Three, because an encryption of fewer leaves no key byte in this
    file even with `secure_delete` off: SQLite happens to rewrite the
    page they are on.
    """
    return _created(path, chain, _wallet(XPRV), _wallet(XPRV2), _wallet(XPRV, 1))


def _secrets(*xprvs: str) -> list[bytes]:
    """Return every spelling of a key searched for in a file.

    Each piece of the xprv's base58, as the file writes it, and the 32
    bytes of its private key, raw and in hex.
    """
    found: list[bytes] = []
    for xprv in xprvs:
        found += [str(piece).encode() for piece in windows(xprv)]
        key = BIP32KeyData.b58decode(xprv).key[1:]
        found += [key, key.hex().encode()]
    return found


def _key_bytes(directory: Path, secrets: list[bytes]) -> dict[str, int]:
    """Return how many spellings of a key each file in `directory` holds."""
    return {
        path.name: sum(path.read_bytes().count(secret) for secret in secrets)
        for path in sorted(directory.iterdir())
    }


def _funded(ledger: Ledger, chain: FakeChain) -> None:
    """Pay the ledger from outside and confirm it."""
    chain.mine([chain.pay([TxOut(100_000, script_of(ledger.new_address()))])])
    ledger.sync()


def _outside() -> TxOut:
    """Return an output paying somebody else."""
    other = source("wpkh({}/84h/1h/9h/{}/*)", (0,))
    return TxOut(30_000, other.script_pub_key(0, 0))


def _signs(ledger: Ledger) -> bool:
    """Whether the ledger signs a spend of its coin."""
    psbt = ledger.fund([_outside()]).psbt
    signed = ledger.sign(psbt)
    return all(psbt_in.partial_sigs for psbt_in in signed.inputs)


# -- the key bytes in the files --------------------------------------------


def test_an_encrypted_file_and_its_backup_hold_no_key_byte(
    chain: FakeChain, tmp_path: Path
) -> None:
    """After a clean encryption no file holds a key byte, nor a backup."""
    directory = tmp_path / "ledger"
    directory.mkdir()
    path = directory / "ledger.sqlite"
    secrets = _secrets(XPRV, XPRV2)
    with _three(path, chain) as ledger:
        _funded(ledger, chain)
        ledger.spend([_outside()])
        chain.mine(list(chain.mempool.values()))
        ledger.sync()
        before = tmp_path / "before.bak"
        ledger.backup(before)
        # the control: the plain file holds the keys the search looks for
        assert _key_bytes(directory, secrets)["ledger.sqlite"] > 0
        ledger.encrypt(PASSPHRASE)
        assert ledger.unlocked_until == 0
        after = tmp_path / "after.bak"
        ledger.backup(after)
        assert set(_key_bytes(directory, secrets).values()) == {0}
    assert set(_key_bytes(directory, secrets).values()) == {0}
    assert sum(after.read_bytes().count(secret) for secret in secrets) == 0
    # a backup taken before is not encrypted by the encryption after it
    assert sum(before.read_bytes().count(secret) for secret in secrets) > 0


def test_secure_delete_is_what_zeroes_the_keys_replaced(
    chain: FakeChain, tmp_path: Path
) -> None:
    """With `secure_delete` turned off, an encryption leaves key bytes.

    The control of the searches here: they see what a write leaves, and
    the pragma every connection turns on is what clears it.
    """
    secrets = _secrets(XPRV, XPRV2)
    for pragma in ("OFF", "ON"):
        directory = tmp_path / pragma
        directory.mkdir()
        with _three(directory / "ledger.sqlite", chain) as ledger:
            ledger._store._db.execute(f"PRAGMA secure_delete = {pragma}")
            ledger.encrypt(PASSPHRASE)
        left = sum(_key_bytes(directory, secrets).values())
        assert (left > 0) is (pragma == "OFF")


_KILLED = """
import os, signal, sys
from btclib_wallet.ledger import Ledger, crypto

crypto._SCRYPT_N = 2**4
path, marker, passphrase = sys.argv[1:]
ledger = Ledger.load(path, "regtest", None)
kill = getattr(signal, "SIGKILL", signal.SIGTERM)

def trace(statement):
    if statement.startswith(marker):
        os.kill(os.getpid(), kill)

ledger._store._db.set_trace_callback(trace)
ledger.encrypt(passphrase)
os.kill(os.getpid(), kill)
"""


@pytest.mark.parametrize(
    "marker",
    ["INSERT INTO master_key", "UPDATE sources", "COMMIT", "the end"],
)
def test_a_process_killed_mid_encryption_leaves_no_key_once_encrypted(
    chain: FakeChain, tmp_path: Path, marker: str
) -> None:
    """Killed before the commit, the file is plain; after it, it holds no key.

    A process is killed as SQLite starts the statement `marker` opens,
    or once `encrypt` returns. Where the kill came before the commit, the
    next load rolls the journal back and finds the ledger unencrypted,
    and the encryption done again leaves no key byte in any file.
    """
    directory = tmp_path / "ledger"
    directory.mkdir()
    path = directory / "ledger.sqlite"
    secrets = _secrets(XPRV, XPRV2)
    _three(path, chain).close()
    killed = subprocess.run(  # noqa: S603
        [sys.executable, "-c", _KILLED, str(path), marker, PASSPHRASE],
        check=False,
        capture_output=True,
    )
    assert killed.returncode != 0
    left = _key_bytes(directory, secrets)
    with _loaded(path, chain) as ledger:
        if marker == "the end":
            assert ledger.unlocked_until == 0
            assert set(left.values()) == {0}
        else:
            assert ledger.unlocked_until is None
            assert left["ledger.sqlite"] > 0
            ledger.encrypt(PASSPHRASE)
    assert set(_key_bytes(directory, secrets).values()) == {0}


def test_a_failed_encryption_leaves_the_ledger_as_it_was(
    chain: FakeChain, tmp_path: Path
) -> None:
    """A write that fails mid-encryption leaves the file plain, and no copy.

    The second source's rewrite is made to fail, after the first one's:
    the transaction rolls back, the ledger is not encrypted and signs,
    no file holds a key byte more than before, and an encryption once
    the failure is gone leaves none.
    """
    directory = tmp_path / "ledger"
    directory.mkdir()
    path = directory / "ledger.sqlite"
    secrets = _secrets(XPRV, XPRV2)
    with _three(path, chain) as ledger:
        _funded(ledger, chain)
        before = _key_bytes(directory, secrets)
        db = ledger._store._db
        db.execute(
            "CREATE TEMP TRIGGER fail BEFORE UPDATE ON main.sources"
            " WHEN NEW.id = 1 BEGIN SELECT RAISE(ABORT, 'forced'); END"
        )
        with pytest.raises(sqlite3.IntegrityError, match="forced"):
            ledger.encrypt(PASSPHRASE)
        assert _key_bytes(directory, secrets) == before
        assert ledger.unlocked_until is None
        assert _signs(ledger)
        db.execute("DROP TRIGGER fail")
        ledger.encrypt(PASSPHRASE)
    assert set(_key_bytes(directory, secrets).values()) == {0}
    with _loaded(path, chain) as loaded:
        assert loaded.unlocked_until == 0


# -- encrypt ------------------------------------------------------------------


def test_encrypt_refuses_as_core_does(chain: FakeChain, path: Path) -> None:
    """No key, encrypted already, an empty passphrase, in Core's order."""
    with _created(path, chain) as ledger:
        with pytest.raises(BTClibValueError, match="nothing to encrypt"):
            ledger.encrypt("")
        ledger.add_source(_watch_only())
        with pytest.raises(BTClibValueError, match="nothing to encrypt"):
            ledger.encrypt(PASSPHRASE)
        ledger.add_source(_wallet(XPRV, 1))
        with pytest.raises(BTClibValueError, match="the passphrase is empty"):
            ledger.encrypt("")
        with pytest.raises(BTClibTypeError, match="passphrase"):
            ledger.encrypt(b"pass")  # type: ignore[arg-type]
        ledger.encrypt(PASSPHRASE)
        with pytest.raises(BTClibValueError, match="encrypted already"):
            ledger.encrypt("")


def test_a_source_derived_hardened_at_every_index_is_refused(
    chain: FakeChain, path: Path
) -> None:
    """A ``/*h`` needs a key at every index, which a locked ledger lacks."""
    prv_keys: dict[str, str] = {}
    hardened = DescriptorWallet(
        [
            parse(f"wpkh({XPRV}/84h/1h/0h/0/*)", "regtest", prv_keys),
            parse(f"wpkh({XPRV}/84h/1h/0h/1/*h)", "regtest", prv_keys),
        ],
        prv_keys,
    )
    with _created(path, chain, hardened) as ledger:
        with pytest.raises(BTClibValueError, match="a locked ledger cannot watch"):
            ledger.encrypt(PASSPHRASE)
        assert ledger.unlocked_until is None
    with _created(path.with_suffix(".2"), chain, _wallet(XPRV)) as ledger:
        ledger.encrypt(PASSPHRASE)
        ledger.unlock_keys(PASSPHRASE, 60)
        with pytest.raises(BTClibValueError, match="a locked ledger cannot watch"):
            ledger.add_source(hardened)


def test_a_locked_ledger_syncs_answers_and_funds(
    chain: FakeChain, path: Path, clock: Clock
) -> None:
    """Everything but a signature works locked, on the same scripts."""
    with _created(path, chain, _wallet(XPRV), _watch_only()) as ledger:
        _funded(ledger, chain)
        addresses = [ledger.sources[0].address(b, i) for b in (0, 1) for i in (0, 9)]
        ledger.encrypt(PASSPHRASE)
        assert ledger.sources[0].prv_keys is None
        assert addresses == [
            ledger.sources[0].address(b, i) for b in (0, 1) for i in (0, 9)
        ]
    with _loaded(path, chain) as ledger:
        assert ledger.unlocked_until == 0
        assert ledger.sources[0].prv_keys is None
        balance = ledger.balances().trusted
        _funded(ledger, chain)
        assert ledger.balances().trusted == balance + 100_000
        funded = ledger.fund([_outside()])
        with pytest.raises(BTClibValueError, match="the ledger is locked"):
            ledger.sign(funded.psbt)
        ledger.unlock_keys(PASSPHRASE, 60)
        assert _signs(ledger)


def test_a_locked_ledger_refuses_a_spend_before_writing_anything(
    chain: FakeChain, path: Path
) -> None:
    """Nothing is recorded and no change address is handed out."""
    with _created(path, chain, _wallet(XPRV)) as ledger:
        _funded(ledger, chain)
        ledger.encrypt(PASSPHRASE)
        txs = ledger.transactions
        change = ledger.sources[0].address(1, 0)
        with pytest.raises(BTClibValueError, match="the ledger is locked"):
            ledger.spend([_outside()])
        assert ledger.transactions == txs
        assert ledger.new_change_address() == change
        ledger.unlock_keys(PASSPHRASE, 60)
        spent = ledger.spend([_outside()])
        assert ledger.transaction(spent.id).wallet_tx.state is TxState.MEMPOOL


def test_a_source_added_to_an_encrypted_ledger_is_encrypted(
    chain: FakeChain, tmp_path: Path, clock: Clock
) -> None:
    """Refused locked where it holds keys, written encrypted unlocked."""
    directory = tmp_path / "ledger"
    directory.mkdir()
    path = directory / "ledger.sqlite"
    with _created(path, chain, _wallet(XPRV)) as ledger:
        ledger.encrypt(PASSPHRASE)
        with pytest.raises(BTClibValueError, match="the ledger is locked"):
            ledger.add_source(_wallet(XPRV2))
        ledger.add_source(_watch_only())
        ledger.unlock_keys(PASSPHRASE, 60)
        source_id = ledger.add_source(_wallet(XPRV2))
        assert ledger.sources[source_id].prv_keys is None
    assert set(_key_bytes(directory, _secrets(XPRV, XPRV2)).values()) == {0}
    with _loaded(path, chain) as ledger:
        chain.mine([chain.pay([TxOut(70_000, script_of(ledger.new_address(2)))])])
        ledger.sync()
        ledger.unlock_keys(PASSPHRASE, 60)
        assert _signs(ledger)


# -- unlock, lock and the timeout ----------------------------------------------


def test_an_unencrypted_ledger_refuses_the_passphrase_calls(
    chain: FakeChain, path: Path
) -> None:
    """Core's -15 for the three calls that need an encrypted wallet."""
    with _created(path, chain, _wallet(XPRV)) as ledger:
        assert ledger.unlocked_until is None
        with pytest.raises(BTClibValueError, match="not encrypted"):
            ledger.unlock_keys("ff", 1)
        with pytest.raises(BTClibValueError, match="not encrypted"):
            ledger.change_passphrase("ff", "ff")
        with pytest.raises(BTClibValueError, match="not encrypted"):
            ledger.lock_keys()


def test_an_unlock_is_refused_as_core_refuses_it(chain: FakeChain, path: Path) -> None:
    """A negative timeout, an empty passphrase, a wrong one, a bad type."""
    with _created(path, chain, _wallet(XPRV)) as ledger:
        ledger.encrypt(PASSPHRASE)
        with pytest.raises(BTClibValueError, match="negative timeout"):
            ledger.unlock_keys(PASSPHRASE, -10)
        with pytest.raises(BTClibValueError, match="the passphrase is empty"):
            ledger.unlock_keys("", 1)
        with pytest.raises(BTClibValueError, match="the passphrase is wrong"):
            ledger.unlock_keys(PASSPHRASE + "wrong", 10)
        with pytest.raises(BTClibTypeError, match="invalid timeout type"):
            ledger.unlock_keys(PASSPHRASE, 1.5)  # type: ignore[arg-type]
        with pytest.raises(BTClibTypeError, match="passphrase"):
            ledger.unlock_keys(None, 1)  # type: ignore[arg-type]
        with pytest.raises(BTClibValueError, match="not encodable"):
            ledger.unlock_keys("\ud800", 1)
        assert ledger.unlocked_until == 0


def test_the_keys_lock_at_the_timeout(
    chain: FakeChain, path: Path, clock: Clock
) -> None:
    """Signing works until the timeout, and a new unlock sets it anew."""
    with _created(path, chain, _wallet(XPRV)) as ledger:
        _funded(ledger, chain)
        ledger.encrypt(PASSPHRASE)
        ledger.unlock_keys(PASSPHRASE, 2)
        assert ledger.unlocked_until == NOW + 2
        assert _signs(ledger)
        key = ledger._key
        assert key is not None
        clock.tick(2)
        with pytest.raises(BTClibValueError, match="the ledger is locked"):
            ledger.sign(Psbt.from_tx(ledger.fund([_outside()]).psbt.tx))
        assert key == bytearray(32)
        assert ledger.unlocked_until == 0
        ledger.unlock_keys(PASSPHRASE, 0)
        assert ledger.unlocked_until == 0
        ledger.unlock_keys(PASSPHRASE, 10)
        ledger.unlock_keys(PASSPHRASE, 20)
        assert ledger.unlocked_until == NOW + 2 + 20


def test_the_timeout_is_kept_on_the_monotonic_clock(
    chain: FakeChain, path: Path, clock: Clock
) -> None:
    """A jump of the wall clock moves what is reported, not the lock."""
    with _created(path, chain, _wallet(XPRV)) as ledger:
        ledger.encrypt(PASSPHRASE)
        ledger.unlock_keys(PASSPHRASE, 2)
        clock.now += 3600
        assert ledger.unlocked_until == NOW + 2
        assert ledger._key is not None
        clock.now -= 7200
        clock.elapsed += 2
        assert ledger.unlocked_until == 0
        assert ledger._key is None


def _calls(ledger: Ledger, chain: FakeChain, tmp_path: Path) -> dict[str, object]:
    """Return a call of each public member of `ledger`, by its name."""
    info = ledger.transactions[0]
    txid = info.wallet_tx.tx.id
    outpoint = ledger.utxos()[0].outpoint
    psbt = ledger.fund([_outside()]).psbt
    address = ledger.new_address()
    script = script_of(address)
    return {
        "abandon": lambda: ledger.abandon(txid),
        "add_source": lambda: ledger.add_source(_watch_only()),
        "address_groupings": lambda: ledger.address_groupings,
        "addresses_by_label": lambda: ledger.addresses_by_label(""),
        "backup": lambda: ledger.backup(tmp_path / "relocked.bak"),
        "balances": ledger.balances,
        "change_passphrase": lambda: ledger.change_passphrase("wrong", "new"),
        "close": ledger.close,
        "encrypt": lambda: ledger.encrypt("another"),
        "fund": lambda: ledger.fund([_outside()]),
        "label_of": lambda: ledger.label_of(address),
        "labels": ledger.labels,
        "lock": lambda: ledger.lock(outpoint),
        "lock_keys": ledger.lock_keys,
        "locked": lambda: ledger.locked,
        "new_address": ledger.new_address,
        "new_change_address": ledger.new_change_address,
        "position_of": lambda: ledger.position_of(script),
        "received_by_address": lambda: ledger.received_by_address(address),
        "received_by_label": lambda: ledger.received_by_label(""),
        "resubmit": ledger.resubmit,
        "set_label": lambda: ledger.set_label(address, "relocked"),
        "sign": lambda: ledger.sign(psbt),
        "sources": lambda: ledger.sources,
        "spend": lambda: ledger.spend([_outside()]),
        "sync": ledger.sync,
        "tip": lambda: ledger.tip,
        "transaction": lambda: ledger.transaction(txid),
        "transactions": lambda: ledger.transactions,
        "unlock": lambda: ledger.unlock(outpoint),
        "unlock_keys": lambda: ledger.unlock_keys("wrong", 10),
        "unlocked_until": lambda: ledger.unlocked_until,
        "utxos": ledger.utxos,
    }


_CONSTRUCTORS = {"create", "load", "restore"}


def test_every_public_member_relocks_the_keys_once_due(
    chain: FakeChain, path: Path, tmp_path: Path, clock: Clock
) -> None:
    """The first call due zeroes the key, whichever member it is.

    The table is checked against `Ledger`'s public names, so a member
    added without a call here fails this test.
    """
    public = {name for name in dir(Ledger) if not name.startswith("_")}
    with _created(path, chain, _wallet(XPRV)) as ledger:
        _funded(ledger, chain)
        ledger.encrypt(PASSPHRASE)
        assert set(_calls(ledger, chain, tmp_path)) == public - _CONSTRUCTORS
    for name in sorted(public - _CONSTRUCTORS):
        with _loaded(path, chain) as ledger:
            ledger.unlock_keys(PASSPHRASE, 2)
            key = ledger._key
            assert key is not None
            call = _calls(ledger, chain, tmp_path)[name]
            assert ledger._key is key
            clock.tick(2)
            with contextlib.suppress(BTClibValueError):
                call()  # type: ignore[operator]
            assert key == bytearray(32), name
            assert ledger._key is None, name


def test_a_timeout_lapsing_inside_a_spend_does_not_stop_it(
    chain: FakeChain, path: Path, clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only a call from outside relocks: `spend` signs what it funded.

    The timeout lapses while `fund` runs, after `spend` checked it. The
    next call from outside zeroes the key.
    """
    with _created(path, chain, _wallet(XPRV)) as ledger:
        _funded(ledger, chain)
        ledger.encrypt(PASSPHRASE)
        ledger.unlock_keys(PASSPHRASE, 5)
        key = ledger._key
        assert key is not None
        fee_rate = ledger._fee_rate

        def slow(rate: FeeRate | None) -> FeeRate:
            clock.tick(10)
            return fee_rate(rate)

        monkeypatch.setattr(ledger, "_fee_rate", slow)
        tx = ledger.spend([_outside()])
        assert tx.id in chain.mempool
        assert ledger._key is key
        assert ledger.unlocked_until == 0
        assert key == bytearray(32)


def test_a_call_running_in_any_thread_keeps_the_key(
    chain: FakeChain, path: Path, clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The count of calls is exact, and a call in any thread holds the key.

    Threads read a member at once, which loses a count kept without a
    lock on an interpreter without the GIL, and the count ends at 0.
    Then a call blocked in another thread keeps the key past the
    timeout, and the first call after it ends zeroes the key.
    """
    with _created(path, chain, _wallet(XPRV)) as ledger:
        ledger.encrypt(PASSPHRASE)
        ledger.unlock_keys(PASSPHRASE, 10)
        key = ledger._key
        assert key is not None

        def reads() -> None:
            for _ in range(20_000):
                assert ledger.locked == frozenset()

        threads = [threading.Thread(target=reads) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert ledger._running == 0
        assert ledger._key is key

        entered, release = threading.Event(), threading.Event()

        def blocked(txid: bytes) -> None:
            entered.set()
            assert release.wait(timeout=30), "transaction was not released"
            raise BTClibValueError(f"unknown txid: {txid.hex()}")

        def asks() -> None:
            with contextlib.suppress(BTClibValueError):
                ledger.transaction(bytes(32))

        monkeypatch.setattr(ledger, "_held", blocked)
        thread = threading.Thread(target=asks, daemon=True)
        thread.start()
        try:
            assert entered.wait(timeout=30), "transaction never reached the hook"
            clock.tick(10)
            assert ledger.locked == frozenset()
            assert ledger._key is key
        finally:
            release.set()
            thread.join(timeout=30)
        assert not thread.is_alive(), "transaction did not finish"
        assert ledger._running == 0
        assert ledger.unlocked_until == 0
        assert key == bytearray(32)


@pytest.mark.parametrize(
    "where, relock, refused",
    [
        ("_opened", "lock_keys", True),
        ("_opened", "unlock_keys", True),
        ("_updated", "lock_keys", True),
        ("_updated", "unlock_keys", False),
    ],
)
def test_keys_locked_from_another_thread_mid_sign_refuse_it_as_locked(
    chain: FakeChain,
    path: Path,
    monkeypatch: pytest.MonkeyPatch,
    where: str,
    relock: str,
    refused: bool,
) -> None:
    """`sign` in a thread, the keys locked or unlocked again in another.

    `_updated` runs before `sign` reads the key, `_opened` as it decrypts
    with it. A key zeroed under it, or none left, is refused as a ledger
    locked during the call, not as a damaged file or a psbt left
    unsigned, and holds neither the keys nor the passphrase; a key
    unlocked again before it is read signs.
    """
    with _created(path, chain, _wallet(XPRV)) as ledger:
        _funded(ledger, chain)
        ledger.encrypt(PASSPHRASE)
        ledger.unlock_keys(PASSPHRASE, 600)
        assert ledger._key is not None
        secrets: list[str | bytes] = [XPRV, PASSPHRASE, bytes(ledger._key)]
        secrets.append(BIP32KeyData.b58decode(XPRV).key[1:])
        psbt = ledger.fund([_outside()]).psbt
        entered, release = threading.Event(), threading.Event()
        target: object = ledger_module if where == "_opened" else ledger
        real = getattr(target, where)

        def held(*args: object) -> object:
            if threading.current_thread() is not threading.main_thread():
                entered.set()
                assert release.wait(timeout=30), "sign was not released"
            return real(*args)

        monkeypatch.setattr(target, where, held)
        outcomes: list[object] = []

        def signs() -> None:
            try:
                outcomes.append(ledger.sign(psbt))
            except BTClibValueError as refusal:
                outcomes.append(refusal)

        thread = threading.Thread(target=signs, daemon=True)
        thread.start()
        try:
            assert entered.wait(timeout=30), "sign never reached the hook"
            if relock == "lock_keys":
                ledger.lock_keys()
            else:
                ledger.unlock_keys(PASSPHRASE, 600)
        finally:
            release.set()
            thread.join(timeout=30)
        assert not thread.is_alive(), "sign did not finish"
        if refused:
            (refusal,) = outcomes
            assert isinstance(refusal, BTClibValueError)
            assert str(refusal) == ledger_module._LOCKED_DURING
            assert_secret_free(refusal, secrets)
        else:
            (signed,) = outcomes
            assert isinstance(signed, Psbt)
            assert all(psbt_in.partial_sigs for psbt_in in signed.inputs)


@pytest.mark.parametrize("relock", ["lock_keys", "close"])
def test_keys_locked_from_another_thread_mid_add_source_refuse_it(
    chain: FakeChain, path: Path, monkeypatch: pytest.MonkeyPatch, relock: str
) -> None:
    """`add_source` encrypting keys, the keys locked in another thread.

    The ledger's own thread runs `add_source`, since SQLite refuses its
    connection to any other, and `close` from another thread zeroes the
    key before SQLite refuses it. What was encrypted may be under zeros,
    so the call is refused as a ledger locked during it, holds neither
    the keys nor the passphrase, and writes nothing: the file unlocks and
    holds one source.
    """
    with _created(path, chain, _wallet(XPRV)) as ledger:
        ledger.encrypt(PASSPHRASE)
        ledger.unlock_keys(PASSPHRASE, 600)
        assert ledger._key is not None
        secrets: list[str | bytes] = [
            XPRV,
            XPRV2,
            PASSPHRASE,
            bytes(ledger._key),
            *(BIP32KeyData.b58decode(xprv).key[1:] for xprv in (XPRV, XPRV2)),
        ]
        real = crypto._sealed
        relocked: list[BaseException | None] = []

        def relocks() -> None:
            try:
                getattr(ledger, relock)()
            except sqlite3.ProgrammingError as refusal:
                relocked.append(refusal)
            else:
                relocked.append(None)

        def held(key: bytearray, plaintext: bytes | bytearray, aad: bytes) -> bytes:
            thread = threading.Thread(target=relocks, daemon=True)
            thread.start()
            thread.join(timeout=30)
            assert not thread.is_alive(), f"{relock} did not finish"
            return real(key, plaintext, aad)

        monkeypatch.setattr(ledger_module, "_sealed", held)
        with pytest.raises(BTClibValueError) as refusal:
            ledger.add_source(_wallet(XPRV2))
        assert str(refusal.value) == ledger_module._LOCKED_DURING
        assert_secret_free(refusal.value, secrets)
        (outcome,) = relocked
        assert (outcome is None) == (relock == "lock_keys")
    with _loaded(path, chain) as ledger:
        ledger.unlock_keys(PASSPHRASE, 60)
        assert len(ledger.sources) == 1


def test_the_timeout_is_capped_as_cores(
    chain: FakeChain, path: Path, clock: Clock
) -> None:
    """Below the cap as asked, above it at the cap."""
    with _created(path, chain, _wallet(XPRV)) as ledger:
        ledger.encrypt(PASSPHRASE)
        ledger.unlock_keys(PASSPHRASE, MAX_UNLOCK_TIME - 600)
        assert ledger.unlocked_until == NOW + MAX_UNLOCK_TIME - 600
        ledger.unlock_keys(PASSPHRASE, MAX_UNLOCK_TIME + 1000)
        assert ledger.unlocked_until == NOW + MAX_UNLOCK_TIME


def test_a_lock_zeroes_the_master_key(
    chain: FakeChain, path: Path, clock: Clock
) -> None:
    """`lock_keys` and `close` zero the buffer the master key is in."""
    with _created(path, chain, _wallet(XPRV)) as ledger:
        _funded(ledger, chain)
        ledger.encrypt(PASSPHRASE)
        ledger.unlock_keys(PASSPHRASE, 60)
        key = ledger._key
        assert key is not None
        assert key != bytearray(32)
        ledger.lock_keys()
        assert key == bytearray(32)
        assert ledger.unlocked_until == 0
        with pytest.raises(BTClibValueError, match="the ledger is locked"):
            _signs(ledger)
        ledger.lock_keys()
        ledger.unlock_keys(PASSPHRASE, 60)
        key = ledger._key
        assert key is not None
    assert key == bytearray(32)


def test_a_ledger_loaded_before_the_encryption_writes_no_plain_key(
    chain: FakeChain, tmp_path: Path
) -> None:
    """Another ledger on the file adds no key in plain text, nor encrypts again.

    The file keeps no byte of the key it was refused, and loads.
    """
    directory = tmp_path / "ledger"
    directory.mkdir()
    path = directory / "ledger.sqlite"
    with _created(path, chain, _wallet(XPRV)) as ledger, _loaded(path, chain) as other:
        ledger.encrypt(PASSPHRASE)
        with pytest.raises(BTClibValueError, match="no key is written in plain"):
            other.add_source(_wallet(XPRV2))
        with pytest.raises(BTClibValueError, match="encrypted already"):
            other.encrypt("another")
        other.add_source(_watch_only())
    assert set(_key_bytes(directory, _secrets(XPRV, XPRV2)).values()) == {0}
    with _loaded(path, chain) as loaded:
        assert len(loaded.sources) == 2
        loaded.unlock_keys(PASSPHRASE, 10)


def test_an_encryption_missing_a_source_another_ledger_added_is_refused(
    chain: FakeChain, path: Path
) -> None:
    """A source with keys this ledger does not hold would stay plain."""
    with _created(path, chain, _wallet(XPRV)) as ledger, _loaded(path, chain) as other:
        other.add_source(_wallet(XPRV2))
        with pytest.raises(BTClibValueError, match="source 1 of the ledger file"):
            ledger.encrypt(PASSPHRASE)
        assert ledger.unlocked_until is None
    with _loaded(path, chain) as loaded:
        assert loaded.unlocked_until is None
        loaded.encrypt(PASSPHRASE)


def test_two_ledgers_on_one_file_unlock_each_its_own(
    chain: FakeChain, path: Path, clock: Clock
) -> None:
    """The keys unlocked are the process's, held by one ledger."""
    with _created(path, chain, _wallet(XPRV)) as ledger:
        _funded(ledger, chain)
        ledger.encrypt(PASSPHRASE)
        with _loaded(path, chain) as other:
            ledger.unlock_keys(PASSPHRASE, 60)
            assert other.unlocked_until == 0
            assert _signs(ledger)


# -- change_passphrase --------------------------------------------------------


def test_a_new_passphrase_replaces_the_old_one(
    chain: FakeChain, path: Path, clock: Clock
) -> None:
    """The old one is wrong after, and locked or unlocked stays so."""
    with _created(path, chain, _wallet(XPRV)) as ledger:
        _funded(ledger, chain)
        ledger.encrypt(PASSPHRASE)
        with pytest.raises(BTClibValueError, match="the passphrase is empty"):
            ledger.change_passphrase("", "ff")
        with pytest.raises(BTClibValueError, match="the passphrase is empty"):
            ledger.change_passphrase(PASSPHRASE, "")
        with pytest.raises(BTClibValueError, match="the passphrase is wrong"):
            ledger.change_passphrase("ff", "new")
        with pytest.raises(BTClibTypeError, match="new"):
            ledger.change_passphrase(PASSPHRASE, b"new")  # type: ignore[arg-type]
        ledger.change_passphrase(PASSPHRASE, "second")
        assert ledger.unlocked_until == 0
        ledger.unlock_keys("second", 60)
        ledger.change_passphrase("second", "third")
        assert ledger.unlocked_until == NOW + 60
        assert _signs(ledger)
    with _loaded(path, chain) as ledger:
        for wrong in (PASSPHRASE, "second"):
            with pytest.raises(BTClibValueError, match="the passphrase is wrong"):
                ledger.unlock_keys(wrong, 10)
        ledger.unlock_keys("third", 10)
        assert _signs(ledger)


def test_a_refused_passphrase_change_locks_the_ledger(
    chain: FakeChain, path: Path, clock: Clock
) -> None:
    """Core's `ChangeWalletPassphrase` locks before it reads the old one.

    An empty passphrase is refused before that, and locks nothing.
    """
    with _created(path, chain, _wallet(XPRV)) as ledger:
        ledger.encrypt(PASSPHRASE)
        for old, new in (("wrong", "new"), (PASSPHRASE, UNENCODABLE)):
            ledger.unlock_keys(PASSPHRASE, 60)
            key = ledger._key
            assert key is not None
            with pytest.raises(BTClibValueError, match="wrong|not encodable"):
                ledger.change_passphrase(old, new)
            assert ledger.unlocked_until == 0
            assert key == bytearray(32)
        ledger.unlock_keys(PASSPHRASE, 60)
        with pytest.raises(BTClibValueError, match="the passphrase is empty"):
            ledger.change_passphrase("", "new")
        assert ledger.unlocked_until == NOW + 60
        ledger.change_passphrase(PASSPHRASE, "new")
        assert ledger.unlocked_until == NOW + 60


# a fixed random passphrase, as `assert_secret_free` asks, with a lone
# surrogate UTF-8 cannot encode
UNENCODABLE = "q7R2v9L4mX8tK3pZ6w1J \ud800 5N0s7B4h2G9c8F1k"


def test_an_unencodable_passphrase_is_refused_holding_no_secret(
    chain: FakeChain, path: Path
) -> None:
    """The refusal neither chains nor keeps as context the encoding error.

    A UnicodeEncodeError holds the whole string it failed on.
    """
    with _created(path, chain, _wallet(XPRV)) as ledger:
        calls: list[Callable[[], object]] = [lambda: ledger.encrypt(UNENCODABLE)]
        for call in calls:
            with pytest.raises(BTClibValueError, match="not encodable") as refused:
                call()
            assert_secret_free(refused.value, [UNENCODABLE])
        ledger.encrypt(PASSPHRASE)
        calls = [
            lambda: ledger.unlock_keys(UNENCODABLE, 10),
            lambda: ledger.change_passphrase(UNENCODABLE, "new"),
            lambda: ledger.change_passphrase(PASSPHRASE, UNENCODABLE),
        ]
        for call in calls:
            with pytest.raises(BTClibValueError, match="not encodable") as refused:
                call()
            assert refused.value.__context__ is None
            assert_secret_free(refused.value, [UNENCODABLE])


# fixed random passphrases, the right one and a wrong one; not credentials
SECRET = "Zq8v1Lx4Rt7mW2pK9sB3nH6c"  # noqa: S105  # pragma: allowlist secret
WRONG = "Gh5Tz2Qw8Lm4Xv7Pk1Rs9Bn3"  # pragma: allowlist secret


def _hardened(xprv: str) -> DescriptorWallet:
    """Return a wallet deriving hardened at every index, as ``/*h`` does."""
    prv_keys: dict[str, str] = {}
    descriptor = parse(f"wpkh({xprv}/84h/1h/0h/0/*h)", "regtest", prv_keys)
    return DescriptorWallet([descriptor], prv_keys)


def test_every_refusal_a_secret_reaches_holds_none(
    chain: FakeChain, tmp_path: Path
) -> None:
    """Each refusal where a key or a passphrase is at hand holds neither.

    The refusals of `encrypt`, `add_source`, `unlock_keys` and
    `change_passphrase` that a key or a passphrase reaches, `cryptography`
    missing among them; the load and the restore of a file holding plain
    keys beside a master key, and of an encrypted file without
    `cryptography`; and the load of a file not encrypted whose plain keys
    sit beside a ciphertext that is no blob, or that no master key
    decrypts. A passphrase UTF-8
    cannot encode is the test above's. Fed both xprvs, their raw private
    keys, and the passphrase right and wrong. `assert_secret_free` walks
    every cause and context, a context `from None` hides included.
    """
    secrets: list[str | bytes] = [XPRV, XPRV2, SECRET, WRONG]
    secrets += [BIP32KeyData.b58decode(xprv).key[1:] for xprv in (XPRV, XPRV2)]
    refusals: list[BaseException] = []
    errors = (BTClibRuntimeError, BTClibTypeError, BTClibValueError)

    def refused(call: Callable[[], object], err_msg: str) -> None:
        with pytest.raises(errors, match=err_msg) as e:
            call()
        refusals.append(e.value)

    def without_scrypt(call: Callable[[], object]) -> None:
        with pytest.MonkeyPatch.context() as patched:
            patched.setattr(crypto, "_HASHLIB_HAS_SCRYPT", False)
            refused(call, "hashlib.scrypt is missing")

    def no_cryptography(call: Callable[[], object]) -> None:
        with pytest.MonkeyPatch.context() as patched:
            without_cryptography(patched)
            refused(call, r"install btclib-wallet\[encryption\]")

    prv_keys: dict[str, str] = {}
    descriptor = parse(f"wpkh({XPRV2}/84h/1h/0h/0/*)", "testnet", prv_keys)
    testnet = DescriptorWallet([descriptor], prv_keys)

    path = tmp_path / "watch-only.sqlite"
    with _created(path, chain, _watch_only()) as ledger:
        refused(lambda: ledger.encrypt(SECRET), "nothing to encrypt")
        refused(lambda: ledger.unlock_keys(SECRET, 10), "not encrypted")
        refused(lambda: ledger.change_passphrase(SECRET, WRONG), "not encrypted")
    path = tmp_path / "missing.sqlite"
    with _created(path, chain, _wallet(XPRV)) as ledger, _loaded(path, chain) as other:
        refused(lambda: ledger.encrypt(""), "the passphrase is empty")
        refused(lambda: ledger.encrypt(SECRET.encode()), "passphrase")  # type: ignore[arg-type]
        without_scrypt(lambda: ledger.encrypt(SECRET))
        no_cryptography(lambda: ledger.encrypt(SECRET))
        other.add_source(_wallet(XPRV2))
        refused(lambda: ledger.encrypt(SECRET), "holds keys this ledger does not")
    path = tmp_path / "hardened.sqlite"
    with _created(path, chain, _wallet(XPRV), _hardened(XPRV2)) as ledger:
        refused(lambda: ledger.encrypt(SECRET), "a locked ledger cannot watch")
        # raised `from None`: the context walked is the parser's refusal
        assert len(list(chained(refusals[-1]))) == 2
    path = tmp_path / "encrypted.sqlite"
    with _created(path, chain, _wallet(XPRV)) as ledger, _loaded(path, chain) as stale:
        ledger.encrypt(SECRET)
        refused(lambda: ledger.encrypt(WRONG), "the ledger is encrypted already")
        refused(lambda: stale.encrypt(WRONG), "the ledger file is encrypted already")
        names = [type(e).__name__ for e in chained(refusals[-1])]
        assert names == ["BTClibValueError", "IntegrityError"]
        refused(lambda: stale.add_source(_wallet(XPRV2)), "no key is written in plain")
        refused(lambda: ledger.add_source(_wallet(XPRV2)), "the ledger is locked")
        refused(lambda: ledger.add_source(XPRV2), "invalid wallet type")  # type: ignore[arg-type]
        refused(
            lambda: ledger.add_source(_wallet(XPRV2), lookahead=-1),
            "negative lookahead",
        )
        refused(
            lambda: ledger.add_source(_wallet(XPRV2), birth_height=-1),
            "negative birth_height",
        )
        refused(lambda: ledger.add_source(testnet), "a testnet wallet")
        refused(lambda: ledger.unlock_keys(WRONG, 10), "the passphrase is wrong")
        refused(lambda: ledger.unlock_keys("", 10), "the passphrase is empty")
        refused(lambda: ledger.unlock_keys(SECRET, -1), "negative timeout")
        refused(lambda: ledger.unlock_keys(WRONG, SECRET), "invalid timeout type")  # type: ignore[arg-type]
        refused(lambda: ledger.unlock_keys(SECRET.encode(), 10), "passphrase")  # type: ignore[arg-type]
        without_scrypt(lambda: ledger.unlock_keys(SECRET, 10))
        refused(lambda: ledger.change_passphrase(WRONG, SECRET), "passphrase is wrong")
        refused(lambda: ledger.change_passphrase("", WRONG), "the passphrase is empty")
        refused(lambda: ledger.change_passphrase(SECRET, ""), "the passphrase is empty")
        refused(lambda: ledger.change_passphrase(SECRET.encode(), WRONG), "old")  # type: ignore[arg-type]
        refused(lambda: ledger.change_passphrase(SECRET, WRONG.encode()), "new")  # type: ignore[arg-type]
        without_scrypt(lambda: ledger.change_passphrase(SECRET, WRONG))
        ledger.unlock_keys(SECRET, 60)
        refused(lambda: ledger.add_source(_hardened(XPRV2)), "cannot watch")
    encrypted = _encrypted(path)
    flipped = encrypted[:-1] + bytes([encrypted[-1] ^ 1])
    _damaged(path, "UPDATE sources SET encrypted = ?", flipped)
    with _loaded(path, chain) as ledger:
        refused(lambda: ledger.unlock_keys(SECRET, 10), "keys do not decrypt")
        names = [type(e).__name__ for e in chained(refusals[-1])]
        assert names == ["BTClibValueError", "_WrongKeyError", "InvalidTag"]
    path = tmp_path / "raced.sqlite"
    with _created(path, chain, _wallet(XPRV)) as ledger:
        ledger.encrypt(SECRET)
        with _loaded(path, chain) as other, pytest.MonkeyPatch.context() as patched:
            written = ledger._store.set_master_key

            def raced(old: crypto._MasterKey, new: crypto._MasterKey) -> None:
                other.change_passphrase(SECRET, WRONG)
                written(old, new)

            patched.setattr(ledger._store, "set_master_key", raced)
            refused(
                lambda: ledger.change_passphrase(SECRET, WRONG),
                "changed by another ledger",
            )
        ledger.backup(tmp_path / "raced.bak")
        no_cryptography(lambda: ledger.unlock_keys(WRONG, 10))
        no_cryptography(lambda: ledger.change_passphrase(WRONG, SECRET))
    no_cryptography(lambda: _loaded(path, chain))
    no_cryptography(
        lambda: Ledger.restore(
            tmp_path / "raced.bak", tmp_path / "raced-copy.sqlite", "regtest", chain
        )
    )
    path = tmp_path / "short.sqlite"
    with _created(path, chain, _wallet(XPRV)) as ledger:
        ledger.encrypt(SECRET)
        short = crypto._master_key(SECRET, bytearray(31))
        _damaged(
            path,
            "UPDATE master_key SET salt = ?, encrypted = ?",
            short.salt,
            short.encrypted,
        )
        refused(lambda: ledger.unlock_keys(SECRET, 10), "no 32 bytes")
        refused(lambda: ledger.change_passphrase(SECRET, WRONG), "no 32 bytes")
        for statement, err_msg in (
            ("UPDATE master_key SET kdf = 'pbkdf2'", "unknown kdf"),
            ("UPDATE master_key SET kdf = 'scrypt', n = 'n'", "a malformed master key"),
            ("UPDATE master_key SET n = 3", "outside what this release writes"),
        ):
            _damaged(path, statement)
            refused(lambda: ledger.unlock_keys(SECRET, 10), err_msg)
            refused(lambda: ledger.change_passphrase(SECRET, WRONG), err_msg)
        _damaged(path, "DELETE FROM master_key")
        refused(lambda: ledger.unlock_keys(SECRET, 10), "its master key is gone")
        refused(lambda: ledger.change_passphrase(SECRET, WRONG), "master key is gone")
    path = tmp_path / "both.sqlite"
    with _created(path, chain, _wallet(XPRV)) as ledger:
        db = sqlite3.connect(path)
        (prv_keys,) = db.execute("SELECT prv_keys FROM sources").fetchone()
        db.close()
        ledger.encrypt(SECRET)
        _damaged(path, "UPDATE sources SET prv_keys = ?", prv_keys)
        ledger.backup(tmp_path / "both.bak")
    refused(lambda: _loaded(path, chain), "plain in an encrypted file")
    refused(
        lambda: Ledger.restore(
            tmp_path / "both.bak", tmp_path / "restored.sqlite", "regtest", chain
        ),
        "plain in an encrypted file",
    )
    # a file not encrypted, its plain keys beside a ciphertext
    for value, err_msg in (
        ("'text'", "source 0's encrypted keys are no blob"),
        ("x'00'", "source 0's keys have no master key"),
    ):
        path = tmp_path / f"plain-{len(refusals)}.sqlite"
        _created(path, chain, _wallet(XPRV)).close()
        _damaged(path, f"UPDATE sources SET encrypted = {value}")  # noqa: S608
        refused(lambda: _loaded(path, chain), err_msg)  # noqa: B023
    for refusal in refusals:
        assert_secret_free(refusal, secrets)


def test_a_passphrase_holding_nul_characters_is_read_whole(
    chain: FakeChain, path: Path, clock: Clock
) -> None:
    """Neither the part before a NUL nor one more NUL unlocks."""
    with_nulls = "Phrase\0With\0Nulls"
    with _created(path, chain, _wallet(XPRV)) as ledger:
        _funded(ledger, chain)
        ledger.encrypt(PASSPHRASE)
        ledger.change_passphrase(PASSPHRASE, with_nulls)
        for wrong in (with_nulls.partition("\0")[0], with_nulls + "\0"):
            with pytest.raises(BTClibValueError, match="the passphrase is wrong"):
                ledger.unlock_keys(wrong, 10)
            with pytest.raises(BTClibValueError, match="the passphrase is wrong"):
                ledger.change_passphrase(wrong, "abc")
        ledger.unlock_keys(with_nulls, 10)
        assert _signs(ledger)


# -- what the file holds -----------------------------------------------------


def _damaged(path: Path, statement: str, *parameters: object) -> None:
    db = sqlite3.connect(path)
    with db:
        db.execute(statement, parameters)
    db.close()


def _encrypted(path: Path) -> bytes:
    db = sqlite3.connect(path)
    (encrypted,) = db.execute("SELECT encrypted FROM sources").fetchone()
    db.close()
    return bytes(encrypted)


def test_a_damaged_ciphertext_is_told_from_a_wrong_passphrase(
    chain: FakeChain, path: Path, clock: Clock
) -> None:
    """A source's ciphertext that fails under the right master key."""
    with _created(path, chain, _wallet(XPRV)) as ledger:
        ledger.encrypt(PASSPHRASE)
    encrypted = _encrypted(path)
    flipped = encrypted[:40] + bytes([encrypted[40] ^ 1]) + encrypted[41:]
    _damaged(path, "UPDATE sources SET encrypted = ?", flipped)
    with _loaded(path, chain) as ledger:
        with pytest.raises(BTClibValueError, match="source 0's keys do not decrypt"):
            ledger.unlock_keys(PASSPHRASE, 10)
        assert ledger.unlocked_until == 0
    _damaged(path, "UPDATE sources SET encrypted = x'00'")
    with (
        _loaded(path, chain) as ledger,
        pytest.raises(BTClibValueError, match="source 0's keys do not decrypt"),
    ):
        ledger.unlock_keys(PASSPHRASE, 10)
    # a damaged master key fails as a wrong passphrase does: the tag
    # tells neither from the other
    _damaged(path, "UPDATE master_key SET encrypted = zeroblob(60)")
    with (
        _loaded(path, chain) as ledger,
        pytest.raises(BTClibValueError, match="the passphrase is wrong"),
    ):
        ledger.unlock_keys(PASSPHRASE, 10)


class _Recorded(bytearray):
    """A bytearray `crypto` makes, kept to be read after."""

    made: ClassVar[list[bytearray]] = []

    def __init__(self, *args: object) -> None:
        super().__init__(*args)
        _Recorded.made.append(self)


def _left(call: Callable[[], object], secret: bytes) -> int:
    """Return how many buffers `crypto` made in `call` still hold `secret`."""
    _Recorded.made = []
    with pytest.MonkeyPatch.context() as patched:
        patched.setattr(crypto, "bytearray", _Recorded, raising=False)
        with pytest.raises(BTClibValueError):
            call()
    assert _Recorded.made
    return sum(secret in bytes(buffer) for buffer in _Recorded.made)


def test_a_tag_that_fails_leaves_no_plaintext_in_a_buffer(
    chain: FakeChain, path: Path
) -> None:
    """`decrypt_into` writes the plaintext before it checks the tag.

    A source's ciphertext and the master key, each with its last byte
    flipped, decrypted under the right key.
    """
    with _created(path, chain, _wallet(XPRV)) as ledger:
        ledger.encrypt(PASSPHRASE)
        ledger.unlock_keys(PASSPHRASE, 10)
        assert ledger._key is not None
        master_key = bytes(ledger._key)
    encrypted = _encrypted(path)
    _damaged(
        path,
        "UPDATE sources SET encrypted = ?",
        encrypted[:-1] + bytes([encrypted[-1] ^ 1]),
    )
    with _loaded(path, chain) as ledger:
        call = lambda: ledger.unlock_keys(PASSPHRASE, 10)  # noqa: E731
        assert _left(call, XPRV.encode()) == 0
    db = sqlite3.connect(path)
    (encrypted,) = db.execute("SELECT encrypted FROM master_key").fetchone()
    db.close()
    flipped = encrypted[:-1] + bytes([encrypted[-1] ^ 1])
    _damaged(path, "UPDATE master_key SET encrypted = ?", flipped)
    with _loaded(path, chain) as ledger:
        call = lambda: ledger.unlock_keys(PASSPHRASE, 10)  # noqa: E731
        assert _left(call, master_key) == 0


def test_an_unlock_failing_any_way_zeroes_the_key(
    chain: FakeChain, path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Not only a refusal: an interrupt while the sources decrypt too."""
    with _created(path, chain, _wallet(XPRV)) as ledger:
        ledger.encrypt(PASSPHRASE)
        keys: list[bytearray] = []
        unlocked = crypto._unlocked

        def kept(passphrase: str, master_key: crypto._MasterKey) -> bytearray:
            key = unlocked(passphrase, master_key)
            assert key is not None
            keys.append(key)
            return key

        def interrupted(*args: object) -> None:
            raise KeyboardInterrupt

        monkeypatch.setattr(ledger_module, "_unlocked", kept)
        monkeypatch.setattr(ledger, "_decrypted", interrupted)
        with pytest.raises(KeyboardInterrupt):
            ledger.unlock_keys(PASSPHRASE, 10)
        assert keys == [bytearray(32)]
        assert ledger._key is None


def test_a_passphrase_another_ledger_changed_is_the_files(
    chain: FakeChain, path: Path
) -> None:
    """Each unlock and change reads the master key the file holds now.

    A change written over one this ledger did not read is refused.
    """
    with _created(path, chain, _wallet(XPRV)) as ledger:
        ledger.encrypt(PASSPHRASE)
        with _loaded(path, chain) as other:
            stale = other._master_key
            assert stale is not None
            ledger.change_passphrase(PASSPHRASE, "second")
            with pytest.raises(BTClibValueError, match="the passphrase is wrong"):
                other.unlock_keys(PASSPHRASE, 10)
            with pytest.raises(BTClibValueError, match="the passphrase is wrong"):
                other.change_passphrase(PASSPHRASE, "third")
            other.unlock_keys("second", 10)
            current = other._master_key
            assert current is not None
            with pytest.raises(BTClibValueError, match="changed by another ledger"):
                other._store.set_master_key(stale, current)
            other.change_passphrase("second", "third")
        with pytest.raises(BTClibValueError, match="the passphrase is wrong"):
            ledger.unlock_keys("second", 10)
        ledger.unlock_keys("third", 10)
        _damaged(path, "DELETE FROM master_key")
        with pytest.raises(BTClibValueError, match="its master key is gone"):
            ledger.unlock_keys("third", 10)


@pytest.mark.parametrize(
    "statement, err_msg",
    [
        ("DELETE FROM master_key", "source 0's keys have no master key"),
        ("UPDATE master_key SET kdf = 'pbkdf2'", "unknown kdf 'pbkdf2'"),
        (
            'UPDATE sources SET encrypted = NULL, prv_keys = \'{"a": "b"}\'',
            "source 0's keys are plain in an encrypted file",
        ),
        (
            'UPDATE sources SET prv_keys = \'{"a": "b"}\'',
            "source 0's keys are plain in an encrypted file",
        ),
        ("UPDATE master_key SET salt = 'salt'", "a malformed master key"),
        ("UPDATE master_key SET n = 'n'", "a malformed master key"),
        (
            "UPDATE sources SET encrypted = 'text'",
            "source 0's encrypted keys are no blob",
        ),
    ],
)
def test_a_malformed_encryption_is_refused_at_the_load(
    chain: FakeChain, path: Path, statement: str, err_msg: str
) -> None:
    """What `store` reads of the encryption is checked as it is read."""
    with _created(path, chain, _wallet(XPRV)) as ledger:
        ledger.encrypt(PASSPHRASE)
    _damaged(path, statement)
    with pytest.raises(BTClibValueError, match=err_msg):
        _loaded(path, chain)


def test_plain_keys_beside_their_ciphertext_are_refused_at_a_restore(
    chain: FakeChain, path: Path, tmp_path: Path
) -> None:
    """A backup holding both is refused too: no key is handed out plain."""
    with _created(path, chain, _wallet(XPRV)) as ledger:
        db = sqlite3.connect(path)
        (prv_keys,) = db.execute("SELECT prv_keys FROM sources").fetchone()
        db.close()
        ledger.encrypt(PASSPHRASE)
        _damaged(path, "UPDATE sources SET prv_keys = ?", prv_keys)
        ledger.backup(tmp_path / "both.bak")
    with pytest.raises(BTClibValueError, match="plain in an encrypted file"):
        Ledger.restore(
            tmp_path / "both.bak", tmp_path / "restored.sqlite", "regtest", chain
        )


@pytest.mark.parametrize(
    "column, value",
    [("n", 3), ("n", 1), ("n", 2**30), ("r", 0), ("r", 9), ("p", 0), ("p", 2)],
)
def test_a_cost_above_what_this_release_writes_is_refused(
    chain: FakeChain, path: Path, column: str, value: int
) -> None:
    """A crafted file cannot make an unlock run scrypt at any cost it names.

    Refused at the load, before scrypt runs: N no power of 2 from 2 to
    `crypto._SCRYPT_N`, r and p outside 1 to `_SCRYPT_R` and `_SCRYPT_P`.
    """
    with _created(path, chain, _wallet(XPRV)) as ledger:
        ledger.encrypt(PASSPHRASE)
    _damaged(path, f"UPDATE master_key SET {column} = {value}")  # noqa: S608
    with pytest.raises(BTClibValueError, match="outside what this release writes"):
        _loaded(path, chain)


def test_a_master_key_of_another_size_is_refused() -> None:
    """The passphrase decrypts it, and it is no 32 bytes."""
    master_key = crypto._master_key(PASSPHRASE, bytearray(31))
    with pytest.raises(BTClibValueError, match="the master key is no 32 bytes"):
        crypto._unlocked(PASSPHRASE, master_key)


def test_a_master_keys_repr_holds_neither_salt_nor_ciphertext() -> None:
    """Its repr and its str show scrypt's cost, and leave the rest out."""
    master_key = crypto._master_key(PASSPHRASE, bytearray(32))
    for text in (repr(master_key), str(master_key)):
        assert f"n={master_key.n}" in text
        for value in (master_key.salt, master_key.encrypted):
            assert repr(value) not in text
            assert value.hex() not in text
        assert "salt" not in text
        assert "encrypted" not in text


def test_without_scrypt_encryption_is_refused(
    chain: FakeChain, path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Where the interpreter's OpenSSL lacks scrypt, as `bip38` refuses."""
    monkeypatch.setattr(crypto, "_HASHLIB_HAS_SCRYPT", False)
    with _created(path, chain, _wallet(XPRV)) as ledger:
        with pytest.raises(BTClibRuntimeError, match="hashlib.scrypt is missing"):
            ledger.encrypt(PASSPHRASE)
        assert ledger.unlocked_until is None


def test_a_new_passphrase_costs_what_crypto_says(
    chain: FakeChain, path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The file holds scrypt's cost, and the clock is the system's."""
    monkeypatch.undo()
    with _created(path, chain, _wallet(XPRV)) as ledger:
        ledger.encrypt(PASSPHRASE)
        master_key = ledger._store.master_key()
        assert master_key is not None
        assert (master_key.n, master_key.r, master_key.p) == (2**17, 8, 1)
        ledger.unlock_keys(PASSPHRASE, 1000)
        until = ledger.unlocked_until
        assert until is not None
        assert abs(until - 1000 - time.time()) < 60
