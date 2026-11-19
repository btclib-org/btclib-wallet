# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A `Ledger` spending a coin of a ``tr()`` with a leaf, or paying it change.

`fund` sizes such an input for the keys the ledger holds of it (issue
#1076): its key path where it holds the internal key, its leaf where it
holds the leaf's key alone, and its largest spend where it holds no key,
watch-only or locked. A fee is compared with the transaction the
ledger, or the ledger holding the keys, then signs: the rate is never
underpaid, and where the ledger holds the keys it is paid exactly. Where
no ledger here signs the spend, as of a quorum or a p2wsh script, the
fee is compared with the estimate `miniscript_sizer` gives.
"""

from __future__ import annotations

import re
import threading
from pathlib import Path
from typing import Any

import pytest
from bip32_descriptors.bip32 import rootxprv_from_seed
from bip32_descriptors.bip32.bip32 import derive, pub_keyinfo_from_xkey
from bip32_descriptors.bip32.key_origin import BIP32KeyOrigin
from bip32_descriptors.descriptors import normalized, parse
from btclib.exceptions import BTClibValueError
from btclib.fee import FeeRate, fee_from_vsize
from btclib.network import NETWORKS
from btclib.script import type_and_payload
from btclib.tx import Tx, TxOut
from typing_extensions import override

from btclib_wallet.ledger import Ledger, crypto
from btclib_wallet.ledger import ledger as ledger_module
from btclib_wallet.psbt.psbt import extract_tx, finalize
from btclib_wallet.psbt.psbt_size import miniscript_sizer
from btclib_wallet.psbt_signer import SoftwareSigner
from btclib_wallet.tx_builder import FundedPsbt
from btclib_wallet.wallet import DescriptorWallet
from tests.ledger.conftest import LOOKAHEAD, XPRV, FakeChain, script_of, source

RATE = FeeRate.from_sats_per_vbyte(2)
PASSPHRASE = "WalletPassphrase"  # noqa: S105  # pragma: allowlist secret
# a second master key, whose private key no ledger here holds
XPRV2 = rootxprv_from_seed(bytes(range(32)), NETWORKS["testnet"].bip32_prv)
# the internal key K and a leaf pk(A), A of an account of its own
TR = f"tr({{}}/86h/1h/0h/{{}}/*,pk({XPRV}/86h/1h/5h/0/0))"
WPKH = f"wpkh({XPRV}/84h/1h/0h/{{}}/*)"


def _wallet(receive: str, change: str) -> DescriptorWallet:
    """Return a wallet of `receive` on branch 0 and `change` on branch 1."""
    prv_keys: dict[str, str] = {}
    descriptors = [parse(text, "regtest", prv_keys) for text in (receive, change)]
    return DescriptorWallet(descriptors, prv_keys)


def _held() -> DescriptorWallet:
    """Return the wallet of a ``tr(K,pk(A))``, both keys held."""
    return _wallet(TR.format(XPRV, 0), TR.format(XPRV, 1))


def _watched_key(branch: int, account: int = 0) -> str:
    """Return an account xpub of `XPRV2` on `branch`, as a KEY expression."""
    prv_keys: dict[str, str] = {}
    text = f"tr({XPRV2}/86h/1h/{account}h/{branch}/*)"
    descriptor = parse(text, "regtest", prv_keys)
    text = str(normalized(descriptor, prv_keys))
    match = re.fullmatch(r"tr\((.+)\)(#[a-z0-9]+)?", text)
    assert match is not None
    return match[1]


def _watch_only(wallet: DescriptorWallet) -> DescriptorWallet:
    """Return the wallet with no private key, of the same scripts."""
    watched = ledger_module._watched(wallet, "")
    return DescriptorWallet([parse(text, "regtest") for text in watched.values()])


def _ledger(path: Path, chain: FakeChain, wallet: DescriptorWallet) -> Ledger:
    """Return a ledger of one source over `chain`, at `RATE` for every spend."""
    ledger = Ledger.create(
        path,
        "regtest",
        chain,
        broadcaster=chain,
        fee_estimator=chain,
        relay_fee_reader=chain,
        fallback_fee_rate=RATE,
    )
    ledger.add_source(wallet, lookahead=LOOKAHEAD)
    return ledger


def _paid(chain: FakeChain, ledger: Ledger) -> None:
    """Pay the ledger's next address from outside, and confirm it."""
    chain.mine([chain.pay([TxOut(100_000, script_of(ledger.new_address()))])])
    ledger.sync()


def _outside() -> TxOut:
    """Return an output paying somebody else."""
    other = source("wpkh({}/84h/1h/9h/{}/*)", (0,))
    return TxOut(30_000, other.script_pub_key(0, 0))


def _signed(ledger: Ledger, funded: FundedPsbt) -> Tx:
    """Return the transaction the ledger signs and finalizes of `funded`."""
    return extract_tx(finalize(ledger.sign(funded.psbt)))


def _witnesses(tx: Tx) -> list[list[int]]:
    """Return the size of each witness element of each input."""
    return [[len(item) for item in tx_in.script_witness.stack] for tx_in in tx.vin]


def test_a_coin_whose_internal_key_is_held_is_sized_at_its_key_path(
    chain: FakeChain, path: Path
) -> None:
    """The fee is the rate over what the ledger then signs: one signature.

    The coin is at the second address, at index 1 of source 0.
    """
    with _ledger(path, chain, _held()) as ledger:
        ledger.new_address()
        _paid(chain, ledger)
        funded = ledger.fund([_outside()])
        tx = _signed(ledger, funded)
        assert _witnesses(tx) == [[64]]
        assert funded.fee == fee_from_vsize(tx.vsize, RATE)


def test_a_coin_whose_leaf_key_alone_is_held_is_sized_at_its_leaf(
    chain: FakeChain, path: Path
) -> None:
    """The internal key is an xpub: the ledger signs and pays for the leaf."""
    with _ledger(path, chain, _leaf_only()) as ledger:
        _paid(chain, ledger)
        funded = ledger.fund([_outside()])
        tx = _signed(ledger, funded)
        # the signature, the script <A> OP_CHECKSIG, a control block of a
        # tree of one leaf
        assert _witnesses(tx) == [[64, 34, 33]]
        assert funded.fee == fee_from_vsize(tx.vsize, RATE)


def test_a_watch_only_ledger_sizes_the_largest_spend(
    chain: FakeChain, path: Path
) -> None:
    """A signer outside may take the leaf, so the leaf is what is paid for.

    The ledger holding the keys signs the same coin by its key path, which
    costs less than what was paid.
    """
    with (
        _ledger(path, chain, _held()) as held,
        _ledger(path.with_suffix(".2"), chain, _watch_only(_held())) as watched,
    ):
        _paid(chain, watched)
        held.sync()
        funded = watched.fund([_outside()])
        assert funded.fee == fee_from_vsize(
            funded.psbt.vsize_estimate(miniscript_sizer), RATE
        )
        tx = _signed(held, funded)
        assert _witnesses(tx) == [[64]]
        assert funded.fee > fee_from_vsize(tx.vsize, RATE)


def test_a_script_two_sources_watch_is_sized_for_the_one_holding_its_keys(
    chain: FakeChain, path: Path
) -> None:
    """Source 0 watches the script and source 1 holds its keys: the key path."""
    with _ledger(path, chain, _watch_only(_held())) as ledger:
        ledger.add_source(_held(), lookahead=LOOKAHEAD)
        _paid(chain, ledger)
        funded = ledger.fund([_outside()])
        tx = _signed(ledger, funded)
        assert _witnesses(tx) == [[64]]
        assert funded.fee == fee_from_vsize(tx.vsize, RATE)


def _unlocked(ledger: Ledger, encrypted: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    """Encrypt the ledger and unlock it, where `encrypted` asks for it."""
    if encrypted:
        monkeypatch.setattr(crypto, "_SCRYPT_N", 2**4)
        ledger.encrypt(PASSPHRASE)
        ledger.unlock_keys(PASSPHRASE, 60)


@pytest.mark.parametrize("encrypted", [False, True], ids=["plain", "encrypted"])
def test_two_keys_claiming_one_origin_are_sized_as_the_signer_signs(
    chain: FakeChain, path: Path, monkeypatch: pytest.MonkeyPatch, encrypted: bool
) -> None:
    """K and A both claim deadbeef/86h/1h/0h: the signer keeps A's account.

    A's account derives no K at K's path, so the signer signs the leaf
    alone, and the leaf is what is paid for.
    """
    origin = "[deadbeef/86h/1h/0h]"
    k_account = derive(XPRV, "m/86h/1h/0h")
    a_account = derive(XPRV2, "m/86h/1h/0h")
    receive, change = (
        f"tr({origin}{k_account}/{b}/*,pk({origin}{a_account}/{b}/*))" for b in (0, 1)
    )
    with _ledger(path, chain, _wallet(receive, change)) as ledger:
        _paid(chain, ledger)
        _unlocked(ledger, encrypted, monkeypatch)
        funded = ledger.fund([_outside()])
        tx = _signed(ledger, funded)
        assert _witnesses(tx) == [[64, 34, 33]]
        assert funded.fee == fee_from_vsize(tx.vsize, RATE)


@pytest.mark.parametrize("encrypted", [False, True], ids=["plain", "encrypted"])
def test_a_watched_script_is_sized_for_the_signer_of_its_internal_key(
    chain: FakeChain, path: Path, monkeypatch: pytest.MonkeyPatch, encrypted: bool
) -> None:
    """Source 0 watches tr(K,pk(B)), source 1 holds K's master in tr(K).

    The scripts differ, so the coin is source 0's alone: source 1's
    signer derives K at its origin and signs the key path.
    """
    watched = _watch_only(
        _wallet(
            *(f"tr({XPRV}/86h/1h/0h/{b}/*,pk({_watched_key(b, 1)}))" for b in (0, 1))
        )
    )
    with _ledger(path, chain, watched) as ledger:
        ledger.add_source(
            _wallet(*(f"tr({XPRV}/86h/1h/0h/{b}/*)" for b in (0, 1))),
            lookahead=LOOKAHEAD,
        )
        _paid(chain, ledger)
        _unlocked(ledger, encrypted, monkeypatch)
        funded = ledger.fund([_outside()])
        tx = _signed(ledger, funded)
        assert _witnesses(tx) == [[64]]
        assert funded.fee == fee_from_vsize(tx.vsize, RATE)


def test_a_key_no_account_of_the_signer_starts_is_not_signed_for() -> None:
    """The signer of deadbeef holds 86h/1h/0h: not 49h/1h/0h, of the same."""
    master = bytes.fromhex("deadbeef")
    account = derive(XPRV, "m/86h/1h/0h")
    signer = SoftwareSigner.from_accounts(master, {"m/86h/1h/0h": account})
    x_only = pub_keyinfo_from_xkey(derive(account, [0, 0]))[0][1:]
    held = BIP32KeyOrigin(master, "m/86h/1h/0h/0/0")
    assert ledger_module._signs(signer, x_only, held)
    # another key at the same path, whichever way the two sort
    for other in (bytes(32), b"\xff" * 32):
        assert not ledger_module._signs(signer, other, held)
    elsewhere = BIP32KeyOrigin(master, "m/49h/1h/0h/0/0")
    assert not ledger_module._signs(signer, x_only, elsewhere)
    assert not ledger_module._signs(None, x_only, held)


def test_a_locked_ledger_sizes_the_largest_spend(
    chain: FakeChain, path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Locked, it reads no key; unlocked, the key path it then signs."""
    monkeypatch.setattr(crypto, "_SCRYPT_N", 2**4)
    with _ledger(path, chain, _held()) as ledger:
        _paid(chain, ledger)
        ledger.encrypt(PASSPHRASE)
        locked = ledger.fund([_outside()])
        assert locked.fee == fee_from_vsize(
            locked.psbt.vsize_estimate(miniscript_sizer), RATE
        )
        ledger.unlock_keys(PASSPHRASE, 60)
        unlocked = ledger.fund([_outside()])
        tx = _signed(ledger, unlocked)
        assert _witnesses(tx) == [[64]]
        assert unlocked.fee == fee_from_vsize(tx.vsize, RATE)
        assert locked.fee > unlocked.fee


def _leaf_only() -> DescriptorWallet:
    """Return the wallet of a ``tr(K,pk(A))`` whose key A alone is held."""
    receive, change = (
        f"tr({_watched_key(b)},pk({XPRV}/86h/1h/5h/0/0))" for b in (0, 1)
    )
    return _wallet(receive, change)


@pytest.mark.parametrize(
    "wallet, witnesses",
    [
        (_wallet(*(f"tr({XPRV}/86h/1h/0h/{b}/*)" for b in (0, 1))), [[64]]),
        (_held(), [[64]]),
        (_leaf_only(), [[64, 34, 33]]),
    ],
    ids=["tr(K)", "tr(K,pk(A))", "tr(K,pk(A)), A alone held"],
)
def test_an_unlocked_ledger_sizes_its_keys_without_decrypting_them(
    chain: FakeChain,
    path: Path,
    monkeypatch: pytest.MonkeyPatch,
    wallet: DescriptorWallet,
    witnesses: list[list[int]],
) -> None:
    """`fund` reads the keys `unlock_keys` recorded, and decrypts none."""
    monkeypatch.setattr(crypto, "_SCRYPT_N", 2**4)
    with _ledger(path, chain, wallet) as ledger:
        _paid(chain, ledger)
        ledger.encrypt(PASSPHRASE)
        ledger.unlock_keys(PASSPHRASE, 60)
        decrypted: list[int] = []
        decrypt = ledger._decrypted

        def counted(*args: Any, **kwargs: Any) -> DescriptorWallet:
            decrypted.append(args[1])
            return decrypt(*args, **kwargs)

        monkeypatch.setattr(ledger, "_decrypted", counted)
        funded = ledger.fund([_outside()])
        assert not decrypted
        tx = _signed(ledger, funded)
        assert _witnesses(tx) == witnesses
        assert funded.fee == fee_from_vsize(tx.vsize, RATE)


def test_a_lock_while_funding_does_not_refuse_it(
    chain: FakeChain, path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Another thread locks the ledger as `fund` sizes: it funds all the same.

    The lock lands at the first read of the held keys, or of a source's
    decryption. The keys held when the call started size the input, so
    the fee is the one of the key path the ledger signs once unlocked.
    """
    monkeypatch.setattr(crypto, "_SCRYPT_N", 2**4)
    with _ledger(path, chain, _held()) as ledger:
        _paid(chain, ledger)
        ledger.encrypt(PASSPHRASE)
        ledger.unlock_keys(PASSPHRASE, 60)
        locks: list[threading.Thread] = []

        def locking(name: str) -> Any:
            original = getattr(ledger, name)

            def run(*args: Any, **kwargs: Any) -> Any:
                if not locks:
                    locks.append(threading.Thread(target=ledger.lock_keys))
                    locks[0].start()
                    locks[0].join()
                return original(*args, **kwargs)

            return run

        for name in ("_held_keys", "_decrypted"):
            monkeypatch.setattr(ledger, name, locking(name))
        funded = ledger.fund([_outside()])
        assert locks
        assert ledger.unlocked_until == 0
        monkeypatch.undo()
        monkeypatch.setattr(crypto, "_SCRYPT_N", 2**4)
        ledger.unlock_keys(PASSPHRASE, 60)
        tx = _signed(ledger, funded)
        assert _witnesses(tx) == [[64]]
        assert funded.fee == fee_from_vsize(tx.vsize, RATE)


def test_a_source_added_while_unlocked_is_sized_for_its_keys(
    chain: FakeChain, path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Its keys are recorded as it is encrypted, forgotten at each lock.

    Recorded again at each unlock: the key path while unlocked, the
    largest spend while locked.
    """
    monkeypatch.setattr(crypto, "_SCRYPT_N", 2**4)
    with _ledger(path, chain, _wallet(WPKH.format(0), WPKH.format(1))) as ledger:
        ledger.encrypt(PASSPHRASE)
        ledger.unlock_keys(PASSPHRASE, 60)
        source = ledger.add_source(_held(), lookahead=LOOKAHEAD)
        chain.mine([chain.pay([TxOut(100_000, script_of(ledger.new_address(source)))])])
        ledger.sync()
        for _ in range(2):
            funded = ledger.fund([_outside()])
            tx = _signed(ledger, funded)
            assert _witnesses(tx) == [[64]]
            assert funded.fee == fee_from_vsize(tx.vsize, RATE)
            ledger.lock_keys()
            locked = ledger.fund([_outside()])
            assert locked.fee == fee_from_vsize(
                locked.psbt.vsize_estimate(miniscript_sizer), RATE
            )
            ledger.unlock_keys(PASSPHRASE, 60)


def test_a_source_added_as_the_ledger_locks_is_recorded_at_the_next_unlock(
    chain: FakeChain, path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Another thread locks the ledger once the source's keys are sealed.

    The source is added, its keys unrecorded: the locked ledger sizes
    its largest spend, and once unlocked the key path it signs.
    """
    monkeypatch.setattr(crypto, "_SCRYPT_N", 2**4)
    with _ledger(path, chain, _wallet(WPKH.format(0), WPKH.format(1))) as ledger:
        ledger.encrypt(PASSPHRASE)
        ledger.unlock_keys(PASSPHRASE, 60)
        sealed = ledger._sealed_source

        def locking(*args: Any) -> Any:
            result = sealed(*args)
            thread = threading.Thread(target=ledger.lock_keys)
            thread.start()
            thread.join()
            return result

        monkeypatch.setattr(ledger, "_sealed_source", locking)
        source = ledger.add_source(_held(), lookahead=LOOKAHEAD)
        assert ledger.unlocked_until == 0
        chain.mine([chain.pay([TxOut(100_000, script_of(ledger.new_address(source)))])])
        ledger.sync()
        locked = ledger.fund([_outside()])
        assert locked.fee == fee_from_vsize(
            locked.psbt.vsize_estimate(miniscript_sizer), RATE
        )
        ledger.unlock_keys(PASSPHRASE, 60)
        funded = ledger.fund([_outside()])
        tx = _signed(ledger, funded)
        assert _witnesses(tx) == [[64]]
        assert funded.fee == fee_from_vsize(tx.vsize, RATE)


def test_a_lock_is_not_held_up_by_an_add_source_in_progress(
    chain: FakeChain, path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`add_source` decrypts the sources outside the master key's lock.

    `lock_keys`, in another thread as the first source decrypts, returns
    at once. The source is added all the same, its keys unrecorded: the
    locked ledger sizes its largest spend, and once unlocked the key path.
    """
    monkeypatch.setattr(crypto, "_SCRYPT_N", 2**4)
    with _ledger(path, chain, _wallet(WPKH.format(0), WPKH.format(1))) as ledger:
        ledger.encrypt(PASSPHRASE)
        ledger.unlock_keys(PASSPHRASE, 60)
        decrypt = ledger._decrypted
        held_up: list[bool] = []

        def locking(*args: Any, **kwargs: Any) -> Any:
            thread = threading.Thread(target=ledger.lock_keys)
            thread.start()
            thread.join(timeout=5)
            held_up.append(thread.is_alive())
            return decrypt(*args, **kwargs)

        monkeypatch.setattr(ledger, "_decrypted", locking)
        source = ledger.add_source(_held(), lookahead=LOOKAHEAD)
        # one source decrypted, and the lock not waiting for it
        assert held_up == [False]
        assert ledger.unlocked_until == 0
        monkeypatch.setattr(ledger, "_decrypted", decrypt)
        chain.mine([chain.pay([TxOut(100_000, script_of(ledger.new_address(source)))])])
        ledger.sync()
        locked = ledger.fund([_outside()])
        assert locked.fee == fee_from_vsize(
            locked.psbt.vsize_estimate(miniscript_sizer), RATE
        )
        ledger.unlock_keys(PASSPHRASE, 60)
        funded = ledger.fund([_outside()])
        tx = _signed(ledger, funded)
        assert _witnesses(tx) == [[64]]
        assert funded.fee == fee_from_vsize(tx.vsize, RATE)


def test_a_source_added_while_the_ledger_unlocks_is_recorded(
    chain: FakeChain, path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`add_source` runs as `unlock_keys` decrypts the sources.

    In the ledger's own thread, which its file is bound to, as an
    `unlock_keys` in another thread would let it run. The unlock finds a
    source it did not decrypt, and decrypts them again.
    Source 1 watches tr(K,pk(B)), K at 86h/1h/7h of the master source 0
    holds and names no path under: only source 1's own path, recorded,
    lets the encrypted ledger derive K, and sign for it by the key path.
    """
    monkeypatch.setattr(crypto, "_SCRYPT_N", 2**4)
    master = _wallet(*(f"tr({XPRV}/86h/1h/0h/{b}/*)" for b in (0, 1)))
    watched = _watch_only(
        _wallet(
            *(f"tr({XPRV}/86h/1h/7h/{b}/*,pk({_watched_key(b, 1)}))" for b in (0, 1))
        )
    )
    with _ledger(path, chain, master) as ledger:
        ledger.encrypt(PASSPHRASE)
        build = ledger._decrypted_xpubs
        added: list[int] = []

        def adding(*args: Any, **kwargs: Any) -> Any:
            if not added:
                added.append(ledger.add_source(watched, lookahead=LOOKAHEAD))
            return build(*args, **kwargs)

        monkeypatch.setattr(ledger, "_decrypted_xpubs", adding)
        ledger.unlock_keys(PASSPHRASE, 60)
        (source,) = added
        chain.mine([chain.pay([TxOut(100_000, script_of(ledger.new_address(source)))])])
        ledger.sync()
        funded = ledger.fund([_outside()])
        tx = _signed(ledger, funded)
        assert _witnesses(tx) == [[64]]
        assert funded.fee == fee_from_vsize(tx.vsize, RATE)


class _Checked(dict[int, DescriptorWallet]):
    """Sources whose `keys`, as an unlock checks them, wait for an add.

    The keys are read before the wait, so the unlock finds the sources it
    decrypted; `checking` says it is there, and it waits for `added`, set
    once `add_source` returns, or two seconds where the add waits for the
    unlock.
    """

    def __init__(self, sources: dict[int, DescriptorWallet]) -> None:
        super().__init__(sources)
        self.checking = threading.Event()
        self.added = threading.Event()

    @override
    def keys(self) -> Any:
        keys = set(super().keys())
        self.checking.set()
        self.added.wait(timeout=2)
        return keys


def test_a_source_added_once_an_unlock_checked_the_sources_is_recorded(
    chain: FakeChain, path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`unlock_keys` in another thread finds no source added, then one is.

    `add_source` reads the master key under its lock, so it waits for the
    unlock to set its key, and builds the record again under it: source
    1's path is in it, and the ledger signs K by the key path.
    """
    monkeypatch.setattr(crypto, "_SCRYPT_N", 2**4)
    master = _wallet(*(f"tr({XPRV}/86h/1h/0h/{b}/*)" for b in (0, 1)))
    watched = _watch_only(
        _wallet(
            *(f"tr({XPRV}/86h/1h/7h/{b}/*,pk({_watched_key(b, 1)}))" for b in (0, 1))
        )
    )
    with _ledger(path, chain, master) as ledger:
        ledger.encrypt(PASSPHRASE)
        checked = _Checked(ledger._sources)
        ledger._sources = checked
        unlock = threading.Thread(target=ledger.unlock_keys, args=(PASSPHRASE, 60))
        unlock.start()
        assert checked.checking.wait(timeout=30)
        source = ledger.add_source(watched, lookahead=LOOKAHEAD)
        checked.added.set()
        unlock.join(timeout=30)
        assert not unlock.is_alive()
        assert ledger.unlocked_until
        chain.mine([chain.pay([TxOut(100_000, script_of(ledger.new_address(source)))])])
        ledger.sync()
        funded = ledger.fund([_outside()])
        tx = _signed(ledger, funded)
        assert _witnesses(tx) == [[64]]
        assert funded.fee == fee_from_vsize(tx.vsize, RATE)


def test_change_paid_to_a_tr_with_a_leaf_is_spent_by_its_key_path(
    chain: FakeChain, path: Path
) -> None:
    """The change of one spend is the coin of the next, each at the rate."""
    wallet = _wallet(WPKH.format(0), TR.format(XPRV, 1))
    with _ledger(path, chain, wallet) as ledger:
        _paid(chain, ledger)
        first = ledger.spend([_outside()])
        (change,) = (out for out in first.vout if out != _outside())
        assert type_and_payload(change.script_pub_key.script)[0] == "p2tr"
        chain.mine([first])
        ledger.sync()
        funded = ledger.fund([TxOut(20_000, _outside().script_pub_key)])
        tx = _signed(ledger, funded)
        assert [tx_in.prev_out.tx_id for tx_in in tx.vin] == [first.id]
        assert _witnesses(tx) == [[64]]
        assert funded.fee == fee_from_vsize(tx.vsize, RATE)


def test_a_leaf_no_miniscript_reads_is_refused_unless_the_key_path_is_held(
    chain: FakeChain, path: Path
) -> None:
    """A watch-only ledger refuses the coin; the one holding K spends it."""
    text = "tr({}/86h/1h/0h/{}/*,raw(7551))"
    wallet = _wallet(text.format(XPRV, 0), text.format(XPRV, 1))
    with (
        _ledger(path, chain, wallet) as held,
        _ledger(path.with_suffix(".2"), chain, _watch_only(wallet)) as watched,
    ):
        _paid(chain, watched)
        held.sync()
        with pytest.raises(BTClibValueError, match="no estimate for a taproot"):
            watched.fund([_outside()])
        funded = held.fund([_outside()])
        tx = _signed(held, funded)
        assert _witnesses(tx) == [[64]]
        assert funded.fee == fee_from_vsize(tx.vsize, RATE)


def test_a_quorum_leaf_the_ledger_holds_one_key_of_is_sized_at_its_largest(
    chain: FakeChain, path: Path
) -> None:
    """Its keys satisfy no spend: the leaf is sized for a full quorum."""
    receive, change = (
        f"tr({_watched_key(b)},multi_a(2,{XPRV}/86h/1h/5h/0/0,{_watched_key(b, 1)}))"
        for b in (0, 1)
    )
    with _ledger(path, chain, _wallet(receive, change)) as ledger:
        _paid(chain, ledger)
        funded = ledger.fund([_outside()])
        assert funded.fee == fee_from_vsize(
            funded.psbt.vsize_estimate(miniscript_sizer), RATE
        )


def test_a_p2wsh_miniscript_coin_is_sized_at_its_largest_spend(
    chain: FakeChain, path: Path
) -> None:
    """No taproot input: the ledger's keys are not read, as before."""
    text = f"wsh(and_v(v:pk({XPRV}/84h/1h/2h/{{}}/*),older(10)))"
    with _ledger(path, chain, _wallet(text.format(0), text.format(1))) as ledger:
        _paid(chain, ledger)
        funded = ledger.fund([_outside()])
        assert funded.fee == fee_from_vsize(
            funded.psbt.vsize_estimate(miniscript_sizer), RATE
        )


@pytest.mark.parametrize("encrypted", [False, True], ids=["plain", "encrypted"])
@pytest.mark.parametrize(
    "wallet, witnesses",
    [(_held(), [[64]]), (_leaf_only(), [[64, 34, 33]])],
    ids=["K and A held", "A alone held"],
)
def test_a_bump_is_sized_for_the_keys_the_ledger_signs_for(
    chain: FakeChain,
    path: Path,
    monkeypatch: pytest.MonkeyPatch,
    encrypted: bool,
    wallet: DescriptorWallet,
    witnesses: list[list[int]],
) -> None:
    """`bump_psbt` sizes the replacement as `fund` does: at what is signed."""
    with _ledger(path, chain, wallet) as ledger:
        _paid(chain, ledger)
        _unlocked(ledger, encrypted, monkeypatch)
        spent = ledger.spend([_outside()])
        rate = FeeRate.from_sats_per_vbyte(7)
        bumped = ledger.bump_psbt(spent.id, rate)
        tx = extract_tx(finalize(ledger.sign(bumped.psbt)))
        assert _witnesses(tx) == witnesses
        assert bumped.fee == fee_from_vsize(tx.vsize, rate)
