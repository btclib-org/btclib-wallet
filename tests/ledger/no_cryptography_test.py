# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A ledger with `cryptography` out of reach, as on Windows arm64.

`without_cryptography` makes the import fail as an install on Windows
arm64, which leaves the package out, does, so these run whether or not
it is installed. A ledger that was never encrypted works; what needs
the cipher is refused, naming the `encryption` extra.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from btclib.exceptions import BTClibRuntimeError
from btclib.tx import TxOut

from btclib_wallet.ledger import Ledger, crypto
from tests.ledger.conftest import FakeChain, script_of, source, without_cryptography

# a fixed random passphrase; not a credential of anything
_PASSPHRASE = "Zq8v1Lx4Rt7mW2pK9sB3nH6c"  # noqa: S105  # pragma: allowlist secret
_MISSING = r"the cryptography package is missing.*btclib-wallet\[encryption\]"


def _outside() -> TxOut:
    """Return an output paying somebody else."""
    return TxOut(30_000, source("wpkh({}/84h/1h/9h/{}/*)", (0,)).script_pub_key(0, 0))


def test_a_ledger_never_encrypted_signs_and_refuses_to_encrypt(
    ledger: Ledger, chain: FakeChain, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Everything but the encryption works, and `encrypt` names the extra."""
    without_cryptography(monkeypatch)
    chain.mine([chain.pay([TxOut(100_000, script_of(ledger.new_address()))])])
    ledger.sync()
    signed = ledger.sign(ledger.fund([_outside()]).psbt)
    assert all(psbt_in.partial_sigs for psbt_in in signed.inputs)
    with pytest.raises(BTClibRuntimeError, match=_MISSING):
        ledger.encrypt(_PASSPHRASE)
    assert ledger.unlocked_until is None


def test_an_encrypted_file_is_refused_without_it(
    chain: FakeChain, path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Its load and its restore, and the unlock of a ledger loaded before.

    The file is encrypted with `cryptography` in reach, so this one needs
    it installed. A ledger loaded before it went out of reach still
    answers locked.
    """
    pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    monkeypatch.setattr(crypto, "_SCRYPT_N", 2**4)
    with Ledger.create(path, "regtest", chain) as created:
        created.add_source(source())
        created.encrypt(_PASSPHRASE)
        created.backup(tmp_path / "encrypted.bak")
    with Ledger.load(path, "regtest", chain) as loaded:
        without_cryptography(monkeypatch)
        assert loaded.balances().trusted == 0
        with pytest.raises(BTClibRuntimeError, match=_MISSING):
            loaded.unlock_keys(_PASSPHRASE, 10)
        with pytest.raises(BTClibRuntimeError, match=_MISSING):
            loaded.change_passphrase(_PASSPHRASE, "new")
        assert loaded.unlocked_until == 0
    with pytest.raises(BTClibRuntimeError, match=_MISSING):
        Ledger.load(path, "regtest", chain)
    restored = tmp_path / "restored.sqlite"
    with pytest.raises(BTClibRuntimeError, match=_MISSING):
        Ledger.restore(tmp_path / "encrypted.bak", restored, "regtest", chain)
    assert not restored.exists()
