# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The signatures of a DLC: adaptor signatures on CETs, and the witnesses.

https://github.com/discreetlogcontracts/dlcspecs/blob/master/ECDSA-adaptor.md

Each party gives the other an adaptor signature of every CET, encrypted
under the outcome's signature point (`btclib_ecc.ecc.ecdsa_adaptor`), so
whoever holds the oracle's attestation decrypts it into an ordinary
signature. The refund transaction is signed outright. All of them spend
the funding output with SIGHASH_ALL.

**Only the agreed transactions are signed.** `sig_hash`, `sign` and
`adaptor_sign` take the `Dlc` and the unsigned transaction, and refuse
any that `btclib_wallet.dlc.transactions` does not build from those
terms: a CET of one of their payouts, or the refund. `verify_adaptor`
answers False for any other. The script code and the funding value come
from the terms.

**Funding inputs are not signed here.** The wallet's signer signs them,
whatever the script; `complete_funding_tx` only places the witnesses it
produced.

**Adaptor signatures encrypt a secret the oracle knows.** The scheme
leaks a Diffie-Hellman key per signature, so it is for a signature point
of an oracle's attestation and for nothing else: see
`btclib_ecc.ecc.ecdsa_adaptor`. A refusal never prints a key or a scalar.
"""

from __future__ import annotations

from collections.abc import Mapping

from btclib.alias import Integer, Octets, Point
from btclib.exceptions import BTClibValueError
from btclib.script.sig_hash import ALL, segwit_v0
from btclib.script.witness import Witness
from btclib.tx import OutPoint, Tx, TxIn
from btclib.utils import assert_type
from btclib_ecc.ecc import dsa, ecdsa_adaptor

from btclib_wallet.dlc.transactions import (
    Dlc,
    build_cet,
    build_funding_tx,
    build_refund_tx,
    funding_script,
)

__all__ = [
    "adaptor_sign",
    "complete_cet",
    "complete_funding_tx",
    "complete_spend",
    "sig_hash",
    "sign",
    "verify_adaptor",
]


def _funding_script(tx: Tx) -> bytes:
    """Return the funding script an unsigned CET or refund carries."""
    assert_type(tx, Tx, "tx")
    if len(tx.vin) != 1 or len(tx.vin[0].script_witness.stack) < 1:
        raise BTClibValueError("not a transaction spending the funding output")
    return tx.vin[0].script_witness.stack[-1]


def _agreed_funding_value(dlc: Dlc, tx: Tx) -> int | None:
    """Return the funding output's value if tx is one the terms agree on."""
    assert_type(tx, Tx, "tx")
    funding_tx, vout = build_funding_tx(dlc)
    total = dlc.offer.collateral + dlc.accept.collateral
    payouts = set(dlc.offer_payouts)
    # a CET's offerer payout is one of its output values, or the rest of
    # the total: a payout under the dust limit has no output
    values = {o.value for o in tx.vout}
    candidates = {p for v in values for p in (v, total - v) if p in payouts}
    agreed = [build_refund_tx(dlc, funding_tx, vout)]
    agreed += [build_cet(dlc, funding_tx, vout, p) for p in candidates]
    return funding_tx.vout[vout].value if tx in agreed else None


def _funding_value(dlc: Dlc, tx: Tx) -> int:
    """Return the funding output's value, if tx is one the terms agree on."""
    value = _agreed_funding_value(dlc, tx)
    if value is None:
        raise BTClibValueError("not a transaction of this DLC's terms")
    return value


def _sig_hash(dlc: Dlc, tx: Tx, value: int) -> bytes:
    """Return the BIP143 SIGHASH_ALL hash of tx's funding input."""
    script = funding_script(dlc.offer.funding_pub_key, dlc.accept.funding_pub_key)
    return segwit_v0(script, tx, 0, ALL, value)


def sig_hash(dlc: Dlc, tx: Tx) -> bytes:
    """Return the BIP143 SIGHASH_ALL hash of the funding input of tx.

    tx is a CET of the terms' payouts or their refund, as built.
    """
    return _sig_hash(dlc, tx, _funding_value(dlc, tx))


def sign(dlc: Dlc, tx: Tx, prv_key: Integer) -> bytes:
    """Return the signature of tx's funding input, DER and SIGHASH_ALL."""
    sig = dsa.sign_(sig_hash(dlc, tx), prv_key)
    return sig.serialize() + bytes([ALL])


def adaptor_sign(
    dlc: Dlc,
    tx: Tx,
    prv_key: Integer,
    sig_point: Point,
    aux: Octets | None = None,
) -> bytes:
    """Return the adaptor signature of tx under the outcome's signature point.

    `aux` is 32 octets of randomness, fresh when absent. Fixing it makes
    the signature repeatable: do it only to check a vector.
    """
    assert_type(sig_point, tuple, "signature point")
    return ecdsa_adaptor.encrypt(sig_hash(dlc, tx), prv_key, sig_point, aux)


def verify_adaptor(
    dlc: Dlc,
    tx: Tx,
    adaptor_sig: Octets,
    pub_key: Octets,
    sig_point: Point,
) -> bool:
    """Return whether adaptor_sig decrypts to pub_key's signature of tx.

    The adaptor signature is encrypted under sig_point. A transaction the
    terms do not agree on answers False: it is a wrong value, not a
    malformed argument.
    """
    assert_type(sig_point, tuple, "signature point")
    value = _agreed_funding_value(dlc, tx)
    if value is None:
        # the signature, key and point are still checked, against a zero
        # digest, so that a malformed one raises as it does for an agreed
        # transaction; the answer is False whatever it says
        ecdsa_adaptor.verify(adaptor_sig, bytes(32), pub_key, sig_point)
        return False
    return ecdsa_adaptor.verify(
        adaptor_sig, _sig_hash(dlc, tx, value), pub_key, sig_point
    )


def complete_spend(tx: Tx, sigs: Mapping[bytes, bytes]) -> Tx:
    """Return tx with the witness of the funding output's 2-of-2 spend.

    `sigs` maps each of the two funding keys to its DER and SIGHASH_ALL
    signature, in either order: the witness orders them as the script
    does. No signature is verified here: a caller verifies the completed
    transaction with `btclib.script.engine.verify_transaction`, and
    Protocol.md rejects the contract when the counterparty's refund
    signature fails.
    """
    script = _funding_script(tx)
    assert_type(sigs, Mapping, "signatures")
    keys = [script[2:35], script[36:69]]
    for key, sig in sigs.items():
        assert_type(key, bytes, "funding key")
        assert_type(sig, bytes, "signature")
    if sorted(sigs) != keys:
        raise BTClibValueError("the signatures are not the funding keys'")
    vin = [
        TxIn(
            tx.vin[0].prev_out,
            tx.vin[0].script_sig,
            tx.vin[0].sequence,
            Witness([b"", *(sigs[k] for k in keys), script]),
        )
    ]
    return Tx(tx.version, tx.lock_time, vin, tx.vout)


def complete_cet(
    cet: Tx,
    *,
    local_pub_key: bytes,
    local_sig: bytes,
    remote_pub_key: bytes,
    remote_adaptor_sig: Octets,
    decryption_key: Integer,
) -> Tx:
    """Return the CET with both signatures placed in its witness.

    The remote signature is the remote adaptor signature decrypted with
    the sum of the oracle signatures' scalars: the decryption key of the
    outcome's signature point. Neither signature is verified here: call
    `verify_adaptor` on the remote adaptor signature first.
    """
    assert_type(local_pub_key, bytes, "local public key")
    assert_type(remote_pub_key, bytes, "remote public key")
    remote_sig = ecdsa_adaptor.decrypt(remote_adaptor_sig, decryption_key)
    return complete_spend(
        cet,
        {
            local_pub_key: local_sig,
            remote_pub_key: remote_sig.serialize() + bytes([ALL]),
        },
    )


def complete_funding_tx(funding_tx: Tx, witnesses: Mapping[OutPoint, Witness]) -> Tx:
    """Return the funding transaction with each input's witness in place."""
    assert_type(funding_tx, Tx, "funding tx")
    assert_type(witnesses, Mapping, "witnesses")
    for witness in witnesses.values():
        assert_type(witness, Witness, "witness")
    spent = [i.prev_out for i in funding_tx.vin]
    if set(witnesses) != set(spent):
        raise BTClibValueError("the witnesses are not those of the inputs")
    vin = [
        TxIn(i.prev_out, i.script_sig, i.sequence, witnesses[i.prev_out])
        for i in funding_tx.vin
    ]
    return Tx(funding_tx.version, funding_tx.lock_time, vin, funding_tx.vout)
