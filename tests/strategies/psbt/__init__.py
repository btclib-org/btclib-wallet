# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Structurally valid PSBTs, including Taproot and MuSig2 metadata.

These are codec inputs, not signed spends: a signature has the wire
shape its field requires, without asserting that it signs the transaction.
The transaction strategy is copied from the locked btclib release.
"""

from copy import deepcopy

from btclib_ecc.curves import bytes_from_point, mult
from hypothesis import strategies as st

from btclib_wallet.bip32 import BIP32KeyOrigin
from btclib_wallet.psbt import Psbt, PsbtIn, PsbtOut
from tests.strategies import TXS

_OCTETS = st.binary(max_size=300)
_HASH = st.binary(min_size=32, max_size=32)
_ORIGINS = st.builds(
    BIP32KeyOrigin,
    st.binary(min_size=4, max_size=4),
    st.lists(st.integers(0, 0xFFFFFFFF), max_size=5),
)
_KEYS = st.integers(1, 32).map(lambda k: bytes_from_point(mult(k)))
# R is a point's x-coordinate, so a parser that checks it (BIP340) reads
# the field; s and the sighash byte are drawn freely
_SCHNORR = st.tuples(_KEYS, _HASH).map(lambda pair: pair[0][1:] + pair[1])
_SIGNATURES = st.one_of(
    _SCHNORR,
    st.tuples(_SCHNORR, st.sampled_from([1, 2, 3, 0x81, 0x82, 0x83])).map(
        lambda pair: pair[0] + bytes([pair[1]])
    ),
)
# 0xfc names a proprietary field. Its identifier length and subtype are
# encoded even when the identifier is empty (BIP174's proprietary key).
_UNKNOWN = st.dictionaries(
    st.binary(max_size=8).map(lambda tail: b"\xfc\x00\x00" + tail),
    _OCTETS,
    max_size=3,
)


@st.composite
def psbts(
    draw: st.DrawFn,
    version: int,
    *,
    taproot: bool = False,
    musig2: bool = False,
) -> Psbt:
    """Draw a v0 or v2 PSBT with independent optional metadata families."""
    transactions = TXS
    if version == 2:
        # Psbt's v2 model uses an empty script as an absent output field.
        # Keep those transactions in the v0 draws rather than asking that
        # model to represent an output it refuses to construct.
        transactions = transactions.filter(
            lambda tx: all(output.script_pub_key.script for output in tx.vout)
        )
    psbt = Psbt.from_tx(deepcopy(draw(transactions)))
    psbt.version = version
    psbt.unknown = draw(_UNKNOWN)
    if version == 2:
        psbt.tx_modifiable = draw(st.one_of(st.none(), st.integers(0, 255)))
    maps: list[PsbtIn | PsbtOut] = [*psbt.inputs, *psbt.outputs]
    for item in maps:
        item.unknown = draw(_UNKNOWN)
        if taproot:
            pub_key = draw(_KEYS)
            leaf_hashes = draw(st.lists(_HASH, max_size=3))
            item.taproot_internal_key = pub_key[1:]
            item.taproot_hd_key_paths = {pub_key[1:]: (leaf_hashes, draw(_ORIGINS))}
            if isinstance(item, PsbtOut):
                item.taproot_tree = [(0, 0xC0, draw(_OCTETS))]
        if musig2:
            aggregate = draw(_KEYS)
            participants = draw(st.lists(_KEYS, min_size=1, max_size=3))
            item.musig2_participant_pub_keys = {aggregate: participants}
    for psbt_in in psbt.inputs:
        if taproot:
            psbt_in.taproot_merkle_root = draw(_HASH)
            psbt_in.taproot_key_spend_signature = draw(_SIGNATURES)
            psbt_in.taproot_script_spend_signatures = {
                draw(_KEYS)[1:] + draw(_HASH): draw(_SIGNATURES)
            }
            control = bytes([draw(st.sampled_from([0xC0, 0xC1]))])
            control += draw(_KEYS)[1:]
            control += b"".join(draw(st.lists(_HASH, max_size=3)))
            psbt_in.taproot_leaf_scripts = {control: (draw(_OCTETS), 0xC0)}
        if musig2:
            aggregate, participants = next(
                iter(psbt_in.musig2_participant_pub_keys.items())
            )
            session = participants[0] + aggregate
            session += draw(st.one_of(st.just(b""), _HASH))
            psbt_in.musig2_pub_nonces = {session: draw(_KEYS) + draw(_KEYS)}
            psbt_in.musig2_partial_sigs = {session: draw(_HASH)}
    psbt.assert_valid()
    return psbt
