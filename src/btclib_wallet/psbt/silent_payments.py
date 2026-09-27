# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The BIP375 roles: sending a silent payment through a psbt.

https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki

`btclib_wallet.psbt.psbt_in` and `btclib_wallet.psbt.psbt_out` carry BIP375's
six fields; this is what the two roles BIP375 adds *do* with them, and it is a
module rather than a function for the reason `btclib_wallet.psbt.musig2` is: a
role is a sequence of steps different parties take at different times.

**Why it matters more than a signature does.** A silent payment output
script is derived, not signed: get it wrong and the transaction is still
consensus-valid, so it confirms and the money is gone. The shares and the
BIP374 proofs are what make that derivation checkable by somebody holding
none of the keys -- and the Transaction Extractor is where the check has
to happen, being the last party before the bytes go on the wire.

The Signer's side, in the order BIP375 puts it:

- `set_input_share` writes an ECDH share and its proof for one input the
  Signer holds the key of; `set_global_share` writes the one pair that
  stands for every eligible input, which a Signer holding all the keys
  may do instead.
- `assert_shares_as_valid` is what a Signer does with the shares it did
  *not* write: every proof verified against the key of the input it
  covers, or against the sum of them for a global one.
- `set_output_scripts` computes what the recipients are paid, once every
  eligible input is covered, and clears the two modifiable flags -- the
  scripts depend on the input set, so nothing may be added afterwards.

`assert_as_valid` is the Extractor's, and it is the four checks BIP375's
own validator publishes, in its order: the fields, then the share
coverage and the proofs, then which inputs are allowed to be there at
all, then the output scripts recomputed and compared.

`btclib_wallet.psbt.psbt.sign` and `btclib_wallet.psbt.psbt.extract_tx`
run the checks of their own role whenever an output carries
PSBT_OUT_SP_V0_INFO: `_assert_signable` and `_assert_extractable` are
what each asks. `btclib_wallet.psbt_signer.request_signatures` asks
`_assert_signable` too, before a signer outside the process sees the psbt.

**What a psbt input's public key is, and why it needs its own reader.**
`btclib_wallet.silent_payments.pub_key_from_input` reads it off a *signed*
input, from the witness or the scriptSig. An unsigned input has neither,
and BIP375 says where to look instead: the Updater "should add a
PSBT_IN_BIP32_DERIVATION for any p2wpkh, p2sh-p2wpkh, or p2pkh input so
the public key is available for creating the ecdh_shared_secret when the
private key is not known". `input_pub_key` is that reader, and it answers
None for an input BIP352 does not count -- a taproot NUMS internal key, a
p2sh wrapping anything but p2wpkh, a script type off the list.

**Which inputs count is decided by the script each one spends**, and not
by whether a key was found: the recipient sums the key of every input its
script type counts, so an input whose key the psbt does not carry is not
left out of the sum but refused. And nothing the psbt says about an input
is taken on its word -- a derivation key, a redeem script, a NUMS internal
key, a final scriptSig or witness each count only once checked against the
spent script, `_input_eligibility` saying how.

**The share is not the shared secret**, which is the thing in BIP375
easiest to get wrong: `a*B_scan` carries no input hash, and BIP352's
shared secret is `input_hash*a*B_scan`. So the Extractor multiplies the
share by the input hash, and the input hash needs the *sum of the public
keys* of the eligible inputs -- which is why reading those keys is the
first thing here and not an aside.

**The k of an output** is BIP375's own rule and not BIP352's ordering: it
counts per scan key, over the outputs in index order. That is what the
BIP's vectors and its reference validator do and *not* what its prose
says, which asks for the codes to be sorted lexicographically;
`_ordered_sp_outputs` is where the discrepancy is documented, and
`tests/psbt/silent_payments_test.py` says which of the vectors pins it.
"""

from __future__ import annotations

from collections.abc import Sequence

from btclib.alias import Integer, Octets, Point
from btclib.curves import (
    bytes_from_point,
    mult,
    point_from_octets,
    point_from_pub_key,
    scalar_from_prv_key,
    secp256k1,
)
from btclib.ecc import dleq
from btclib.ecc.ssa import point_from_bip340pub_key
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160
from btclib.script import serialize
from btclib.script.script_pub_key import (
    is_p2pkh,
    is_p2sh,
    is_p2tr,
    is_p2wpkh,
)
from btclib.script.sig_hash import ALL
from btclib.script.taproot import check_output_pubkey, output_pubkey_from_merkle_root

from btclib_wallet import silent_payments as sp
from btclib_wallet.psbt.psbt import (
    INPUTS_MODIFIABLE,
    OUTPUTS_MODIFIABLE,
    Psbt,
    _prev_out,
)
from btclib_wallet.psbt.psbt_in import PsbtIn
from btclib_wallet.psbt.psbt_out import PsbtOut
from btclib_wallet.psbt.psbt_utils import SP_SCAN_KEY_SIZE

__all__ = [
    "assert_as_valid",
    "assert_eligibility_as_valid",
    "assert_output_scripts_as_valid",
    "assert_shares_as_valid",
    "eligible_pub_keys",
    "input_pub_key",
    "output_scripts",
    "set_global_share",
    "set_input_share",
    "set_output_scripts",
    "shared_secret_from_share",
]

# the highest witness version an input may spend while a silent payment
# output is present. Above it the spent script is one this protocol
# version has no rule for, and BIP352 skips such a transaction rather
# than guess -- so a sender must not build one
_MAX_WITNESS_VERSION = 1

# OP_1, which a version 1 witness program starts with: the versions run
# OP_1..OP_16 as 0x51..0x60, so a first byte above this is a version above 1
_OP_1 = 0x51

# the push opcodes of a scriptSig: OP_0 and the direct pushes run up to
# OP_PUSHDATA4, the PUSHDATA ones reading a length of 1, 2 or 4 bytes
_OP_PUSHDATA1 = 0x4C
_OP_PUSHDATA4 = 0x4E
# OP_1NEGATE, which with OP_1..OP_16 pushes a number and no data
_OP_1NEGATE = 0x4F

# BIP341's first byte of an annex, the witness element a spend may carry
# above its control block
_ANNEX_PREFIX = 0x50

# the two sizes of a SEC public key: BIP352 counts the compressed one and
# skips an input spent with the other
_COMPRESSED_SIZE = 33
_UNCOMPRESSED_SIZE = 65

# whether BIP352 counts an input, and the key it counts it with where the
# psbt carries one the spent script commits to
_Eligibility = tuple[bool, Point | None]
_INELIGIBLE: _Eligibility = (False, None)


def _witness_version(script: bytes) -> int | None:
    """Return the witness version of a program, or None if it is none.

    The shape and not the length, which is deliberate: what this answers
    is whether a version is above 1, and a v2-or-later program of a length
    no BIP defines is still an input BIP352 has no rule for.
    """
    if len(script) < 2 or script[1] != len(script) - 2:
        return None
    if script[0] == 0:
        return 0
    if _OP_1 <= script[0] <= _OP_1 + 15:
        return script[0] - _OP_1 + 1
    return None


def _script_pub_key(psbt_in: PsbtIn) -> bytes:
    """Return the script_pub_key of the output an input spends, or b""."""
    prev_out = _prev_out(psbt_in)
    return b"" if prev_out is None else prev_out.script_pub_key.script


def _witness_stack(psbt_in: PsbtIn) -> list[bytes]:
    """Return the final witness stack, BIP341's annex popped if present."""
    stack = list(psbt_in.final_script_witness.stack)
    if len(stack) > 1 and stack[-1][:1] == bytes([_ANNEX_PREFIX]):
        stack.pop()
    return stack


def _key_candidates(psbt_in: PsbtIn, *, script_sig_windows: bool) -> list[bytes]:
    """Return every string the psbt offers as the key of a single-key input.

    The key data of PSBT_IN_BIP32_DERIVATION, and the last element of the
    final witness. With `script_sig_windows`, every 33- and 65-byte window
    of the final scriptSig too, BIP352's own reading of a p2pkh spend,
    whose scriptSig a third party can pad. None of them is trusted:
    `_committed_key` keeps the one the spent script commits to.
    """
    candidates = list(psbt_in.hd_key_paths)
    stack = _witness_stack(psbt_in)
    if stack:
        candidates.append(stack[-1])
    if script_sig_windows:
        script_sig = psbt_in.final_script_sig
        for size in (_COMPRESSED_SIZE, _UNCOMPRESSED_SIZE):
            candidates += [
                script_sig[j : j + size] for j in range(len(script_sig) - size + 1)
            ]
    return candidates


def _committed_key(key_hash: bytes, candidates: list[bytes]) -> _Eligibility:
    """Return what the key a script commits to by its hash says of the input.

    The candidate whose hash160 is the one in the script, and no other: a
    key the psbt names but the script does not commit to is a key nothing
    binds to the input, and a share proved against it proves nothing about
    what the recipient will sum. A compressed key is the input's key; an
    uncompressed one is an input BIP352 skips; none found is an input
    BIP352 counts whose key this psbt does not carry.
    """
    committed = sorted(c for c in candidates if hash160(c) == key_hash)
    for candidate in committed:
        if len(candidate) == _COMPRESSED_SIZE:
            try:
                return True, point_from_octets(candidate, secp256k1)
            except ValueError:
                continue
    if any(len(c) == _UNCOMPRESSED_SIZE for c in committed):
        return _INELIGIBLE
    return True, None


def _last_push(script: bytes) -> bytes | None:
    """Return the data of a push-only script's last push, or None.

    BIP16's reading of a p2sh scriptSig: it must be push-only, and its last
    push is the redeem script. A script with an opcode that is no push, or
    one that ends inside a push, has no redeem script to read.
    """
    pushed = None
    i = 0
    while i < len(script):
        op = script[i]
        i += 1
        if op <= _OP_PUSHDATA4:
            if op < _OP_PUSHDATA1:
                size = op
            else:
                width = 1 << (op - _OP_PUSHDATA1)
                size = int.from_bytes(script[i : i + width], "little")
                i += width
            if i + size > len(script):
                return None
            pushed = script[i : i + size]
            i += size
        elif op == _OP_1NEGATE:
            pushed = b"\x81"
        elif _OP_1 <= op <= _OP_1 + 15:
            pushed = bytes([op - _OP_1 + 1])
        else:
            return None
    return pushed


def _redeem_script(psbt_in: PsbtIn, script_hash: bytes) -> bytes | None:
    """Return the redeem script a p2sh input spends, if the psbt carries it.

    PSBT_IN_REDEEM_SCRIPT, or the last push of the final scriptSig, which
    is where BIP16 puts it whatever it wraps; either only where it hashes
    to the script_pub_key.
    """
    candidates = [psbt_in.redeem_script]
    if psbt_in.final_script_sig:
        last = _last_push(psbt_in.final_script_sig)
        if last is not None:
            candidates.append(last)
    for candidate in candidates:
        if candidate and hash160(candidate) == script_hash:
            return candidate
    return None


def _is_proven_nums(psbt_in: PsbtIn, output_key: bytes) -> bool:
    """Answer whether the output's internal key is proven to be NUMS_H.

    BIP352 skips a taproot input whose internal key is BIP341's NUMS
    point, which has no key path. The psbt's word for it is believed only
    with a proof against the output key: PSBT_IN_TAP_INTERNAL_KEY tweaked
    by PSBT_IN_TAP_MERKLE_ROOT, or a control block -- of a
    PSBT_IN_TAP_LEAF_SCRIPT, or of the final witness -- that proves its
    leaf. A claim without one proves nothing: the input is then counted,
    and its key is the output key, which is bound to it by construction.
    """
    if psbt_in.taproot_internal_key == sp.NUMS_H:
        tweaked, _ = output_pubkey_from_merkle_root(
            sp.NUMS_H, psbt_in.taproot_merkle_root
        )
        if tweaked == output_key:
            return True
    leaves = [
        (script, control)
        for control, (script, _) in psbt_in.taproot_leaf_scripts.items()
    ]
    stack = _witness_stack(psbt_in)
    if len(stack) > 1:
        leaves.append((stack[-2], stack[-1]))
    for script, control in leaves:
        if control[1:33] != sp.NUMS_H:
            continue
        try:
            if check_output_pubkey(output_key, script, control):
                return True
        except ValueError:
            continue
    return False


def _input_eligibility(psbt_in: PsbtIn) -> _Eligibility:
    """Return whether BIP352 counts one psbt input, and its key if found.

    Decided by the script the input spends, BIP352's four types, and by
    the two exclusions that are not the type: a taproot output whose
    internal key is NUMS_H, and a p2sh that wraps anything but p2wpkh.
    Every claim the psbt makes towards the answer -- a derivation key, a
    redeem script, an internal key, the final scriptSig and witness -- is
    checked against that script before it counts, so that a claim cannot
    take a counted input out of the sum. A final scriptSig or witness most
    of all: consensus has not checked it yet, and whoever wrote it can
    replace it after the other Signers signed.

    A p2sh input whose redeem script the psbt does not carry is counted
    and has no key: BIP352 may count it, and the answer is the psbt's to
    give, not a default's.
    """
    script = _script_pub_key(psbt_in)
    if is_p2tr(script):
        return _taproot_eligibility(psbt_in, script[2:])
    if is_p2pkh(script):
        candidates = _key_candidates(psbt_in, script_sig_windows=True)
        return _committed_key(script[3:23], candidates)
    program = script
    if is_p2sh(script):
        redeem_script = _redeem_script(psbt_in, script[2:22])
        if redeem_script is None:
            return True, None
        # counted only where it wraps a p2wpkh, and read as that p2wpkh
        program = redeem_script
    if is_p2wpkh(program):
        candidates = _key_candidates(psbt_in, script_sig_windows=False)
        return _committed_key(program[2:], candidates)
    return _INELIGIBLE


def _taproot_eligibility(psbt_in: PsbtIn, output_key: bytes) -> _Eligibility:
    """Return what BIP352 makes of a taproot input: its output key, or skip.

    Skipped only where NUMS_H is proven to be the internal key; an output
    key that is no x coordinate is counted and keyless.
    """
    if _is_proven_nums(psbt_in, output_key):
        return _INELIGIBLE
    try:
        return True, point_from_bip340pub_key(output_key, secp256k1)
    except ValueError:
        return True, None


def _no_key_error(i: int) -> BTClibValueError:
    """Return the refusal of a counted input whose key the psbt lacks."""
    err_msg = f"input {i}: BIP352 counts it and the psbt carries no public key "
    err_msg += "the script it spends commits to; BIP375 asks an Updater for "
    err_msg += "PSBT_IN_BIP32_DERIVATION so that there is one"
    return BTClibValueError(err_msg)


def input_pub_key(psbt_in: PsbtIn) -> Point | None:
    """Return the public key of one psbt input, or None if it has none.

    A taproot input's key is the output key the script_pub_key carries:
    it is what the recipient sums, script path or not, and the psbt need
    not say anything for it to be readable. Every other eligible kind
    keeps its key in the key data of PSBT_IN_BIP32_DERIVATION, which is
    what BIP375 asks an Updater to add for exactly this, or in the final
    scripts of an input already finalized -- `PsbtIn.serialize` drops the
    derivation then, so a psbt that crossed the wire after the Finalizer
    carries the key there or nowhere.

    Only a key the spent script commits to is answered, the lowest such
    where there is more than one. None is both an input BIP352 does not
    count and a counted one whose key the psbt does not carry;
    `eligible_pub_keys` is what tells the two apart.
    """
    return _input_eligibility(psbt_in)[1]


def _eligible_keys(psbt: Psbt) -> dict[int, Point | None]:
    """Return every input BIP352 counts, by index, with its key if found."""
    eligible = {}
    for i, psbt_in in enumerate(psbt.inputs):
        counted, pub_key = _input_eligibility(psbt_in)
        if counted:
            eligible[i] = pub_key
    return eligible


def eligible_pub_keys(psbt: Psbt) -> dict[int, Point]:
    """Return the public key of every input BIP352 counts, by index.

    The index is kept because the per-input shares are filed per input: a
    coverage rule that answered "how many" rather than "which" could not
    name the input whose share is missing.

    A counted input whose key the psbt does not carry is refused rather
    than left out: the recipient sums every counted input's key, so a sum
    of the others derives a script nobody scans for.
    """
    keys = {}
    for i, pub_key in _eligible_keys(psbt).items():
        if pub_key is None:
            raise _no_key_error(i)
        keys[i] = pub_key
    return keys


def _scan_keys(psbt: Psbt) -> list[bytes]:
    """Return the scan key of every silent payment output, deduplicated."""
    seen: dict[bytes, None] = {}
    for psbt_out in psbt.outputs:
        if psbt_out.sp_v0_info:
            seen[psbt_out.sp_v0_info[:SP_SCAN_KEY_SIZE]] = None
    return list(seen)


def _share_and_sum(psbt: Psbt, scan_key: bytes) -> tuple[bytes, Point] | None:
    """Return the share standing for every eligible input, and their sum.

    The global share where there is one, else the sum of the per-input
    shares of the eligible inputs -- which is what makes the two
    interchangeable downstream: `a_1*B + a_2*B` is `(a_1 + a_2)*B`, so a
    transaction whose signers each contributed one share derives the same
    outputs as one whose single signer contributed the lot.

    None when there is nothing to derive from: no share at all, or no
    eligible input to take a public key from. A counted input whose key
    the psbt does not carry is refused, by `eligible_pub_keys`, once there
    is a share to derive from.
    """
    eligible = _eligible_keys(psbt)
    share = psbt.sp_ecdh_shares.get(scan_key)
    if share is None:
        shares = [
            psbt.inputs[i].sp_ecdh_shares[scan_key]
            for i in eligible
            if scan_key in psbt.inputs[i].sp_ecdh_shares
        ]
        if not shares:
            return None
        share = bytes_from_point(sp.pub_key_sum(shares), secp256k1)
    if not eligible:
        return None
    return share, sp.pub_key_sum(list(eligible_pub_keys(psbt).values()))


def shared_secret_from_share(psbt: Psbt, share: Octets, A_sum: Point) -> Point:
    """Return BIP352's shared secret from a BIP375 share.

    The step the two BIPs do not share a name for, and the one worth
    spelling out: the psbt carries `a*B_scan`, with no input hash in it,
    where BIP352's secret is `input_hash*a*B_scan`. So the share is
    multiplied by the input hash here, and the input hash is what binds
    the derivation to this transaction's smallest outpoint -- which is why
    the psbt is an argument and the share alone would not do.
    """
    outpoints = [psbt_in.prev_out for psbt_in in psbt.inputs]
    return sp.shared_secret(sp.input_hash(outpoints, A_sum), share)


def _ordered_sp_outputs(psbt: Psbt) -> list[tuple[int, PsbtOut]]:
    """Return the silent payment outputs in the order their k follows.

    Output index order, per scan key -- which is **not** what BIP375's
    prose says, and the discrepancy is upstream's rather than a choice
    made here. The BIP says: "If there are multiple silent payment codes
    with the same scan key, sort the codes lexicographically in ascending
    order to determine the ordering of the k value."

    Measured against `bip375_test_vectors.json`, that sort produces the
    wrong scripts. Its "two sp outputs - output 0 uses label=3 / output 1
    uses label=1" case is published as *valid* and its two spend keys are
    in descending order, so a lexicographic sort assigns k = 0 to output 1
    -- and the scripts the file carries are the ones index order derives.
    Neither reading of "the codes" rescues the prose: sorting the 66-byte
    info fields and sorting the bech32m address strings both order that
    pair the other way round.

    So two of upstream's three artefacts agree on index order -- the
    vectors and `bip-0375/validator/validate_psbt.py`, which tracks k per
    scan key while walking the outputs in index order -- and only the
    prose dissents. Index order is therefore what interoperates, and the
    two "output scripts" invalid vectors named after ordering are refused
    under it anyway: each carries a k assignment no ascending rule
    produces, the two values swapped in one and three permuted in the
    other. `tests/psbt/silent_payments_test.py` pins each of those facts,
    so a revision of the BIP that settles it the other way fails here
    rather than passing quietly -- which is what bitcoin/bips#2207 proposes,
    correcting the vectors and the validator to match the prose.
    """
    return [(i, o) for i, o in enumerate(psbt.outputs) if o.sp_v0_info]


def output_scripts(psbt: Psbt) -> dict[int, bytes]:
    """Return the script every silent payment output should pay, by index.

    An output whose scan key has no share is absent from the answer rather
    than raising: a psbt under construction is allowed to have one, which
    is the "in progress" half of BIP375's own vectors, and what refuses
    the ones that are not allowed is `assert_output_scripts_as_valid`. A
    counted input whose key the psbt does not carry raises instead, the
    sum every script depends on being unknown.
    """
    scripts: dict[int, bytes] = {}
    counters: dict[bytes, int] = {}
    for i, psbt_out in _ordered_sp_outputs(psbt):
        scan_key = psbt_out.sp_v0_info[:SP_SCAN_KEY_SIZE]
        found = _share_and_sum(psbt, scan_key)
        if found is None:
            continue
        share, A_sum = found
        k = counters.get(scan_key, 0)
        counters[scan_key] = k + 1
        secret = shared_secret_from_share(psbt, share, A_sum)
        B_m = psbt_out.sp_v0_info[SP_SCAN_KEY_SIZE:]
        # `serialize(["OP_1", key])` and not `ScriptPubKey.p2tr(key)`: that
        # classmethod takes an *internal* key and applies BIP341's tweak,
        # where what BIP352 derives is already the output key. Tweaking it
        # a second time is a script no recipient scans for
        scripts[i] = serialize(["OP_1", sp.output_key(secret, B_m, k)])
    return scripts


def _assert_pair(
    shares: dict[bytes, bytes], proofs: dict[bytes, bytes], what: str
) -> None:
    """Raise unless the shares and the proofs name the same scan keys.

    Each half is useless without the other: a share nobody can hold its
    writer to is what carrying a proof exists to prevent, and a proof of a
    share that is not there proves nothing at all.
    """
    for scan_key in shares:
        if scan_key not in proofs:
            err_msg = f"{what} ECDH share with no proof beside it: scan key "
            err_msg += scan_key.hex()
            raise BTClibValueError(err_msg)
    for scan_key in proofs:
        if scan_key not in shares:
            err_msg = f"{what} DLEQ proof with no share to prove: scan key "
            err_msg += scan_key.hex()
            raise BTClibValueError(err_msg)


def _assert_global_shares(psbt: Psbt) -> None:
    """Raise unless the global shares are proved against the input sum.

    A global share stands for every eligible input at once, so what proves
    it is the sum of their public keys -- and a psbt carrying one with no
    eligible input to sum is a psbt whose share nothing can be checked
    against, which is a different failure from a proof that does not
    verify.
    """
    _assert_pair(psbt.sp_ecdh_shares, psbt.sp_dleq_proofs, "global")
    if not psbt.sp_ecdh_shares:
        return
    pub_keys = eligible_pub_keys(psbt)
    if not pub_keys:
        err_msg = "global ECDH share with no eligible input to prove it against"
        raise BTClibValueError(err_msg)
    A_sum = sp.pub_key_sum(list(pub_keys.values()))
    for scan_key, share in psbt.sp_ecdh_shares.items():
        if not dleq.verify_proof(A_sum, scan_key, share, psbt.sp_dleq_proofs[scan_key]):
            raise BTClibValueError(f"invalid global DLEQ proof for {scan_key.hex()}")


def _assert_input_shares(psbt: Psbt, eligible: dict[int, Point | None]) -> None:
    """Raise unless every per-input share is proved against its own key.

    A share on an input BIP352 does not count is passed over rather than
    refused: `_share_and_sum` gives it no weight either, and one of
    BIP375's valid vectors carries exactly that. An input that *is*
    counted and carries no public key is the opposite case and is refused
    -- BIP375 asks an Updater for PSBT_IN_BIP32_DERIVATION so that there
    is one, and one of its invalid vectors is that field missing.
    """
    for i, psbt_in in enumerate(psbt.inputs):
        if psbt_in.sp_ecdh_shares and i not in eligible:
            continue
        _assert_pair(psbt_in.sp_ecdh_shares, psbt_in.sp_dleq_proofs, f"input {i}")
        for scan_key, share in psbt_in.sp_ecdh_shares.items():
            A = eligible.get(i)
            if A is None:
                err_msg = f"input {i}: ECDH share on an input with no public key to "
                err_msg += "prove it against; BIP375 asks an Updater for "
                err_msg += "PSBT_IN_BIP32_DERIVATION so that there is one"
                raise BTClibValueError(err_msg)
            proof = psbt_in.sp_dleq_proofs[scan_key]
            if not dleq.verify_proof(A, scan_key, share, proof):
                err_msg = f"input {i}: invalid DLEQ proof for {scan_key.hex()}"
                raise BTClibValueError(err_msg)


def assert_shares_as_valid(psbt: Psbt) -> None:
    """Raise unless every ECDH share the psbt carries is proved.

    BIP375's second check, and the one that makes a share worth reading: a
    proof is verified against the public key of what it covers -- the sum
    of the eligible inputs' keys for a global share, that one input's key
    for a per-input one -- so a share can be trusted by a party holding
    none of the private keys.
    """
    _assert_global_shares(psbt)
    _assert_input_shares(psbt, _eligible_keys(psbt))


def _assert_covered(psbt: Psbt, scan_key: bytes) -> None:
    """Raise unless every eligible input contributes to this scan key.

    Asked of a scan key whose output script is set, or about to be:
    before that the psbt is under construction, and a share that has not
    arrived is a signer that has not signed. A script is a claim about
    every eligible input, so a missing share means the script was derived
    from fewer keys than the recipient will sum -- and the recipient would
    find nothing.

    The walk is over the inputs BIP352 counts, whether or not their key
    was found: an input whose key is missing is still summed by the
    recipient, so it is refused for the key, which is what it lacks first.
    """
    if scan_key in psbt.sp_ecdh_shares:
        return
    for i, pub_key in _eligible_keys(psbt).items():
        if pub_key is None:
            raise _no_key_error(i)
        if scan_key not in psbt.inputs[i].sp_ecdh_shares:
            err_msg = f"input {i}: no ECDH share for scan key {scan_key.hex()}, "
            err_msg += "which every counted input owes a script derived for it"
            raise BTClibValueError(err_msg)


def assert_eligibility_as_valid(psbt: Psbt) -> None:
    """Raise unless every input may be there at all, silent payments present.

    BIP375's third check, and the two rules are BIP352's reasons in a
    psbt's terms. An input spending a witness program above version 1 is
    one this protocol version has no derivation rule for, so BIP352 skips
    the whole transaction -- which makes building one a way to pay an
    address nobody will scan. And a sighash type other than SIGHASH_ALL
    lets the inputs or the outputs change after the scripts were derived
    from them: BIP352 permits NONE and SINGLE, BIP375 does not, because
    here the scripts are computed from the number and the position of the
    codes.
    """
    if not _scan_keys(psbt):
        return
    for i, psbt_in in enumerate(psbt.inputs):
        version = _witness_version(_script_pub_key(psbt_in))
        if version is not None and version > _MAX_WITNESS_VERSION:
            err_msg = f"input {i}: spends witness version {version}, which a psbt "
            err_msg += "with a silent payment output must not"
            raise BTClibValueError(err_msg)
        if psbt_in.sig_hash_type is not None and psbt_in.sig_hash_type != ALL:
            err_msg = f"input {i}: sig hash type {psbt_in.sig_hash_type}, where a "
            err_msg += "psbt with a silent payment output requires SIGHASH_ALL"
            raise BTClibValueError(err_msg)


def assert_output_scripts_as_valid(psbt: Psbt) -> None:
    """Raise unless every silent payment script is the one derived.

    BIP375's fourth check and the Extractor's reason to exist: this is the
    error a signature cannot catch, a wrong output script being
    consensus-valid. An output that carries no script yet is passed over
    -- that is a psbt still being built -- and one that carries a script
    without the shares to derive it is not.
    """
    scripted = [
        (i, psbt_out)
        for i, psbt_out in enumerate(psbt.outputs)
        if psbt_out.sp_v0_info and psbt_out.script_pub_key
    ]
    # coverage before derivation: a script derived from fewer inputs than
    # the recipient sums is the error to name, rather than whichever
    # refusal deriving it would meet first
    for _, psbt_out in scripted:
        _assert_covered(psbt, psbt_out.sp_v0_info[:SP_SCAN_KEY_SIZE])
    derived = output_scripts(psbt) if scripted else {}
    for i, psbt_out in scripted:
        script = psbt_out.script_pub_key
        scan_key = psbt_out.sp_v0_info[:SP_SCAN_KEY_SIZE]
        if i not in derived:
            err_msg = f"output {i}: PSBT_OUT_SCRIPT with no ECDH share to derive it "
            err_msg += f"from, for scan key {scan_key.hex()}"
            raise BTClibValueError(err_msg)
        if script != derived[i]:
            err_msg = f"output {i}: PSBT_OUT_SCRIPT is not the silent payment script "
            err_msg += f"its address derives: {script.hex()} instead of "
            err_msg += derived[i].hex()
            raise BTClibValueError(err_msg)


def _assert_modifiable_cleared(psbt: Psbt) -> None:
    """Raise if a derived output script may still have its inputs changed.

    BIP375: a Signer that sets a missing PSBT_OUT_SCRIPT "must set the
    Inputs Modifiable and Outputs Modifiable flags to False". The script
    is a function of the input set and of the position of the codes, so a
    psbt that publishes one and still invites changes publishes a script
    that the next Constructor invalidates.
    """
    if psbt.tx_modifiable is None:
        return
    if not any(o.sp_v0_info and o.script_pub_key for o in psbt.outputs):
        return
    if psbt.tx_modifiable & (INPUTS_MODIFIABLE | OUTPUTS_MODIFIABLE):
        err_msg = "PSBT_GLOBAL_TX_MODIFIABLE still invites changes, with a silent "
        err_msg += "payment output script already derived from what it would change"
        raise BTClibValueError(err_msg)


def assert_as_valid(psbt: Psbt) -> None:
    """Raise unless the psbt satisfies BIP375, the roles included.

    `Psbt.assert_valid` is the format; this is the protocol on top of it,
    and it is what a Transaction Extractor owes a silent payment before it
    hands the bytes over. The four checks in BIP375's own order, each
    naming what failed: the fields, the shares and their proofs, which
    inputs may be present, and the output scripts.

    A psbt with no silent payment output passes everything here, there
    being nothing to derive.
    """
    psbt.assert_valid()
    _assert_modifiable_cleared(psbt)
    assert_shares_as_valid(psbt)
    assert_eligibility_as_valid(psbt)
    assert_output_scripts_as_valid(psbt)


def _assert_output_scripts_set(psbt: Psbt, what: str) -> None:
    """Raise if a silent payment output has no PSBT_OUT_SCRIPT yet.

    A refusal the checks above do not make, since a psbt under
    construction may lack a script: signed or extracted, such an output
    pays the empty script, which anybody can spend.
    """
    for i, psbt_out in enumerate(psbt.outputs):
        if psbt_out.sp_v0_info and not psbt_out.script_pub_key:
            err_msg = f"output {i}: silent payment output with no PSBT_OUT_SCRIPT, "
            raise BTClibValueError(err_msg + what)


def _assert_signable(psbt: Psbt) -> None:
    """Raise unless BIP375 lets a Signer sign this psbt.

    `btclib_wallet.psbt.psbt.sign` asks it whenever an output carries
    PSBT_OUT_SP_V0_INFO. First the modifiable flags, whose violation
    makes the psbt one of BIP375's invalid ones whatever the role; then
    the two rules "the Signer must fail" on, an input spending a witness
    version above 1 and a sighash type other than SIGHASH_ALL; then the
    shares other Signers wrote, which the Signer "should verify". Each of
    those says the psbt is wrong, where the missing script, next, says
    only that it is early: "the Signer must not yet add a signature"
    names a psbt waiting for `set_output_scripts`. Last, every
    script present is the one the shares derive, a signature being what
    commits the funds to it.
    """
    _assert_modifiable_cleared(psbt)
    assert_eligibility_as_valid(psbt)
    assert_shares_as_valid(psbt)
    what = "and BIP375's Signer must not yet sign: set_output_scripts derives it"
    _assert_output_scripts_set(psbt, what)
    assert_output_scripts_as_valid(psbt)


def _assert_extractable(psbt: Psbt) -> None:
    """Raise unless BIP375 lets a Transaction Extractor extract this psbt.

    `btclib_wallet.psbt.psbt.extract_tx` asks it whenever an output
    carries PSBT_OUT_SP_V0_INFO: `assert_as_valid`, and a script on every
    silent payment output, the Extractor being where a psbt stops being
    under construction.
    """
    assert_as_valid(psbt)
    what = "so the extracted transaction would pay the empty script"
    _assert_output_scripts_set(psbt, what)


def _share_for(a: int, scan_key: bytes, aux: Octets | None) -> tuple[bytes, bytes]:
    """Return the ECDH share for one scalar and scan key, and its proof."""
    B_scan = point_from_pub_key(scan_key)
    share = bytes_from_point(mult(a, B_scan), secp256k1)
    return share, dleq.generate_proof(a, B_scan, aux)


def set_input_share(
    psbt: Psbt, vin_i: int, prv_key: Integer, aux: Octets | None = None
) -> None:
    """Write the ECDH share and proof of one input, for every recipient.

    What a Signer holding one input's key does: one share per scan key the
    psbt pays, each with the BIP374 proof that it was computed with the
    private key of *this* input's public key -- which is what lets the
    other signers check it without holding that key.

    The input must be one BIP352 counts, and the key must be its own: a
    share proved against a public key the input does not have is a share
    every verifier rejects, so it is refused here instead of written.
    """
    psbt_in = psbt.inputs[vin_i]
    counted, A = _input_eligibility(psbt_in)
    if not counted:
        err_msg = f"input {vin_i}: no public key, so no share BIP352 would count"
        raise BTClibValueError(err_msg)
    if A is None:
        raise _no_key_error(vin_i)
    a = scalar_from_prv_key(prv_key)
    if mult(a) != A:
        err_msg = f"input {vin_i}: the private key is not the one of its public key"
        raise BTClibValueError(err_msg)
    for scan_key in _scan_keys(psbt):
        share, proof = _share_for(a, scan_key, aux)
        psbt_in.sp_ecdh_shares[scan_key] = share
        psbt_in.sp_dleq_proofs[scan_key] = proof


def set_global_share(
    psbt: Psbt, prv_keys: Sequence[Integer], aux: Octets | None = None
) -> None:
    """Write the one ECDH share standing for every eligible input.

    What a Signer holding *every* eligible input's key may do instead of
    one share each: the sum of those keys, once, with one proof against
    the sum of their public keys. Fewer bytes in the psbt and one
    verification for every reader of it.

    The keys are given in the order of the eligible inputs, and the sum is
    checked against the sum of their public keys before anything is
    written: a global share proved against the wrong sum is a share that
    fails for every recipient at once.
    """
    pub_keys = eligible_pub_keys(psbt)
    if len(prv_keys) != len(pub_keys):
        err_msg = f"{len(prv_keys)} private keys for {len(pub_keys)} eligible inputs"
        raise BTClibValueError(err_msg)
    a = 0
    for prv_key in prv_keys:
        a = (a + scalar_from_prv_key(prv_key)) % secp256k1.n
    if a == 0:
        raise BTClibValueError("input private keys sum to zero")
    if mult(a) != sp.pub_key_sum(list(pub_keys.values())):
        err_msg = "the private keys do not sum to the eligible inputs' public keys"
        raise BTClibValueError(err_msg)
    for scan_key in _scan_keys(psbt):
        share, proof = _share_for(a, scan_key, aux)
        psbt.sp_ecdh_shares[scan_key] = share
        psbt.sp_dleq_proofs[scan_key] = proof


def set_output_scripts(psbt: Psbt) -> None:
    """Derive every silent payment output script, and freeze the psbt.

    The Signer's last step before it signs: BIP375 forbids a signature
    while an output has no script, and requires the two modifiable flags
    cleared once one is written -- the script is a function of the input
    set, so a psbt that still invites inputs invites its own scripts to
    become wrong.

    Every silent payment output must be derivable, or nothing is written:
    a psbt half-derived is one whose recipients each need the other's
    signer to have finished. And derivable means BIP375's "if all
    eligible inputs have an ECDH share or the global ECDH share is set":
    a script summed from the shares that have arrived is one
    `assert_output_scripts_as_valid` refuses.
    """
    for scan_key in _scan_keys(psbt):
        _assert_covered(psbt, scan_key)
    scripts = output_scripts(psbt)
    missing = [
        i for i, o in enumerate(psbt.outputs) if o.sp_v0_info and i not in scripts
    ]
    if missing:
        err_msg = f"no ECDH share to derive the script of output(s) {missing}"
        raise BTClibValueError(err_msg)
    if not scripts:
        return
    for i, script in scripts.items():
        psbt.outputs[i].script_pub_key = script
    psbt.tx_modifiable = (psbt.tx_modifiable or 0) & ~(
        INPUTS_MODIFIABLE | OUTPUTS_MODIFIABLE
    )
