# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib_wallet.silent_payments` module.

The vectors are BIP352's own `send_and_receive_test_vectors.json`,
vendored whole under `tests/_data/`; `tests/_data/README.md` pins the
revision. Every case is exercised from both ends, and every intermediate
value the file publishes is asserted at the step that produces it -- the
private key sum, the public key sum, the tweak data and the per-recipient
shared secrets -- rather than only the outputs at the end. That is what
makes a failure name the step: the 2026 revision added those fields for
exactly this, and a test that checked the outputs alone would report
"wrong output" for outpoints sorted wrongly, a missed negation and a wrong
label alike.

The receiving side goes one step further than the file: every output
found is signed with the key `prv_key_from_tweak` derives and the
signature verified against the output key, which is the only assertion
that says the output is *spendable* rather than merely predicted.
"""

from __future__ import annotations

import re
import string
from hashlib import sha256
from typing import Any, cast

import pytest
from btclib.b32 import power_of_2_base_conversion
from btclib.bech32 import BECH32_M_CONST, encode
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash160
from btclib.script.witness import Witness
from btclib.tx.out_point import OutPoint
from ecc.curves import bytes_from_point, mult, secp256k1
from ecc.ecc import ssa

from btclib_wallet import silent_payments
from tests import NOT_STRIPPED, load, needs_bindings, vector_id

# the bindings, None where they are not installed: every test reading
# them is marked `bindings`, skipped in that configuration
try:
    from btclib_secp256k1 import silentpayments as libsecp256k1_silentpayments
except ImportError:  # pragma: no cover -- only an install without them
    libsecp256k1_silentpayments = None  # type: ignore[assignment]

_VECTORS = load("_data", "send_and_receive_test_vectors.json", encoding="utf-8")

# the message and the auxiliary randomness the reference signs with, so
# that a signature here is the signature its harness produces
_MSG = sha256(b"message").digest()
_AUX = sha256(b"random auxiliary data").digest()


def _sending_params() -> tuple[list[tuple[int, Any]], list[str]]:
    """Flatten every sending sub-test into its own parametrized case."""
    params = [
        (index, test) for index, case in enumerate(_VECTORS) for test in case["sending"]
    ]
    ids = [vector_id(index, _VECTORS[index]["comment"]) for index, _ in params]
    return params, ids


def _receiving_params() -> tuple[list[tuple[int, Any]], list[str]]:
    """Flatten the receiving sub-tests, of which one case has two."""
    params = [
        (index, test)
        for index, case in enumerate(_VECTORS)
        for test in case["receiving"]
    ]
    ids = [
        vector_id(index, _VECTORS[index]["comment"], position)
        for position, (index, _) in enumerate(params)
    ]
    return params, ids


_SENDING, _SENDING_IDS = _sending_params()
_RECEIVING, _RECEIVING_IDS = _receiving_params()


def _witness(txinwitness: str) -> Witness | None:
    """Parse a witness, an empty column being a non-segwit input."""
    return Witness.parse(txinwitness) if txinwitness else None


def _outpoints(vin: list[dict[str, Any]]) -> list[OutPoint]:
    """Every outpoint of the transaction, eligible input or not."""
    return [OutPoint(v["txid"], v["vout"]) for v in vin]


def _pub_key_of(v: dict[str, Any]) -> tuple[int, int] | None:
    """Read one input's public key, or None where BIP352 skips it."""
    return silent_payments.pub_key_from_input(
        v["prevout"]["scriptPubKey"]["hex"], v["scriptSig"], _witness(v["txinwitness"])
    )


def _recipients(given: dict[str, Any]) -> list[dict[str, str]]:
    """Expand the file's `count` shorthand into one entry per payment."""
    expanded = []
    for recipient in given["recipients"]:
        expanded.extend([recipient] * recipient.get("count", 1))
    return expanded


@pytest.mark.parametrize("index,test", _SENDING, ids=_SENDING_IDS)
def test_sending_vectors(index: int, test: dict[str, Any]) -> None:
    """Derive the outputs a sender pays, and every value on the way."""
    given, expected = test["given"], test["expected"]

    prv_keys = []
    pub_keys = []
    for v in given["vin"]:
        pub_key = _pub_key_of(v)
        if pub_key is None:
            continue
        prv_keys.append((v["private_key"], v["prevout"]["scriptPubKey"]["hex"]))
        pub_keys.append(pub_key)
    assert [bytes_from_point(pk).hex() for pk in pub_keys] == expected["input_pub_keys"]

    if not pub_keys:
        # nothing eligible to derive a secret from: no outputs, and the
        # sender has to notice before it composes a transaction
        assert expected["outputs"] == [[]]
        return

    recipients = _recipients(given)
    addresses = [recipient["address"] for recipient in recipients]

    if expected.get("input_private_key_sum") is None:
        # the two keys are negatives of one another, so a is zero and the
        # shared secret would be the point at infinity
        with pytest.raises(BTClibValueError, match="sum to zero"):
            silent_payments.prv_key_sum(prv_keys)
        with pytest.raises(BTClibValueError, match="sum to zero"):
            silent_payments.output_keys(prv_keys, _outpoints(given["vin"]), addresses)
        assert expected["outputs"] == [[]]
        return

    a = silent_payments.prv_key_sum(prv_keys)
    assert a == int(expected["input_private_key_sum"], 16)

    outpoints = _outpoints(given["vin"])
    input_hash = silent_payments.input_hash(outpoints, mult(a))
    scalar = (input_hash * a) % secp256k1.n
    # one shared secret per recipient, which for a group is the same point
    # repeated: the file lists as many as it has values for
    for recipient, expected_secret in zip(
        recipients, expected["shared_secrets"], strict=False
    ):
        B_scan, B_m, network_type = silent_payments.keys_from_address(
            recipient["address"]
        )
        assert bytes_from_point(B_scan).hex() == recipient["scan_pub_key"]
        assert bytes_from_point(B_m).hex() == recipient["spend_pub_key"]
        assert network_type == "main"
        if expected_secret is None:
            # the K_MAX case, which fails before a secret is derived: the
            # file publishes the private key sum and then a null
            continue
        secret = silent_payments.shared_secret(scalar, B_scan)
        assert bytes_from_point(secret).hex() == expected_secret

    if len(recipients) > silent_payments.K_MAX:
        with pytest.raises(BTClibValueError, match="K_MAX"):
            silent_payments.output_keys(prv_keys, outpoints, addresses)
        assert expected["outputs"] == [[]]
        return

    keys = silent_payments.output_keys(prv_keys, outpoints, addresses)
    # the order of the addresses is not fixed, and a different order pays
    # the labelled addresses of one recipient different outputs, so the
    # file lists every valid set and one of them has to match
    found = {key.hex() for key in keys}
    assert any(found == set(valid) for valid in expected["outputs"])


@pytest.mark.parametrize("index,test", _RECEIVING, ids=_RECEIVING_IDS)
def test_receiving_vectors(index: int, test: dict[str, Any]) -> None:
    """Scan for the outputs of one transaction, and spend each one."""
    given, expected = test["given"], test["expected"]

    b_scan = given["key_material"]["scan_priv_key"]
    b_spend = given["key_material"]["spend_priv_key"]
    B_spend = mult(b_spend)

    addresses = [silent_payments.address_from_keys(mult(b_scan), B_spend)]
    addresses += [
        silent_payments.labeled_address_from_keys(b_scan, B_spend, m)
        for m in given["labels"]
    ]
    assert addresses == expected["addresses"]

    pub_keys = [
        pub_key for v in given["vin"] if (pub_key := _pub_key_of(v)) is not None
    ]
    if not pub_keys:
        assert expected["outputs"] == []
        return

    try:
        A_sum = silent_payments.pub_key_sum(pub_keys)
    except BTClibValueError:
        # the input keys sum to infinity: BIP352 skips the transaction,
        # which is the same fact the sending side reports as a failure
        assert expected["outputs"] == []
        return
    assert bytes_from_point(A_sum).hex() == expected["input_pub_key_sum"]

    outpoints = _outpoints(given["vin"])
    tweak = silent_payments.tweak_data(outpoints, A_sum)
    assert bytes_from_point(tweak).hex() == expected["tweak"]
    secret = silent_payments.shared_secret(b_scan, tweak)
    assert bytes_from_point(secret).hex() == expected["shared_secret"]

    labels = silent_payments.label_lookup(b_scan, given["labels"])
    found = silent_payments.scan_outputs(
        b_scan, B_spend, tweak, given["outputs"], labels
    )

    # the full-node entry point, given the same transaction data rather
    # than the already-reduced tweak: `scan_outputs`'s light-client
    # answer is what it has to match, on whichever arm this environment
    # runs -- delegated where the bindings serve, `scan_outputs` itself
    # otherwise, which is what makes this the vector this arm's own
    # entry in `tests/py_arm_authority_test.py` cites
    pub_keys_with_scripts = [
        (pub_key, v["prevout"]["scriptPubKey"]["hex"])
        for v in given["vin"]
        if (pub_key := _pub_key_of(v)) is not None
    ]
    transaction_found = silent_payments.scan_transaction_outputs(
        b_scan, B_spend, outpoints, pub_keys_with_scripts, given["outputs"], labels
    )
    assert {(o.pub_key, o.prv_key_tweak) for o in transaction_found} == {
        (o.pub_key, o.prv_key_tweak) for o in found
    }

    if "n_outputs" in expected:
        # the K_MAX case, where the file counts rather than lists: the
        # transaction holds one output more than a scan is allowed to look
        assert len(found) == expected["n_outputs"]
    else:
        assert {(o.pub_key.hex(), o.prv_key_tweak) for o in found} == {
            (o["pub_key"], int(o["priv_key_tweak"], 16)) for o in expected["outputs"]
        }

    for output in found:
        d = silent_payments.prv_key_from_tweak(b_spend, output.prv_key_tweak)
        sig = ssa.sign_(_MSG, d, _AUX)
        assert ssa.verify_(_MSG, output.pub_key, sig)


# a wallet of its own for the cases the vector file has none of
_B_SCAN_PRV = 0x0F694E068028A717F8AF6B9411F9A133DD3565258714CC226594B34DB90C1F2C
_B_SPEND_PRV = 0x9D6AD855CE3417EF84E836692E31A6A11FBC69AC0C0844A2CD6F0D5ED4D3B58B

# 5 is not the x coordinate of any point of secp256k1, which is why
# btclib spells the point at infinity (5, 0): 32 bytes of it is a taproot
# output nobody can spend, and a scan has to walk past one rather than
# raise on it
_NOT_AN_X = (5).to_bytes(32, "big")


def _address(m: int | None = None, network: str = "mainnet") -> str:
    """Return the test wallet's address, labelled or not."""
    B_spend = mult(_B_SPEND_PRV)
    if m is None:
        return silent_payments.address_from_keys(mult(_B_SCAN_PRV), B_spend, network)
    return silent_payments.labeled_address_from_keys(_B_SCAN_PRV, B_spend, m, network)


def _reencoded(version: int, payload: bytes, hrp: str = "sp") -> str:
    """Compose an address out of a version and a payload, valid or not."""
    data = [version, *power_of_2_base_conversion(payload, 8, 5)]
    return encode(hrp, data, BECH32_M_CONST).decode("ascii")


def test_the_address_round_trip_on_every_network() -> None:
    """Each network's hrp, and the network type read back.

    "tsp" is shared by testnet, testnet4 and signet, and "sprt" is
    regtest's: both read back as "test".
    """
    B_scan, B_spend = mult(_B_SCAN_PRV), mult(_B_SPEND_PRV)
    for network, hrp, network_type in (
        ("mainnet", "sp", "main"),
        ("testnet", "tsp", "test"),
        ("signet", "tsp", "test"),
        ("testnet4", "tsp", "test"),
        ("regtest", "sprt", "test"),
    ):
        address = _address(network=network)
        assert address.startswith(f"{hrp}1q")
        assert silent_payments.keys_from_address(address) == (
            B_scan,
            B_spend,
            network_type,
        )

    # a spelling of the name that `network_type_from_network` accepts
    regtest = _address(network=" Regtest ")
    assert regtest.startswith("sprt1q")
    assert silent_payments.keys_from_address(regtest.upper())[2] == "test"

    # and the address is read back in upper case and whatever the spacing,
    # as every other btclib bech32 address is
    address = _address()
    assert silent_payments.keys_from_address(f"  {address.upper()} ") == (
        B_scan,
        B_spend,
        "main",
    )


def test_an_address_bech32_refuses_is_refused_here_too() -> None:
    """A mixed-case spelling, and a letter that only lowers onto ASCII.

    BIP173 says a decoder must not accept a mixed-case string, and BIP352
    inherits the rule through bech32m. U+212A KELVIN SIGN is its own upper
    case and `str.lower` maps it onto "k", so in an all-uppercase address
    it would pass for the "k" it replaces.
    """
    address = _address()
    assert "k" in address  # otherwise the replacement below replaces nothing
    with pytest.raises(BTClibValueError, match="mixed case"):
        silent_payments.keys_from_address(address[:10] + address[10:].upper())
    kelvin = address.upper().replace("K", "\N{KELVIN SIGN}")
    with pytest.raises(BTClibValueError, match="non-ASCII character"):
        silent_payments.keys_from_address(kelvin)


def test_a_network_no_network_has_is_refused() -> None:
    """The hrp comes from the network, so the name has to be one.

    Through `network_type_from_network`, which is what refuses it: indexing
    `NETWORKS` would answer a bare `KeyError`, and being a `LookupError`
    that is an exception no caller filtering this library's bad input is
    told to expect.
    """
    B_scan, B_spend = mult(_B_SCAN_PRV), mult(_B_SPEND_PRV)
    for network in ("mainet", "", "bitcoin"):
        with pytest.raises(BTClibValueError, match="unknown network"):
            silent_payments.address_from_keys(B_scan, B_spend, network)
        with pytest.raises(BTClibValueError, match="unknown network"):
            silent_payments.labeled_address_from_keys(_B_SCAN_PRV, B_spend, 0, network)
    # and the tolerance every other network name gets is this one's too
    assert silent_payments.address_from_keys(
        B_scan, B_spend, "  MainNet "
    ) == silent_payments.address_from_keys(B_scan, B_spend)


def test_a_labeled_address_differs_in_the_spend_key_alone() -> None:
    """The scan key is shared, which is what one wallet means."""
    B_scan, B_spend, _ = silent_payments.keys_from_address(_address())
    for m in (0, 1, 0xFFFFFFFF):
        labeled_scan, labeled_spend, _ = silent_payments.keys_from_address(_address(m))
        assert labeled_scan == B_scan
        assert labeled_spend != B_spend
        # and the difference is the label tweak times G
        tweak = silent_payments.label_tweak(_B_SCAN_PRV, m)
        assert labeled_spend == secp256k1.add_var(B_spend, mult(tweak))


def test_a_label_is_a_32_bit_unsigned_integer() -> None:
    """Four bytes hold a label, so 2^32 has no serialization and nor has -1."""
    for m in (-1, 2**32):
        with pytest.raises(BTClibValueError, match="label not in"):
            silent_payments.label_tweak(_B_SCAN_PRV, m)
    # a bool is an int and would label 0 or 1 by accident, a label read
    # back from json being where that arrives
    with pytest.raises(BTClibTypeError, match="non-integer label"):
        silent_payments.label_tweak(_B_SCAN_PRV, True)
    with pytest.raises(BTClibTypeError, match="non-integer label"):
        silent_payments.label_tweak(_B_SCAN_PRV, 1.0)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="non-integer label"):
        silent_payments.label_tweak(_B_SCAN_PRV, "1")  # type: ignore[arg-type]


def test_a_hash_outside_the_scalar_range_is_refused() -> None:
    """BIP352's "fail" wherever a hash is no scalar, at all three sites.

    Not reachable through the public functions -- each of the three hashes
    is a sha256 and a preimage of 0 or of n is what nobody has -- so the
    helper the three share is what is held to it, at both ends of the
    range.
    """
    for data in (bytes(32), secp256k1.n.to_bytes(32, "big"), b"\xff" * 32):
        with pytest.raises(BTClibValueError, match="not in 1..n-1"):
            silent_payments._scalar(data, "label")


def test_an_address_no_longer_than_a_bech32m_string_should_be() -> None:
    """1023 characters, which is BIP352's bound and not BIP173's 90."""
    address = _address()
    padded = address + "q" * (1024 - len(address))
    with pytest.raises(BTClibValueError, match="invalid address length"):
        silent_payments.keys_from_address(padded)


def test_an_hrp_that_is_not_a_silent_payment_one_is_refused() -> None:
    """A segwit hrp on a silent payment payload is not an address."""
    payload = bytes_from_point(mult(_B_SCAN_PRV)) + bytes_from_point(mult(_B_SPEND_PRV))
    with pytest.raises(BTClibValueError, match="invalid hrp"):
        silent_payments.keys_from_address(_reencoded(0, payload, "bc"))


def test_an_address_with_no_data_part_is_refused() -> None:
    """`decode` does not require one when the checksum constant is given.

    Which is what passing it costs: the segwit spelling reads the witness
    version off the first data value to pick between bech32 and bech32m,
    and refuses an empty data part on the way. Here the constant is
    BIP352's whatever the version, so nothing else asks.
    """
    with pytest.raises(BTClibValueError, match="empty data"):
        silent_payments.keys_from_address(encode("sp", [], BECH32_M_CONST))


def test_version_31_is_refused_and_the_others_are_read() -> None:
    """v31 is the version reserved for breaking exactly this compatibility.

    v1 through v30 are read as far as v0 defines them -- the first 66
    bytes, the rest discarded -- so that a v0 wallet can pay an address of
    a version it has never heard of. v31 says that reading it that way
    would be wrong, and there is nothing else a v0 wallet can do with it.
    """
    B_scan, B_spend = mult(_B_SCAN_PRV), mult(_B_SPEND_PRV)
    payload = bytes_from_point(B_scan) + bytes_from_point(B_spend)

    with pytest.raises(BTClibValueError, match="reserved silent payment version"):
        silent_payments.keys_from_address(_reencoded(31, payload))

    for version in (1, 17, 30):
        # a longer payload is what a later version is expected to bring,
        # and the extra bytes are the part v0 does not understand
        extended = _reencoded(version, payload + b"\x2a" * 7)
        assert silent_payments.keys_from_address(extended) == (B_scan, B_spend, "main")
        # too short is not forward compatibility but a broken address
        with pytest.raises(BTClibValueError, match="is less than"):
            silent_payments.keys_from_address(_reencoded(version, payload[:-1]))


def test_a_v0_payload_is_exactly_the_two_keys() -> None:
    """No truncation and no extension: v0 says 66 bytes and means it."""
    payload = bytes_from_point(mult(_B_SCAN_PRV)) + bytes_from_point(mult(_B_SPEND_PRV))
    for damaged in (payload[:-1], payload + b"\x2a"):
        with pytest.raises(BTClibValueError, match="invalid v0 payload length"):
            silent_payments.keys_from_address(_reencoded(0, damaged))


def test_an_input_of_no_eligible_type_is_skipped() -> None:
    """p2wsh, p2ms, p2pk and nulldata are not on BIP352's list.

    Each of them either has several public keys or a script that a peer
    could satisfy another way, which is the malleability the list exists
    to avoid; a p2pk has one key and is left out all the same, BIP352
    naming four types and not five.
    """
    for script_pub_key in (
        "0020" + "11" * 32,  # p2wsh
        "5121" + "02" + "11" * 32 + "51ae",  # p2ms 1-of-1
        "21" + "02" + "11" * 32 + "ac",  # p2pk
        "6a0568656c6c6f",  # nulldata
        "",  # no script at all
    ):
        assert silent_payments.pub_key_from_input(script_pub_key) is None


def test_an_eligible_input_that_carries_no_key_is_skipped() -> None:
    """The type is on the list and the spend still has no key to read."""
    p2wpkh = "0014" + "11" * 20
    p2sh = "a914" + "11" * 20 + "87"
    p2tr = "5120" + bytes_from_point(mult(3))[1:].hex()

    # a witness that is not there: a p2wpkh or a p2sh-p2wpkh input read out
    # of a transaction that has not been signed yet
    assert silent_payments.pub_key_from_input(p2wpkh) is None
    assert silent_payments.pub_key_from_input(p2sh, "16" + p2wpkh) is None
    assert silent_payments.pub_key_from_input(p2tr) is None

    # a p2sh wrapping something that is not p2wpkh: p2sh-p2wsh, and every
    # other redeem script, is not on the list
    witness = Witness(["11" * 33])
    redeem = "0020" + "11" * 32
    assert silent_payments.pub_key_from_input(p2sh, "22" + redeem, witness) is None

    # and a taproot output whose 32 bytes are no x coordinate: unspendable
    # rather than ineligible, and skipped either way
    assert (
        silent_payments.pub_key_from_input("5120" + _NOT_AN_X.hex(), "", witness)
        is None
    )


def test_a_sum_with_nothing_in_it_is_infinity() -> None:
    """Which is the answer for a transaction of only skipped inputs."""
    with pytest.raises(BTClibValueError, match="sum to infinity"):
        silent_payments.pub_key_sum([])
    with pytest.raises(BTClibValueError, match="sum to zero"):
        silent_payments.prv_key_sum([])


def test_the_input_hash_needs_an_outpoint() -> None:
    """The smallest of none is not a value, and the hash binds to it."""
    with pytest.raises(BTClibValueError, match="no outpoint"):
        silent_payments.input_hash([], mult(_B_SCAN_PRV))


@pytest.mark.parametrize("m_values", [[0], [0, 1]], ids=["addition", "subtraction"])
def test_a_scan_walks_past_an_output_that_is_no_point(m_values: list[int]) -> None:
    """A taproot output key is 32 bytes nobody checked.

    With one label and one output the scan adds the label and never lifts
    the output. With more labels than outputs it subtracts, so the output
    has to be lifted and there is nothing to subtract: the output is
    skipped rather than raised on -- which the direct comparison in front
    of it never needed to notice, comparing x coordinates and not points.
    """
    tweak = silent_payments.tweak_data([OutPoint(bytes(32), 0)], mult(_B_SCAN_PRV))
    labels = silent_payments.label_lookup(_B_SCAN_PRV, m_values)
    found = silent_payments.scan_outputs(
        _B_SCAN_PRV, mult(_B_SPEND_PRV), tweak, [_NOT_AN_X], labels
    )
    assert found == []


def _paid_with_labels(m_values: list[int]) -> tuple[list[OutPoint], list[bytes]]:
    """Pay this wallet's labelled addresses from one input, in order."""
    a = 0xEADC78165FF1F8EA94AD7CFDC54990738A4C53F6E0507B42154201B8E5DFF3B1
    script_pub_key = "0014" + hash160(bytes_from_point(mult(a))).hex()
    outpoints = [OutPoint("00" * 31 + "01", 7)]
    addresses = [_address(m) for m in m_values]
    return outpoints, silent_payments.output_keys(
        [(a, script_pub_key)], outpoints, addresses
    )


def _scan_paid(
    outpoints: list[OutPoint], outputs: list[bytes], labels: dict[bytes, bytes]
) -> list[silent_payments.SilentPaymentOutput]:
    """Scan the transaction of `_paid_with_labels` for the test wallet.

    Through `scan_outputs`, which is the Python scan whatever the labels.
    """
    a = 0xEADC78165FF1F8EA94AD7CFDC54990738A4C53F6E0507B42154201B8E5DFF3B1
    tweak = silent_payments.tweak_data(outpoints, mult(a))
    return silent_payments.scan_outputs(
        _B_SCAN_PRV, mult(_B_SPEND_PRV), tweak, outputs, labels
    )


def test_labels_are_found_by_addition_and_by_subtraction() -> None:
    """The two ways of checking a label find the same outputs, spendable.

    Four labels over eight outputs are added to P_k; twenty labels over
    the same eight are subtracted from the outputs. The outputs are
    given in the order the sender made them and in the reverse one.
    The output key is x-only, and a label found from it is P_k plus the
    label for one parity of that key and minus it for the other, so the
    outputs found must have both: the assertion on the parities says the
    outputs chosen here do.
    """
    m_values = [0, 3, 1, 3, 2, 0, 1, 2]
    outpoints, keys = _paid_with_labels(m_values)
    assert len(set(keys)) == len(m_values)

    for labelled in (list(range(4)), list(range(20))):
        labels = silent_payments.label_lookup(_B_SCAN_PRV, labelled)
        for outputs in (keys, keys[::-1]):
            found = _scan_paid(outpoints, outputs, labels)
            assert [output.pub_key for output in found] == keys
            parities = set()
            for output in found:
                d = silent_payments.prv_key_from_tweak(
                    _B_SPEND_PRV, output.prv_key_tweak
                )
                parities.add(mult(d)[1] % 2)
                sig = ssa.sign_(_MSG, d, _AUX)
                assert ssa.verify_(_MSG, output.pub_key, sig)
            assert parities == {0, 1}


@needs_bindings
def test_the_two_scans_agree_on_labelled_outputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The bindings and the Python scan find the same outputs and tweaks.

    The vectors have few labels; here the wallet holds one, four or
    twenty, and the outputs are ours, partly ours or not at all.
    """
    a = 0xEADC78165FF1F8EA94AD7CFDC54990738A4C53F6E0507B42154201B8E5DFF3B1
    script_pub_key = "0014" + hash160(bytes_from_point(mult(a))).hex()
    pub_keys = [(mult(a), script_pub_key)]
    outpoints, keys = _paid_with_labels([0, 3, 1, 3, 2, 0, 1, 2])
    strangers = [bytes_from_point(mult(i + 2))[1:] for i in range(3)]
    for outputs in (keys, keys[::-1], strangers + keys[:3], strangers):
        for labelled in ([0], [0, 1, 2, 3], list(range(20))):
            labels = silent_payments.label_lookup(_B_SCAN_PRV, labelled)
            args = (_B_SCAN_PRV, outpoints, pub_keys, mult(_B_SPEND_PRV), outputs)
            delegated = silent_payments._delegated_scan_outputs(*args, labels)
            with monkeypatch.context() as arm:
                arm.setattr(silent_payments, "is_libsecp256k1_serving", lambda: False)
                python = silent_payments.scan_transaction_outputs(
                    _B_SCAN_PRV,
                    mult(_B_SPEND_PRV),
                    outpoints,
                    pub_keys,
                    outputs,
                    labels,
                )
            assert delegated == python


def _malformed_label_cases() -> list[
    tuple[list[OutPoint], list[bytes], dict[bytes, bytes], int]
]:
    """Return (outpoints, outputs, labels, outputs found) with a bad label.

    A label key that is no point is first in the map, with a tweak in
    1..n-1: the locked bindings and `_assert_labels` refuse any other,
    whether or not the key matches. One output is ours, by label 0, and
    the map holds label 0 or not. The bad label alone is added over one
    output and over two. With label 0 it is subtracted over one output,
    there being more labels than outputs, and added over two.
    """
    outpoints, keys = _paid_with_labels([0])
    stranger = bytes_from_point(mult(2))[1:]
    bad = {b"\x02" + _NOT_AN_X: (1).to_bytes(32, "big")}
    good = silent_payments.label_lookup(_B_SCAN_PRV, [0])
    return [
        (outpoints, outputs, labels, found)
        for outputs in (keys, [stranger, *keys])
        for labels, found in ((bad, 0), ({**bad, **good}, 1))
    ]


def test_a_label_that_is_no_point_matches_nothing() -> None:
    """It is left out of the scan, in both directions, as it never matches."""
    for outpoints, outputs, labels, found in _malformed_label_cases():
        assert len(_scan_paid(outpoints, outputs, labels)) == found


def _label_keyed_in_another_form() -> list[
    tuple[dict[bytes, bytes], type[Exception], str]
]:
    """Return (label 0 keyed otherwise, error, message), as the bindings refuse.

    The key is label 0's 65-byte form, its compressed form cut to 32
    bytes, or its hex string.
    """
    ((key, tweak),) = silent_payments.label_lookup(_B_SCAN_PRV, [0]).items()
    point = mult(silent_payments.label_tweak(_B_SCAN_PRV, 0))
    assert bytes_from_point(point) == key
    uncompressed = bytes_from_point(point, compressed=False)
    return [
        ({uncompressed: tweak}, BTClibValueError, "the label must be 33 bytes"),
        ({key[1:]: tweak}, BTClibValueError, "the label must be 33 bytes"),
        (
            cast("dict[bytes, bytes]", {key.hex(): tweak}),
            BTClibTypeError,
            "the label must be bytes, not str",
        ),
    ]


def test_a_label_keyed_in_another_form_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Python scan refuses it, whichever way it would check labels.

    Label 0 pays the one output. Alone, it is added; with label 1 beside
    it, there are more labels than outputs, and they are subtracted. Both
    `scan_outputs` and `scan_transaction_outputs` refuse it.
    """
    a = 0xEADC78165FF1F8EA94AD7CFDC54990738A4C53F6E0507B42154201B8E5DFF3B1
    script_pub_key = "0014" + hash160(bytes_from_point(mult(a))).hex()
    outpoints, keys = _paid_with_labels([0])
    other = silent_payments.label_lookup(_B_SCAN_PRV, [1])
    monkeypatch.setattr(silent_payments, "is_libsecp256k1_serving", lambda: False)
    for bad, error, message in _label_keyed_in_another_form():
        for labels in (bad, {**bad, **other}):
            with pytest.raises(error, match=f"^{message}$"):
                _scan_paid(outpoints, keys, labels)
            with pytest.raises(error, match=f"^{message}$"):
                silent_payments.scan_transaction_outputs(
                    _B_SCAN_PRV,
                    mult(_B_SPEND_PRV),
                    outpoints,
                    [(mult(a), script_pub_key)],
                    keys,
                    labels,
                )


@needs_bindings
def test_the_bindings_refuse_a_label_keyed_in_another_form_alike() -> None:
    """The bindings give the error and message the Python scan gives.

    Twenty labels beside it over one output: the dispatch sends the scan
    to the bindings, and it is refused there too, an output that is no
    point included, which the bindings' retry would otherwise drop. The
    bindings themselves refuse it with that message, a hex string with
    their own TypeError.
    """
    a = 0xEADC78165FF1F8EA94AD7CFDC54990738A4C53F6E0507B42154201B8E5DFF3B1
    pub_keys = [(mult(a), "0014" + hash160(bytes_from_point(mult(a))).hex())]
    outpoints, keys = _paid_with_labels([0])
    many = silent_payments.label_lookup(_B_SCAN_PRV, range(1, 21))
    for bad, error, message in _label_keyed_in_another_form():
        labels = {**bad, **many}
        for outputs in (keys, [_NOT_AN_X]):
            with pytest.raises(error, match=f"^{message}$"):
                silent_payments.scan_transaction_outputs(
                    _B_SCAN_PRV,
                    mult(_B_SPEND_PRV),
                    outpoints,
                    pub_keys,
                    outputs,
                    labels,
                )
        # `_delegated_scan_outputs` wraps the bindings' ValueError only
        raw = TypeError if error is BTClibTypeError else error
        with pytest.raises(raw, match=f"^{message}$"):
            silent_payments._delegated_scan_outputs(
                _B_SCAN_PRV, outpoints, pub_keys, mult(_B_SPEND_PRV), keys, labels
            )


def _label_with_a_bad_tweak() -> list[tuple[dict[bytes, bytes], type[Exception], str]]:
    """Return (label 5 with a bad tweak, error, message) the bindings give.

    Label 5 pays no output of `_paid_with_labels([0])`, so a scan that
    reads a tweak only on a match never reads this one. The tweak is 0,
    n, n+1, 31 bytes, an int, or a memoryview of 4-byte items.
    """
    ((key, tweak),) = silent_payments.label_lookup(_B_SCAN_PRV, [5]).items()
    n = secp256k1.n
    in_range = "the label tweak must be in [1, n-1]"
    bad_tweaks: list[tuple[object, type[Exception], str]] = [
        (bytes(32), BTClibValueError, in_range),
        (n.to_bytes(32, "big"), BTClibValueError, in_range),
        ((n + 1).to_bytes(32, "big"), BTClibValueError, in_range),
        (tweak[1:], BTClibValueError, "the label tweak must be 32 bytes"),
        (
            int.from_bytes(tweak, "big"),
            BTClibTypeError,
            "the label tweak must be bytes, not int",
        ),
        (
            memoryview(tweak).cast("I"),
            BTClibTypeError,
            "the label tweak must be a memoryview of bytes, not of 4-byte items",
        ),
    ]
    return [
        (cast("dict[bytes, bytes]", {key: bad}), error, message)
        for bad, error, message in bad_tweaks
    ]


def test_an_unmatched_label_with_a_bad_tweak_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Python scan refuses it, though it matches no output.

    Label 0 pays the one output. The bad label alone is added; with label
    0 beside it, there are more labels than outputs, and they are
    subtracted. Both `scan_outputs` and `scan_transaction_outputs` refuse
    it, with the bindings' error and message.
    """
    a = 0xEADC78165FF1F8EA94AD7CFDC54990738A4C53F6E0507B42154201B8E5DFF3B1
    pub_keys = [(mult(a), "0014" + hash160(bytes_from_point(mult(a))).hex())]
    outpoints, keys = _paid_with_labels([0])
    change = silent_payments.label_lookup(_B_SCAN_PRV, [0])
    assert len(_scan_paid(outpoints, keys, change)) == 1
    monkeypatch.setattr(silent_payments, "is_libsecp256k1_serving", lambda: False)
    for bad, error, message in _label_with_a_bad_tweak():
        for labels in (bad, {**bad, **change}):
            with pytest.raises(error, match=f"^{re.escape(message)}$"):
                _scan_paid(outpoints, keys, labels)
            with pytest.raises(error, match=f"^{re.escape(message)}$"):
                silent_payments.scan_transaction_outputs(
                    _B_SCAN_PRV, mult(_B_SPEND_PRV), outpoints, pub_keys, keys, labels
                )


@needs_bindings
def test_the_dispatch_refuses_an_unmatched_label_with_a_bad_tweak() -> None:
    """`_assert_labels` refuses it before the dispatch, with 2 labels or 22.

    The bindings, called directly, refuse it with the same message, their
    TypeError unwrapped.
    """
    a = 0xEADC78165FF1F8EA94AD7CFDC54990738A4C53F6E0507B42154201B8E5DFF3B1
    pub_keys = [(mult(a), "0014" + hash160(bytes_from_point(mult(a))).hex())]
    outpoints, keys = _paid_with_labels([0])
    change = silent_payments.label_lookup(_B_SCAN_PRV, [0])
    many = silent_payments.label_lookup(_B_SCAN_PRV, range(6, 26))
    for bad, error, message in _label_with_a_bad_tweak():
        for labels in ({**bad, **change}, {**bad, **change, **many}):
            with pytest.raises(error, match=f"^{re.escape(message)}$"):
                silent_payments.scan_transaction_outputs(
                    _B_SCAN_PRV, mult(_B_SPEND_PRV), outpoints, pub_keys, keys, labels
                )
            # `_delegated_scan_outputs` wraps the bindings' ValueError only
            raw = TypeError if error is BTClibTypeError else error
            with pytest.raises(raw, match=f"^{re.escape(message)}$"):
                silent_payments._delegated_scan_outputs(
                    _B_SCAN_PRV, outpoints, pub_keys, mult(_B_SPEND_PRV), keys, labels
                )


def _strided(octets: bytes) -> memoryview:
    """Return a memoryview of `octets` that is not contiguous."""
    view = memoryview(bytes(byte for octet in octets for byte in (octet, 0)))[::2]
    assert not view.c_contiguous
    assert bytes(view) == octets
    return view


def _strided_tweak_cases() -> list[
    tuple[list[OutPoint], list[bytes], dict[bytes, bytes], dict[bytes, bytes]]
]:
    """Return (outpoints, outputs, labels, the same labels as bytes).

    Label 5 carries its tweak in a memoryview that is not contiguous. It
    pays the one output, or label 0 does and label 5 matches nothing.
    Alone, label 5 is added; with label 0 beside it, there are more
    labels than outputs, and they are subtracted.
    """
    ((key, tweak),) = silent_payments.label_lookup(_B_SCAN_PRV, [5]).items()
    change = silent_payments.label_lookup(_B_SCAN_PRV, [0])
    strided = cast("dict[bytes, bytes]", {key: _strided(tweak)})
    paid = [
        (*_paid_with_labels(m_values), extra)
        for m_values, extra in (
            ([5], {}),
            ([5], change),
            ([0], change),
        )
    ]
    return [
        (outpoints, keys, {**strided, **extra}, {key: tweak, **extra})
        for outpoints, keys, extra in paid
    ]


def test_a_label_tweak_not_contiguous_is_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Python scan finds what it finds with the same tweak as bytes.

    The bindings accept such a tweak, and `int.from_bytes` and
    `scalar_from_prv_key` refuse it unless it is copied first.
    """
    a = 0xEADC78165FF1F8EA94AD7CFDC54990738A4C53F6E0507B42154201B8E5DFF3B1
    pub_keys = [(mult(a), "0014" + hash160(bytes_from_point(mult(a))).hex())]
    monkeypatch.setattr(silent_payments, "is_libsecp256k1_serving", lambda: False)
    for outpoints, outputs, labels, as_bytes in _strided_tweak_cases():
        expected = _scan_paid(outpoints, outputs, as_bytes)
        assert len(expected) == 1
        assert _scan_paid(outpoints, outputs, labels) == expected
        found = silent_payments.scan_transaction_outputs(
            _B_SCAN_PRV, mult(_B_SPEND_PRV), outpoints, pub_keys, outputs, labels
        )
        assert found == expected


@needs_bindings
def test_the_dispatch_reads_a_label_tweak_not_contiguous() -> None:
    """Beside twenty more labels it reaches the bindings, which read it too."""
    a = 0xEADC78165FF1F8EA94AD7CFDC54990738A4C53F6E0507B42154201B8E5DFF3B1
    pub_keys = [(mult(a), "0014" + hash160(bytes_from_point(mult(a))).hex())]
    many = silent_payments.label_lookup(_B_SCAN_PRV, range(6, 26))
    for outpoints, outputs, labels, as_bytes in _strided_tweak_cases():
        expected = _scan_paid(outpoints, outputs, as_bytes)
        assert len(expected) == 1
        for extra in ({}, many):
            found = silent_payments.scan_transaction_outputs(
                _B_SCAN_PRV,
                mult(_B_SPEND_PRV),
                outpoints,
                pub_keys,
                outputs,
                {**labels, **extra},
            )
            assert found == expected
        delegated = silent_payments._delegated_scan_outputs(
            _B_SCAN_PRV, outpoints, pub_keys, mult(_B_SPEND_PRV), outputs, labels
        )
        assert delegated == expected


def test_labels_that_are_no_mapping_are_refused() -> None:
    """A list or a tuple of labels is refused, as the bindings refuse it."""
    a = 0xEADC78165FF1F8EA94AD7CFDC54990738A4C53F6E0507B42154201B8E5DFF3B1
    pub_keys = [(mult(a), "0014" + hash160(bytes_from_point(mult(a))).hex())]
    outpoints, keys = _paid_with_labels([0])
    ((key, tweak),) = silent_payments.label_lookup(_B_SCAN_PRV, [0]).items()
    for labels in ([key], ((key, tweak),)):
        message = f"^the labels must be a mapping, not {type(labels).__name__}$"
        bad = cast("dict[bytes, bytes]", labels)
        with pytest.raises(BTClibTypeError, match=message):
            _scan_paid(outpoints, keys, bad)
        with pytest.raises(BTClibTypeError, match=message):
            silent_payments.scan_transaction_outputs(
                _B_SCAN_PRV, mult(_B_SPEND_PRV), outpoints, pub_keys, keys, bad
            )


@needs_bindings
def test_the_bindings_refuse_labels_that_are_no_mapping_alike() -> None:
    """The bindings give the same message, with their own TypeError."""
    a = 0xEADC78165FF1F8EA94AD7CFDC54990738A4C53F6E0507B42154201B8E5DFF3B1
    pub_keys = [(mult(a), "0014" + hash160(bytes_from_point(mult(a))).hex())]
    outpoints, keys = _paid_with_labels([0])
    ((key, _tweak),) = silent_payments.label_lookup(_B_SCAN_PRV, [0]).items()
    with pytest.raises(TypeError, match="^the labels must be a mapping, not list$"):
        silent_payments._delegated_scan_outputs(
            _B_SCAN_PRV,
            outpoints,
            pub_keys,
            mult(_B_SPEND_PRV),
            keys,
            cast("dict[bytes, bytes]", [key]),
        )


@needs_bindings
def test_the_bindings_skip_a_label_that_is_no_point_too() -> None:
    """The same cases as `test_a_label_that_is_no_point_matches_nothing`."""
    a = 0xEADC78165FF1F8EA94AD7CFDC54990738A4C53F6E0507B42154201B8E5DFF3B1
    script_pub_key = "0014" + hash160(bytes_from_point(mult(a))).hex()
    for outpoints, outputs, labels, found in _malformed_label_cases():
        scanned = silent_payments._delegated_scan_outputs(
            _B_SCAN_PRV,
            outpoints,
            [(mult(a), script_pub_key)],
            mult(_B_SPEND_PRV),
            outputs,
            labels,
        )
        assert len(scanned) == found


def test_a_scan_stops_at_an_output_whose_label_it_does_not_hold() -> None:
    """The first k that matches nothing ends the walk, label or not.

    The third output carries label 5, which the wallet does not hold in
    either of the two ways of checking, so only the first two are found
    though the fourth would be.
    """
    outpoints, keys = _paid_with_labels([0, 1, 5, 0])
    for labelled in ([0, 1], list(range(5))):
        labels = silent_payments.label_lookup(_B_SCAN_PRV, labelled)
        found = _scan_paid(outpoints, keys, labels)
        assert [output.pub_key for output in found] == keys[:2]


def test_a_label_that_cancels_p_k_is_no_output() -> None:
    """P_k plus the label is infinity, which has no x-only key to match.

    The spend key is chosen so that P_0 is the negative of label 0's
    point: a wallet whose keys are so related to its labels can only be
    built on purpose, and the scan has to walk past it and not raise.
    """
    outpoints = [OutPoint("00" * 31 + "01", 7)]
    tweak = silent_payments.tweak_data(outpoints, mult(3))
    secret = silent_payments.shared_secret(_B_SCAN_PRV, tweak)
    t_0 = silent_payments._output_tweak(secret, 0)
    label = silent_payments.label_tweak(_B_SCAN_PRV, 0)
    b_spend = secp256k1.n - (t_0 + label) % secp256k1.n
    labels = silent_payments.label_lookup(_B_SCAN_PRV, [0])
    other = bytes_from_point(mult(5))[1:]

    found = silent_payments.scan_outputs(
        _B_SCAN_PRV, mult(b_spend), tweak, [other], labels
    )
    assert found == []


def test_a_spending_key_of_zero_is_refused() -> None:
    """b_spend + tweak is a private key, and zero is not one."""
    tweak = secp256k1.n - _B_SPEND_PRV
    with pytest.raises(BTClibValueError, match="sum to zero"):
        silent_payments.prv_key_from_tweak(_B_SPEND_PRV, tweak)


@needs_bindings
@pytest.mark.parametrize("index,test", _SENDING, ids=_SENDING_IDS)
def test_output_keys_matches_across_arms(
    index: int, test: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The delegated and the Python arm answer the same set of outputs.

    `output_keys`'s own dispatch is `is_libsecp256k1_serving()`,
    imported into this module's own namespace the way `dsa` and
    `ssa` import theirs, so a vector is run twice with the predicate
    patched between the two -- the same shape `dsa_test.py`'s own
    cross-arm tests use. `test_sending_vectors` already carries every
    other assertion this file makes about a vector, including the two
    refusals (a zero private-key sum, more than K_MAX recipients sharing
    a scan key), which is why this asks only whether the two arms refuse
    together or agree on the answer.
    """
    given, expected = test["given"], test["expected"]
    prv_keys = [
        (v["private_key"], v["prevout"]["scriptPubKey"]["hex"])
        for v in given["vin"]
        if _pub_key_of(v) is not None
    ]
    if not prv_keys:
        pytest.skip("nothing eligible to derive a secret from")
    addresses = [recipient["address"] for recipient in _recipients(given)]
    outpoints = _outpoints(given["vin"])

    def _keys(*, delegated: bool) -> list[bytes] | None:
        with monkeypatch.context() as arm:
            if not delegated:
                arm.setattr(silent_payments, "is_libsecp256k1_serving", lambda: False)
            try:
                return silent_payments.output_keys(prv_keys, outpoints, addresses)
            except BTClibValueError:
                return None

    delegated_keys = _keys(delegated=True)
    python_keys = _keys(delegated=False)
    assert (delegated_keys is None) == (python_keys is None)
    if delegated_keys is not None:
        assert python_keys is not None
        assert set(delegated_keys) == set(python_keys)
        assert expected["outputs"] and any(
            {key.hex() for key in delegated_keys} == set(valid)
            for valid in expected["outputs"]
        )


@needs_bindings
def test_output_keys_interleaved_groups_match_across_arms(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two scan keys interleaved, one of them labelled, taproot and not.

    The vector file has no case mixing a taproot and a non-taproot input
    while addressing two recipients out of order -- X, Y, X's second
    label -- so this is the case built by hand: it is the one shape where
    a grouping mismatch between the two arms would show up as a wrong
    *set*, not merely a wrong order, because `keys_from_address(X)`'s
    second address shares X's group and gets the next k after X's first.
    """
    a_taproot = 0xEADC78165FF1F8EA94AD7CFDC54990738A4C53F6E0507B42154201B8E5DFF3B1
    a_legacy = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCD
    taproot_script = "5120" + bytes_from_point(mult(a_taproot))[1:].hex()
    legacy_script = "0014" + hash160(bytes_from_point(mult(a_legacy))).hex()
    prv_keys = [(a_taproot, taproot_script), (a_legacy, legacy_script)]
    outpoints = [OutPoint("00" * 31 + "01", 0), OutPoint("00" * 31 + "02", 1)]

    x_scan, x_spend = 0x11, 0x22
    y_scan, y_spend = 0x33, 0x44
    x_address = silent_payments.address_from_keys(mult(x_scan), mult(x_spend))
    y_address = silent_payments.address_from_keys(mult(y_scan), mult(y_spend))
    x_labelled = silent_payments.labeled_address_from_keys(x_scan, mult(x_spend), 1)
    addresses = [x_address, y_address, x_labelled]

    delegated = silent_payments.output_keys(prv_keys, outpoints, addresses)
    with monkeypatch.context() as no_bindings:
        no_bindings.setattr(silent_payments, "is_libsecp256k1_serving", lambda: False)
        python = silent_payments.output_keys(prv_keys, outpoints, addresses)
    assert len(delegated) == len(addresses)
    assert set(delegated) == set(python)


@pytest.mark.parametrize(
    "delegated",
    [pytest.param(True, marks=needs_bindings, id="bindings"), False],
    ids=["bindings", "python"],
)
def test_output_keys_come_back_in_address_order(
    delegated: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Key i belongs to address i, though A1 and A2 share a scan key.

    `[A1, B, A2]` is grouped A1, A2, B inside, and k is assigned per
    group: 0 for A1, 1 for A2, 0 for B. Each expected key is built by
    hand from `output_key` with that k, so the test fails both on a key
    out of place and on a k assigned by position in the list.
    """
    a = 0xEADC78165FF1F8EA94AD7CFDC54990738A4C53F6E0507B42154201B8E5DFF3B1
    prv_keys = [(a, "5120" + bytes_from_point(mult(a))[1:].hex())]
    outpoints = [OutPoint("00" * 31 + "01", 0)]

    a_scan, a_spend, b_scan, b_spend = 0x11, 0x22, 0x33, 0x44
    a1 = silent_payments.address_from_keys(mult(a_scan), mult(a_spend))
    a2 = silent_payments.labeled_address_from_keys(a_scan, mult(a_spend), 1)
    b = silent_payments.address_from_keys(mult(b_scan), mult(b_spend))
    addresses = [a1, b, a2]

    scalar = (
        silent_payments.input_hash(
            outpoints, mult(silent_payments.prv_key_sum(prv_keys))
        )
        * silent_payments.prv_key_sum(prv_keys)
    ) % secp256k1.n
    expected = []
    for address, k in zip(addresses, [0, 0, 1], strict=True):
        B_scan, B_m, _ = silent_payments.keys_from_address(address)
        secret = silent_payments.shared_secret(scalar, B_scan)
        expected.append(silent_payments.output_key(secret, B_m, k))

    with monkeypatch.context() as arm:
        if not delegated:
            arm.setattr(silent_payments, "is_libsecp256k1_serving", lambda: False)
        keys = silent_payments.output_keys(prv_keys, outpoints, addresses)
    assert keys == expected


def test_output_keys_pays_nothing_for_no_addresses() -> None:
    """No recipient is nothing to derive, on either arm.

    `create_outputs` itself refuses an empty recipient list -- "at least
    one recipient is required" -- so `output_keys` answers before
    reaching it, the same `[]` the Python loop below would have built
    from an empty `groups`.
    """
    script_pub_key = "0014" + hash160(bytes_from_point(mult(_B_SCAN_PRV))).hex()
    outpoints = [OutPoint("00" * 31 + "01", 0)]
    assert (
        silent_payments.output_keys([(_B_SCAN_PRV, script_pub_key)], outpoints, [])
        == []
    )


_NETWORKS = ("mainnet", "testnet", "signet", "testnet4", "regtest")
_HRPS = {
    "mainnet": "sp",
    "testnet": "tsp",
    "signet": "tsp",
    "testnet4": "tsp",
    "regtest": "sprt",
}
# (network, the network whose address it is given), with another hrp
_MISMATCHES = [
    (network, other)
    for network in _NETWORKS
    for other in _NETWORKS
    if _HRPS[network] != _HRPS[other]
]


def _pay(addresses: list[str], network: str | None = None) -> list[bytes]:
    """Call `output_keys` from one segwit input, on `network` where given."""
    script_pub_key = "0014" + hash160(bytes_from_point(mult(_B_SCAN_PRV))).hex()
    prv_keys = [(_B_SCAN_PRV, script_pub_key)]
    outpoints = [OutPoint("00" * 31 + "01", 0)]
    if network is None:
        return silent_payments.output_keys(prv_keys, outpoints, addresses)
    return silent_payments.output_keys(prv_keys, outpoints, addresses, network)


@pytest.mark.parametrize("network", _NETWORKS)
def test_output_keys_accepts_the_address_of_its_network(network: str) -> None:
    """Each network's own address is paid, and the key does not depend on it."""
    assert _pay([_address(network=network)], network) == _pay([_address()])


def test_output_keys_defaults_to_mainnet() -> None:
    """No `network` is mainnet: an "sp" address is paid, the others refused."""
    assert len(_pay([_address()])) == 1
    for network in _NETWORKS[1:]:
        with pytest.raises(BTClibValueError, match="invalid hrp for mainnet"):
            _pay([_address(network=network)])


@pytest.mark.parametrize("network,address_network", _MISMATCHES)
def test_output_keys_refuses_the_address_of_another_network(
    network: str, address_network: str
) -> None:
    """The hrp has to be the network's own: "tsp" is not regtest's "sprt"."""
    with pytest.raises(BTClibValueError, match="invalid hrp for"):
        _pay([_address(network=address_network)], network)
    # one wrong address among right ones refuses the whole call
    with pytest.raises(BTClibValueError, match="invalid hrp for"):
        _pay([_address(network=network), _address(network=address_network)], network)


def test_output_keys_refuses_an_unknown_network_first() -> None:
    """The network is checked before any key is read.

    An empty key list is refused by `prv_key_sum` too: the message says
    which check came first.
    """
    outpoints = [OutPoint("00" * 31 + "01", 0)]
    with pytest.raises(BTClibValueError, match="sum to zero"):
        silent_payments.output_keys([], outpoints, [_address()])
    with pytest.raises(BTClibValueError, match="unknown network: 'mainet'"):
        silent_payments.output_keys([], outpoints, [_address()], "mainet")


@needs_bindings
def test_output_keys_wraps_a_delegated_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    """`create_outputs`'s own ValueError still comes back a BTClibValueError.

    `prv_key_sum` and `input_hash` already cover the two refusals a real
    transaction can trigger -- a zero private-key sum, no outpoint -- so
    this is not a case the vector file has: the bindings' own message for
    whatever else `secp256k1_silentpayments_sender_create_outputs` itself
    refuses (an output landing on the point at infinity, say) is
    substituted for rather than reproduced.
    """

    def _refuse(*_args: object, **_kwargs: object) -> list[bytes]:
        raise ValueError("silent payment output creation failed")

    monkeypatch.setattr(libsecp256k1_silentpayments, "create_outputs", _refuse)
    script_pub_key = "0014" + hash160(bytes_from_point(mult(_B_SCAN_PRV))).hex()
    outpoints = [OutPoint("00" * 31 + "01", 0)]
    with pytest.raises(BTClibValueError, match="silent payment output creation failed"):
        silent_payments.output_keys(
            [(_B_SCAN_PRV, script_pub_key)], outpoints, [_address()]
        )


@needs_bindings
@pytest.mark.parametrize("index,test", _RECEIVING, ids=_RECEIVING_IDS)
def test_scan_transaction_outputs_matches_across_arms(
    index: int, test: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The delegated and the Python arm of the full-node scan agree.

    The delegated arm is called itself, and the Python one through
    `scan_transaction_outputs` with `is_libsecp256k1_serving()` patched,
    `test_output_keys_matches_across_arms`'s own shape.
    `test_receiving_vectors` already checks the light client's
    `scan_outputs` against the vector file directly; this asks whether
    the full-node entry point's two arms agree with each other and with
    that same file.
    """
    given, expected = test["given"], test["expected"]
    b_scan = given["key_material"]["scan_priv_key"]
    b_spend = given["key_material"]["spend_priv_key"]
    B_spend = mult(b_spend)

    pub_keys = [
        (pub_key, v["prevout"]["scriptPubKey"]["hex"])
        for v in given["vin"]
        if (pub_key := _pub_key_of(v)) is not None
    ]
    if not pub_keys:
        pytest.skip("nothing eligible to derive a shared secret from")

    outpoints = _outpoints(given["vin"])
    labels = silent_payments.label_lookup(b_scan, given["labels"])

    def _scan(*, delegated: bool) -> list[silent_payments.SilentPaymentOutput] | None:
        with monkeypatch.context() as arm:
            if not delegated:
                arm.setattr(silent_payments, "is_libsecp256k1_serving", lambda: False)
            try:
                if delegated:
                    # the arm itself: which of the two the dispatch picks
                    # depends on the labels, and is tested apart
                    return silent_payments._delegated_scan_outputs(
                        b_scan, outpoints, pub_keys, B_spend, given["outputs"], labels
                    )
                return silent_payments.scan_transaction_outputs(
                    b_scan, B_spend, outpoints, pub_keys, given["outputs"], labels
                )
            except BTClibValueError:
                return None

    delegated_found = _scan(delegated=True)
    python_found = _scan(delegated=False)
    assert (delegated_found is None) == (python_found is None)
    if delegated_found is None:
        # the input public keys sum to infinity: BIP352 skips the
        # transaction, which `test_receiving_vectors` already reads as
        # an empty outputs list for this same vector
        assert expected["outputs"] == []
        return
    assert python_found is not None

    delegated_set = {(o.pub_key.hex(), o.prv_key_tweak) for o in delegated_found}
    python_set = {(o.pub_key.hex(), o.prv_key_tweak) for o in python_found}
    assert delegated_set == python_set

    if "n_outputs" in expected:
        # the K_MAX case, where the file counts rather than lists
        assert len(delegated_found) == expected["n_outputs"]
    else:
        assert delegated_set == {
            (o["pub_key"], int(o["priv_key_tweak"], 16)) for o in expected["outputs"]
        }


@needs_bindings
@pytest.mark.parametrize("index,test", _RECEIVING, ids=_RECEIVING_IDS)
def test_scan_transaction_outputs_accepts_no_labels_on_the_real_bindings(
    index: int, test: dict[str, Any]
) -> None:
    """`labels=None` reaches `silentpayments.scan_outputs` unconverted.

    The arm is called itself: no labels is a wallet the dispatch scans
    in Python.

    Every other real-bindings call in this file always builds a
    `label_lookup(...)` map first -- `test_receiving_vectors` and
    `test_scan_transaction_outputs_matches_across_arms` both do --  and
    `test_scan_transaction_outputs_wraps_a_delegated_refusal` calls with
    `labels=None` but monkeypatches `scan_outputs` itself, so the real
    function never sees `None` in either case. This is the one test that
    does, and it asks the same question `test_receiving_vectors` asks of
    the filled-map case: that the full-node entry point's delegated arm
    agrees with the light client's own Python arm, `scan_outputs`, on the
    same input -- here, no labels at all.
    """
    given, expected = test["given"], test["expected"]
    b_scan = given["key_material"]["scan_priv_key"]
    b_spend = given["key_material"]["spend_priv_key"]
    B_spend = mult(b_spend)

    pub_keys = [
        (pub_key, v["prevout"]["scriptPubKey"]["hex"])
        for v in given["vin"]
        if (pub_key := _pub_key_of(v)) is not None
    ]
    if not pub_keys:
        pytest.skip("nothing eligible to derive a shared secret from")

    outpoints = _outpoints(given["vin"])

    try:
        delegated_found = silent_payments._delegated_scan_outputs(
            b_scan, outpoints, pub_keys, B_spend, given["outputs"], labels=None
        )
    except BTClibValueError:
        # the input public keys sum to infinity: BIP352 skips the
        # transaction, the same fact `test_receiving_vectors` reads as an
        # empty outputs list for this same vector
        assert expected["outputs"] == []
        return

    A_sum = silent_payments.pub_key_sum([pub_key for pub_key, _ in pub_keys])
    tweak = silent_payments.tweak_data(outpoints, A_sum)
    light_client_found = silent_payments.scan_outputs(
        b_scan, B_spend, tweak, given["outputs"], labels=None
    )
    assert {(o.pub_key, o.prv_key_tweak) for o in delegated_found} == {
        (o.pub_key, o.prv_key_tweak) for o in light_client_found
    }


@needs_bindings
def test_scan_transaction_outputs_wraps_a_delegated_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`silentpayments.scan_outputs`'s own ValueError comes back wrapped.

    `pub_key_sum` and `input_hash` already cover the two refusals a real
    transaction can trigger -- infinite input key sum, no outpoint -- the
    same pair `test_output_keys_wraps_a_delegated_refusal` names, so this
    is not a case the vector file has either: the bindings' own message
    for whatever else `secp256k1_silentpayments_receiver_scan_outputs`
    refuses is substituted for rather than reproduced.
    """

    def _refuse(*_args: object, **_kwargs: object) -> list[tuple[bytes, bytes, None]]:
        raise ValueError("silent payment scan failed")

    monkeypatch.setattr(libsecp256k1_silentpayments, "scan_outputs", _refuse)
    script_pub_key = "0014" + hash160(bytes_from_point(mult(_B_SCAN_PRV))).hex()
    pub_keys = [(mult(_B_SCAN_PRV), script_pub_key)]
    outpoints = [OutPoint("00" * 31 + "01", 0)]
    labels = silent_payments.label_lookup(_B_SCAN_PRV, range(4))
    with pytest.raises(BTClibValueError, match="silent payment scan failed"):
        silent_payments.scan_transaction_outputs(
            _B_SCAN_PRV,
            mult(_B_SPEND_PRV),
            outpoints,
            pub_keys,
            [bytes_from_point(mult(2))[1:]],
            labels,
        )


@needs_bindings
@pytest.mark.parametrize(
    "n_labels,n_outputs,delegated",
    [
        (0, 1, False),
        (3, 1, False),
        (3, 100, False),
        (4, 1, True),
        (4, 39, True),
        (4, 40, False),
        (5, 49, True),
        (5, 50, False),
        (20, 100, True),
        (20, 200, False),
    ],
)
def test_the_scan_is_delegated_above_the_label_rule(
    n_labels: int,
    n_outputs: int,
    delegated: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The dispatch rule sends the scan to the bindings or keeps it.

    Both sides of each edge of the dispatch rule. The outputs are arbitrary x
    coordinates, none of them ours, so the delegated arm is replaced by
    a spy.
    """
    calls = []

    def _spy(*args: object) -> list[silent_payments.SilentPaymentOutput]:
        calls.append(args)
        return []

    monkeypatch.setattr(silent_payments, "_delegated_scan_outputs", _spy)
    script_pub_key = "0014" + hash160(bytes_from_point(mult(_B_SCAN_PRV))).hex()
    pub_keys = [(mult(_B_SCAN_PRV), script_pub_key)]
    outpoints = [OutPoint("00" * 31 + "01", 0)]
    labels = silent_payments.label_lookup(_B_SCAN_PRV, range(n_labels))
    outputs = [bytes_from_point(mult(i + 2))[1:] for i in range(n_outputs)]
    found = silent_payments.scan_transaction_outputs(
        _B_SCAN_PRV, mult(_B_SPEND_PRV), outpoints, pub_keys, outputs, labels
    )
    assert found == []
    assert bool(calls) is delegated


def test_without_the_bindings_the_python_scan_always_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Many labels, few outputs: the rule would delegate, nothing serves.

    The delegated arm is replaced by None, which raises if it is called.
    """
    monkeypatch.setattr(silent_payments, "is_libsecp256k1_serving", lambda: False)
    monkeypatch.setattr(silent_payments, "_delegated_scan_outputs", None)
    script_pub_key = "0014" + hash160(bytes_from_point(mult(_B_SCAN_PRV))).hex()
    pub_keys = [(mult(_B_SCAN_PRV), script_pub_key)]
    outpoints = [OutPoint("00" * 31 + "01", 0)]
    labels = silent_payments.label_lookup(_B_SCAN_PRV, range(20))
    assert (
        silent_payments.scan_transaction_outputs(
            _B_SCAN_PRV, mult(_B_SPEND_PRV), outpoints, pub_keys, [_NOT_AN_X], labels
        )
        == []
    )


@pytest.mark.parametrize("n_labels", [0, 2, 5, 20])
def test_the_scan_answers_alike_whatever_the_labels(
    n_labels: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No outputs is refused, and an output that is no point is walked past.

    The rule picks the scan by the number of labels, and the answer must
    not depend on it: the bindings refuse both, the Python scan neither,
    and `scan_transaction_outputs` makes them one.
    """
    script_pub_key = "0014" + hash160(bytes_from_point(mult(_B_SCAN_PRV))).hex()
    pub_keys = [(mult(_B_SCAN_PRV), script_pub_key)]
    outpoints = [OutPoint("00" * 31 + "01", 0)]
    labels = silent_payments.label_lookup(_B_SCAN_PRV, range(n_labels))
    for serving in (True, False):
        with monkeypatch.context() as arm:
            if not serving:
                arm.setattr(silent_payments, "is_libsecp256k1_serving", lambda: False)
            with pytest.raises(BTClibValueError, match="no outputs"):
                silent_payments.scan_transaction_outputs(
                    _B_SCAN_PRV, mult(_B_SPEND_PRV), outpoints, pub_keys, [], labels
                )
            assert (
                silent_payments.scan_transaction_outputs(
                    _B_SCAN_PRV,
                    mult(_B_SPEND_PRV),
                    outpoints,
                    pub_keys,
                    [_NOT_AN_X],
                    labels,
                )
                == []
            )
            # and the outputs that are points are still scanned
            tweak = silent_payments.tweak_data(outpoints, mult(_B_SCAN_PRV))
            secret = silent_payments.shared_secret(_B_SCAN_PRV, tweak)
            ours = silent_payments.output_key(secret, mult(_B_SPEND_PRV), 0)
            found = silent_payments.scan_transaction_outputs(
                _B_SCAN_PRV,
                mult(_B_SPEND_PRV),
                outpoints,
                pub_keys,
                [_NOT_AN_X, ours],
                labels,
            )
            assert [output.pub_key for output in found] == [ours]


@pytest.mark.parametrize("n_labels", [0, 2, 5, 20])
def test_a_bad_key_is_refused_whatever_the_scan(
    n_labels: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A scan key out of range and a spend key off the curve are refused.

    With no output a point, the bindings refuse the outputs and the scan
    answers [] without a retry, so the keys are checked before either
    scan is chosen. The refusal is the same error whichever scan the rule
    picks.
    """
    script_pub_key = "0014" + hash160(bytes_from_point(mult(_B_SCAN_PRV))).hex()
    pub_keys = [(mult(_B_SCAN_PRV), script_pub_key)]
    outpoints = [OutPoint("00" * 31 + "01", 0)]
    labels = silent_payments.label_lookup(_B_SCAN_PRV, range(n_labels))
    bad_keys: list[tuple[int, tuple[int, int] | bytes, str]] = [
        (0, mult(_B_SPEND_PRV), "private key not in 1..n-1"),
        (_B_SCAN_PRV, b"\x02" + _NOT_AN_X, "not a public key"),
    ]
    classes = set()
    for serving in (True, False):
        with monkeypatch.context() as arm:
            if not serving:
                arm.setattr(silent_payments, "is_libsecp256k1_serving", lambda: False)
            for outputs in ([_NOT_AN_X], [_NOT_AN_X, bytes_from_point(mult(2))[1:]]):
                for b_scan, B_spend, message in bad_keys:
                    with pytest.raises(ValueError, match=message) as refused:
                        silent_payments.scan_transaction_outputs(
                            b_scan, B_spend, outpoints, pub_keys, outputs, labels
                        )
                    classes.add(type(refused.value))
    assert len(classes) == 1


def _earliest_cases() -> tuple[
    list[
        tuple[
            list[bytes],
            list[silent_payments.SilentPaymentOutput],
            list[list[int]],
        ]
    ],
    tuple[list[OutPoint], list[tuple[tuple[int, int], str]], tuple[int, int]],
    tuple[int, int],
]:
    """Return a transaction where P_0 matches directly and by labels 1 and 2.

    The outputs in four orders with what a scan must find in each and the
    label lists to scan them with, and what a scan takes: the outpoints,
    the input keys, the tweak data and B_spend.
    """
    a = 0xEADC78165FF1F8EA94AD7CFDC54990738A4C53F6E0507B42154201B8E5DFF3B1
    script_pub_key = "0014" + hash160(bytes_from_point(mult(a))).hex()
    outpoints = [OutPoint("00" * 31 + "01", 7)]
    tweak = silent_payments.tweak_data(outpoints, mult(a))
    secret = silent_payments.shared_secret(_B_SCAN_PRV, tweak)
    B_spend = mult(_B_SPEND_PRV)
    labelled = silent_payments.output_key(
        secret, silent_payments.keys_from_address(_address(1))[1], 0
    )
    direct = silent_payments.output_key(secret, B_spend, 0)
    t_0 = silent_payments._output_tweak(secret, 0)
    label = silent_payments.label_tweak(_B_SCAN_PRV, 1)
    by_label = silent_payments.SilentPaymentOutput(
        labelled, (t_0 + label) % secp256k1.n
    )
    by_direct = silent_payments.SilentPaymentOutput(direct, t_0)
    labelled_2 = silent_payments.output_key(
        secret, silent_payments.keys_from_address(_address(2))[1], 0
    )
    by_label_2 = silent_payments.SilentPaymentOutput(
        labelled_2, (t_0 + silent_payments.label_tweak(_B_SCAN_PRV, 2)) % secp256k1.n
    )
    direct_labels = [[0, 1], [1, 0], list(range(5))]
    # both match through a label: the earlier output, not the first label
    # of the map, and the map in both orders
    both_labels = [[1, 2], [2, 1], list(range(5))]
    cases = [
        ([labelled, direct], [by_label], direct_labels),
        ([direct, labelled], [by_direct], direct_labels),
        ([labelled_2, labelled], [by_label_2], both_labels),
        ([labelled, labelled_2], [by_label], both_labels),
    ]
    return cases, (outpoints, [(mult(a), script_pub_key)], tweak), B_spend


def test_the_earliest_output_wins_whether_direct_or_by_label() -> None:
    """At one k, an earlier output by label beats a later direct match.

    BIP352 and libsecp256k1 walk the outputs in order and take the first
    that matches P_k, directly or through a label. The transaction has
    P_0 plus label 1 first and P_0 itself second, and then the other way
    round; then P_0 plus label 2 and P_0 plus label 1, in both orders. The
    labels are given addition's way (as many as outputs) and
    subtraction's (more).
    """
    cases, (_, _, tweak), B_spend = _earliest_cases()
    for outputs, expected, label_lists in cases:
        for m_values in label_lists:
            labels = silent_payments.label_lookup(_B_SCAN_PRV, m_values)
            found = silent_payments.scan_outputs(
                _B_SCAN_PRV, B_spend, tweak, outputs, labels
            )
            assert found == expected


@needs_bindings
def test_the_bindings_take_the_earliest_output_too() -> None:
    """The same transaction as `test_the_earliest_output_wins...`."""
    cases, (outpoints, pub_keys, _tweak), B_spend = _earliest_cases()
    for outputs, expected, label_lists in cases:
        for m_values in label_lists:
            labels = silent_payments.label_lookup(_B_SCAN_PRV, m_values)
            found = silent_payments._delegated_scan_outputs(
                _B_SCAN_PRV, outpoints, pub_keys, B_spend, outputs, labels
            )
            assert found == expected


def test_one_output_is_not_a_list_of_them() -> None:
    """Octets are a Sequence too, and iterating one yields its octets.

    A caller passing the one output it has, rather than a list holding
    it, would otherwise zip through its bytes and check each as its own
    output (issue btclib-org/btclib#1405). Both scan entry points refuse it.
    """
    script_pub_key = "0014" + hash160(bytes_from_point(mult(_B_SCAN_PRV))).hex()
    pub_keys = [(mult(_B_SCAN_PRV), script_pub_key)]
    outpoints = [OutPoint("00" * 31 + "01", 0)]

    with pytest.raises(BTClibTypeError, match="invalid outputs_to_check type"):
        silent_payments.scan_transaction_outputs(
            _B_SCAN_PRV,
            mult(_B_SPEND_PRV),
            outpoints,
            pub_keys,
            cast("Any", _NOT_AN_X),
        )
    with pytest.raises(BTClibTypeError, match="invalid outputs_to_check type"):
        silent_payments.scan_transaction_outputs(
            _B_SCAN_PRV, mult(_B_SPEND_PRV), outpoints, pub_keys, cast("Any", None)
        )
    with pytest.raises(BTClibTypeError, match="invalid outputs_to_check type"):
        silent_payments.scan_outputs(
            _B_SCAN_PRV, mult(_B_SPEND_PRV), mult(3), cast("Any", _NOT_AN_X)
        )


def test_the_whole_round_trip_without_a_vector() -> None:
    """Pay this wallet from one input, then find and spend the output.

    The vectors do this too, from both ends, but each end reads the
    other's answer out of the file. Here the sender's output is the
    scanner's input, so the two halves are held to each other rather than
    to a recorded value -- which is what would catch the pair drifting
    together.
    """
    a = 0xEADC78165FF1F8EA94AD7CFDC54990738A4C53F6E0507B42154201B8E5DFF3B1
    script_pub_key = "0014" + hash160(bytes_from_point(mult(a))).hex()
    outpoints = [OutPoint("00" * 31 + "01", 7), OutPoint("00" * 31 + "02", 0)]
    addresses = [_address(), _address(0), _address(0)]

    keys = silent_payments.output_keys([(a, script_pub_key)], outpoints, addresses)
    assert len(set(keys)) == len(addresses)

    A_sum = silent_payments.pub_key_sum([mult(a)])
    tweak = silent_payments.tweak_data(outpoints, A_sum)
    labels = silent_payments.label_lookup(_B_SCAN_PRV, [0])
    found = silent_payments.scan_outputs(
        _B_SCAN_PRV, mult(_B_SPEND_PRV), tweak, keys, labels
    )
    assert [output.pub_key for output in found] == keys

    for output in found:
        d = silent_payments.prv_key_from_tweak(_B_SPEND_PRV, output.prv_key_tweak)
        assert ssa.verify_(_MSG, output.pub_key, ssa.sign_(_MSG, d, _AUX))


def test_a_hash160_match_that_is_no_public_key_is_walked_past() -> None:
    """A window whose hash matches need not hold a key: the walk goes on.

    Which is what `_pub_key_from_p2pkh`'s comment says and what nothing
    exercised: every p2pkh input elsewhere here carries the key the
    script commits to, so the match was always a key and the loop always
    returned on it. `0x02` over a value that is no x coordinate is 33
    bytes that hash to whatever they hash to, and a script_pub_key built
    from that hash is an input consensus never had to accept -- a
    scanner reading one off a transaction has bytes, not a promise.
    """
    candidate = b"\x02" + _NOT_AN_X
    script_pub_key = b"\x76\xa9\x14" + hash160(candidate) + b"\x88\xac"

    assert (
        silent_payments.pub_key_from_input(script_pub_key, b"\x21" + candidate) is None
    )


def test_a_script_path_spend_counts_unless_its_internal_key_is_nums() -> None:
    """The output key is what a script-path input contributes.

    The NUMS exception is what the vectors exercise, so the comparison
    ran one way only: an input skipped for saying there is no key path to
    sign with, and never one that says there is. The key that counts is
    the output key either way -- not the one the spend used -- so a
    coinjoin peer who could re-spend through the script path cannot
    derive the shared secret with one key and publish a transaction
    proving another.
    """
    output_key = bytes_from_point(mult(3))[1:]
    script_pub_key = b"\x51\x20" + output_key
    tapscript = b"\x51"

    internal_key = bytes_from_point(mult(7))[1:]
    witness = Witness([tapscript, b"\xc0" + internal_key])
    assert silent_payments.pub_key_from_input(script_pub_key, b"", witness) == mult(3)

    nums = Witness([tapscript, b"\xc0" + silent_payments.NUMS_H])
    assert silent_payments.pub_key_from_input(script_pub_key, b"", nums) is None


# The vector bitcoin/bips#2339 adds to BIP352's
# `send_and_receive_test_vectors.json`. Where it is pinned, and why it is
# not in the vendored file, `tests/_data/README.md` says.
_CONTROL_BLOCK_VECTOR = {
    "comment": "Single recipient: taproot script-path spend with invalid control block "
    "size is skipped",
    "sending": [
        {
            "given": {
                "vin": [
                    {
                        "txid": "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
                        "vout": 0,
                        "scriptSig": "",
                        "txinwitness": "0340c459b671370d12cfb5acee76da7e3ba7cc29b0b4653e3af8388591082660137d087fdc8e89a612cd5d15be0febe61fc7cdcf3161a26e599a4514aa5c3e86f47b22205a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5ac22c05a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be500",
                        "prevout": {
                            "scriptPubKey": {
                                "hex": "51205a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5"
                            }
                        },
                        "private_key": "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
                    }
                ],
                "recipients": [
                    {
                        "address": "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
                        "scan_pub_key": "0220bcfac5b99e04ad1a06ddfb016ee13582609d60b6291e98d01a9bc9a16c96d4",
                        "spend_pub_key": "025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36",
                    }
                ],
            },
            "expected": {
                "outputs": [[]],
                "shared_secrets": [None],
                "input_pub_keys": [],
            },
        }
    ],
    "receiving": [
        {
            "given": {
                "vin": [
                    {
                        "txid": "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
                        "vout": 0,
                        "scriptSig": "",
                        "txinwitness": "0340c459b671370d12cfb5acee76da7e3ba7cc29b0b4653e3af8388591082660137d087fdc8e89a612cd5d15be0febe61fc7cdcf3161a26e599a4514aa5c3e86f47b22205a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5ac22c05a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be500",
                        "prevout": {
                            "scriptPubKey": {
                                "hex": "51205a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5"
                            }
                        },
                    }
                ],
                "outputs": [
                    "67fee277da9e8542b5d2e6f32d660a9bbd3f0e107c2d53638ab1d869088882d6"
                ],
                "key_material": {
                    "spend_priv_key": "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
                    "scan_priv_key": "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
                },
                "labels": [],
            },
            "expected": {
                "addresses": [
                    "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv"
                ],
                "outputs": [],
                "tweak": None,
                "shared_secret": None,
            },
        }
    ],
}


def test_a_control_block_vector_skips_the_input_on_the_sending_side() -> None:
    """The 34-byte control block of the vector's witness counts for nothing."""
    # the vector has no position in the vendored file
    test_sending_vectors(-1, _CONTROL_BLOCK_VECTOR["sending"][0])


def test_a_control_block_vector_skips_the_input_on_the_receiving_side() -> None:
    """The output paid to the receiver is not found: the input is skipped."""
    test_receiving_vectors(-1, _CONTROL_BLOCK_VECTOR["receiving"][0])


def _control_block_input(size: int, *, annex: bool) -> Witness:
    """Return a script-path witness whose control block is `size` bytes."""
    internal_key = bytes_from_point(mult(7))[1:]
    control_block = (b"\xc0" + internal_key + bytes(max(0, size - 33)))[:size]
    stack = [b"\x51", control_block]
    return Witness([*stack, b"\x50"] if annex else stack)


@pytest.mark.parametrize(
    "size, counts",
    [
        (1, False),
        (33, True),
        (33 + 32 * 128, True),
        (32, False),
        (33 + 32 * 129, False),
        (33 + 1, False),
    ],
)
@pytest.mark.parametrize("annex", [False, True])
def test_a_control_block_counts_only_at_a_length_bip341_allows(
    size: int, counts: bool, annex: bool
) -> None:
    """33 plus a multiple of 32, up to 128 of them; the annex is not in it."""
    output_key = bytes_from_point(mult(3))[1:]
    script_pub_key = b"\x51\x20" + output_key
    witness = _control_block_input(size, annex=annex)

    expected = mult(3) if counts else None
    assert silent_payments.pub_key_from_input(script_pub_key, b"", witness) == expected


@pytest.mark.parametrize("element", [b"\x01", bytes(64), bytes(33 + 1)])
def test_a_key_path_spend_has_no_control_block_to_measure(element: bytes) -> None:
    """One element is a signature, whatever its length."""
    script_pub_key = b"\x51\x20" + bytes_from_point(mult(3))[1:]
    witness = Witness([element])
    assert silent_payments.pub_key_from_input(script_pub_key, b"", witness) == mult(3)


def test_only_ascii_whitespace_is_stripped_from_an_address() -> None:
    """The six characters of Bitcoin Core's `IsSpace`, and nothing else."""
    address = _address()
    expected = silent_payments.keys_from_address(address)
    padded = string.whitespace + address + string.whitespace
    assert silent_payments.keys_from_address(padded) == expected
    for pad in NOT_STRIPPED:
        for spelling in (address, address.upper()):
            with pytest.raises(BTClibValueError):
                silent_payments.keys_from_address(pad + spelling + pad)


def test_repr_leaves_out_the_tweak() -> None:
    """The tweak is a secret.

    With one output's private key it gives the spend private key.
    """
    tweak = 0xDEADBEEF1234
    output = silent_payments.SilentPaymentOutput(b"\x11" * 32, tweak)
    assert str(tweak) not in repr(output)
    assert "prv_key_tweak" not in repr(output)
    assert output.prv_key_tweak == tweak
