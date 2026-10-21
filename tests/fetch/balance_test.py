# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for btclib_wallet.fetch.balance: the address check and `Balance`."""

from __future__ import annotations

import pytest
from btclib.exceptions import BTClibTypeError, BTClibValueError

from btclib_wallet.fetch.balance import Balance, script_pub_key_for_network

P2PKH = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
P2WPKH = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"  # pragma: allowlist secret
TESTNET_P2WPKH = (
    "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"  # pragma: allowlist secret
)
TESTNET_P2PKH = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"  # pragma: allowlist secret


def test_balance_carries_a_signed_mempool_change() -> None:
    """`unconfirmed` is a change to `confirmed`, so it may be negative."""
    balance = Balance(confirmed=10, unconfirmed=-4)
    assert (balance.confirmed, balance.unconfirmed) == (10, -4)


@pytest.mark.parametrize(
    "address, network",
    [
        (P2PKH, "mainnet"),
        (P2WPKH, "mainnet"),
        (TESTNET_P2WPKH, "testnet"),
        (TESTNET_P2WPKH, "testnet4"),
        (TESTNET_P2WPKH, "signet"),
        (TESTNET_P2PKH, "regtest"),
    ],
)
def test_an_address_of_the_network_is_labelled_for_it(
    address: str, network: str
) -> None:
    """The script comes back labelled for the network asked, same spelling."""
    script_pub_key = script_pub_key_for_network(address, network)
    assert script_pub_key.network == network
    assert script_pub_key.address == address


def test_the_spelling_returned_is_the_canonical_one() -> None:
    """Upper case bech32 and surrounding whitespace decode to one address."""
    script_pub_key = script_pub_key_for_network(f" {P2WPKH.upper()}\n", "mainnet")
    assert script_pub_key.address == P2WPKH


@pytest.mark.parametrize(
    "address, network",
    [
        (P2PKH, "testnet"),
        (P2WPKH, "regtest"),
        (TESTNET_P2WPKH, "mainnet"),
        (TESTNET_P2WPKH, "regtest"),
    ],
)
def test_an_address_of_another_network_is_refused(address: str, network: str) -> None:
    """Refused, rather than looked up on a chain it does not belong to."""
    with pytest.raises(BTClibValueError, match=f"^not an address of {network}$"):
        script_pub_key_for_network(address, network)


def test_a_malformed_address_is_refused() -> None:
    """The decoder of btclib is what refuses it."""
    with pytest.raises(BTClibValueError):
        script_pub_key_for_network("not an address", "mainnet")


@pytest.mark.parametrize("address", [P2PKH.encode(), None, 1])
def test_an_address_that_is_no_string_is_refused(address: object) -> None:
    """A wrong type is named, and not rendered."""
    name = type(address).__name__
    with pytest.raises(BTClibTypeError, match=f"^invalid address type: {name}$"):
        script_pub_key_for_network(address, "mainnet")  # type: ignore[arg-type]


def test_an_unknown_network_is_refused() -> None:
    """The network name is checked as every other one is."""
    with pytest.raises(BTClibValueError, match="unknown network"):
        script_pub_key_for_network(P2PKH, "liquid")
