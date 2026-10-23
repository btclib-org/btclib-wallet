# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The interface a chain backend answers to report the balance of an address.

Kept apart from `Fetcher`, as `Broadcaster` and `FeeEstimator` are,
because not every backend can answer it. `EsploraFetcher` satisfies it.

Not `runtime_checkable`, for the reason `Broadcaster` is not: the
contract below is not what `isinstance(x, BalanceReader)` would verify.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.script import ScriptPubKey

__all__ = ["Balance", "BalanceReader", "script_pub_key_for_network"]


@dataclass(frozen=True)
class Balance:
    """The satoshis an address holds, and the change the mempool makes to them.

    `confirmed` is what confirmed outputs hold. `unconfirmed` is a signed
    change to it, not a second total: it is negative where a mempool
    transaction spends a confirmed output.
    """

    confirmed: int
    unconfirmed: int


def script_pub_key_for_network(address: str, network: str) -> ScriptPubKey:
    """Return the script of `address`, labelled for `network`.

    Refused: an `address` that is not a string (`BTClibTypeError`), that
    btclib cannot decode, or that is spelled differently on `network`
    (`BTClibValueError`). Testnet, testnet4 and signet share their
    prefixes, and regtest shares the base58 ones, so an address is
    accepted on each network that spells it the same way.
    """
    if not isinstance(address, str):
        raise BTClibTypeError(f"invalid address type: {type(address).__name__}")
    decoded = ScriptPubKey.from_address(address)
    script_pub_key = ScriptPubKey(decoded.script, network)
    if script_pub_key.address != decoded.address:
        raise BTClibValueError(f"not an address of {script_pub_key.network}")
    return script_pub_key


class BalanceReader(Protocol):
    """A backend able to report the balance of an address.

    One method and one contract, binding on every implementation of it:

    - the address is checked by `script_pub_key_for_network` before any
      request, so an address of another network is refused rather than
      looked up;
    - the amounts are integers in satoshis, and `confirmed` is not
      negative: an answer breaking either is a `FetchError`.
    """

    def get_balance(self, address: str) -> Balance:
        """Return the balance of `address`."""
        ...
