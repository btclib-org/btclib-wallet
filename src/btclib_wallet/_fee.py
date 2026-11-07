# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Fee ceilings shared by transaction construction and extraction."""

from btclib.exceptions import BTClibValueError
from btclib.fee import FeeRate, fee_from_vsize

__all__: list[str] = []

# Core's DEFAULT_MAX_RAW_TX_FEE_RATE (src/node/transaction.h,
# bitcoin/bitcoin@f0de87f040), the default `maxfeerate` of
# `sendrawtransaction`: 0.10 BTC per kvB. Kept below both callers to avoid
# a circular import between the builder and the PSBT it builds.
_DEFAULT_MAX_FEE_RATE = FeeRate(sats_per_kvbyte=10_000_000)


def _assert_max_fee_rate(fee: int, vsize: int, max_fee_rate: FeeRate) -> None:
    """Refuse a fee above the rate ceiling, rounded as CFeeRate::GetFee."""
    ceiling = fee_from_vsize(vsize, max_fee_rate)
    if fee > ceiling:
        err_msg = f"a fee of {fee} satoshi on {vsize} vbytes exceeds "
        err_msg += f"max_fee_rate, which allows {ceiling} satoshi"
        raise BTClibValueError(err_msg)
