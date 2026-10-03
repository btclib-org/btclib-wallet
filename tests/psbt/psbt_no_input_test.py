# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A PSBT's global unsigned transaction is read as Core reads it.

Core reads that field as `TX_NO_WITNESS` (`src/psbt.h`), so a `00` after
the version is an empty input list and the next octet the output count,
never BIP144's marker and flag (issue #196).

The vectors are the output of Bitcoin Core v31.1.0's `createpsbt`, called
with no input and the outputs below, each paying a P2WPKH address of its
wallet; the output values are those `decodepsbt` printed.
"""

from __future__ import annotations

import pytest

from btclib_wallet.psbt import Psbt

# createpsbt [] [{<address>: 0.01}, {<address>: 0.02}, ...]
CORE_NO_INPUT = {
    1: (
        "cHNidP8BACkCAAAAAAFAQg8AAAAAABYAFEkcnKypSywk/dz+LDdK2TGoHiefAAAAAAAA",
        [1000000],
    ),
    2: (
        "cHNidP8BAEgCAAAAAAJAQg8AAAAAABYAFEkcnKypSywk/dz+LDdK2TGoHiefgIQeAAAAAAAWABTkHQEV3Yt24uLSeQqYK1zER6ojFwAAAAAAAAA=",
        [1000000, 2000000],
    ),
    3: (
        "cHNidP8BAGcCAAAAAANAQg8AAAAAABYAFEkcnKypSywk/dz+LDdK2TGoHiefgIQeAAAAAAAWABTkHQEV3Yt24uLSeQqYK1zER6ojF8DGLQAAAAAAFgAUbuSuy7dbQxsDUI7aEBI4BJ1qy7sAAAAAAAAAAA==",
        [1000000, 2000000, 3000000],
    ),
    8: (
        "cHNidP8BAP0CAQIAAAAACEBCDwAAAAAAFgAUSRycrKlLLCT93P4sN0rZMageJ5+AhB4AAAAAABYAFOQdARXdi3bi4tJ5CpgrXMRHqiMXwMYtAAAAAAAWABRu5K7Lt1tDGwNQjtoQEjgEnWrLuwAJPQAAAAAAFgAUH8xNltGFiT945ff7E8zm1DJrLvVAS0wAAAAAABYAFC13/xIeHVW7Z4KlfGZ5WkmuuEDzgI1bAAAAAAAWABS0TM8RQH7J54MR+DD5QiuMndgeMMDPagAAAAAAFgAUY2IdeENVVNlhZVjdVBhCYxqtNtkAEnoAAAAAABYAFJL4VgPeDXzRjbOPmpslUfTMoASXAAAAAAAAAAAAAAAAAA==",
        [1000000, 2000000, 3000000, 4000000, 5000000, 6000000, 7000000, 8000000],
    ),
}


@pytest.mark.parametrize("outputs", CORE_NO_INPUT, ids=lambda n: f"{n} outputs")
def test_no_input_psbt_is_read_as_core_reads_it(outputs: int) -> None:
    """A PSBT with no input and `outputs` outputs is read and written back.

    The round trip is the writing side: the unsigned transaction is
    serialized without marker or witness, byte for byte as Core wrote it.
    """
    encoded, values = CORE_NO_INPUT[outputs]
    psbt = Psbt.b64decode(encoded)
    assert psbt.tx.vin == []
    assert [tx_out.value for tx_out in psbt.tx.vout] == values
    assert psbt.tx.version == 2
    assert psbt.tx.lock_time == 0
    assert psbt.b64encode() == encoded
