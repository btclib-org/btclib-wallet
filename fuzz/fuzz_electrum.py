# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing the response decoders of `btclib_wallet.electrum`.

An Electrum server answers with one line of JSON, and a hostile server
chooses every byte of it. Each typed `*_response` decoder but
`scripthash_get_balance_batch_response` hands the line to
`decode_response`, under the method its request names, and reads the
`result` it returns; the batch decoder reads its array itself. This
harness hands the same bytes to each of them: what the line says decides
which of them accepts it.

`decode_response` is not called on its own. It accepts every reply
object that answers the id with a `result`, whatever that result holds,
so as an entry point it would accept a seed that the decoder written for
it wrongly refuses, and `tests/fuzz_corpus_test.py` would not see that
refusal. `transaction_get_response` and `block_header_response` both
read a `result` that is a bare hex string, so each still accepts the
other's seed.

The line is bytes, and `REQUEST_ID` is the id every seed under
`fuzz/corpus/fuzz_electrum/` answers. `HEADERS_ASKED` is the number of
headers the request behind `block_headers.bin` asked for, and `BATCH_IDS`
the ids a balance batch asked for.

`scripthash_get_history.bin` is written from the seeds beside it. Its
`tx_hash` is the id `Tx.parse` gives the transaction
`transaction_get.bin` answers. Its `height` is 170:
`assert_merkle_proof` proves that id, with the branch
`transaction_get_merkle.bin` answers, against the header
`block_header.bin` answers, and `headers_subscribe.bin` answers that
header at height 170.

`BTClibException` is the decoders' own refusal of a line that is no
valid answer, and `RpcError` is a server's own error object, which is
one too. Any other exception is a defect in the decoder and propagates
to atheris as the finding it is.

No round trip is asserted: the answer is a JSON line, which has many
spellings of one value (whitespace, key order, escapes, number forms), and
what the decoders return is not a serialization of it.
"""

from __future__ import annotations

import contextlib
import sys

import atheris
from btclib.exceptions import BTClibException

from btclib_wallet import electrum

REQUEST_ID = 1
HEADERS_ASKED = 2
BATCH_IDS = (1,)

# what each entry point takes after the line. tests/fuzz_corpus_test.py
# reads this with ast and checks it against fuzz_target's calls. It also
# loads this module with a placeholder for the CI-only atheris, so
# atheris may be called only from main()
ENTRY_POINTS = {
    "btclib_wallet.electrum:transaction_get_response": (REQUEST_ID,),
    "btclib_wallet.electrum:headers_subscribe_response": (REQUEST_ID,),
    "btclib_wallet.electrum:block_header_response": (REQUEST_ID,),
    "btclib_wallet.electrum:block_headers_response": (REQUEST_ID, HEADERS_ASKED),
    "btclib_wallet.electrum:transaction_get_merkle_response": (REQUEST_ID,),
    "btclib_wallet.electrum:estimate_fee_response": (REQUEST_ID,),
    "btclib_wallet.electrum:scripthash_get_balance_response": (REQUEST_ID,),
    "btclib_wallet.electrum:scripthash_get_balance_batch_response": (BATCH_IDS,),
    "btclib_wallet.electrum:scripthash_get_history_response": (REQUEST_ID,),
}


def fuzz_target(data: bytes) -> None:
    """Decode `data` as the answer to each request in turn."""
    with contextlib.suppress(BTClibException):
        electrum.transaction_get_response(data, REQUEST_ID)
    with contextlib.suppress(BTClibException):
        electrum.headers_subscribe_response(data, REQUEST_ID)
    with contextlib.suppress(BTClibException):
        electrum.block_header_response(data, REQUEST_ID)
    with contextlib.suppress(BTClibException):
        electrum.block_headers_response(data, REQUEST_ID, HEADERS_ASKED)
    with contextlib.suppress(BTClibException):
        electrum.transaction_get_merkle_response(data, REQUEST_ID)
    with contextlib.suppress(BTClibException):
        electrum.estimate_fee_response(data, REQUEST_ID)
    with contextlib.suppress(BTClibException):
        electrum.scripthash_get_balance_response(data, REQUEST_ID)
    with contextlib.suppress(BTClibException):
        electrum.scripthash_get_balance_batch_response(data, BATCH_IDS)
    with contextlib.suppress(BTClibException):
        electrum.scripthash_get_history_response(data, REQUEST_ID)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
