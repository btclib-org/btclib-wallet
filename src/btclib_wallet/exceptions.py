# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The exception classes this package raises and btclib does not.

Each derives from btclib's class of its kind, so `except BTClibException`
catches these as it catches btclib's own, and `except ValueError` or
`except RuntimeError` catches them too.

The classes carrying a field hand every constructor argument to
`BaseException.__init__` and compose the message in `__str__`. That is
what keeps them picklable, for the reason `btclib.exceptions`' own
docstring gives.
"""

from __future__ import annotations

from typing import Any

from btclib.exceptions import BTClibRuntimeError, BTClibValueError
from typing_extensions import override

__all__ = [
    "FetchError",
    "HttpError",
    "InconclusiveError",
    "NoDescriptorError",
    "RpcError",
    "SignerError",
    "SignerNotFoundError",
]


class FetchError(BTClibRuntimeError):
    """A backend did not answer, or did not answer this.

    A RuntimeError and not a ValueError, which is the distinction worth
    keeping: nothing the caller passed is wrong. The node is down, the
    credentials are stale, the explorer sent html, the transaction is not
    in the index -- retrying later can work, and correcting the argument
    cannot.

    It covers the conversion of an answer too. A backend that replies with
    something which is not a transaction has failed, and reporting that as
    the BTClibValueError `Tx.parse` raised would name the parser rather
    than the host that has to be fixed.

    Declared here rather than taken from `bitcoin_core_rpc`, which raises
    a class of the same name: that package declares zero dependencies and
    imports nothing of btclib's, so its `FetchError` derives from a
    `BTClibRuntimeError` of its own, and an `except BTClibRuntimeError`
    written against btclib would not catch it.
    `btclib_wallet.fetch.fetcher.client_errors` is the one place the two meet.
    """


class HttpError(FetchError):
    """A backend failed at the HTTP layer, and `status` is what it said.

    A field because acting on a status is the caller's job and this
    package retries nothing: a 401 says the credentials are wrong and will
    stay wrong until they are changed, while a 503 from bitcoind says its
    rpc work queue is full and the same request works when the queue
    drains. A caller writing that policy needs to recognise the status,
    and matching on the text of a message is what a field spares them.

    Not every FetchError carries one, and that is the distinction: a
    refused connection and an expired timeout are failures of an exchange
    that never produced a status, and stay a plain FetchError.

    A FetchError still, so code catching that keeps catching this.
    """

    def __init__(self, message: str, status: int) -> None:
        self.status = status
        super().__init__(message, status)

    @override
    def __str__(self) -> str:
        # the message alone, which is what BaseException returns for a
        # single argument and not for the two this carries
        return str(self.args[0])


class RpcError(FetchError):
    """A backend answered with a JSON-RPC error object, and this is it.

    `code` is the backend's own. From bitcoind, `src/rpc/protocol.h`: -5
    is RPC_INVALID_ADDRESS_OR_KEY, which is what `getrawtransaction`
    returns for a transaction it cannot find -- including every
    non-wallet transaction on a node running without `-txindex`. From an
    Electrum server (`btclib_wallet.electrum`), the field carries that
    server's own JSON-RPC 2.0 code instead, nothing here asking anything
    bitcoind-specific of it. A caller that means to tell "no such
    transaction" from "the backend is unreachable" needs the number, and
    parsing it back out of the message is what having a field avoids.

    `data` is JSON-RPC's optional third member of an error object, kept as
    it arrived. Core leaves it out today, so it is None for every error a
    node sends; a method that starts sending one -- or a proxy between the
    two adding its own -- would otherwise have it dropped here, which is
    the one place it cannot be recovered from.

    A FetchError still, so code catching that keeps catching this.
    """

    def __init__(self, message: str, code: int, data: Any = None) -> None:
        self.code = code
        self.data = data
        super().__init__(message, code, data)

    @override
    def __str__(self) -> str:
        return f"{self.args[0]} (rpc error code {self.code})"


class SignerError(BTClibRuntimeError):
    """An external signer failed, and `code` is the number it gave.

    What `btclib_wallet.psbt_signer`'s contract fails with, and what
    `btclib_wallet.hwi` raises around HWI's structured errors: the JSON CLI
    answers `{"error": <msg>, "code": <n>}`, and the number is the part a
    caller acts on. -14 is ACTION_CANCELED, which is somebody pressing the
    button that says no and is not worth a retry; -3 is DEVICE_CONN_ERROR,
    which is a cable and is worth one; -9 is UNAVAILABLE_ACTION, which
    says this model will never do it. Matching on the text of a message is
    what a field spares a caller writing that policy.

    A RuntimeError for the reason `FetchError` is one: nothing the caller
    passed is wrong. The device is unplugged, locked, busy, or its owner
    said no -- retrying can work, and correcting an argument cannot. The
    numbers HWI reserves for a bad argument (-2, -7) arrive here too, that
    being the one thing the code says and the class cannot.

    `code` is None where the failure produced no number: a backend that
    could not be started, an answer that was not JSON, an output past the
    limit. Those are failures of the exchange rather than of the device.
    """

    def __init__(self, message: str, code: int | None = None) -> None:
        self.code = code
        super().__init__(message, code)

    @override
    def __str__(self) -> str:
        if self.code is None:
            return str(self.args[0])
        return f"{self.args[0]} (signer error code {self.code})"


class SignerNotFoundError(SignerError):
    """The backend an adapter runs is not installed.

    A `SignerError` still, so a caller catching that keeps catching this,
    and separate because it is the one failure that is not about a
    device: nothing is unplugged, locked or busy, and no retry will
    change it. A caller that offers signers of several kinds tells "there
    is no hardware here" from "the hardware could not be reached" on this
    class, and the two are not the same thing to report before a signing
    operation.

    Without it the distinction is not recoverable. `btclib_wallet.hwi` turns
    every `OSError` into a `SignerError` -- a missing executable and a
    permission the udev rules do not grant arrive as one class with one
    `code` of None -- so a caller had to either match on the text of a
    message or look for the executable itself, and looking for it is
    asking a second question that can disagree with the first.

    `code` is None, as for every failure of the exchange rather than of a
    device.
    """


class InconclusiveError(BTClibValueError):
    """Not invalid, and not something today's rules can call valid.

    BIP322 answers a signature with one of three states rather than two,
    and this is the third: a `to_sign` whose version is neither 0 nor 2,
    an upgradeable NOP, a witness program of an unknown version. Each of
    them satisfies the script as it runs today, and each is what a soft
    fork can give a meaning to, so a validator saying "valid" would be
    speaking for rules it does not have.

    A BTClibValueError, so code catching that keeps catching this, and
    so that `btclib_wallet.bip322.verify` answers False without a second
    `except`: an inconclusive signature is not one that verified. A
    caller that means to tell the two apart names this class.
    """


class NoDescriptorError(BTClibValueError):
    """No output descriptor states this script: it is not that a lift failed.

    What `btclib_wallet.wallet.ScriptWallet.descriptor` refuses with, and
    the one refusal there that is a fact about the wallet rather than about
    the code asking: a script spelling its timelock `<n> OP_CSV OP_DROP`, or
    ordering a quorum after derivation inside a combinator, is a script
    BIP380 to BIP390 cannot write down -- and will still be one at the
    next release. A caller catching this has an answer ("watch these
    addresses instead"), where a caller catching a parse failure has a
    bug report.

    A BTClibValueError, so code catching that keeps catching this: the
    refusal it most often stands in front of is
    `btclib_wallet.descriptors.miniscript.from_script`'s, which is one.
    """
