# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The btclib_wallet package: what it publishes, and the version metadata.

Everything from a seed to a signed, broadcast transaction, and every
module with a counterparty outside the process -- a device, a node, a
server, a file from another wallet -- built on the protocol package
`btclib`. The dependency points one way: this package imports `btclib`,
and nothing in `btclib` imports this one. A name of this package is
published here and only here: `btclib` does not re-export it.

`__all__` is the root of the package's public tree: the packages and
top-level modules a caller reaches from this name, each of which declares
its own `__all__`. A list rather than `pkgutil.iter_modules`, so that a
module added to the directory does not publish itself.

`name` and the metadata dunders are not in it: each is still an
attribute here, `btclib_wallet.__version__` being how a caller reads the
version.

Nothing is imported eagerly. A module is imported when it is first asked
for, through the `__getattr__` at the bottom of this file, so `import
btclib_wallet` is the metadata lookup below and nothing else, and the
import graph keeps its shape: tests/imports_test.py imports each module
first, in a fresh interpreter, which an eager root would make impossible.
What that costs is that mypy reads a module-level `__getattr__` as a
promise that any attribute may exist, so a misspelling on this package is
a runtime `AttributeError` rather than a reported error; `from
btclib_wallet import bip32` and `import btclib_wallet.bip32` resolve
against the real modules and stay checked.
"""

from importlib import import_module
from importlib.metadata import PackageNotFoundError, version
from types import ModuleType

name = "btclib_wallet"
# read back from the installed distribution, so that pyproject.toml is the
# only place the version is written
try:
    __version__ = version("btclib-wallet")
except PackageNotFoundError:
    # git clone and import, with nothing installed: any number here would
    # be a guess, and importing has to keep working
    __version__ = "unknown"

__all__ = [
    "bip21",
    "bip32",
    "bip38",
    "bip44",
    "bip85",
    "bip322",
    "bolt9",
    "bolt11",
    "coin_selection",
    "core_import",
    "descriptors",
    "fetch",
    "hwi",
    "minikey",
    "mnemonic",
    "psbt",
    "psbt_signer",
    "psbt_signer_contract",
    "silent_payments",
    "slip132",
    "tx_builder",
    "tx_or_psbt",
    "wallet",
]


def __getattr__(published: str) -> ModuleType:
    """Import a published module the first time it is asked for.

    PEP 562: this runs only for a name the package does not already have,
    so it answers `btclib_wallet.bip32` once and the import machinery's
    own attribute answers it from then on. What it makes work is
    `getattr(btclib_wallet, "bip32")` on a fresh interpreter, which is how
    a walker reading `__all__` descends, and `from btclib_wallet import
    *`, which asks for each name in the list.

    Anything not in `__all__` raises `AttributeError`, with the
    interpreter's own wording.
    """
    if published in __all__:
        return import_module(f"{__name__}.{published}")
    raise AttributeError(f"module {__name__!r} has no attribute {published!r}")


def __dir__() -> list[str]:
    """Answer with the published tree beside what the package already has.

    `dir(btclib_wallet)` consults this rather than the namespace, so a
    module not yet imported is still in the completion a caller gets at an
    interactive prompt.
    """
    return sorted({*__all__, *globals()})
