# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""`btclib_wallet.fetch` with `cryptography` out of reach, as on Windows arm64.

An install on Windows arm64 leaves `cryptography` out unless the
`encryption` extra asks for it. The package still imports, and
`V2PeerTransport`, whose cipher needs it, refuses on construction,
naming the extra. These run whether or not it is installed.
"""

from __future__ import annotations

import subprocess
import sys

import pytest
from btclib.exceptions import BTClibRuntimeError, BTClibValueError

from btclib_wallet.fetch import V2PeerTransport

_MISSING = r"the cryptography package is missing.*btclib-wallet\[encryption\]"

# a fresh interpreter, where every import of `cryptography` fails
_BLOCKED_IMPORT = """
import importlib.abc
import sys


class Refuse(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path, target=None):
        if name.partition(".")[0] == "cryptography":
            raise ImportError(name)
        return None


sys.meta_path.insert(0, Refuse())
import btclib_wallet.fetch
"""


def test_fetch_imports_without_cryptography() -> None:
    """Nothing `btclib_wallet.fetch` imports needs it at import time."""
    run = subprocess.run(  # noqa: S603
        [sys.executable, "-c", _BLOCKED_IMPORT],
        capture_output=True,
        encoding="utf-8",
        check=False,
    )
    assert run.returncode == 0, run.stderr


def test_a_v2_transport_refuses_on_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The refusal names the extra, and the arguments are checked first.

    A module named None in `sys.modules` fails its import, and
    `btclib.p2p.bip324` is imported again, as on a first construction.
    """
    for name in [each for each in sys.modules if each.startswith("cryptography")]:
        monkeypatch.setitem(sys.modules, name, None)
    monkeypatch.setitem(sys.modules, "cryptography", None)
    monkeypatch.delitem(sys.modules, "btclib.p2p.bip324", raising=False)
    with pytest.raises(BTClibRuntimeError, match=_MISSING):
        V2PeerTransport("peer.example", 18444)
    with pytest.raises(BTClibRuntimeError, match=_MISSING):
        V2PeerTransport("peer.example", 18444, v1_fallback=True)
    with pytest.raises(BTClibValueError, match="empty host"):
        V2PeerTransport("", 18444)
