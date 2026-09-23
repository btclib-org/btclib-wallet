# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BIP32 derivation with btclib_secp256k1 not installed, in a subprocess.

`btclib._libsecp256k1` asks for the bindings once, at import, so whether
a derivation answers without them can only be asked of an interpreter
that has not imported btclib yet. The bindings are put out of reach by a
meta path finder that refuses the name, in a child interpreter, and this
package is imported after that -- which is what the import does on a
machine that never had them. btclib's own `no_bindings_test.py` asks the
same of btclib's layers.

What the child returns is compared with what this process computes with
the bindings in reach: agreement between the two implementations is the
property, and a child that merely fails to crash proves nothing about it.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

from btclib._libsecp256k1 import ENABLED, INSTALLED

from btclib_wallet.bip32.bip32 import derive, rootxprv_from_seed, xpub_from_xprv
from tests import needs_bindings

# the seed and the paths the child works from: constants, because the two
# processes have to be asked the same question
_SEED = "0f" * 32
_DERIVATION = "m/44h/0h/0h/0/7"
_PUBLIC_DERIVATION = "m/0/7"

# the finder first, the package after it, and the answers as json on
# stdout. `-c` and not a file, so that nothing has to be written to disk
# and cleaned up
_CHILD = """
import json, sys


class RefuseTheBindings:
    def find_spec(self, name, path=None, target=None):
        if name == "btclib_secp256k1" or name.startswith("btclib_secp256k1."):
            raise ImportError("btclib_secp256k1 is out of reach")
        return None


sys.meta_path.insert(0, RefuseTheBindings())

from btclib._libsecp256k1 import INSTALLED
from btclib_wallet.bip32.bip32 import derive, rootxprv_from_seed, xpub_from_xprv

assert "btclib_secp256k1" not in sys.modules, "the finder let the bindings in"

rootxprv = rootxprv_from_seed({seed!r})
print(json.dumps({{
    "installed": INSTALLED,
    "xprv": derive(rootxprv, {derivation!r}),
    "xpub": derive(xpub_from_xprv(rootxprv), {public_derivation!r}),
}}))
"""


def _child_answers() -> dict[str, Any]:
    """Run the child and return what it printed, failing on its stderr."""
    source = _CHILD.format(
        seed=_SEED, derivation=_DERIVATION, public_derivation=_PUBLIC_DERIVATION
    )
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c", source],
        capture_output=True,
        encoding="utf-8",
        check=False,
        # there so that a child that hangs fails as this test rather than
        # as a slow suite holding an xdist worker
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    answers: dict[str, Any] = json.loads(completed.stdout)
    return answers


@needs_bindings
def test_bip32_answers_with_the_bindings_out_of_reach() -> None:
    """Both derivations answer what the bindings answer."""
    assert INSTALLED
    assert ENABLED
    rootxprv = rootxprv_from_seed(_SEED)

    answers = _child_answers()

    assert answers["installed"] is False
    assert answers["xprv"] == derive(rootxprv, _DERIVATION)
    assert answers["xpub"] == derive(xpub_from_xprv(rootxprv), _PUBLIC_DERIVATION)
