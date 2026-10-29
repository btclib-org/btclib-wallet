# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An unclosed "{" after a key fragment, as Bitcoin Core v31.1 reports it.

Issue btclib-org/btclib-wallet#607. Core's ``Expr`` counts a brace as a
bracket, so after ``pk(K){`` the fragment it cuts runs on until a ")"
closes the "{", and the key it reads, ``K){,pk(K2)``, is the fault.
"""

import pytest
from btclib.exceptions import BTClibValueError
from btclib.key import PrvKeyData

from btclib_wallet.descriptors import parse
from btclib_wallet.descriptors.miniscript import P2WSH, TAPSCRIPT
from btclib_wallet.descriptors.miniscript import parse as parse_miniscript

_K = PrvKeyData(1).pub.sec.hex()
_K2 = PrvKeyData(2).pub.sec.hex()
_X = _K[2:]
_X2 = _K2[2:]
_NOT_A_KEY = "^not a key expression$"
_INVALID_KEY = "^invalid key expression$"
_P2WSH_FAULT = "^A function is needed within P2WSH$"


@pytest.mark.parametrize(
    "descriptor,message",
    [
        (f"wsh(and_v(v:pk({_K}){{,pk({_K2})))", _NOT_A_KEY),
        (f"tr({_X},and_v(v:pk({_X}){{,pk({_X2})))", _NOT_A_KEY),
        (f"wsh(or_d(pk({_K}),and_v(v:pk({_K2}){{,older(1))))", _NOT_A_KEY),
        (f"wsh(thresh(1,pk({_K}){{,s:pk({_K2})))", _NOT_A_KEY),
        (f"wsh(and_v(v:pkh({_K}){{,pk({_K2})))", _NOT_A_KEY),
        (f"wsh(and_v(v:pk_k({_K}){{,pk({_K2})))", _NOT_A_KEY),
        (f"wsh(and_v(v:pk_h({_K}){{,pk({_K2})))", _NOT_A_KEY),
        (f"wsh(and_v(v:pk({_K}){{),pk({_K2}))", _INVALID_KEY),
        (f"wsh(and_v(v:pk({_K}{{),pk({_K2})))", _NOT_A_KEY),
        (f"wsh(and_v(v:pk({{{_K}),pk({_K2})))", _NOT_A_KEY),
        (f"wsh(and_v(v:pk({_K})(,pk({_K2})))", _NOT_A_KEY),
    ],
)
def test_a_brace_after_a_key_fragment_is_the_key_fault(
    descriptor: str, message: str
) -> None:
    """Core names the key the brace runs into, not its fallback."""
    with pytest.raises(BTClibValueError, match=message):
        parse(descriptor)


@pytest.mark.parametrize("fragment", ["older", "after"])
def test_a_brace_after_a_timelock_is_the_fallback(fragment: str) -> None:
    """Core reads the number up to the same bracket and refuses it."""
    descriptor = f"wsh(and_v(v:{fragment}(1){{,pk({_K2})))"
    with pytest.raises(BTClibValueError, match=_P2WSH_FAULT):
        parse(descriptor)


@pytest.mark.parametrize(
    "expression,context",
    [
        (f"and_v(v:pk({_K}){{,pk({_K2}))", P2WSH),
        (f"and_v(v:pk({_X}){{,pk({_X2}))", TAPSCRIPT),
    ],
)
def test_the_miniscript_parser_reads_the_key_as_core_does(
    expression: str, context: str
) -> None:
    """The standalone parser cuts the key fragment as the descriptor does."""
    with pytest.raises(BTClibValueError, match=_NOT_A_KEY):
        parse_miniscript(expression, context)
