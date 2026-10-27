# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Miniscript parse failures, as Bitcoin Core v31.1 reports them.

Issue btclib-org/btclib-wallet#525. Where Core's miniscript parser fails
without naming a key, Core's descriptor reader names its own fallback:
"A function is needed within P2WSH" inside wsh(), and "'<leaf>' is not a
valid descriptor function" in a tr() leaf, which parse names without the
leaf. What Core names for each descriptor here is what getdescriptorinfo
answered on an offline node.
"""

import pytest
from btclib.b58 import wif_from_prv_key
from btclib.exceptions import BTClibValueError
from btclib.key import PrvKeyData

from btclib_wallet.descriptors import parse
from btclib_wallet.descriptors.miniscript import P2WSH, TAPSCRIPT, Miniscript
from btclib_wallet.descriptors.miniscript import parse as parse_miniscript

K = PrvKeyData(1).pub.sec.hex()
K2 = PrvKeyData(2).pub.sec.hex()
X, X2 = K[2:], K2[2:]
# of the network parse reads by default
WIF = wif_from_prv_key(1, "mainnet")
_P2WSH_FAULT = "^A function is needed within P2WSH$"
_TR_LEAF_FAULT = r"^tr\(\) leaf is not a valid descriptor function$"
_KEY_FAULT = "^invalid key expression$"
_TOO_LARGE = "and_v(v:sha256(" + "00" * 32 + "),"

# a miniscript Core's parser fails on, written for p2wsh with the key K
# and for a tapscript with the key X
FALLBACKS = [
    "foo(1)",
    "and_v(v:pk(K),sha256(zz))",
    "and_v(v:pk(K),sha256(00))",
    "thresh(0,pk(K))",
    "thresh(0,pk(zz))",
    "thresh(2,pk(K))",
    "thresh(x,pk(K))",
    "thresh(99999999999,pk(K))",
    "thresh(9223372036854775808,pk(zz))",
    "thresh(99999999999999999999,pk(zz))",
    "thresh(1)",
    "and_v(v:pk(K),MULTI(x,K))",
    "and_v(v:MULTI(x,K{),pk(K))",
    "and_v(v:MULTI(0,K),pk(K2))",
    "and_v(v:MULTI(1,K,),pk(K2))",
    "and_v(v:MULTI(1),pk(K2))",
    "and_v(v:MULTI(9223372036854775808,zz),pk(K2))",
    "q:pk(K)",
    "vv:pk(K)",
    "vv:pk(zz)",
    "v:v:pk(K)",
    "and_v(v:pk(K),(1))",
    "and_v(v:pk(K),older)",
    "and_v(v:pk(K),pk(K2)x)",
    "and_v(v:pk(K),pk(K2),1)",
    "andor(pk(K),pk(K2))",
    "and_v(v:pk(K),pk(K2))x",
]


def _written_for(expression: str, context: str) -> str:
    """Return the expression with the keys and the multisig of the context."""
    if context == P2WSH:
        return expression.replace("K2", K2).replace("K", K).replace("MULTI", "multi")
    return expression.replace("K2", X2).replace("K", X).replace("MULTI", "multi_a")


@pytest.mark.parametrize("expression", FALLBACKS)
def test_wsh_names_the_p2wsh_fallback(expression: str) -> None:
    """Core names its fallback for wsh(), whatever its parser failed on."""
    text = _written_for(expression, P2WSH)
    for descriptor in (f"wsh({text})", f"sh(wsh({text}))"):
        with pytest.raises(BTClibValueError, match=_P2WSH_FAULT):
            parse(descriptor)


@pytest.mark.parametrize("expression", FALLBACKS)
def test_a_tr_leaf_names_the_leaf_fallback(expression: str) -> None:
    """Core names its fallback for a leaf, whatever its parser failed on."""
    text = _written_for(expression, TAPSCRIPT)
    for descriptor in (f"tr({X},{text})", f"tr({X},{{pk({X2}),{text}}})"):
        with pytest.raises(BTClibValueError, match=_TR_LEAF_FAULT):
            parse(descriptor)


def test_an_empty_expression_is_the_fallback() -> None:
    """Core reads no fragment in an empty argument, and names its fallback."""
    with pytest.raises(BTClibValueError, match=_P2WSH_FAULT):
        parse("wsh()")
    with pytest.raises(BTClibValueError, match=_TR_LEAF_FAULT):
        parse(f"tr({X},)")


def test_a_script_past_the_p2wsh_size_is_the_fallback() -> None:
    """Core counts the size as it reads, and stops at the limit."""
    text = _TOO_LARGE * 100 + "1" + ")" * 100
    with pytest.raises(BTClibValueError, match=_P2WSH_FAULT):
        parse(f"wsh(and_v(v:pk({K}),{text}))")


def test_a_leaf_with_a_private_key_is_not_echoed() -> None:
    """Core's message holds the leaf, and the leaf can hold a private key."""
    with pytest.raises(BTClibValueError) as caught:
        parse(f"tr({X},and_v(v:pk({WIF}),foo(1)))")
    assert WIF not in str(caught.value)


@pytest.mark.parametrize(
    "descriptor",
    [
        f"wsh(and_v(v:pk(zz),pk({K})))",
        f"wsh(and_v(v:multi(1,zz),pk({K2})))",
        f"wsh(and_v(v:multi(-1,zz),pk({K2})))",
        f"tr({X},and_v(v:multi_a(-1,zz),pk({X2})))",
        f"tr({X},and_v(v:pk(zz),pk({X})))",
        "wsh(thresh(99999999999,pk(zz)))",
        f"tr({X},thresh(99999999999,pk(zz)))",
        "wsh(thresh(9223372036854775807,pk(zz)))",
        f"wsh(and_v(v:pk({K}),thresh(12345678901,pk({K2}),s:pk(zz))))",
    ],
)
def test_a_key_core_reads_first_is_the_fault(descriptor: str) -> None:
    """Core names a key it refuses, after a negative or huge threshold too."""
    with pytest.raises(BTClibValueError, match=_KEY_FAULT):
        parse(descriptor)


@pytest.mark.parametrize(
    "descriptor",
    [
        f"wsh(and_v(v:pk({K}),pk({K2})),{K})",
        f"wsh(and_v(v:pk({K}),pk({K2})),)",
        f"sh(wsh(and_v(v:pk({K}),pk({K2})),{K}))",
    ],
)
def test_text_after_a_comma_is_not_the_miniscript_fault(descriptor: str) -> None:
    """Core reads the miniscript up to the comma, and refuses what follows.

    It names no fault there, so parse keeps its own.
    """
    with pytest.raises(
        BTClibValueError, match="^trailing characters after the miniscript$"
    ):
        parse(descriptor)


@pytest.mark.parametrize(
    "expression,context,message",
    [
        ("foo(1)", P2WSH, "^unknown miniscript fragment$"),
        (f"thresh(0,pk({K}))", P2WSH, r"^invalid thresh\(\) threshold: 0$"),
        (f"thresh(2,pk({X}))", TAPSCRIPT, r"^invalid thresh\(\) threshold: 2 of 1$"),
        (f"vv:pk({K})", P2WSH, "^invalid miniscript wrappers: vv:$"),
        (f"and_v(v:pk({K}),sha256(00))", P2WSH, "^invalid size: 1 bytes instead"),
        (
            f"and_v(v:pk({K}),thresh(99999999999,pk({K2})))",
            P2WSH,
            r"^invalid thresh\(\) threshold: 99999999999 of 1$",
        ),
        (
            f"thresh(9223372036854775808,pk({K}))",
            P2WSH,
            r"^invalid thresh\(\) threshold: past an int64_t$",
        ),
        (f"multi(0,{K})", P2WSH, "^invalid k in k-of-n multi: 0$"),
    ],
)
def test_the_standalone_parser_keeps_its_diagnostic(
    expression: str, context: str, message: str
) -> None:
    """The language parser names the fault it found."""
    with pytest.raises(BTClibValueError, match=message):
        parse_miniscript(expression, context)


def test_a_hand_built_thresh_is_refused_past_its_arguments() -> None:
    """The node bounds a threshold that parse refuses before building it."""
    key = parse_miniscript(f"pk({K})")
    with pytest.raises(
        BTClibValueError, match=r"^invalid thresh\(\) threshold: 2 of 1$"
    ):
        Miniscript("thresh", P2WSH, (key,), threshold=2)
