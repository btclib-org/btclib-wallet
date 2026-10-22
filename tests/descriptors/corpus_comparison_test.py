# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Where `parse` agrees with Bitcoin Core and rust-miniscript does not.

`.github/scripts/compare_descriptors.py` hands the descriptors this
repository holds to `parse`, to Bitcoin Core v31.1 and to rust-miniscript
96a1c917. Each test here pins one kind of input on which Core and `parse`
agree and rust-miniscript differs, or on which `parse` stays with the
answer it gives where Core differs. An address is the one Core's
`deriveaddresses` gave on a mainnet node with no chain.

Each test fails if its rule is flipped.
"""

import re

import pytest
from btclib.exceptions import BTClibValueError

from btclib_wallet.descriptors import multipath_descriptors, parse

A = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
B = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
C = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
XA, XB, XC = A[2:], B[2:], C[2:]
# the master key of BIP32's first test vector
XPRV = (
    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6L"
    "nF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
)
XPUB = (
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje"
    "8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
)


@pytest.mark.parametrize(
    "descriptor, addresses",
    [
        pytest.param(
            "addr(3PUNyaW7M55oKWJ3kDukwk9bsKvryra15j)",
            ["3PUNyaW7M55oKWJ3kDukwk9bsKvryra15j"],
            id="addr",
        ),
        pytest.param(
            f"combo({A})",
            [
                "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN",
            ],
            id="combo",
        ),
        pytest.param(
            f"rawtr({XA})",
            ["bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"],
            id="rawtr",
        ),
        pytest.param(
            f"tr(musig({A},{B}))",
            ["bc1p405nwnnqu3gcl77xrxcde0vw26jc5ffae540a50cm6cffcxxstkqytw7l8"],
            id="musig-internal-key",
        ),
        pytest.param(
            f"tr({XA},pk(musig({B},{C})))",
            ["bc1pr2u2a2prvyttkuv2lj7qgqry4wuxnk62z8r2ypcjgncpe56zmvqs6nnvuq"],
            id="musig-in-a-leaf",
        ),
    ],
)
def test_a_function_rust_miniscript_does_not_implement_is_read(
    descriptor: str, addresses: list[str]
) -> None:
    """Bitcoin Core accepts it, rust-miniscript refuses it.

    rust-miniscript has no `addr()` of BIP385, `combo()` of BIP384,
    `rawtr()` of BIP386 or `musig()` of BIP390. It says `unrecognized name`
    for the first three, and for `musig()` a parse error.
    """
    # a bare key's script has no address
    assert [a for a in parse(descriptor).addresses() if a] == addresses


def test_a_raw_script_has_no_address() -> None:
    """Core accepts it with no address; rust-miniscript has no `raw()`."""
    descriptor = parse("raw(deadbeef)")
    assert descriptor.script_pub_key().script == bytes.fromhex("deadbeef")
    assert descriptor.address() == ""


@pytest.mark.parametrize(
    "descriptor, address",
    [
        pytest.param(
            f"wsh(multi(01,{A}))",
            "bc1q9qs9xv7mjghkd69fgx62xttxmeww5q7eekjxu0nxtzf4yu4ekf8s4plngs",
            id="multi",
        ),
        pytest.param(
            f"tr({XA},multi_a(01,{XB},{XC}))",
            "bc1phz287wvezcqqp8zd3s98ghha0xwwc0cvtnwse4ymnsnrlfnwnv6qapma8r",
            id="multi_a",
        ),
    ],
)
def test_a_threshold_with_a_leading_zero_is_read(descriptor: str, address: str) -> None:
    """Bitcoin Core accepts it, rust-miniscript refuses it.

    Core reads the threshold with `ToIntegral`, which uses `std::from_chars`;
    rust-miniscript says `numbers must start with 1-9, not 0`.
    """
    assert parse(descriptor).address() == address


def test_a_multipath_xprv_with_a_hardened_step_on_one_path_is_read() -> None:
    """Bitcoin Core accepts it, rust-miniscript refuses it.

    Both single-path descriptors are read, the second of which needs the
    private key to derive. rust-miniscript says it cannot make a multi-xpriv
    with hardened derivation steps that are not shared among all paths.
    """
    descriptors = multipath_descriptors(f"pkh({XPRV}/<0;1h>)", "mainnet")
    assert len(descriptors) == 2
    assert parse(descriptors[0]).address() == "1FHz8bpEE5qUZ9XhfjzAbCCwo5bT1HMNAc"
    assert parse(descriptors[1]).is_ranged is False


@pytest.mark.parametrize(
    "descriptor, fault",
    [
        pytest.param(
            "wsh(after(100))",
            "after(100) is not sane: witnesses without signature exist",
            id="wsh-no-signature",
        ),
        pytest.param(
            "wsh(or_i(1,1))",
            "or_i(1,1) is not sane: malleable witnesses exist",
            id="wsh-malleable",
        ),
        pytest.param(
            "wsh(or_b(0,a:0))",
            "or_b(0,a:0) is not satisfiable",
            id="wsh-unsatisfiable",
        ),
        pytest.param(
            f"tr({XA},after(100))",
            "after(100) is not sane: witnesses without signature exist",
            id="tr-no-signature",
        ),
        pytest.param(
            f"tr({XA},or_i(1,1))",
            "or_i(1,1) is not sane: malleable witnesses exist",
            id="tr-malleable",
        ),
        pytest.param(
            f"tr({XA},or_b(0,a:0))",
            "or_b(0,a:0) is not satisfiable",
            id="tr-unsatisfiable",
        ),
    ],
)
def test_a_miniscript_that_is_not_sane_is_refused_in_a_descriptor(
    descriptor: str, fault: str
) -> None:
    """Bitcoin Core refuses it; rust-miniscript takes some of these.

    rust-miniscript checks that a miniscript is sane in a `tr()` and not in
    a `wsh()` (rust-bitcoin/rust-miniscript#734), so it refuses the first
    two in a `tr()` only. Its sanity checks do not ask whether a miniscript
    can be satisfied, so it takes `or_b(0,a:0)` in both.
    """
    with pytest.raises(BTClibValueError, match=f"^{re.escape(fault)}$"):
        parse(descriptor)


def test_two_hardened_children_of_one_xprv_are_two_keys() -> None:
    """Bitcoin Core v31.1 refuses it as a duplicate, rust-miniscript accepts it.

    Core v31.1 compares the keys of a miniscript after deriving each with no
    private key at hand (`PubkeyProvider::operator<`, `descriptor.cpp`),
    which fails for a hardened step, so two of them compare equal.
    bitcoin/bitcoin#34697 fixed it on master after v31.1. Here they are two
    keys, and the same hardened child twice is still one.
    """
    assert parse(f"wsh(or_d(pk({XPRV}/0h),pk({XPRV}/1h)))").is_ranged is False
    with pytest.raises(BTClibValueError, match="is not sane: it repeats a public key$"):
        parse(f"wsh(or_d(pk({XPRV}/0h),pk({XPRV}/0h)))")


def test_a_key_repeated_on_a_later_path_is_refused() -> None:
    """Bitcoin Core and rust-miniscript accept it, `parse` refuses it.

    The two keys differ on the first path and are the same on the second,
    so the second single-path descriptor is not sane. Core checks the keys
    of the first path only (`KeyParser::KeyCompare` takes `.at(0)`).
    """
    descriptor = f"wsh(or_d(pk({XPUB}/<0;1>),pk({XPUB}/<2;1>)))"
    with pytest.raises(BTClibValueError, match="is not sane: it repeats a public key$"):
        multipath_descriptors(descriptor, "mainnet")


def test_a_multipath_step_with_a_repeated_element_is_refused() -> None:
    """Bitcoin Core refuses it, rust-miniscript accepts it.

    BIP389: "Duplicate NUMs within a tuple are not allowed."
    """
    with pytest.raises(
        BTClibValueError,
        match="^Duplicated key path value 1 in multipath specifier$",
    ):
        parse(f"wpkh({XPUB}/<1;1>)")


@pytest.mark.parametrize(
    "thresh, address",
    [
        pytest.param(
            f"thresh(2,dv:older(42),s:pk({XB}),s:pk({XC}))",
            "bc1p67wl2vget9fka58av9v2aqct9lk7zyufc80e3nj3raysdek9xudq25tfg3",
            id="first",
        ),
        pytest.param(
            f"thresh(2,pk({XB}),s:pk({XC}),sdv:older(42))",
            "bc1ptrfzmflee0np9af92kyjpw8tnc7dkgduhltwpwtl9kxn3mqch6gq96ye4a",
            id="last",
        ),
    ],
)
def test_d_is_a_unit_in_tapscript_and_not_in_p2wsh(thresh: str, address: str) -> None:
    """Bitcoin Core accepts it in a `tr()`, rust-miniscript refuses it.

    BIP379 gives `d:X` the type `u` in Tapscript only, and Core's
    `miniscript.cpp` has it for `IsTapscript`. rust-miniscript says the
    fragment `is not a unit`. In P2WSH it is no unit, and a `thresh()` that
    needs one is ill-typed.
    """
    assert parse(f"tr({XA},{thresh})").address() == address
    with pytest.raises(BTClibValueError, match="^ill-typed miniscript: thresh over "):
        parse(f"wsh({thresh.replace(XB, B).replace(XC, C)})")
