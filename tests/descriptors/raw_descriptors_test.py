# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for ``rawnode()``, ``rawleaf()``, ``rawpkh()`` and nested ``raw()``.

No BIP specifies ``rawnode()``, ``rawleaf()`` or ``rawpkh()``. BIP385
refuses a nested ``raw()``, and the draft BIP of bitcoin/bips#1721 allows
it. Bitcoin Core v31.1 reads none of them. The
vectors come from two closed proposals, read at the pins of
`tests/_data/README.md`:

- bitcoin/bitcoin PR 30243, which implements ``rawnode()`` and
  ``rawleaf()``: its `Check` cases are `CORE_CHECKS`, in the private and
  the public spelling, and its `CheckUnparsable` cases are
  `CORE_UNPARSABLE`. Core reads the error of the public string alone, so
  the private one is only held to be refused;
- the draft BIP of bitcoin/bips PR 1721, which specifies ``raw()`` inside
  ``sh()``, ``wsh()`` and a ``tr()`` tree: `BIP_VECTORS` and `BIP_INVALID`.

`OWN_VECTORS` are computed here. Each script was derived by hand with
btclib's hashes and taproot primitives and `hashlib`, importing nothing of
`btclib_wallet.descriptors`: the script of a ``rawpkh()`` is
``DUP HASH160 <20 bytes> EQUALVERIFY CHECKSIG``, the output of a ``sh()``
or a ``wsh()`` is the hash160 or the sha256 of its script, and a tree is
folded with BIP341's tagged hashes, a ``rawnode()`` standing for the leaf
hash of the leaf it hides. Where Bitcoin Core reads an equivalent
descriptor, each script was also compared with Core v31.1.0's
`deriveaddresses` of it, which `tests/integration/raw_descriptors_test.py`
asks again. That equivalent is the third entry. Core has none for another
leaf version, and those scripts are btclib's `output_pubkey` of the tree.

Core's `raw()` is top level only, and it refuses ``sh(raw(00))``. This
package accepts it.
"""

from __future__ import annotations

import pytest
from btclib.alias import Octets
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160
from btclib.script.taproot import check_output_pubkey

from btclib_wallet.descriptors import (
    MiniscriptDescriptor,
    RawDescriptor,
    RawLeaf,
    RawNode,
    RawPkhDescriptor,
    ShDescriptor,
    TrDescriptor,
    WshDescriptor,
    add_checksum,
    infer_descriptor,
    parse,
    wallet_policy,
)
from btclib_wallet.descriptors.miniscript import (
    TAPSCRIPT,
    Miniscript,
    _has_raw_key_hash,
)
from btclib_wallet.descriptors.miniscript import parse as miniscript_parse
from tests import vector_id
from tests.descriptors.descriptors_test import psbt_paying, psbt_spending
from tests.exception_family_test import VALUE_ERRORS

WIF = "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1"
XONLY = "a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
LEAF = (
    "41069228de6902abb4f541791f6d7f925b10e2078ccb1298856e5ea5cc5fd667"
    "f930eac37a00cc07f9a91ef3c2d17bf7a17db04552ff90ac312a5b8b4caca6c97aa4ac"
)
NODE = "e960f9fcfb646b5a6eb3a091d9270497738f7bcd99c2dda549acc699f02b043b"
OTHER_NODE = "fe59e853cc46a633e556950a65a47b61098b669775b876e517339076a4970c23"

# bitcoin/bitcoin PR 30243, src/test/descriptor_tests.cpp: the private
# spelling, the public one, and the script each expands to
CORE_CHECKS = [
    (
        f"tr({WIF},rawnode({NODE}))",
        f"tr({XONLY},rawnode({NODE}))",
        "512085d8d2f800c2fdf8b671f16c3ec75aa6e134aa6ae98c08b5351408abef957452",
    ),
    (
        f"tr({WIF},{{rawnode({NODE}),rawnode({OTHER_NODE})}})",
        f"tr({XONLY},{{rawnode({NODE}),rawnode({OTHER_NODE})}})",
        "5120117ee4eb20c920ef1f1c088536903624997626423c9ce6737c2d0476f8ca27e3",
    ),
    (
        f"tr({WIF},{{rawnode({NODE}),pk({WIF})}})",
        f"tr({XONLY},{{rawnode({NODE}),pk({XONLY})}})",
        "512013ed7d909ab69e6581906f54cb9e6f564fbd102d3a2f6e2bbeb2824bb9a68344",
    ),
    (
        f"tr({WIF},rawleaf({LEAF},c0))",
        f"tr({XONLY},rawleaf({LEAF},c0))",
        "51209eff65f093c70a94a43bbf6fe508fa557dc1b81551759d3fb15e09b521a42a2f",
    ),
    (
        f"tr({WIF},rawleaf({LEAF},cc))",
        f"tr({XONLY},rawleaf({LEAF},cc))",
        "5120ed4f8863f232246c6bb9c6e8877a3f586ea9c52203b35658e5a15776ce60aaa6",
    ),
    (
        f"tr({WIF},rawleaf({LEAF},66))",
        f"tr({XONLY},rawleaf({LEAF},66))",
        "5120ab7116360411e36c55ba4f6e7a47a26b4725f55b87c31dca5ecf2b7b5d9dc294",
    ),
    (
        f"tr({WIF},{{rawleaf({LEAF},c0),pk({WIF})}})",
        f"tr({XONLY},{{rawleaf({LEAF},c0),pk({XONLY})}})",
        "51203ae76d659be52428698fc98f897b9c492c413e8cadc8115038ba0684b2050dea",
    ),
]

# the same file's `CheckUnparsable` cases: the private spelling, the public
# one, and the message `parse` refuses the public one with. Core's message
# is the same, except for the two that name the position: Core says "Can
# only have rawnode() inside tr()" and "Can only have rawleaf() inside
# tr()", and `parse` words every position fault as "NAME() is not allowed
# inside CONTEXT"
CORE_UNPARSABLE = [
    (
        f"rawnode({NODE})",
        f"rawnode({NODE})",
        r"^rawnode\(\) is not allowed inside top level$",
    ),
    (
        f"tr({WIF},rawnode(e9))",
        f"tr({XONLY},rawnode(e9))",
        "^256 bits digest expected$",
    ),
    (
        f"tr({WIF},rawnode(e9))",
        f"tr({XONLY},rawnode(zzzz))",
        "^Rawnode hash is not hex$",
    ),
    (
        f"rawleaf({LEAF})",
        f"rawleaf({LEAF})",
        r"^rawleaf\(\) is not allowed inside top level$",
    ),
    (
        f"tr({WIF},rawleaf(z,c0))",
        f"tr({XONLY},rawleaf(z,c0))",
        "^Leaf Script is not hex$",
    ),
    (
        f"tr({WIF},rawleaf(a0,ca00))",
        f"tr({XONLY},rawleaf(a0,ca00))",
        "^Leaf Version is too large$",
    ),
    (
        f"tr({WIF},rawleaf(a0,z0))",
        f"tr({XONLY},rawleaf(a0,z0))",
        "^Leaf Version is not hex$",
    ),
    (
        f"tr({WIF},rawleaf(a0,))",
        f"tr({XONLY},rawleaf(a0,))",
        "^Expected Leaf Version but not provided$",
    ),
    (
        f"tr({WIF},rawleaf(a0,z0))",
        f"tr({XONLY},rawleaf(a0,bf))",
        "^Leaf Version is invalid$",
    ),
    (
        f"tr({WIF},rawleaf(a0,z0))",
        f"tr({XONLY},rawleaf(a0,c1))",
        "^Leaf Version is invalid$",
    ),
    (
        f"tr({WIF},rawleaf(a0,z0))",
        f"tr({XONLY},rawleaf(a0,ff))",
        "^Leaf Version is invalid$",
    ),
]

# the valid vectors of the draft BIP of bitcoin/bips PR 1721. Its
# prose says a wsh() script is "OP_0 <hash160(HEX_script)>", and its vector
# is OP_0 and the 32 bytes of the sha256 of the witness script
BIP_VECTORS = [
    ("sh(raw(5387))", "a9149e02f205612b4d7fe9466a789764b0eafe7eb07287"),
    ("sh(wsh(raw(5387)))", "a9140d1a6a9fd7e20b6e4091e2c10284fb1130afd46787"),
    (
        "wsh(raw(5387))",
        "00205c5fc1afc3d712a8e8602cee8590234ab2213be58943fca65436439f08017a64",
    ),
]

# its invalid vectors, the spaces after a comma left out: Core refuses a
# function name that starts with a space. The `key` of tr(raw(asdf), pk(key))
# is written as XONLY. The vector whose hash is a placeholder, "<complete me
# with a 32-bit non-hex hash>", is left out
BIP_INVALID = [
    ("sh(raw(asdf))", "^Raw script is not hex$"),
    (f"tr({XONLY},rawnode(kjke))", "^Rawnode hash is not hex$"),
    (f"tr(raw(asdf),pk({XONLY}))", "^not a key expression$"),
]

# x-only keys of the private keys 1, 2 and 3
X1 = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
X2 = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
X3 = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
KEY = "03" + XONLY
HASH160_KEY = "9a1c78a507689f6f54b847ad1cef1e614ee23f1e"
# a second compressed key, the key of X2, and its hash160
KEY_B = "02" + X2
HASH160_B = "06afd46bcdfd22ef94ac122aa11f241244a37ecc"
# the hash160 of the x-only key X2, which is what a tapscript pkh() hashes
HASH160_X2 = "9b652a14674a506079f574d20ca7daef6f9a66bb"
# and_v(v:pkh(KEY),pkh(KEY_B)) in a p2wsh, from its witness script
# 76a914{h}88ad76a914{h'}88ac written out by hand
WSH_TWO_KEYS = "0020e1525eec19af925e8ee3aea49233bd905e9c64d0752535302b28601b7226ad01"
PK_SCRIPT = f"21{KEY}ac"
PK_X2_SCRIPT = f"20{X2}ac"
PK_X3_SCRIPT = f"20{X3}ac"
# the tapleaf hashes of pk(X2), and of {pk(X1),pk(X2)}
LEAF_HASH_X1 = "763e9da064b9dc0471fb0f3c8fa2c84b4b84d2ca992497c12d2274386795aa8e"
LEAF_HASH_X2 = "ab11b8ce98a88b0dccf33a8144f90266dd8228b9fec6fa0cc0f7d4c0a28b8977"
BRANCH_X1_X2 = "4ca63a41f6849e2043baedd8f34ad532e6f4e5f458f26c4ac3e166055bd5ac2f"

# each: the descriptor, the script it describes, and the descriptor Core
# reads that describes the same script (None where Core reads none)
OWN_VECTORS = [
    (
        f"rawpkh({HASH160_KEY})",
        "76a9149a1c78a507689f6f54b847ad1cef1e614ee23f1e88ac",
        f"pkh({KEY})",
    ),
    (
        f"sh(rawpkh({HASH160_KEY}))",
        "a9141a31ad23bf49c247dd531a623c2ef57da3c400c587",
        f"sh(pkh({KEY}))",
    ),
    (
        f"wsh(rawpkh({HASH160_KEY}))",
        "0020338e023079b91c58571b20e602d7805fb808c22473cbc391a41b1bd3a192e75b",
        f"wsh(pkh({KEY}))",
    ),
    (
        f"sh(raw({PK_SCRIPT}))",
        "a9141857af51a5e516552b3086430fd8ce55f7c1a52487",
        f"sh(pk({KEY}))",
    ),
    (
        f"wsh(raw({PK_SCRIPT}))",
        "00202e271faa2325c199d25d22e1ead982e45b64eeb4f31e73dbdf41bd4b5fec23fa",
        f"wsh(pk({KEY}))",
    ),
    (
        f"sh(wsh(raw({PK_SCRIPT})))",
        "a91472d0c5a3bfad8c3e7bd5303a72b94240e80b6f1787",
        f"sh(wsh(pk({KEY})))",
    ),
    (
        f"tr({XONLY},raw(20{X1}ac))",
        "5120c41be2eb2db1e15b2f5c6d6208caab4e4f3cd8aadd5d6c7ce41a7f7c17724c2f",
        f"tr({XONLY},pk({X1}))",
    ),
    (
        f"tr({XONLY},rawnode({LEAF_HASH_X1}))",
        "5120c41be2eb2db1e15b2f5c6d6208caab4e4f3cd8aadd5d6c7ce41a7f7c17724c2f",
        f"tr({XONLY},pk({X1}))",
    ),
    (
        f"tr({XONLY},{{pk({X1}),raw({PK_X2_SCRIPT})}})",
        "5120ab7213f1750f93102de41fa30ab996503056c4db8f84679c8d5c4b09d906aa87",
        f"tr({XONLY},{{pk({X1}),pk({X2})}})",
    ),
    (
        f"tr({XONLY},{{pk({X1}),rawleaf({PK_X2_SCRIPT},c0)}})",
        "5120ab7213f1750f93102de41fa30ab996503056c4db8f84679c8d5c4b09d906aa87",
        f"tr({XONLY},{{pk({X1}),pk({X2})}})",
    ),
    (
        f"tr({XONLY},{{pk({X1}),rawnode({LEAF_HASH_X2})}})",
        "5120ab7213f1750f93102de41fa30ab996503056c4db8f84679c8d5c4b09d906aa87",
        f"tr({XONLY},{{pk({X1}),pk({X2})}})",
    ),
    (
        f"tr({XONLY},{{{{pk({X1}),rawnode({LEAF_HASH_X2})}},raw({PK_X3_SCRIPT})}})",
        "5120b49983e5bb88ebccb75f24074542eb01a9fc165844aab2a49da511bd4078e895",
        f"tr({XONLY},{{{{pk({X1}),pk({X2})}},pk({X3})}})",
    ),
    (
        f"tr({XONLY},{{rawnode({BRANCH_X1_X2}),pk({X3})}})",
        "5120b49983e5bb88ebccb75f24074542eb01a9fc165844aab2a49da511bd4078e895",
        f"tr({XONLY},{{{{pk({X1}),pk({X2})}},pk({X3})}})",
    ),
    (
        f"tr({XONLY},rawleaf(51,c2))",
        "5120105f6c1f89a2cdca3c3b472240424b430f141f996b4fe54326b2b889a3307903",
        None,
    ),
    (
        f"tr({XONLY},{{pk({X1}),rawleaf(51,00)}})",
        "5120e4b7921e6f6836c5b505cee22e301288409fa63cce2306f6d39a036e1000a297",
        None,
    ),
    (
        f"tr({XONLY},{{pk({X1}),rawleaf(51,06)}})",
        "51200affce0418684241ec302ffecb2f91c414726c633fce37390f07b49d762e5e60",
        None,
    ),
    (
        f"wsh(and_v(v:pkh({KEY}),rawpkh({HASH160_B})))",
        WSH_TWO_KEYS,
        f"wsh(and_v(v:pkh({KEY}),pkh({KEY_B})))",
    ),
    (
        f"wsh(and_v(v:rawpkh({HASH160_KEY}),pkh({KEY_B})))",
        WSH_TWO_KEYS,
        f"wsh(and_v(v:pkh({KEY}),pkh({KEY_B})))",
    ),
    (
        f"sh(wsh(and_v(v:pkh({KEY}),rawpkh({HASH160_B}))))",
        "a9147581ab75ee6df9f4f0be99138867b37aa5c99d2287",
        f"sh(wsh(and_v(v:pkh({KEY}),pkh({KEY_B}))))",
    ),
    (
        f"wsh(or_d(pkh({KEY}),rawpkh({HASH160_B})))",
        "00200fb27c6d76bdf4f1a27353b0cf1cbc10b10d72e35ff07dc702890967a7fee3d1",
        f"wsh(or_d(pkh({KEY}),pkh({KEY_B})))",
    ),
    # a tapscript leaf 76a914{hash160 of X2}88ac, hashed with the tapleaf
    # and tapbranch tags by hand
    (
        f"tr({XONLY},rawpkh({HASH160_X2}))",
        "512017ef067f0c1dd65fb4e6c9d1f3846a83da2e68c506753fd6be2970b8dae7c47e",
        f"tr({XONLY},pkh({X2}))",
    ),
    (
        f"tr({XONLY},{{pk({X1}),rawpkh({HASH160_X2})}})",
        "5120ee85bf6d9c5fbd55f3e08198056b0f6e4e1df98478f63deca50b043eda5f57d8",
        f"tr({XONLY},{{pk({X1}),pkh({X2})}})",
    ),
]


def _script(descriptor: str) -> str:
    return parse(descriptor).script_pub_key().script.hex()


def _tr(descriptor: str) -> TrDescriptor:
    parsed = parse(descriptor)
    assert isinstance(parsed, TrDescriptor)
    return parsed


@pytest.mark.parametrize(
    "private, public, script",
    [
        pytest.param(private, public, script, id=vector_id(index, public))
        for index, (private, public, script) in enumerate(CORE_CHECKS)
    ],
)
def test_core_check(private: str, public: str, script: str) -> None:
    """Both spellings print as the public one and expand to Core's script."""
    for text in (private, public):
        parsed = parse(text)
        assert str(parsed) == public
        assert parsed.script_pub_key().script.hex() == script
        assert not parsed.is_ranged


@pytest.mark.parametrize(
    "private, public, message",
    [
        pytest.param(private, public, message, id=vector_id(index, public))
        for index, (private, public, message) in enumerate(CORE_UNPARSABLE)
    ],
)
def test_core_unparsable(private: str, public: str, message: str) -> None:
    """Refuse both spellings, naming the fault of the public one."""
    with pytest.raises(VALUE_ERRORS):
        parse(private)
    with pytest.raises(BTClibValueError, match=message):
        parse(public)


@pytest.mark.parametrize(
    "descriptor, script",
    [
        pytest.param(descriptor, script, id=vector_id(index, descriptor))
        for index, (descriptor, script) in enumerate(BIP_VECTORS)
    ],
)
def test_bip_vector(descriptor: str, script: str) -> None:
    """Expand to the script the draft BIP lists."""
    parsed = parse(descriptor)
    assert str(parsed) == descriptor
    assert parsed.script_pub_key().script.hex() == script


def test_bip_vector_hashes_are_the_hashes_of_the_script() -> None:
    """The scripts of the draft BIP are what the BIP says they are."""
    from hashlib import sha256  # noqa: PLC0415

    redeem = bytes.fromhex("5387")
    wsh = b"\x00\x20" + sha256(redeem).digest()
    assert _script("sh(raw(5387))") == (b"\xa9\x14" + hash160(redeem) + b"\x87").hex()
    assert _script("wsh(raw(5387))") == wsh.hex()
    assert _script("sh(wsh(raw(5387)))") == (b"\xa9\x14" + hash160(wsh) + b"\x87").hex()


@pytest.mark.parametrize(
    "descriptor, message",
    [
        pytest.param(descriptor, message, id=vector_id(index, descriptor))
        for index, (descriptor, message) in enumerate(BIP_INVALID)
    ],
)
def test_bip_invalid(descriptor: str, message: str) -> None:
    """Refuse the draft BIP's invalid descriptors."""
    with pytest.raises(BTClibValueError, match=message):
        parse(descriptor)


@pytest.mark.parametrize(
    "descriptor, script, core",
    [
        pytest.param(descriptor, script, core, id=vector_id(index, descriptor))
        for index, (descriptor, script, core) in enumerate(OWN_VECTORS)
    ],
)
def test_own_vector(descriptor: str, script: str, core: str | None) -> None:
    """Expand to the script derived by hand, and print as it was read."""
    parsed = parse(descriptor)
    assert str(parsed) == descriptor
    assert parsed.script_pub_key().script.hex() == script
    if core is not None:
        assert _script(core) == script


def test_a_rawnode_is_the_leaf_hash_it_hides() -> None:
    """Hide a leaf behind its hash and the output key does not change."""
    shown = _tr(f"tr({XONLY},{{pk({X1}),pk({X2})}})")
    hidden = _tr(f"tr({XONLY},{{pk({X1}),rawnode({LEAF_HASH_X2})}})")
    assert hidden.script_pub_key() == shown.script_pub_key()
    assert hidden.taproot_merkle_root() == shown.taproot_merkle_root()


def test_an_empty_raw_is_refused_as_core_refuses_it() -> None:
    """Core refuses ``raw()`` with "Raw script is not hex"; so does `parse`."""
    with pytest.raises(BTClibValueError, match="^Raw script is not hex$"):
        parse("raw()")


@pytest.mark.parametrize("script", ["0", "zz", "0g", "0x00", "00 11", " 00"])
def test_raw_takes_whole_bytes_of_hex_only(script: str) -> None:
    """Refuse what Core's `IsHex` refuses."""
    with pytest.raises(BTClibValueError, match="^Raw script is not hex$"):
        parse(f"raw({script})")


@pytest.mark.parametrize("script", ["00", "AB", "ab01"])
def test_raw_takes_hex_of_either_case(script: str) -> None:
    """Accept whole bytes, and print them in lowercase."""
    assert str(parse(f"raw({script})")) == f"raw({script.lower()})"


@pytest.mark.parametrize(
    "descriptor, message",
    [
        pytest.param(descriptor, message, id=vector_id(index, descriptor))
        for index, (descriptor, message) in enumerate(
            [
                ("sh(raw())", "^Raw script is not hex$"),
                ("wsh(raw())", "^Raw script is not hex$"),
                (f"tr({XONLY},raw())", "^Raw script is not hex$"),
                (f"tr({XONLY},{{pk({X1}),raw()}})", "^Raw script is not hex$"),
                (f"tr({XONLY},rawleaf())", "^Leaf Script is not hex$"),
                (f"tr({XONLY},rawleaf(,c0))", "^Leaf Script is not hex$"),
                (f"tr({XONLY},rawnode())", "^Rawnode hash is not hex$"),
                ("rawpkh()", "^Rawpkh hash is not hex$"),
                ("sh(rawpkh())", "^Rawpkh hash is not hex$"),
                (f"tr({XONLY},rawnode({NODE[:-2]}))", "^256 bits digest expected$"),
                (f"tr({XONLY},rawnode({NODE}00))", "^256 bits digest expected$"),
                (f"rawpkh({HASH160_KEY[:-2]})", "^160 bits digest expected$"),
                (f"rawpkh({HASH160_KEY}00)", "^160 bits digest expected$"),
                (f"rawpkh({HASH160_KEY[:-1]})", "^Rawpkh hash is not hex$"),
                (f"tr({XONLY},rawleaf(51,c0,c0))", "takes a script and a leaf"),
                (f"tr({XONLY},rawnode({NODE},{NODE}))", "takes one argument"),
                (f"tr({XONLY},raw(51,51))", "takes one argument"),
                (f"rawpkh({HASH160_KEY},{HASH160_KEY})", "takes one argument"),
            ]
        )
    ],
)
def test_an_empty_or_ill_formed_argument_is_refused(
    descriptor: str, message: str
) -> None:
    """Refuse an empty or ill-formed HEX in every function.

    Where the size is the fault, the message is the digest's, naming no
    function.
    """
    with pytest.raises(BTClibValueError, match=message):
        parse(descriptor)


@pytest.mark.parametrize(
    "descriptor, message",
    [
        pytest.param(descriptor, message, id=vector_id(index, descriptor))
        for index, (descriptor, message) in enumerate(
            [
                (f"sh(rawnode({NODE}))", r"^rawnode\(\) is not allowed inside sh\(\)$"),
                (
                    f"wsh(rawnode({NODE}))",
                    r"^rawnode\(\) is not allowed inside wsh\(\)$",
                ),
                (f"sh(rawleaf({LEAF}))", r"^rawleaf\(\) is not allowed inside sh\(\)$"),
                (
                    f"wsh(rawleaf({LEAF}))",
                    r"^rawleaf\(\) is not allowed inside wsh\(\)$",
                ),
                (
                    f"wsh(and_v(v:pkh({KEY}),raw_pk_h({HASH160_B})))",
                    r"unknown miniscript fragment",
                ),
                (
                    f"wsh(and_v(v:pkh({KEY}),c:raw_pk_h({HASH160_B})))",
                    r"unknown miniscript fragment",
                ),
                (
                    "sh(sh(raw(00)))",
                    r"^sh\(\) is not allowed inside sh\(\)$",
                ),
                (
                    "wsh(sh(raw(00)))",
                    r"^sh\(\) is not allowed inside wsh\(\)$",
                ),
                (
                    f"tr({XONLY},rawtr({XONLY}))",
                    r"^rawtr\(\) is not allowed inside tr\(\)$",
                ),
                (
                    f"tr({XONLY},addr(1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH))",
                    "not allowed inside",
                ),
                ("tr(raw(00))", "^not a key expression$"),
                (
                    f"tr({XONLY},and_v(v:pk({X1}),raw(51)))",
                    "unknown miniscript fragment",
                ),
                (
                    f"tr({XONLY},and_v(v:pk({X1}),rawnode({NODE})))",
                    "unknown miniscript fragment",
                ),
                (f"tr({XONLY},{{rawnode({NODE})}})", "two subtrees"),
                (f"tr({XONLY},rawnode({NODE})x)", "not a descriptor expression"),
                (f"tr({XONLY},rawnode({NODE})", "not a descriptor expression"),
            ]
        )
    ],
)
def test_the_raw_functions_are_refused_where_they_do_not_belong(
    descriptor: str, message: str
) -> None:
    """Refuse a raw function outside the positions it is allowed in."""
    with pytest.raises(BTClibValueError, match=message):
        parse(descriptor)


@pytest.mark.parametrize(
    "text, printed",
    [
        ("rawleaf(51)", "rawleaf(51,c0)"),
        ("rawleaf(51,C0)", "rawleaf(51,c0)"),
        ("rawleaf(51,00)", "rawleaf(51,00)"),
        ("rawleaf(51,06)", "rawleaf(51,06)"),
        ("rawleaf(51,fe)", "rawleaf(51,fe)"),
        ("raw(51)", "raw(51)"),
        ("raw(5A)", "raw(5a)"),
    ],
)
def test_a_leaf_prints_with_its_version_in_two_digits(text: str, printed: str) -> None:
    """Print ``rawleaf()`` with its version, always in two hex digits.

    Core's PR 30243 prints the version with ``%x``, so version 6 is "6",
    which its own parser refuses as not hex.
    """
    parsed = parse(f"tr({XONLY},{text})")
    assert str(parsed) == f"tr({XONLY},{printed})"
    assert parse(str(parsed)) == parsed


def test_a_tree_takes_raw_and_rawleaf_and_keeps_what_was_written() -> None:
    """Both spell a leaf of version c0, with one script and two texts."""
    raw = parse(f"tr({XONLY},{{pk({X1}),raw(51)}})")
    leaf = parse(f"tr({XONLY},{{pk({X1}),rawleaf(51,c0)}})")
    assert isinstance(raw, TrDescriptor)
    assert isinstance(leaf, TrDescriptor)
    assert raw.script_pub_key() == leaf.script_pub_key()
    assert raw.tree != leaf.tree
    assert raw.tree[1] == RawLeaf(b"\x51", bare=True)  # type: ignore[index]
    assert leaf.tree[1] == RawLeaf(b"\x51")  # type: ignore[index]
    assert str(raw) != str(leaf)


def test_a_bare_leaf_has_no_other_version() -> None:
    """``raw()`` prints without a version, so it cannot hold another."""
    with pytest.raises(BTClibValueError, match="leaf version c0"):
        RawLeaf(b"\x51", 0xC2, bare=True)


def test_rawnode_and_the_leaves_are_numbered_apart() -> None:
    """Number only the leaves a descriptor shows."""
    parsed = _tr(f"tr({XONLY},{{rawnode({NODE}),{{pk({X1}),raw(51)}}}})")
    assert parsed.key_expressions[1].pub_key == bytes.fromhex("02" + X1)
    leaves = parsed.taproot_leaf_scripts()
    assert sorted(script for script, _ in leaves.values()) == sorted(
        [bytes.fromhex(f"20{X1}ac"), b"\x51"]
    )
    # a leaf two levels down has two hashes in its path, and the hidden
    # node is the second
    paths = {script: control[33:] for control, (script, _) in leaves.items()}
    assert paths[b"\x51"][-32:] == bytes.fromhex(NODE)
    assert len(paths[b"\x51"]) == 64


def test_rawpkh_is_what_pkh_is_for_a_known_hash() -> None:
    """The same script, address and network as the ``pkh()`` of the key."""
    for network in ("mainnet", "testnet"):
        raw = parse(f"rawpkh({HASH160_KEY})", network)
        known = parse(f"pkh({KEY})", network)
        assert isinstance(raw, RawPkhDescriptor)
        assert raw.script_pub_key() == known.script_pub_key()
        assert raw.address() == known.address()
        assert raw.network == known.network
        assert raw.key_expressions == ()
    assert hash160(bytes.fromhex(KEY)).hex() == HASH160_KEY


def test_rawpkh_in_a_miniscript_is_pkh_for_a_known_hash() -> None:
    """Take the script, type, size and bounds of ``pkh(KEY)``."""
    known = parse(f"wsh(and_v(v:pkh({KEY}),pkh({KEY_B})))")
    raw = parse(f"wsh(and_v(v:pkh({KEY}),rawpkh({HASH160_B})))")
    assert isinstance(raw, WshDescriptor)
    assert isinstance(known, WshDescriptor)
    assert isinstance(raw.inner, MiniscriptDescriptor)
    assert isinstance(known.inner, MiniscriptDescriptor)
    assert raw.script_pub_key() == known.script_pub_key()
    assert raw.inner.node.properties == known.inner.node.properties
    assert raw.inner.node.script_size == known.inner.node.script_size
    assert raw.inner.node.max_ops == known.inner.node.max_ops
    assert raw.inner.node.max_witness_size == known.inner.node.max_witness_size
    assert raw.inner.node.max_witness_stack == known.inner.node.max_witness_stack
    assert _has_raw_key_hash(raw.inner.node)
    assert not _has_raw_key_hash(known.inner.node)
    assert raw.key_expressions == parse(f"pkh({KEY})").key_expressions
    assert str(parse(str(raw))) == str(raw)


def test_rawpkh_alone_in_a_miniscript_has_the_type_of_pkh() -> None:
    """``c:raw_pk_h`` is what ``pkh()`` is, and the bare fragment a K.

    The bare fragment is no text `parse` reads. It prints as the fragment
    it is, and under a ``c:`` or any wrapper as ``rawpkh(HEX)``.
    """
    known = miniscript_parse(f"pkh({KEY})")
    wrapped = miniscript_parse(f"rawpkh({HASH160_KEY})")
    assert str(wrapped) == f"rawpkh({HASH160_KEY})"
    assert wrapped.properties == known.properties
    # a K is no top-level expression, so the bare fragment is built and
    # read back inside the wrapper that makes it one
    bare = Miniscript("raw_pk_h", data=bytes.fromhex(HASH160_KEY))
    assert str(bare) == f"raw_pk_h({HASH160_KEY})"
    assert "K" in bare.properties
    assert bare.properties == Miniscript("pk_h", keys=known.subs[0].keys).properties
    assert str(Miniscript("c:", subs=(bare,))) == f"rawpkh({HASH160_KEY})"
    text = f"and_v(v:rawpkh({HASH160_KEY}),pkh({KEY}))"
    assert str(miniscript_parse(text)) == text


def test_the_dissatisfaction_of_a_rawpkh_is_estimated_as_pkh_is() -> None:
    """The largest witness of a branch that may be skipped is the same."""
    raw = miniscript_parse(f"or_d(pkh({KEY}),rawpkh({HASH160_B}))")
    known = miniscript_parse(f"or_d(pkh({KEY}),pkh({KEY_B}))")
    assert raw.max_witness_stack == known.max_witness_stack
    assert miniscript_parse(f"or_d(rawpkh({HASH160_B}),pkh({KEY}))").max_witness_stack


def test_a_rawpkh_in_a_miniscript_cannot_be_satisfied() -> None:
    """The key is not known, and a signature does not stand in for it."""
    node = miniscript_parse(f"and_v(v:pkh({KEY}),rawpkh({HASH160_B}))")
    signatures: dict[Octets, Octets] = {bytes.fromhex(KEY): b"\x01" * 64}
    with pytest.raises(BTClibValueError):
        node.satisfy(signatures)
    dsat = miniscript_parse(f"or_d(pkh({KEY}),rawpkh({HASH160_B}))")
    with pytest.raises(BTClibValueError):
        dsat.satisfy({KEY_B: "01" * 64})


def test_infer_reads_no_rawpkh_in_a_miniscript() -> None:
    """A script is read back with the keys the provider has, and no others.

    The hash of a key it lacks makes the script no miniscript, as for
    Core's `InferDescriptor`; the answer is the address.
    """
    parsed = parse(f"wsh(and_v(v:pkh({KEY}),rawpkh({HASH160_B})))")
    inferred = infer_descriptor(parsed.script_pub_key().script, parsed.provider())
    assert inferred == add_checksum(f"addr({parsed.address()})")


@pytest.mark.parametrize(
    "argument, message",
    [
        ("", r"^Rawpkh hash is not hex$"),
        ("zz", r"^Rawpkh hash is not hex$"),
        (HASH160_B[:-1], r"^Rawpkh hash is not hex$"),
        (f"{HASH160_B[:20]} {HASH160_B[20:]}", r"^Rawpkh hash is not hex$"),
        (f"{HASH160_B} ", r"^Rawpkh hash is not hex$"),
        (HASH160_B[:-2], r"^160 bits digest expected$"),
        (HASH160_B + "00", r"^160 bits digest expected$"),
    ],
)
def test_a_rawpkh_in_a_miniscript_is_read_as_rawpkh_is_elsewhere(
    argument: str, message: str
) -> None:
    """Refuse the argument with the messages the descriptor gives."""
    with pytest.raises(BTClibValueError, match=message):
        parse(f"wsh(and_v(v:pkh({KEY}),rawpkh({argument})))")
    with pytest.raises(BTClibValueError, match=message):
        parse(f"rawpkh({argument})")


def test_a_repeated_raw_key_hash_is_a_repeated_key() -> None:
    """Refuse the same hash twice, and the hash of a key named as well."""
    known = r"is not sane: it repeats a public key$"
    for text in (
        f"and_v(v:rawpkh({HASH160_B}),rawpkh({HASH160_B}))",
        f"and_v(v:pkh({KEY_B}),rawpkh({HASH160_B}))",
        f"and_v(v:rawpkh({HASH160_B}),pkh({KEY_B}))",
    ):
        with pytest.raises(BTClibValueError, match=known):
            parse(f"wsh({text})")
    parse(f"wsh(and_v(v:rawpkh({HASH160_KEY}),rawpkh({HASH160_B})))")


def test_rawpkh_in_a_tapscript_hashes_the_x_only_key() -> None:
    """A c0 leaf, as ``pkh(KEY)`` is, with the hash of the 32-byte key."""
    known = _tr(f"tr({XONLY},pkh({X2}))")
    raw = _tr(f"tr({XONLY},rawpkh({HASH160_X2}))")
    assert raw.script_pub_key() == known.script_pub_key()
    assert raw.tree == miniscript_parse(f"rawpkh({HASH160_X2})", TAPSCRIPT)
    assert hash160(bytes.fromhex(X2)).hex() == HASH160_X2
    assert str(parse(str(raw))) == str(raw)
    # the internal key alone: the hash names no key
    assert len(raw.key_expressions) == 1


def test_a_repeated_raw_key_hash_in_a_tapscript_is_a_repeated_key() -> None:
    """The hash of a named key is compared as the x-only key it hashes."""
    known = r"is not sane: it repeats a public key$"
    for text in (
        f"and_v(v:pkh({X2}),rawpkh({HASH160_X2}))",
        f"and_v(v:rawpkh({HASH160_X2}),pkh({X2}))",
        f"and_v(v:rawpkh({HASH160_X2}),rawpkh({HASH160_X2}))",
    ):
        with pytest.raises(BTClibValueError, match=known):
            parse(f"tr({XONLY},{text})")
    # the hash of the SEC key is the key of a p2wsh script and no one's here
    parse(f"tr({XONLY},and_v(v:pkh({X2}),rawpkh({HASH160_B})))")


def test_raw_inside_sh_and_wsh_is_a_script_and_no_key() -> None:
    """Expand the redeem script and the witness script, and know no key."""
    sh = parse(f"sh(raw({PK_SCRIPT}))")
    wsh = parse(f"sh(wsh(raw({PK_SCRIPT})))")
    assert sh.key_expressions == ()
    assert sh.redeem_script().hex() == _script(f"sh(raw({PK_SCRIPT}))")
    assert wsh.provider().scripts == (
        bytes.fromhex(PK_SCRIPT),
        bytes.fromhex(_script(f"wsh(raw({PK_SCRIPT}))")),
    )
    assert sh.provider().scripts == (bytes.fromhex(PK_SCRIPT),)
    assert sh.provider().keys == {}


@pytest.mark.parametrize(
    "descriptor, field, script",
    [
        (f"sh(raw({PK_SCRIPT}))", "redeem_script", PK_SCRIPT),
        (f"wsh(raw({PK_SCRIPT}))", "witness_script", PK_SCRIPT),
        (
            f"sh(rawpkh({HASH160_KEY}))",
            "redeem_script",
            "76a914" + HASH160_KEY + "88ac",
        ),
        (
            f"wsh(rawpkh({HASH160_KEY}))",
            "witness_script",
            "76a914" + HASH160_KEY + "88ac",
        ),
    ],
)
def test_the_updater_writes_the_script_a_raw_function_wraps(
    descriptor: str, field: str, script: str
) -> None:
    """Fill the redeem or the witness script, as for any wrapped script."""
    parsed = parse(descriptor)
    psbt_in = parsed.update_psbt_input(psbt_spending(parsed), 0).inputs[0]
    assert getattr(psbt_in, field) == bytes.fromhex(script)
    assert psbt_in.hd_key_paths == {}


@pytest.mark.parametrize(
    "descriptor, message",
    [
        (f"raw({PK_SCRIPT})", r"^raw\(\) cannot update a psbt: it holds no key$"),
        (
            f"rawpkh({HASH160_KEY})",
            r"^rawpkh\(\) cannot update a psbt: it holds no key$",
        ),
    ],
)
def test_a_raw_function_alone_updates_no_psbt(descriptor: str, message: str) -> None:
    """Refuse at the top level, where the utxo already says the script."""
    parsed = parse(descriptor)
    with pytest.raises(BTClibValueError, match=message):
        parsed.update_psbt_input(psbt_spending(parsed), 0)


@pytest.mark.parametrize(
    "descriptor, message",
    [
        (f"sh(raw({PK_SCRIPT}))", r"^raw\(\) cannot be satisfied: it holds no key$"),
        (f"wsh(raw({PK_SCRIPT}))", r"^raw\(\) cannot be satisfied: it holds no key$"),
        (f"sh(wsh(raw({PK_SCRIPT})))", r"^raw\(\) cannot be satisfied"),
        (f"rawpkh({HASH160_KEY})", r"^rawpkh\(\) cannot be satisfied"),
        (f"wsh(rawpkh({HASH160_KEY}))", r"^rawpkh\(\) cannot be satisfied"),
    ],
)
def test_a_script_of_bytes_cannot_be_satisfied(descriptor: str, message: str) -> None:
    """Refuse, naming the function and not the embedding class."""
    with pytest.raises(BTClibValueError, match=message):
        parse(descriptor).satisfy({})


def _spend(descriptor: str, signer: str) -> tuple[bytes, bytes, bytes]:
    """Return the output key, the leaf script and the control block."""
    parsed = parse(descriptor)
    witness = parsed.satisfy({bytes.fromhex(signer): b"\x01" * 64})[1]
    signature, script, control = witness.stack
    assert signature == b"\x01" * 64
    return parsed.script_pub_key().script[2:], script, control


@pytest.mark.parametrize(
    "descriptor",
    [
        pytest.param(descriptor, id=vector_id(index, descriptor))
        for index, (descriptor, _, _) in enumerate(OWN_VECTORS)
        if "pk(" + X1 in descriptor and "rawleaf(51,c2)" not in descriptor
    ],
)
def test_a_leaf_is_spent_with_a_control_block_through_a_hidden_node(
    descriptor: str,
) -> None:
    """Satisfy the shown leaf and let BIP341 check the proof of it.

    `check_output_pubkey` is btclib's verifier of a control block, not
    this module's.
    """
    output_key, script, control = _spend(descriptor, X1)
    assert script == bytes.fromhex(f"20{X1}ac")
    assert check_output_pubkey(output_key, script, control)


def test_a_raw_leaf_of_another_version_is_proved_under_that_version() -> None:
    """The control block names the leaf version and the parity of the key."""
    descriptor = _tr(f"tr({XONLY},{{pk({X1}),rawleaf(51,06)}})")
    ((control, (script, version)),) = (
        (c, leaf)
        for c, leaf in descriptor.taproot_leaf_scripts().items()
        if leaf[0] == b"\x51"
    )
    assert version == 0x06
    assert control[0] & 0xFE == 0x06
    assert check_output_pubkey(descriptor.script_pub_key().script[2:], script, control)


def test_a_tree_of_bytes_holds_no_key_to_sign_with() -> None:
    """Refuse a spend when the internal key does not sign and no leaf can."""
    with pytest.raises(BTClibValueError, match="no signature for the tr"):
        parse(f"tr({XONLY},{{rawnode({NODE}),raw(51)}})").satisfy({})


def test_a_tree_with_a_hidden_node_publishes_no_whole_tree() -> None:
    """Refuse PSBT_OUT_TAP_TREE, which is every leaf of the tree."""
    hidden = _tr(f"tr({XONLY},{{pk({X1}),rawnode({NODE})}})")
    with pytest.raises(BTClibValueError, match="no whole tree to publish"):
        hidden.taproot_tree()
    shown = _tr(f"tr({XONLY},{{pk({X1}),rawleaf(51,06)}})")
    assert shown.taproot_tree() == [
        (1, 0xC0, bytes.fromhex(f"20{X1}ac")),
        (1, 0x06, b"\x51"),
    ]


def test_the_updater_fills_the_input_of_a_tree_with_a_hidden_node() -> None:
    """The merkle root, and the one leaf with the node in its control block."""
    descriptor = _tr(f"tr({XONLY},{{pk({X1}),rawnode({LEAF_HASH_X2})}})")
    psbt_in = descriptor.update_psbt_input(psbt_spending(descriptor), 0).inputs[0]
    assert (
        psbt_in.taproot_merkle_root
        == _tr(f"tr({XONLY},{{pk({X1}),pk({X2})}})").taproot_merkle_root()
    )
    ((control, (script, version)),) = psbt_in.taproot_leaf_scripts.items()
    assert (script, version) == (bytes.fromhex(f"20{X1}ac"), 0xC0)
    assert control[-32:] == bytes.fromhex(LEAF_HASH_X2)
    with pytest.raises(BTClibValueError, match="no whole tree to publish"):
        descriptor.update_psbt_output(psbt_paying(descriptor.script_pub_key()), 1)


@pytest.mark.parametrize(
    "descriptor",
    [
        f"sh(raw({PK_SCRIPT}))",
        f"wsh(raw({PK_SCRIPT}))",
        f"sh(wsh(raw({PK_SCRIPT})))",
        f"sh(rawpkh({HASH160_KEY}))",
        f"wsh(rawpkh({HASH160_KEY}))",
        f"raw({PK_SCRIPT})",
        f"rawpkh({HASH160_KEY})",
        f"tr({XONLY},raw(51))",
        f"tr({XONLY},rawleaf(51,c0))",
        f"tr({XONLY},rawleaf(51,c2))",
        f"tr({XONLY},rawnode({NODE}))",
        f"tr({XONLY},{{pk({X1}),rawnode({NODE})}})",
        f"tr({XONLY},rawpkh({HASH160_X2}))",
        f"tr({XONLY},{{pk({X1}),and_v(v:pkh({X2}),rawpkh({HASH160_B}))}})",
    ],
)
def test_a_wallet_policy_refuses_each_raw_function(descriptor: str) -> None:
    """BIP388 has no template for a script, a hash or a node given as bytes."""
    with pytest.raises(BTClibValueError):
        wallet_policy(parse(descriptor))


@pytest.mark.parametrize(
    "descriptor, message",
    [
        (
            f"sh(raw({PK_SCRIPT}))",
            r"^raw\(\) in a wallet policy: BIP388 has no template for it$",
        ),
        (
            f"sh(wsh(rawpkh({HASH160_KEY})))",
            r"^rawpkh\(\) in a wallet policy: BIP388 has no template for it$",
        ),
        (
            f"tr({XONLY},{{pk({X1}),raw(51)}})",
            r"^raw\(\) in a wallet policy: BIP388 has no template for it$",
        ),
        (
            f"tr({XONLY},{{{{pk({X1}),rawleaf(51,c0)}},pk({X2})}})",
            r"^rawleaf\(\) in a wallet policy: BIP388 has no template for it$",
        ),
        (
            f"tr({XONLY},{{pk({X1}),rawnode({NODE})}})",
            r"^rawnode\(\) in a wallet policy: BIP388 has no template for it$",
        ),
        (
            f"tr({XONLY},rawpkh({HASH160_X2}))",
            r"^rawpkh\(\) in a wallet policy: BIP388 has no template for it$",
        ),
        (f"raw({PK_SCRIPT})", "is not a BIP388 SCRIPT expression"),
        (f"rawpkh({HASH160_KEY})", "is not a BIP388 SCRIPT expression"),
    ],
)
def test_a_wallet_policy_names_the_raw_function_it_refuses(
    descriptor: str, message: str
) -> None:
    """Name the function, or the class where it stands at the top level."""
    with pytest.raises(BTClibValueError, match=message):
        wallet_policy(parse(descriptor))


@pytest.mark.parametrize(
    "descriptor",
    [
        f"wsh(and_v(v:pkh({KEY}),rawpkh({HASH160_B})))",
        f"sh(wsh(or_d(pkh({KEY}),rawpkh({HASH160_B}))))",
    ],
)
def test_a_wallet_policy_refuses_a_rawpkh_in_a_miniscript(descriptor: str) -> None:
    """BIP388 has no template for a hash where a key belongs."""
    with pytest.raises(
        BTClibValueError,
        match=r"^rawpkh\(\) in a wallet policy: BIP388 has no template for it$",
    ):
        wallet_policy(parse(descriptor))


def test_the_classes_a_caller_reads_off_a_parsed_descriptor() -> None:
    """Read a `RawNode`, a `RawLeaf` and a `RawDescriptor` off a parse."""
    parsed = parse(f"tr({XONLY},{{rawnode({NODE}),rawleaf(51,06)}})")
    assert isinstance(parsed, TrDescriptor)
    assert parsed.tree == (RawNode(bytes.fromhex(NODE)), RawLeaf(b"\x51", 0x06))
    wrapped = parse("sh(raw(51))")
    assert isinstance(wrapped, ShDescriptor)
    assert wrapped.inner == RawDescriptor(b"\x51")


def test_a_hand_built_node_or_hash_of_the_wrong_size_is_refused() -> None:
    """The parser refuses them, and a descriptor built by hand is held too."""
    key = parse(f"tr({XONLY})").key_expressions[0]
    with pytest.raises(BTClibValueError, match="^256 bits digest expected$"):
        TrDescriptor(key, RawNode(b"\x00")).script_pub_key()
    with pytest.raises(BTClibValueError, match="^160 bits digest expected$"):
        RawPkhDescriptor(b"\x00").script_pub_key()


def test_a_hand_built_tree_too_deep_for_a_control_block_is_refused() -> None:
    """The parser stops at 128 levels, and so does the walk of a built tree."""
    key = parse(f"tr({XONLY})").key_expressions[0]
    deep: object = RawLeaf(b"\x51")
    for _ in range(129):
        deep = (deep, RawLeaf(b"\x51"))
    with pytest.raises(BTClibValueError, match="^script tree deeper than 128$"):
        TrDescriptor(key, deep).script_pub_key()  # type: ignore[arg-type]
