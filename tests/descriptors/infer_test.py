# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `infer_descriptor`, held to Bitcoin Core's `InferDescriptor`.

`SHAPES` and `SCRIPTS` are bitcoind v31.1.0's answers. A shape's are what
`scantxoutset` answers for the scripts its descriptor describes at index
0, with the provider that descriptor's expansion fills. A script's are
what `decodescript` answers, with an empty provider.
`tests/integration/infer_test.py` asks the node again.

The rest of the branches need a provider no descriptor expands to, and
are held to Core's source at bitcoin/bitcoin@9be056a8a7 (the v31.1 tag),
`src/script/descriptor.cpp`.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash160
from btclib.key import PubKeyData
from btclib.network import NETWORKS
from btclib.script.script import serialize
from btclib.script.script_pub_key import ScriptPubKey
from btclib.script.taproot import input_script_sig, output_pubkey, tree_helper

from btclib_wallet.bip32 import derive, xpub_from_xprv
from btclib_wallet.bip32.bip32 import rootxprv_from_seed
from btclib_wallet.bip32.key_origin import BIP32KeyOrigin
from btclib_wallet.descriptors import (
    Descriptor,
    Provider,
    TrDescriptor,
    infer_descriptor,
    multipath_descriptors,
    parse,
)
from btclib_wallet.descriptors.descriptors import _multi_a, _rebuilt

# the keys `@0` to `@5` stand for in `SHAPES`
ROOT = rootxprv_from_seed("0f" * 16, NETWORKS["regtest"].bip32_prv)
KEYS = {f"@{i}": xpub_from_xprv(derive(ROOT, f"m/86h/1h/{i}h")) for i in range(6)}

# the keys of the scalars 1 and 34, and the uncompressed and the hybrid
# key of 5: the second has an odd y and a smaller x than the first
K1 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
K34 = "031be68a5a028f2601d0e80d468c344ba331d611b96c358b6032e8b4da0547fc11"
U5 = (
    "042f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4"
    "d8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6"
)
H5 = "06" + U5[2:]

SHAPES = {
    "combo": (
        "combo(@0/0/*)",
        [
            "pk([a79e54e3/0/0]02ace0a881a41606c6f47301bbdce4037a6d07d7ade5e0ad6fcc4553d3dfd95adf)#hmqz55ld",
            "pkh([a79e54e3/0/0]02ace0a881a41606c6f47301bbdce4037a6d07d7ade5e0ad6fcc4553d3dfd95adf)#um294my8",
            "wpkh([a79e54e3/0/0]02ace0a881a41606c6f47301bbdce4037a6d07d7ade5e0ad6fcc4553d3dfd95adf)#4m7vpgyc",
            "sh(wpkh([a79e54e3/0/0]02ace0a881a41606c6f47301bbdce4037a6d07d7ade5e0ad6fcc4553d3dfd95adf))#phrz4wgd",
        ],
    ),
    "combo uncompressed": (
        f"combo({U5})",
        [
            f"pk([8eab8f21]{U5})#079faucw",
            f"pkh([8eab8f21]{U5})#pejtlazj",
        ],
    ),
    "pk": (f"pk({K1})", [f"pk([751e76e8]{K1})#x6xjvu3m"]),
    "pkh": (
        "pkh(@5/0/*)",
        [
            "pkh([9095aae0/0/0]02a41c52e518030a2d97575ea1ee4cbf502b58f0f97a55d64236a2e3b712290563)#azxuqjck"
        ],
    ),
    "wpkh": (
        "wpkh([0badf00d/84h/1h/0h]@2/1/*)",
        [
            "wpkh([0badf00d/84h/1h/0h/1/0]02de9d19219088eb8140f8d353a2036b45a9ca4f6cf017d38fcdd1103406f1b540)#eq2p22dw"
        ],
    ),
    "sh(wpkh)": (
        "sh(wpkh(@3/0/*))",
        [
            "sh(wpkh([7d18f8f3/0/0]0280f99656916001f95c225967d90214aed332b436dc3d2da32b3e6f019866d8f9))#0trd2jk5"
        ],
    ),
    "sh(pk)": (
        "sh(pk(@2/0/*))",
        [
            "sh(pk([40e48c5c/0/0]0211adae08f0ab66f3b266edefba002823c75006bd69a73206681924e4c1191c87))#mt76fdq6"
        ],
    ),
    "wsh(pk)": (
        "wsh(pk(@2/0/*))",
        [
            "wsh(pk([40e48c5c/0/0]0211adae08f0ab66f3b266edefba002823c75006bd69a73206681924e4c1191c87))#zddcx9sh"
        ],
    ),
    "bare sortedmulti": (
        "sortedmulti(2,@1/0/*,@2/0/*,@3/0/*)",
        [
            "multi(2,[40e48c5c/0/0]0211adae08f0ab66f3b266edefba002823c75006bd69a73206681924e4c1191c87,[bf160ac4/0/0]026abeb5a742db5163556f7d7ff7f06630232723b6daee52438a62751d91d11f4a,[7d18f8f3/0/0]0280f99656916001f95c225967d90214aed332b436dc3d2da32b3e6f019866d8f9)#0pwkz4yq"
        ],
    ),
    "sh(sortedmulti)": (
        "sh(sortedmulti(2,@1/0/*,@2/0/*))",
        [
            "sh(multi(2,[40e48c5c/0/0]0211adae08f0ab66f3b266edefba002823c75006bd69a73206681924e4c1191c87,[bf160ac4/0/0]026abeb5a742db5163556f7d7ff7f06630232723b6daee52438a62751d91d11f4a))#nhf087r2"
        ],
    ),
    "wsh(sortedmulti) of hex keys": (
        f"wsh(sortedmulti(1,{K34},{K1}))",
        [f"wsh(multi(1,[751e76e8]{K1},[e142ca9b]{K34}))#2aftvhxp"],
    ),
    "wsh(multi) with an origin": (
        "wsh(multi(1,[deadbeef/48h/1h/0h/2h]@1/0/*,@2/0/*))",
        [
            "wsh(multi(1,[deadbeef/48h/1h/0h/2h/0/0]026abeb5a742db5163556f7d7ff7f06630232723b6daee52438a62751d91d11f4a,[40e48c5c/0/0]0211adae08f0ab66f3b266edefba002823c75006bd69a73206681924e4c1191c87))#wwasn0mp"
        ],
    ),
    "a key spelled twice in a fragment": (
        f"sh(multi(1,[aaaaaaaa/1]{K1},[bbbbbbbb/2]{K1}))",
        [f"sh(multi(1,[bbbbbbbb/2/1]{K1},[bbbbbbbb/2/1]{K1}))#6u587xaj"],
    ),
    "a key spelled in two fragments": (
        f"tr(@0/0/*,{{pk([aaaaaaaa/9]{K1}),pk({K1})}})",
        [
            f"tr([a79e54e3/0/0]ace0a881a41606c6f47301bbdce4037a6d07d7ade5e0ad6fcc4553d3dfd95adf,{{pk([aaaaaaaa/9]{K1[2:]}),pk([aaaaaaaa/9]{K1[2:]})}})#qaqte8tm"
        ],
    ),
    "a key spelled as internal key and leaf": (
        f"tr({K1},pk([aaaaaaaa/9]{K1}))",
        [f"tr([751e76e8]{K1[2:]},pk([751e76e8]{K1[2:]}))#gjqrmcgm"],
    ),
    "multipath sh(wsh(pkh))": (
        "sh(wsh(pkh(@3/<0;1>/*)))",
        [
            "sh(wsh(pkh([7d18f8f3/0/0]0280f99656916001f95c225967d90214aed332b436dc3d2da32b3e6f019866d8f9)))#jysudr3d",
            "sh(wsh(pkh([7d18f8f3/1/0]024eb5bab65716d9fe2263e69d264912032c45b8b523a292d0c286b812a9575ebf)))#gcqns8ae",
        ],
    ),
    "wsh(miniscript)": (
        "wsh(and_v(v:pk(@1/0/*),older(10)))",
        [
            "wsh(and_v(v:pk([bf160ac4/0/0]026abeb5a742db5163556f7d7ff7f06630232723b6daee52438a62751d91d11f4a),older(10)))#eur8pjrr"
        ],
    ),
    "tr key path": (
        "tr(@0/0/*)",
        [
            "tr([a79e54e3/0/0]ace0a881a41606c6f47301bbdce4037a6d07d7ade5e0ad6fcc4553d3dfd95adf)#qpyjl8cw"
        ],
    ),
    "tr x-only leaf key": (
        "tr(@0/0/*,pk(@1/0/*))",
        [
            "tr([a79e54e3/0/0]ace0a881a41606c6f47301bbdce4037a6d07d7ade5e0ad6fcc4553d3dfd95adf,pk([bf160ac4/0/0]6abeb5a742db5163556f7d7ff7f06630232723b6daee52438a62751d91d11f4a))#qz8zruml"
        ],
    ),
    "tr sortedmulti_a of compressed keys": (
        f"tr({K1},sortedmulti_a(1,{K1},{K34}))",
        [
            f"tr([751e76e8]{K1[2:]},multi_a(1,[e142ca9b]{K34[2:]},[751e76e8]{K1[2:]}))#kr2cqa3q"
        ],
    ),
    "tr leaves in Core's order": (
        "tr(@0/0/*,{pk(@1/0/*),{pk(@2/0/*),pk(@3/0/*)}})",
        [
            "tr([a79e54e3/0/0]ace0a881a41606c6f47301bbdce4037a6d07d7ade5e0ad6fcc4553d3dfd95adf,{{pk([40e48c5c/0/0]11adae08f0ab66f3b266edefba002823c75006bd69a73206681924e4c1191c87),pk([7d18f8f3/0/0]80f99656916001f95c225967d90214aed332b436dc3d2da32b3e6f019866d8f9)},pk([bf160ac4/0/0]6abeb5a742db5163556f7d7ff7f06630232723b6daee52438a62751d91d11f4a)})#05uvrcnq"
        ],
    ),
    "tr a leaf at two depths": (
        "tr(@2/9/1,{pk(@2/0/1),{pk(@2/0/1),pk(@2/1/1)}})",
        [
            "tr([40e48c5c/9/1]8046eedd94c2d6db9d9112676f3bd5d7458ae9dcb2d37dcf038fafdd16b195ca,{pk([40e48c5c/0/1]65bdef830bb91a29737026368e18f2febba43bbe1e96f0d990f48300de3f449b),{pk([40e48c5c/0/1]65bdef830bb91a29737026368e18f2febba43bbe1e96f0d990f48300de3f449b),pk([40e48c5c/1/1]c374e721b168f57fea112729b336d486998a31c1bf571cfd655d7753a50c5b4e)}})#dsjhw7nc"
        ],
    ),
    "tr equal leaves": (
        "tr(@0/0/*,{pk(@1/0/*),pk(@1/0/*)})",
        [
            "tr([a79e54e3/0/0]ace0a881a41606c6f47301bbdce4037a6d07d7ade5e0ad6fcc4553d3dfd95adf,{pk([bf160ac4/0/0]6abeb5a742db5163556f7d7ff7f06630232723b6daee52438a62751d91d11f4a),pk([bf160ac4/0/0]6abeb5a742db5163556f7d7ff7f06630232723b6daee52438a62751d91d11f4a)})#8hjz42nv"
        ],
    ),
    "tr equal subtrees": (
        "tr(@0/0/*,{{pk(@1/0/*),pk(@2/0/*)},{pk(@1/0/*),pk(@2/0/*)}})",
        [
            "tr([a79e54e3/0/0]ace0a881a41606c6f47301bbdce4037a6d07d7ade5e0ad6fcc4553d3dfd95adf,{{pk([40e48c5c/0/0]11adae08f0ab66f3b266edefba002823c75006bd69a73206681924e4c1191c87),pk([bf160ac4/0/0]6abeb5a742db5163556f7d7ff7f06630232723b6daee52438a62751d91d11f4a)},{pk([40e48c5c/0/0]11adae08f0ab66f3b266edefba002823c75006bd69a73206681924e4c1191c87),pk([bf160ac4/0/0]6abeb5a742db5163556f7d7ff7f06630232723b6daee52438a62751d91d11f4a)}})#fd3g5mpt"
        ],
    ),
    "tr miniscript leaf": (
        "tr(@0/0/*,and_v(v:pk(@1/0/*),older(5)))",
        [
            "tr([a79e54e3/0/0]ace0a881a41606c6f47301bbdce4037a6d07d7ade5e0ad6fcc4553d3dfd95adf,and_v(v:pk([bf160ac4/0/0]6abeb5a742db5163556f7d7ff7f06630232723b6daee52438a62751d91d11f4a),older(5)))#23gm54zy"
        ],
    ),
    "tr pkh leaf, its key whole": (
        "tr(@0/0/*,and_v(v:pkh(@1/0/*),older(5)))",
        [
            "tr([a79e54e3/0/0]ace0a881a41606c6f47301bbdce4037a6d07d7ade5e0ad6fcc4553d3dfd95adf,and_v(v:pkh([bf160ac4/0/0]026abeb5a742db5163556f7d7ff7f06630232723b6daee52438a62751d91d11f4a),older(5)))#cxnsyf34"
        ],
    ),
    "tr musig of ranged participants": (
        "tr(musig(@1/0/*,@2/0/*))",
        [
            "tr([3b9a754f]94c59619771fb2f455f9a615f7cf4f082c41918b17ba2794438ec0aa706412a5)#9m075unw"
        ],
    ),
    "tr ranged musig": (
        "tr(musig(@1,@2)/0/*)",
        [
            "tr([06e842fb/0/0]867f8aa00efd3304367a031730590e869c0fbb478fe9665f857b4c2d641cfd6e)#m2rggeke"
        ],
    ),
    "rawtr": (
        "rawtr(@4/0/*)",
        [
            "rawtr([e3ffa028/0/0]9579c43cebccbc6ff5d7781981f4388fac3a817bd6b6b903fb8179970ecc1b75)#9plzjrfk"
        ],
    ),
}

# a shape whose answers depend on the keys of its whole range, which
# `scantxoutset` scans here as [0, 1]: Core's answer for each index
RANGED = (
    "wsh(multi(1,[aaaaaaaa/5]@1/0/*,[bbbbbbbb/7]@1/0/1))",
    [
        "wsh(multi(1,[aaaaaaaa/5/0/0]026abeb5a742db5163556f7d7ff7f06630232723b6daee52438a62751d91d11f4a,[bbbbbbbb/7/0/1]0272e19db0432e15aace6b7326ac1231f15650b92da19f6800fca592cb71cc00d6))#7yly7dx0",
        "wsh(multi(1,[bbbbbbbb/7/0/1]0272e19db0432e15aace6b7326ac1231f15650b92da19f6800fca592cb71cc00d6,[bbbbbbbb/7/0/1]0272e19db0432e15aace6b7326ac1231f15650b92da19f6800fca592cb71cc00d6))#ac7fqtls",
    ],
)

SCRIPTS = {
    "p2pkh": (
        "76a914111111111111111111111111111111111111111188ac",
        "addr(mh5CE8Nbj38iND267s4XnvhSmhDW7yWc6Q)#7cjjyjvp",
    ),
    "p2sh": (
        "a914111111111111111111111111111111111111111187",
        "addr(2MtoTvMi65NXBt3sTCXNd1aqKGa7gXsX8CC)#earyk9xv",
    ),
    "p2wpkh": (
        "00141111111111111111111111111111111111111111",
        "addr(bcrt1qzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3lgth6c)#r4xeeasu",
    ),
    "p2wsh": (
        "0020" + "11" * 32,
        "addr(bcrt1qzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs2ns5wu)#hne3n20n",
    ),
    "p2tr": ("5120" + K1[2:], f"rawtr({K1[2:]})#xsjqcczm"),
    "p2tr of no point": (
        "5120" + "ff" * 32,
        "addr(bcrt1plllllllllllllllllllllllllllllllllllllllllllllllllllse0lp4e)#f6jd6wfe",
    ),
    "anchor": ("51024e73", "addr(bcrt1pfeesnyr2tx)#swxgse0y"),
    "witness v2": ("5202aabb", "addr(bcrt1z42asu69sl2)#zu4qu868"),
    "witness v0 of 33 bytes": (
        "0021" + "11" * 33,
        "raw(0021" + "11" * 33 + ")#xh06rmru",
    ),
    "null data": ("6a0401020304", "raw(6a0401020304)#g0fz96j4"),
    "empty": ("", "raw()#58lrscpx"),
    "a push past the end": ("21" + K1[:20], "raw(21" + K1[:20] + ")#5jrx5t25"),
    "p2pk": ("41" + U5 + "ac", f"pk({U5})#2dwmq85f"),
    "p2pk of no point": (
        "21" + "02" + "ff" * 32 + "ac",
        "pk(02" + "ff" * 32 + ")#ragaskvl",
    ),
    "p2pk hybrid": ("41" + H5 + "ac", "raw(41" + H5 + "ac)#vz7md8m0"),
    "p2pk of a key of the wrong size": (
        "2104" + "11" * 32 + "ac",
        "raw(2104" + "11" * 32 + "ac)#aegwnhcl",
    ),
    "not p2pk": ("21" + K1 + "ad", "raw(21" + K1 + "ad)#4dtmfuk2"),
    "multisig": ("5121" + K1 + "51ae", f"multi(1,{K1})#gs8559k9"),
    "multisig of 17 keys": (
        "51" + ("21" + K1) * 17 + "0111ae",
        f"multi(1,{','.join([K1] * 17)})#58a7llg3",
    ),
    "multisig hybrid": ("5141" + H5 + "51ae", "raw(5141" + H5 + "51ae)#ntz4yz8e"),
    "multisig count mismatch": (
        "5121" + K1 + "52ae",
        "raw(5121" + K1 + "52ae)#5phmyqrl",
    ),
    "multisig count not minimal": (
        "5121" + K1 + "0101ae",
        "raw(5121" + K1 + "0101ae)#8zdjuexl",
    ),
    "multisig threshold pushed": (
        "4c0101" + "21" + K1 + "51ae",
        "raw(4c010121" + K1 + "51ae)#u8v6vpqk",
    ),
    "multisig threshold zero": (
        "0021" + K1 + "51ae",
        "raw(0021" + K1 + "51ae)#2gu2ykxx",
    ),
    "multisig with no ops": ("4cae", "raw(4cae)#w3kt2nq0"),
    "multisig with no count": (
        "5121" + K1 + "4cae",
        "raw(5121" + K1 + "4cae)#kt9m4zh4",
    ),
    "multisig ending late": (
        "5121" + K1 + "5100ae",
        "raw(5121" + K1 + "5100ae)#a63dhng4",
    ),
}


def _text(template: str) -> str:
    for name, xpub in KEYS.items():
        template = template.replace(name, xpub)
    return template


def _descriptors(template: str) -> list[Descriptor]:
    return [parse(one, "regtest") for one in multipath_descriptors(_text(template))]


def _provider(descriptors: list[Descriptor], indexes: range = range(1)) -> Provider:
    """Return the provider of `scantxoutset`, by index and then descriptor."""
    provider = Provider()
    for index in indexes:
        for descriptor in descriptors:
            provider = provider.merged(descriptor.provider(index))
    return provider


@pytest.mark.parametrize("shape", SHAPES)
def test_a_shape_infers_what_core_infers(shape: str) -> None:
    """Each script of the descriptor at index 0, with its expansion's keys."""
    template, expected = SHAPES[shape]
    descriptors = _descriptors(template)
    provider = _provider(descriptors)
    inferred = [
        infer_descriptor(script.script, provider, "regtest")
        for descriptor in descriptors
        for script in descriptor.script_pub_keys(0)
    ]
    assert inferred == expected


def test_a_range_infers_with_every_index_merged() -> None:
    """The provider of index 0 wins over the one of index 1, as in Core."""
    template, expected = RANGED
    (descriptor,) = _descriptors(template)
    provider = _provider([descriptor], range(2))
    scripts = [descriptor.script_pub_keys(index)[0].script for index in range(2)]
    assert [infer_descriptor(s, provider, "regtest") for s in scripts] == expected
    alone = infer_descriptor(scripts[1], descriptor.provider(1), "regtest")
    assert alone != expected[1]


@pytest.mark.parametrize("name", SCRIPTS)
def test_a_script_infers_what_core_infers(name: str) -> None:
    """A script read with an empty provider."""
    script, expected = SCRIPTS[name]
    assert infer_descriptor(script, Provider(), "regtest") == expected


def test_core_scantxoutset_vectors() -> None:
    """`test/functional/rpc_scantxoutset.py` at the v31.1 tag, lines 116-118.

    The ``pkh()`` of a ``combo()``, the second of its scripts.
    """
    tprv = (
        "tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQ"
        "AfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK"
    )
    tpub = (
        "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUG"
        "LnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B"
    )
    cases = [
        (f"combo({tprv}/0h/0h/*)", 0, "026dbd8b2315f296d36e6b6920b1579ca75569464875c7ebe869b536a7d9503c8c", "0h/0h/0", "rthll0rg"),
        (f"combo({tprv}/0h/0h/*)", 1, "033e6f25d76c00bedb3a8993c7d5739ee806397f0529b1b31dda31ef890f19a60c", "0h/0h/1", "mcjajulr"),
        (f"combo({tprv}/1/1/0)", 0, "03e1c5b6e650966971d7e71ef2674f80222752740fc1dfd63bbbd220d2da9bd0fb", "1/1/0", "cxmct4w8"),
        (f"combo({tpub}/1/1/*)", 1, "030d820fc9e8211c4169be8530efbc632775d8286167afd178caaf1089b77daba7", "1/1/1", "z2t3ypsa"),
        (f"combo({tpub}/1/1/*)", 1500, "03832901c250025da2aebae2bfb38d5c703a57ab66ad477f9c578bfbcd78abca6f", "1/1/1500", "vchwd07g"),
    ]  # fmt: skip
    for text, index, sec, path, check in cases:
        prv_keys: dict[str, str] = {}
        descriptor = parse(text, "regtest", prv_keys)
        provider = descriptor.provider(index, prv_keys)
        script = descriptor.script_pub_keys(index, prv_keys)[1].script
        expected = f"pkh([0c5f9a1e/{path}]{sec})#{check}"
        assert infer_descriptor(script, provider, "regtest") == expected


def _addr(script: bytes) -> str:
    return infer_descriptor(script, Provider(), "regtest")


def test_a_known_script_inferring_nothing_is_an_address() -> None:
    """A ``sh()`` and a ``wsh()`` whose script is no descriptor's."""
    inner = bytes.fromhex("6a01ff")
    for script in (ScriptPubKey.p2sh(inner).script, ScriptPubKey.p2wsh(inner).script):
        inferred = infer_descriptor(script, Provider(scripts=(inner,)), "regtest")
        assert inferred == _addr(script)
        assert inferred.startswith("addr(")


def test_a_known_key_core_refuses_is_an_address() -> None:
    """`InferPubkey` refuses a hybrid key, and an uncompressed one in a wpkh."""
    hybrid, uncompressed = bytes.fromhex(H5), bytes.fromhex(U5)
    p2pkh = b"\x76\xa9\x14" + hash160(hybrid) + b"\x88\xac"
    p2wpkh = b"\x00\x14" + hash160(uncompressed)
    provider = Provider(keys={hybrid: None, uncompressed: None})
    for script in (p2pkh, p2wpkh):
        inferred = infer_descriptor(script, provider, "regtest")
        assert inferred == _addr(script)
        assert inferred.startswith("addr(")


def test_a_wsh_holds_no_uncompressed_key() -> None:
    """Neither as a ``pk()`` nor as a miniscript's key."""
    inner = bytes.fromhex("41" + U5 + "ac")
    script = ScriptPubKey.p2wsh(inner).script
    inferred = infer_descriptor(script, Provider(scripts=(inner,)), "regtest")
    assert inferred == _addr(script)


def test_a_miniscript_core_refuses_is_no_miniscript() -> None:
    """One that is not sane, and one holding a key that is no key."""
    not_sane = bytes.fromhex("5ab2")
    no_key = bytes.fromhex("2105" + K1[2:] + "ad51b2")
    for inner in (not_sane, no_key):
        script = ScriptPubKey.p2wsh(inner).script
        inferred = infer_descriptor(script, Provider(scripts=(inner,)), "regtest")
        assert inferred == _addr(script)


def _tr(tree: list) -> tuple[bytes, Provider]:  # type: ignore[type-arg]
    """Return a p2tr script of `K1` and a tree, and its provider."""
    sec = bytes.fromhex(K1)
    internal = PubKeyData(sec, "regtest")
    output_key = output_pubkey(internal, tree)[0]
    leaves = {}
    for number, ((leaf_version, _), _) in enumerate(tree_helper(tree)[0]):
        script, control = input_script_sig(internal, tree, number)
        leaves[control] = (serialize(script), leaf_version)
    root = tree_helper(tree)[1]
    trees = {output_key: (sec[1:], root, leaves)}
    return b"\x51\x20" + output_key, Provider(keys={sec: None}, trees=trees)


def test_a_tree_core_cannot_infer_is_a_rawtr() -> None:
    """A leaf of another version, and a leaf that is no descriptor's."""
    for tree in ([(0xC2, [bytes.fromhex(K1[2:]), "OP_CHECKSIG"])], [(0xC0, ["OP_1"])]):
        script, provider = _tr(tree)
        inferred = infer_descriptor(script, provider, "regtest")
        assert inferred.startswith("rawtr(")


def test_a_tree_the_output_key_does_not_commit_to_is_a_rawtr() -> None:
    """Another output's tree, a wrong merkle root, an internal key no point."""
    script, provider = _tr([(0xC0, [bytes.fromhex(K1[2:]), "OP_CHECKSIG"])])
    ((output_key, spend),) = provider.trees.items()
    internal, root, leaves = spend
    assert infer_descriptor(script, provider, "regtest").startswith("tr(")
    other = bytes.fromhex(K34[2:])
    inferred = infer_descriptor(
        b"\x51\x20" + other, replace(provider, trees={other: spend}), "regtest"
    )
    assert inferred == infer_descriptor(b"\x51\x20" + other, Provider(), "regtest")
    wrong_root = replace(provider, trees={output_key: (internal, bytes(32), leaves)})
    no_point = replace(provider, trees={output_key: (bytes(32), root, leaves)})
    for wrong in (wrong_root, no_point):
        assert infer_descriptor(script, wrong, "regtest").startswith("rawtr(")


def test_a_record_proving_nothing_is_skipped() -> None:
    """`InferTaprootTree` skips it, and a tree left incomplete is refused."""
    leaf = [bytes.fromhex(K1[2:]), "OP_CHECKSIG"]
    other = [bytes.fromhex(K34[2:]), "OP_CHECKSIG"]
    script, provider = _tr([[(0xC0, leaf)], [(0xC0, other)]])
    ((output_key, (internal, root, leaves)),) = provider.trees.items()
    expected = infer_descriptor(script, provider, "regtest")
    assert expected.startswith("tr(")
    control, (leaf_script, version) = next(iter(leaves.items()))
    flipped = control[:-1] + bytes([control[-1] ^ 1])
    noise = {
        control + b"\x00": (leaf_script, version),
        bytes([0xC2]) + control[1:]: (leaf_script, version),
        flipped: (leaf_script, version),
        b"\x00" * 33: (leaf_script, 0xC1),
        b"\x01" * 33: (leaf_script, 0x100),
    }
    noisy = {output_key: (internal, root, {**leaves, **noise})}
    assert (
        infer_descriptor(script, replace(provider, trees=noisy), "regtest") == expected
    )
    (other_control, other_leaf) = list(leaves.items())[1]
    half = {output_key: (internal, root, {other_control: other_leaf})}
    inferred = infer_descriptor(script, replace(provider, trees=half), "regtest")
    assert inferred.startswith("rawtr(")
    # the version byte of the other leaf's only record is not its version
    wrong_byte = bytes([0xC2 | control[0] & 1]) + control[1:]
    mislabelled = {wrong_byte: (leaf_script, version), other_control: other_leaf}
    trees = {output_key: (internal, root, mislabelled)}
    inferred = infer_descriptor(script, replace(provider, trees=trees), "regtest")
    assert inferred.startswith("rawtr(")


def test_control_blocks_that_contradict_each_other() -> None:
    """The three refusals of `InferTaprootTree` only a hash collision reaches.

    A leaf where a branch was, a branch below a leaf, and a sibling that
    neither branch is.
    """
    a, b, c, d = (bytes([n]) * 32 for n in (1, 2, 3, 4))
    base = b"\xc0" + bytes(32)
    leaf = (b"", 0xC0)
    for first, second in ((c + b, b), (b, c + b), (b, c)):
        proven = [(leaf, base + first, d), (leaf, base + second, d)]
        assert _rebuilt(a, proven) is None


# OP_CHECKSIGADD, which typos reads as a misspelling when written out
ADD = f"{0xBA:02x}"


@pytest.mark.parametrize(
    "script,expected",
    [
        ("", None),
        ("21" + K1 + "51" + "9c", None),
        ("20" + K1[2:] + "ac" + "51" + "ac", None),
        ("209c", None),
        ("20" + K1[2:] + ADD + "51" + "9c", None),
        ("20" + K1[2:] + "ac" + "21" + K1 + ADD + "51" + "9c", None),
        ("20" + K1[2:] + "ac" + "51" + "51" + "9c", None),
        ("20" + K1[2:] + "ac" + "4c" + "9c", None),
        ("20" + K1[2:] + "ac" + "52" + "9c", None),
        ("20" + K1[2:] + "ac" + "51" + "9c", (1, [bytes.fromhex(K1[2:])])),
        ("20" + K1[2:] + "ac" + ("20" + K1[2:] + ADD) * 999 + "51" + "9c", None),
    ],
)
def test_match_multi_a(script: str, expected: object) -> None:
    """`MatchMultiA`, which only a hand-built tree leaf reaches refusing."""
    assert _multi_a(bytes.fromhex(script)) == expected


def test_the_provider_a_descriptor_expands_to() -> None:
    """The keys, the scripts and the taproot spend data of an expansion."""
    descriptor = parse(_text("sh(wpkh(@3/0/*))"), "regtest")
    provider = descriptor.provider(1)
    ((sec, origin),) = provider.keys.items()
    assert origin == BIP32KeyOrigin(bytes.fromhex("7d18f8f3"), [0, 1])
    assert provider.scripts == (b"\x00\x14" + hash160(sec),)
    assert provider.trees == {}

    tr = parse(_text("tr(@0/0/*,pk(@1/0/*))"), "regtest")
    assert isinstance(tr, TrDescriptor)
    ((output_key, (internal, root, leaves)),) = tr.provider().trees.items()
    assert b"\x51\x20" + output_key == tr.script_pub_key().script
    assert internal == tr.internal_key.sec(0, "regtest")[1:]
    assert root == tr.taproot_merkle_root()
    assert leaves == tr.taproot_leaf_scripts()

    combo = parse(f"combo({U5})", "regtest")
    assert combo.provider().scripts == ()


def test_merged_keeps_what_it_holds() -> None:
    """An origin it holds stays, and a key it holds without one takes one."""
    k1, k34 = bytes.fromhex(K1), bytes.fromhex(K34)
    first, second = (BIP32KeyOrigin(bytes([n]) * 4, []) for n in (1, 2))
    one = Provider(keys={k1: first, k34: None}, scripts=(b"\x51",), trees={})
    two = Provider(keys={k1: second, k34: second}, scripts=(b"\x52", b"\x51"))
    merged = one.merged(two)
    assert merged.keys == {k1: first, k34: second}
    assert merged.scripts == (b"\x51", b"\x52")
    with pytest.raises(BTClibTypeError):
        one.merged({})  # type: ignore[arg-type]


def _wrong(**changes: object) -> Provider:
    return replace(Provider(), **changes)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "provider",
    [
        "provider",
        _wrong(keys=[]),
        _wrong(keys={"02": None}),
        _wrong(keys={b"\x02": "origin"}),
        _wrong(scripts=[]),
        _wrong(scripts=("51",)),
        _wrong(trees=[]),
        _wrong(trees={"output": ()}),
        _wrong(trees={b"": []}),
        _wrong(trees={b"": ("", b"", {})}),
        _wrong(trees={b"": (b"", "", {})}),
        _wrong(trees={b"": (b"", b"", [])}),
        _wrong(trees={bytes(32): (bytes(32), b"", {"control": (b"", 0xC0)})}),
        _wrong(trees={bytes(32): (bytes(32), b"", {b"": []})}),
        _wrong(trees={bytes(32): (bytes(32), b"", {b"": ("", 0xC0)})}),
        _wrong(trees={bytes(32): (bytes(32), b"", {b"": (b"", "c0")})}),
    ],
)
def test_a_provider_of_the_wrong_types_is_refused(provider: object) -> None:
    """A provider, or an entry of it, of a type it does not declare."""
    with pytest.raises(BTClibTypeError):
        infer_descriptor(b"", provider, "regtest")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "trees",
    [
        {bytes(32): (bytes(32), b"")},
        {bytes(31): (bytes(32), b"", {})},
        {bytes(32): (bytes(33), b"", {})},
        {bytes(32): (bytes(32), bytes(31), {})},
        {bytes(32): (bytes(32), b"", {b"": (b"",)})},
    ],
)
def test_a_provider_of_the_wrong_values_is_refused(trees: object) -> None:
    """Taproot spend data of the wrong size."""
    with pytest.raises(BTClibValueError):
        infer_descriptor(b"", _wrong(trees=trees), "regtest")


def test_the_other_arguments_are_checked() -> None:
    """The script, the network, and what `Descriptor.provider` takes."""
    with pytest.raises(BTClibTypeError):
        infer_descriptor(1, Provider())  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError):
        infer_descriptor(b"", Provider(), "no network")
    descriptor = parse(_text("pkh(@5/0/*)"), "regtest")
    with pytest.raises(BTClibTypeError):
        descriptor.provider(0, "prv keys")  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError):
        descriptor.provider(-1)
