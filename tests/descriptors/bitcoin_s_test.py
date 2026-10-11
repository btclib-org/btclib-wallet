# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the descriptor cases of bitcoin-s that no other test here has.

bitcoin-s's `DescriptorTest.scala`, `DescriptorChecksumTest.scala`,
`ScriptDescriptorTest.scala` and `KeyExpressionTest.scala`, under
`core-test/src/test/scala/org/bitcoins/core/protocol/script/descriptor/`.
`tests/_data/README.md` says which cases are here, where their checksums
and addresses come from, the revision and the licence.

The key expressions of `KeyExpressionTest.scala` are written as the
argument of ``pkh()``. None is left out: ``combo()``, ``addr()`` and
``raw()`` are all supported.
"""

import pytest

from btclib_wallet.descriptors import checksum, parse
from tests import vector_id
from tests.exception_family_test import VALUE_ERRORS

# each: the descriptor, its checksum, the script it gives
ACCEPTED = [
    (
        "pkh([bd16bee5/2147483647']xpub69H7F5dQzmVd3vPuLKtcXJziMEQByuDidnX3YdwgtNsecY5HRGtAAQC5mXTt4dsv9RzyjgDjAQs9VGVV6ydYCHnprc9vvaA5YtqWyL6hyds/0)",
        "j6nhxk2j",
        "76a914ebdc90806a9c4356c1c88e42216611e1cb4c1c1788ac",
    ),
    (
        "wpkh([ffffffff/13']xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/0)",
        "7m942rx5",
        "0014326b2249e3a25d5dc60935f044ee835d090ba859",
    ),
    ("raw(deadbeef)", "89f8spxm", "deadbeef"),
    (
        "raw(512103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea23552ae)",
        "y4wedh2a",
        "512103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea23552ae",
    ),
    (
        "raw(a9149a4d9901d6af519b2a23d4a2f51650fcba87ce7b87)",
        "fj9v58cs",
        "a9149a4d9901d6af519b2a23d4a2f51650fcba87ce7b87",
    ),
    (
        "addr(3PUNyaW7M55oKWJ3kDukwk9bsKvryra15j)",
        "6vhk2xgr",
        "a914eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee87",
    ),
    (
        "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,{pk(xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334/0),{{pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL),pk(df12b7035bdac8e3bab862a3a83d06ea6b17b6753d52edecba9be46f5d09e076)},pk(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)}})",
        "qy83vqvg",
        "512071fff39599a7b78bc02623cbe814efebf1a404f5d8ad34ea80f213bd8943f574",
    ),
]

# each: the descriptor, what the refusal says
REFUSED = [
    (
        "pk(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))",
        "not a key expression",
    ),
    (
        "pkh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))",
        "not a key expression",
    ),
    (
        "sh(sh(pkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))",
        "sh\\(\\) is not allowed inside sh",
    ),
    (
        "wsh(wsh(pkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))",
        "wsh\\(\\) is not allowed inside wsh",
    ),
    (
        "sh(wsh(wsh(pkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))))",
        "wsh\\(\\) is not allowed inside wsh",
    ),
    (
        "wpkh(wsh(pkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))",
        "not a key expression",
    ),
    (
        "wsh(combo(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))",
        "combo\\(\\) is not allowed inside wsh",
    ),
    (
        "combo(pkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))",
        "not a key expression",
    ),
    ("sh(raw(deadbeef))", "raw\\(\\) is not allowed inside sh"),
    ("wsh(raw(deadbeef))", "raw\\(\\) is not allowed inside wsh"),
    (
        "sh(addr(3PUNyaW7M55oKWJ3kDukwk9bsKvryra15j))",
        "addr\\(\\) is not allowed inside sh",
    ),
    (
        "wsh(addr(3PUNyaW7M55oKWJ3kDukwk9bsKvryra15j))",
        "addr\\(\\) is not allowed inside wsh",
    ),
    (
        "tr(5kyzdueo39z3fprtux2qbbwgnnp5ztd7yyr2sc1j299sbcnwjss)",
        "invalid key expression",
    ),
    (
        "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd, pkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1))",
        "not a miniscript fragment",
    ),
]

# BIP380's checksum errors, which `DescriptorChecksumTest.scala` tests
CHECKSUM_REFUSED = [
    # no checksum after the '#'
    ("raw(deadbeef)#", "invalid descriptor checksum"),
    # nine characters
    ("raw(deadbeef)#89f8spxmx", "invalid descriptor checksum"),
    # seven characters
    ("raw(deadbeef)#89f8spx", "invalid descriptor checksum"),
    # an error in the payload
    ("raw(deedbeef)#89f8spxm", "invalid descriptor checksum"),
    # a second '#' in the checksum
    ("raw(deadbeef)##9f8spxm", "more than one '#'"),
]

# a ranged descriptor, which `DescriptorChecksumTest.scala` writes with
# 'h' for hardened, and Core's addresses at index 0, 1 and 2
RANGED = "wpkh([d34db33f/84h/0h/0h]xpub6DJ2dNUysrn5Vt36jH2KLBT2i1auw1tTSSomg8PhqNiUtx8QX2SvC9nrHu81fT41fvDUnhMjEzQgXnQjKEu3oaqMSzhSrHMxyyoEAmUHQbY/0/*)"
RANGED_CHECKSUM = "cjjspncu"
RANGED_ADDRESSES = [
    "bc1qg6ucjz7kgdedam7v5yarecy54uqw82yym06z3q",
    "bc1qgxexg7pg982urq8ekk3l8lq65zh7vwsrc9kgp9",
    "bc1q5vf6dw2d9heezqxrjp6jkefveprg90uhgulqj4",
]

# each: the descriptor, Core's addresses at index 0, and at 1 and 2 where ranged
KEY_ACCEPTED = [
    (
        "pkh([deadbeef/0'/0'/0']5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss)",
        ["1HZwkjkeaoZfTSaJxDw6aKkxp45agDiEzN"],
    ),
    (
        "pkh([deadbeef/0'/1'/2']xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc)",
        ["15XVotxCAV7sRx1PSCkQNsGw3W9jT9A94R"],
    ),
    (
        "pkh([deadbeef/0'/1'/2']xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/3/4/5)",
        ["15kaay9X7nP2tMi6DjuQdNvZSkXj2A7MtT"],
    ),
    (
        "pkh([deadbeef/0'/1'/2']xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/3/4/5/*)",
        [
            "1L3jGiW4PxUCrLLd3pCJs756kE7oGv2tYn",
            "1RmEL1phM9Cmd4tswDdwu4ZqZjyMRXoT5",
            "171Cp2MhKDmsE2qVVJkXgv4PZMdXtZuU76",
        ],
    ),
    (
        "pkh(xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/3'/4'/5'/*)",
        [
            "1GcsjAJ7MY47vvdzD9bJt8yqshwTYfSACB",
            "1SXZuCgUh6wQEVptMfapx3iaKTyLrqBMH",
            "1MLpK7xfmYDCb2YCh6G5zTWTM8pA6kPSVD",
        ],
    ),
    (
        "pkh(xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/3'/4'/5'/*')",
        [
            "17x7soVeNv89M2ckptBeGpaUNYMSvsqQqa",
            "1xZR4EknYbMcdamHEXps6CuqVeBKCud96",
            "12oWpWwHzG7Yen7yjdShqgdM11AbxCX8xz",
        ],
    ),
    (
        "pkh([deadbeef/0'/1'/2]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/3'/4'/5'/*')",
        [
            "17x7soVeNv89M2ckptBeGpaUNYMSvsqQqa",
            "1xZR4EknYbMcdamHEXps6CuqVeBKCud96",
            "12oWpWwHzG7Yen7yjdShqgdM11AbxCX8xz",
        ],
    ),
    (
        "pkh([deadbeef/0'/0'/0']0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600)",
        ["1AKcnS2ip6TBkacnz9okU6H4d43KiCSqBv"],
    ),
    (
        "pkh([deadbeef/0'/1'/2']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)",
        ["15XVotxCAV7sRx1PSCkQNsGw3W9jT9A94R"],
    ),
    (
        "pkh([deadbeef/0'/1'/2']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/3/4/5)",
        ["15kaay9X7nP2tMi6DjuQdNvZSkXj2A7MtT"],
    ),
    (
        "pkh([deadbeef/0'/1'/2']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/3/4/5/*)",
        [
            "1L3jGiW4PxUCrLLd3pCJs756kE7oGv2tYn",
            "1RmEL1phM9Cmd4tswDdwu4ZqZjyMRXoT5",
            "171Cp2MhKDmsE2qVVJkXgv4PZMdXtZuU76",
        ],
    ),
]

# each: the descriptor, what the refusal says
KEY_REFUSED = [
    (
        "pkh([deadbeef/0h/0h/0h/*]0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600)",
        "invalid derivation index",
    ),
    (
        "pkh([deadbeef/0h/0h/0h/]0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600)",
        "invalid derivation index",
    ),
    (
        "pkh([deadbef/0h/0h/0h]0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600)",
        "invalid key origin fingerprint",
    ),
    (
        "pkh([deadbeeef/0h/0h/0h]0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600)",
        "invalid key origin fingerprint",
    ),
    (
        "pkh([deadbeef/0f/0f/0f]0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600)",
        "invalid derivation index",
    ),
    (
        "pkh([deadbeef/0H/0H/0H]0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600)",
        "invalid derivation index",
    ),
    (
        "pkh([deadbeef/-0/-0/-0]0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600)",
        "invalid derivation index",
    ),
    (
        "pkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1/0)",
        "derivation path after a key that cannot derive",
    ),
    (
        "pkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1/*)",
        "derivation path after a key that cannot derive",
    ),
]


@pytest.mark.parametrize(
    "descriptor, expected_checksum, script",
    [
        pytest.param(*case, id=vector_id(index, case[0]))
        for index, case in enumerate(ACCEPTED)
    ],
)
def test_accepted(descriptor: str, expected_checksum: str, script: str) -> None:
    """Give the script bitcoin-s expects and the checksum Core computes."""
    prv_keys: dict[str, str] = {}
    parsed = parse(descriptor, prv_keys=prv_keys)
    assert parsed.script_pub_key(prv_keys=prv_keys).script.hex() == script
    assert checksum(descriptor) == expected_checksum
    parse(f"{descriptor}#{expected_checksum}", prv_keys={})


@pytest.mark.parametrize(
    "descriptor, message",
    [
        pytest.param(*case, id=vector_id(index, case[0]))
        for index, case in enumerate(REFUSED + CHECKSUM_REFUSED)
    ],
)
def test_refused(descriptor: str, message: str) -> None:
    """Refuse the descriptors bitcoin-s refuses."""
    with pytest.raises(VALUE_ERRORS, match=message):
        parse(descriptor)


def test_ranged_descriptor() -> None:
    """Keep the 'h' of the input, and derive the addresses Core derives."""
    parsed = parse(RANGED)
    assert str(parsed) == RANGED
    assert checksum(RANGED) == RANGED_CHECKSUM
    assert [parsed.address(index) for index in range(3)] == RANGED_ADDRESSES


def test_a_space_in_a_tr_tree_is_what_is_refused() -> None:
    """Accept the tree bitcoin-s refuses, once its space is gone.

    bitcoin-s refuses ``tr(KEY, pkh(KEY))``. Core refuses it too, for the
    space: it reads `` pkh(KEY)`` as the name of a function. Without the
    space Core accepts a ``pkh()`` leaf, and so does this package.
    """
    internal = "a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
    leaf = "pkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)"
    address = "bc1p0j6yfyle528z65m9dshtd7e6q5a04gzl3t37736rjtv8t8xh3daqn4ux0n"
    assert parse(f"tr({internal},{leaf})").address() == address


@pytest.mark.parametrize(
    "descriptor, addresses",
    [
        pytest.param(*case, id=vector_id(index, case[0]))
        for index, case in enumerate(KEY_ACCEPTED)
    ],
)
def test_key_accepted(descriptor: str, addresses: list[str]) -> None:
    """Derive the addresses Core derives from the key expression."""
    prv_keys: dict[str, str] = {}
    parsed = parse(descriptor, prv_keys=prv_keys)
    assert parsed.is_ranged == (len(addresses) > 1)
    derived = [parsed.address(index, prv_keys) for index in range(len(addresses))]
    assert derived == addresses


@pytest.mark.parametrize(
    "descriptor, message",
    [
        pytest.param(*case, id=vector_id(index, case[0]))
        for index, case in enumerate(KEY_REFUSED)
    ],
)
def test_key_refused(descriptor: str, message: str) -> None:
    """Refuse the key expressions bitcoin-s refuses."""
    with pytest.raises(VALUE_ERRORS, match=message):
        parse(descriptor)
