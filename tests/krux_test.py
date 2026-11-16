# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

# The vectors below are transcribed from Krux's tests, under Krux's
# licence, whose notice they keep:
#
# The MIT License (MIT)
#
# Copyright (c) 2021-2023 Krux contributors
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""Krux's timelocked miniscript psbts, and the Specter wallet files it reads.

Another wallet's files, transcribed under Krux's own names, and
`tests/_data/README.md` pins them. The psbts are what Krux signs in its
tests: the descriptor of each, a psbt as a coordinator made it, and the
psbt Krux returns, which keeps the signatures, the coin spent and the
scripts of a ``wsh()`` input, and drops the rest. The keys that sign
them are of mnemonics Krux's tests publish. The wallet files are
Specter's: a JSON object of a label, a birth height and a descriptor.

What our code reads of each, and what it does not:

- the psbts parse, and are written back with Krux's pairs, but for the
  key path signature Krux keeps beside a final witness;
- each descriptor derives the coin its psbt spends, once its checksum is
  dropped: Krux's checksums are not the ones Bitcoin Core computes. A
  ledger restored from it, its checksum fixed, watches that coin;
- our signer signs each psbt with the key Krux signed with, and the ECDSA
  signature is Krux's;
- the ``wsh()`` spend, combined with the coordinator's psbt, which names
  the key of its ``pkh()``, the key path spend, the recovery leaf signed
  at the sequence its timelock asks and the expanding multisig signed by
  both its keys finalize, and the script engine accepts them;
- the recovery leaf Krux signed does not finalize: its psbt's sequence,
  ``0xfffffffd``, sets the bit that disables a relative lock, so the
  leaf's ``older(6)`` can never be met;
- a Specter file's descriptor and birth height are a BIP139 account, and
  its label and its devices are not: `bip139` does not carry BIP139's
  `name`, and a device names no fingerprint. The expanding multisig's
  file carries a checksum Core refuses too, and the joint custody's a
  descriptor that repeats a public key, which Core refuses as not sane;
- a ledger restored from the account of each file whose descriptor reads
  watches the file's first receive address.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from btclib.exceptions import BTClibValueError
from btclib.script.engine import verify_transaction

from btclib_wallet import bip139
from btclib_wallet.descriptors import add_checksum, multipath_descriptors, parse
from btclib_wallet.ledger import Ledger
from btclib_wallet.mnemonic import bip39
from btclib_wallet.psbt import Psbt
from btclib_wallet.psbt.psbt import (
    assert_signatures_only,
    combine,
    finalize,
    miniscript_solver,
    prevouts,
)
from btclib_wallet.psbt_signer import SoftwareSigner
from tests.ledger.conftest import FakeChain
from tests.psbt import psbt_maps

# tests/test_psbt.py

WSH_MINISCRIPT = (
    "wsh(or_d(pk([73c5da0a/48h/1h/0h/2h]tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyN"
    "dUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEh"
    "eQ/<0;1>/*),and_v(v:pkh([02e8bff2/48h/1h/0h/2h]tpubDESmyzX6RMHRHvzxgLVXy"
    "md193CSYYT6C9M9wa4XK649tbAy2WeEvkPwBgoC7i76MypQxpuruUazQjqibbCogTZuENJX6"
    "YiuZ5Fy8sf7GNi/<0;1>/*),older(65535))))#466dtswe"
)
TR_MINISCRIPT = (
    "tr([73c5da0a/48h/1h/0h/2h]tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8"
    "x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/<0;1>/"
    "*,and_v(v:pk([02e8bff2/48h/1h/0h/2h]tpubDESmyzX6RMHRHvzxgLVXymd193CSYYT6"
    "C9M9wa4XK649tbAy2WeEvkPwBgoC7i76MypQxpuruUazQjqibbCogTZuENJX6YiuZ5Fy8sf7"
    "GNi/<0;1>/*),older(6)))#rfuhsd9c"
)
TR_EXP_MULTI_MINISCRIPT = (
    "tr(tpubD6NzVbkrYhZ4YYQjuKXFp85eRGCk4oA94MXbbHJW6zNAibMfkwZh7JQNVHEhpcQYa"
    "RCUs3b5PhvKPKESGoAJptiLvF8Rm1jhoFsryyFuR1P/<0;1>/*,{and_v(v:multi_a(2,[7"
    "3c5da0a/48h/1h/0h/2h]tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4"
    "j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/<2;3>/*,[02"
    "e8bff2/48h/1h/0h/2h]tpubDESmyzX6RMHRHvzxgLVXymd193CSYYT6C9M9wa4XK649tbAy"
    "2WeEvkPwBgoC7i76MypQxpuruUazQjqibbCogTZuENJX6YiuZ5Fy8sf7GNi/<2;3>/*,[8cb"
    "36b38/48h/1h/0h/2h]tpubDESTVwqbbaSoN2mPq7tcWkPBpRBkaEADrUzUhRTVnNef6oVn6"
    "w2PHL4zoUjUAJSPLJQRBetkgX4sDRcoaCyFHxqHGyWyaiV8REKDkh7zQac/<0;1>/*),olde"
    "r(6)),multi_a(2,[73c5da0a/48h/1h/0h/2h]tpubDFH9dgzveyD8zTbPUFuLrGmCydNvx"
    "ehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3R"
    "WZEheQ/<0;1>/*,[02e8bff2/48h/1h/0h/2h]tpubDESmyzX6RMHRHvzxgLVXymd193CSYY"
    "T6C9M9wa4XK649tbAy2WeEvkPwBgoC7i76MypQxpuruUazQjqibbCogTZuENJX6YiuZ5Fy8s"
    "f7GNi/<0;1>/*)})#6ga85u82"
)
TEST_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon about"
)
TEST_MNEMONIC_BIP85_I0 = (
    "prosper short ramp prepare exchange stove life snack client enough purpose fold"
)
MINIS_P2WSH_PSBT_B64 = (
    "cHNidP8BAKgCAAAAAZZZFyTIyHAAHpgx4RTJClY3DBD/wvYtvHlQBWiIcZydAAAAAAD9////"
    "AyChBwAAAAAAFgAUVpExmvtni79DrSaMRaiKiM2NT2tAQg8AAAAAACIAIJ/v3lcOin2rUPE1"
    "jh1mzXq69rL7BIX/ddrN29OP3A3zq40HAAAAAAAiACDfZk57e1AVXMBz66RuW/0oR+hUhBOk"
    "RWLyvAnNpy8cagAAAAAAAQCiAgAAAAABAU8jn+rTqB80fFdKbj1CdOpWL99Sy8fOXvs6iNQC"
    "MGMmAQAAAAD9////AQZ5HgAAAAAAIgAgGtm2ZA4YoTas6xCsjIQq247clo23ri8+wy0TRq/d"
    "MwcBQD/YWe8kwsYxkM6iEcf+7RaaFH3JU+nFKXO/gFUX23DngDPpbNA4sqoTRJ3/5io1PLJZ"
    "dUZ+T699wfAsNhxhPOQAAAAAAQErBnkeAAAAAAAiACAa2bZkDhihNqzrEKyMhCrbjtyWjbeu"
    "Lz7DLRNGr90zBwEFRCEDaJVy4osP7anWmBwCN9nl3tv+wW3nFD9oCgLtXRWfdYesc2R2qRRQ"
    "ZtW0nWWtzkLdyI8F8UQ/7KmQioitA///ALJoIgYDLMRSZBc2IWvKWJwMwQE43VdzU3UzmLMS"
    "nBUa9H/5NpIcAui/8jAAAIABAACAAAAAgAIAAIAAAAAAAQAAACIGA2iVcuKLD+2p1pgcAjfZ"
    "5d7b/sFt5xQ/aAoC7V0Vn3WHHHPF2gowAACAAQAAgAAAAIACAACAAAAAAAEAAAAAACICAnEf"
    "tmGVk/vJgt8Yn9ZQ0htivPcj0929eTfkCa5qm+oEHALov/IwAACAAQAAgAAAAIACAACAAAAA"
    "AAMAAAAiAgKxoTXVKpUeAQDixkzK2NmSWE0DUbnae31O4vHK0SaoBBxzxdoKMAAAgAEAAIAA"
    "AACAAgAAgAAAAAADAAAAACICAnxuOjHDK8ueogVkcyIpbFujaTY/E2747lrLIcj51R5QHALo"
    "v/IwAACAAQAAgAAAAIACAACAAQAAAAEAAAAiAgL2bDCgfbz9YefFtvrPTmwn+Ue6+suz/A6i"
    "geAWfm6UjRxzxdoKMAAAgAEAAIAAAACAAgAAgAEAAAABAAAAAA=="
)
SIGNED_MINIS_P2WSH_PSBT_B64 = (
    "cHNidP8BAKgCAAAAAZZZFyTIyHAAHpgx4RTJClY3DBD/wvYtvHlQBWiIcZydAAAAAAD9////"
    "AyChBwAAAAAAFgAUVpExmvtni79DrSaMRaiKiM2NT2tAQg8AAAAAACIAIJ/v3lcOin2rUPE1"
    "jh1mzXq69rL7BIX/ddrN29OP3A3zq40HAAAAAAAiACDfZk57e1AVXMBz66RuW/0oR+hUhBOk"
    "RWLyvAnNpy8cagAAAAAAAQCiAgAAAAABAU8jn+rTqB80fFdKbj1CdOpWL99Sy8fOXvs6iNQC"
    "MGMmAQAAAAD9////AQZ5HgAAAAAAIgAgGtm2ZA4YoTas6xCsjIQq247clo23ri8+wy0TRq/d"
    "MwcBQD/YWe8kwsYxkM6iEcf+7RaaFH3JU+nFKXO/gFUX23DngDPpbNA4sqoTRJ3/5io1PLJZ"
    "dUZ+T699wfAsNhxhPOQAAAAAAQErBnkeAAAAAAAiACAa2bZkDhihNqzrEKyMhCrbjtyWjbeu"
    "Lz7DLRNGr90zByICA2iVcuKLD+2p1pgcAjfZ5d7b/sFt5xQ/aAoC7V0Vn3WHRzBEAiAr5ACh"
    "y/GHi+8HhokaVpkLJTNX++B2wlNcr8RUjmrmcAIgHS9cnlMOPP/QgVVM0RV8HH15jj/cqrw9"
    "NsHMBmxsyskBAQVEIQNolXLiiw/tqdaYHAI32eXe2/7BbecUP2gKAu1dFZ91h6xzZHapFFBm"
    "1bSdZa3OQt3IjwXxRD/sqZCKiK0D//8AsmgAAAAA"
)
MINIS_TR_PSBT_B64 = (
    "cHNidP8BALQCAAAAAV1wmxLC1I2zhBvb/xz9D47r6Lj1KCL0xr1jqS3yTIX/AAAAAAD9////"
    "A0BCDwAAAAAAIgAgGtm2ZA4YoTas6xCsjIQq247clo23ri8+wy0TRq/dMwcgoQcAAAAAACJR"
    "IECbDgsZc6aw71iJhjnT+24fhkwwaQcBeQzAKLfYAyKH3YgHAAAAAAAiUSBb9VQQXYabMACh"
    "LSgfclyBxe/EyI9CbdVU55TeBJFyUgAAAAAAAQEr73MeAAAAAAAiUSCKMs95fYJ22tHaq0FO"
    "is38SPVg352JZymPeaMp80ThwyIVwLGhNdUqlR4BAOLGTMrY2ZJYTQNRudp7fU7i8crRJqgE"
    "JSBxH7ZhlZP7yYLfGJ/WUNIbYrz3I9PdvXk35AmuapvqBK1WssAhFnEftmGVk/vJgt8Yn9ZQ"
    "0htivPcj0929eTfkCa5qm+oEPQH3BXv7e9eze4jSTr+PgvfiuCLkXs7bSOlAeCPQqaBnWALo"
    "v/IwAACAAQAAgAAAAIACAACAAAAAAAMAAAAhFrGhNdUqlR4BAOLGTMrY2ZJYTQNRudp7fU7i"
    "8crRJqgEHQBzxdoKMAAAgAEAAIAAAACAAgAAgAAAAAADAAAAARcgsaE11SqVHgEA4sZMytjZ"
    "klhNA1G52nt9TuLxytEmqAQBGCD3BXv7e9eze4jSTr+PgvfiuCLkXs7bSOlAeCPQqaBnWAAA"
    "AQUgCltZwSHuuC9ETlRoJyrNYv9NHUH8NLxR5mwpUS+4ousBBicAwCQgNCGNnpQXkylYa9f6"
    "nYj1HGwVeZN1xflZXOoQv2wj1IOtVrIhBwpbWcEh7rgvRE5UaCcqzWL/TR1B/DS8UeZsKVEv"
    "uKLrHQBzxdoKMAAAgAEAAIAAAACAAgAAgAAAAAAFAAAAIQc0IY2elBeTKVhr1/qdiPUcbBV5"
    "k3XF+Vlc6hC/bCPUgz0B+HPJ7BJ6Q0eyE8RsiTNNmOTI053J2hH40RD+MpDWZP0C6L/yMAAA"
    "gAEAAIAAAACAAgAAgAAAAAAFAAAAAAEFIPZsMKB9vP1h58W2+s9ObCf5R7r6y7P8DqKB4BZ+"
    "bpSNAQYnAMAkIHxuOjHDK8ueogVkcyIpbFujaTY/E2747lrLIcj51R5QrVayIQd8bjoxwyvL"
    "nqIFZHMiKWxbo2k2PxNu+O5ayyHI+dUeUD0Bv3zqft7M8nIO0b3NAPbE7MAFN+VV/xm4ztwJ"
    "x+a3OlQC6L/yMAAAgAEAAIAAAACAAgAAgAEAAAABAAAAIQf2bDCgfbz9YefFtvrPTmwn+Ue6"
    "+suz/A6igeAWfm6UjR0Ac8XaCjAAAIABAACAAAAAgAIAAIABAAAAAQAAAAA="
)
IN_KEY_SIGNED_MINIS_TR_PSBT_B64 = (
    "cHNidP8BALQCAAAAAV1wmxLC1I2zhBvb/xz9D47r6Lj1KCL0xr1jqS3yTIX/AAAAAAD9////"
    "A0BCDwAAAAAAIgAgGtm2ZA4YoTas6xCsjIQq247clo23ri8+wy0TRq/dMwcgoQcAAAAAACJR"
    "IECbDgsZc6aw71iJhjnT+24fhkwwaQcBeQzAKLfYAyKH3YgHAAAAAAAiUSBb9VQQXYabMACh"
    "LSgfclyBxe/EyI9CbdVU55TeBJFyUgAAAAAAAQEr73MeAAAAAAAiUSCKMs95fYJ22tHaq0FO"
    "is38SPVg352JZymPeaMp80ThwwEIQgFAUTOY5FvQfUhNhgBItKAWsTk8aeuhqD/EaYy6fo1q"
    "Yie4TU2Al6T0NPCxu9T3F2kHUGM6erz6cq0Oct1i5NB6SgETQFEzmORb0H1ITYYASLSgFrE5"
    "PGnroag/xGmMun6NamInuE1NgJek9DTwsbvU9xdpB1BjOnq8+nKtDnLdYuTQekoAAAAA"
)
RECOV_M_TR_PSBT_B64 = (
    "cHNidP8BAF4CAAAAAV1wmxLC1I2zhBvb/xz9D47r6Lj1KCL0xr1jqS3yTIX/AAAAAAAGAAAA"
    "AeVuHgAAAAAAIlEgUyuCGLR8U6LzFbFSSNDDHd4ps+LWTQ3qUNvOrhNn9fsAAAAAAAEBK+9z"
    "HgAAAAAAIlEgijLPeX2CdtrR2qtBTorN/Ej1YN+diWcpj3mjKfNE4cMiFcCxoTXVKpUeAQDi"
    "xkzK2NmSWE0DUbnae31O4vHK0SaoBCUgcR+2YZWT+8mC3xif1lDSG2K89yPT3b15N+QJrmqb"
    "6gStVrLAIRZxH7ZhlZP7yYLfGJ/WUNIbYrz3I9PdvXk35AmuapvqBD0B9wV7+3vXs3uI0k6/"
    "j4L34rgi5F7O20jpQHgj0KmgZ1gC6L/yMAAAgAEAAIAAAACAAgAAgAAAAAADAAAAIRaxoTXV"
    "KpUeAQDixkzK2NmSWE0DUbnae31O4vHK0SaoBB0Ac8XaCjAAAIABAACAAAAAgAIAAIAAAAAA"
    "AwAAAAEXILGhNdUqlR4BAOLGTMrY2ZJYTQNRudp7fU7i8crRJqgEARgg9wV7+3vXs3uI0k6/"
    "j4L34rgi5F7O20jpQHgj0KmgZ1gAAA=="
)
TAP_TREE_SIGNED_RECOV_PSBT_B64 = (
    "cHNidP8BALQCAAAAAV1wmxLC1I2zhBvb/xz9D47r6Lj1KCL0xr1jqS3yTIX/AAAAAAD9////"
    "A0BCDwAAAAAAIgAgGtm2ZA4YoTas6xCsjIQq247clo23ri8+wy0TRq/dMwcgoQcAAAAAACJR"
    "IECbDgsZc6aw71iJhjnT+24fhkwwaQcBeQzAKLfYAyKH3YgHAAAAAAAiUSBb9VQQXYabMACh"
    "LSgfclyBxe/EyI9CbdVU55TeBJFyUgAAAAAAAQEr73MeAAAAAAAiUSCKMs95fYJ22tHaq0FO"
    "is38SPVg352JZymPeaMp80Thw0EUcR+2YZWT+8mC3xif1lDSG2K89yPT3b15N+QJrmqb6gT3"
    "BXv7e9eze4jSTr+PgvfiuCLkXs7bSOlAeCPQqaBnWEDg8wrwGzv23h1AWMBv4XNg6uILSii8"
    "NMFIqSXXYHHdQ4vTzesdzCJ3k8tqAltoV/DNvDM+01PwYc79khRcnhoXAAAAAA=="
)
EXP_TR_MINIS_PSBT_B64 = (
    "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"
    "AA=="
)
SIGNED_EXP_TR_MINIS_PSBT_B64 = (
    "cHNidP8BALQCAAAAAX/KhJ3ZhdhzqUx6vZUFYh88sfMBOgVqzWE7wY2IR1zxAAAAAAD9////"
    "AyChBwAAAAAAIlEgh1w/OzuAEMD+BuPcy2rtAMSaDZE/jcMasdolOwplioJAQg8AAAAAACJR"
    "IIoyz3l9gnba0dqrQU6KzfxI9WDfnYlnKY95oynzROHD2oEHAAAAAAAiUSASWqXSxYtSyH69"
    "jbsdSw0s6hDyFkeYkGc8iKQMUCf/OgAAAAAAAQEr5W4eAAAAAAAiUSBTK4IYtHxTovMVsVJI"
    "0MMd3imz4tZNDepQ286uE2f1+0EUUrEvnMbNNYuX+qDx0JJG4ybhHQdvYA6ncG5ztzxuEmXL"
    "ToX/NmN8axrk+UvWU+drbTU4piY9m8SD4Zj49o39ekAEPMhGIog5xZmlR/87j90YTVZHO88f"
    "0V0WMzSkuEQaCJIKMU7q3c2GlpaAAl5XfyPGc7RMcLICj014xRR2efeGQRRolXLiiw/tqdaY"
    "HAI32eXe2/7BbecUP2gKAu1dFZ91h1e7ZIMQ2OzUSBPaEsAhalhjV3AIb1wvXmo/GDKFVcSp"
    "QPk6R2pV+yQ5qD7I895AZouHlkkX56rIeeuX+UdTWDr1KxFlSpt4GHiqGni4HelSDuJqS46t"
    "cs3FVlYfCRGtz5MAAAAA"
)

# tests/pages/home_pages/test_home.py

SPECTER_MINISCRIPT_SINGLE_INHERITANCE_WALLET_DATA = (
    '{"label": "Specter Miniscript Singles Inheritance Wallet 144 blocks", '
    '"blockheight": 0, "descriptor": "wsh(or_d(pk([55f8fc5d/48h/0h/0h/'
    "2h]xpub6EKmKYGYc1WY6t9d3d9SksR8keSaPZbFa6tqsGiH4xVxx8d2YyxSX7WG6yXEX3C"
    "mG54dPCxaapDw1XsjwCmfoqP7tbsAeqMVfKvqSAu4ndy/<0;1>/*),"
    "and_v(v:pkh([73c5da0a/48h/0h/0h/"
    "2h]xpub6DkFAXWQ2dHxq2vatrt9qyA3bXYU4ToWQwCHbf5XB2mSTexcHZCeKS1VZYcPoBd"
    "5X8yVcbXFHJR9R8UCVpt82VX1VhR28mCyxUFL4r6KFrf/<0;1>/*),"
    'older(144))))#7zusggcg"}'
)
SPECTER_MINISCRIPT_EXPANDING_MULTISIG_WALLET_DATA = (
    '{"label": "Specter Miniscript Expanding Multisig Wallet 144 blocks", '
    '"blockheight": 0, "descriptor": "wsh(or_d(multi(2,[55f8fc5d/48h/0h/0h/'
    "2h]xpub6EKmKYGYc1WY6t9d3d9SksR8keSaPZbFa6tqsGiH4xVxx8d2YyxSX7WG6yXEX3C"
    "mG54dPCxaapDw1XsjwCmfoqP7tbsAeqMVfKvqSAu4ndy/<0;1>/*,[3e15470d/48h/0h/"
    "0h/"
    "2h]xpub6F2P6Pz5KLPgCc6pTBd2xxCunaSYWc8CdkL28W5z15pJrN3aCYY7mCUAkCMtqrg"
    "T2wdhAGgRnJxAkCCUpGKoXKxQ57yffEGmPwtYA3DEXwu/<0;1>/*),"
    "and_v(v:thresh(2,pkh([55f8fc5d/48h/0h/0h/"
    "2h]xpub6EKmKYGYc1WY6t9d3d9SksR8keSaPZbFa6tqsGiH4xVxx8d2YyxSX7WG6yXEX3C"
    "mG54dPCxaapDw1XsjwCmfoqP7tbsAeqMVfKvqSAu4ndy/<2;3>/*),a:pkh([3e15470d/"
    "48h/0h/0h/"
    "2h]xpub6F2P6Pz5KLPgCc6pTBd2xxCunaSYWc8CdkL28W5z15pJrN3aCYY7mCUAkCMtqrg"
    "T2wdhAGgRnJxAkCCUpGKoXKxQ57yffEGmPwtYA3DEXwu/<2;3>/*),a:pkh([d3a80c8b/"
    "48h/0h/0h/"
    "2h]xpub6FKYY6y3oVi7ihSCszFKRSeZj5SzrfSsUFXhKqjMV4iigrLhxwMX3mrjioNyLTZ"
    "5iD3u4wU9S3tyzpJGxhd5geaXoQ68jGz2M6dfh2zJrUv/<0;1>/*)),"
    'older(144))))#tx2awx9h", "devices": [{"type": "other", '
    '"label": "Key1"}, {"type": "other", "label": "Key2"}, '
    '{"type": "other", "label": "Key3"}]}'
)
SPECTER_MINISCRIPT_3_KEY_JOINT_CUSTODY_WALLET_DATA = (
    '{"label": "Specter Miniscript 3 Key Joint Custody Wallet", '
    '"blockheight": 0, "descriptor": "wsh(andor(multi(2,[55f8fc5d/48h/0h/'
    "0h/"
    "379h]xpub6EKmKYGYc1WY6t9d3d9SksR8keSaPZbFa6tqsGiH4xVxx8d2YyxSX7WG6yXEX"
    "3CmG54dPCxaapDw1XsjwCmfoqP7tbsAeqMVfKvqSAu4ndy/<0;1>/*,[3e15470d/48h/"
    "0h/0h/"
    "379h]xpub6F2P6Pz5KLPgCc6pTBd2xxCunaSYWc8CdkL28W5z15pJrN3aCYY7mCUAkCMtq"
    "rgT2wdhAGgRnJxAkCCUpGKoXKxQ57yffEGmPwtYA3DEXwu/<0;1>/*,[d3a80c8b/48h/"
    "0h/0h/"
    "379h]xpub6FKYY6y3oVi7ihSCszFKRSeZj5SzrfSsUFXhKqjMV4iigrLhxwMX3mrjioNyL"
    "TZ5iD3u4wU9S3tyzpJGxhd5geaXoQ68jGz2M6dfh2zJrUv/<0;1>/*),"
    "or_i(and_v(v:pkh([d3a80c8b/48h/0h/0h/"
    "380h]xpub6FKYY6y3oVi7ihSCszFKRSeZj5SzrfSsUFXhKqjMV4iigrLhxwMX3mrjioNyL"
    "TZ5iD3u4wU9S3tyzpJGxhd5geaXoQ68jGz2M6dfh2zJrUv/<0;1>/*),after(288)),"
    "thresh(2,pk([55f8fc5d/48h/0h/0h/"
    "2h]xpub6EKmKYGYc1WY6t9d3d9SksR8keSaPZbFa6tqsGiH4xVxx8d2YyxSX7WG6yXEX3C"
    "mG54dPCxaapDw1XsjwCmfoqP7tbsAeqMVfKvqSAu4ndy/<0;1>/*),s:pk([3e15470d/"
    "48h/0h/0h/"
    "2h]xpub6F2P6Pz5KLPgCc6pTBd2xxCunaSYWc8CdkL28W5z15pJrN3aCYY7mCUAkCMtqrg"
    "T2wdhAGgRnJxAkCCUpGKoXKxQ57yffEGmPwtYA3DEXwu/<0;1>/*),s:pk([d3a80c8b/"
    "48h/0h/0h/"
    "2h]xpub6FKYY6y3oVi7ihSCszFKRSeZj5SzrfSsUFXhKqjMV4iigrLhxwMX3mrjioNyLTZ"
    "5iD3u4wU9S3tyzpJGxhd5geaXoQ68jGz2M6dfh2zJrUv/<0;1>/*),"
    "snl:after(144))),and_v(v:thresh(2,pkh([55f8fc5d/48h/0h/0h/"
    "758h]xpub6EKmKYGYc1WY6t9d3d9SksR8keSaPZbFa6tqsGiH4xVxx8d2YyxSX7WG6yXEX"
    "3CmG54dPCxaapDw1XsjwCmfoqP7tbsAeqMVfKvqSAu4ndy/<0;1>/*),"
    "a:pkh([3e15470d/48h/0h/0h/"
    "758h]xpub6F2P6Pz5KLPgCc6pTBd2xxCunaSYWc8CdkL28W5z15pJrN3aCYY7mCUAkCMtq"
    "rgT2wdhAGgRnJxAkCCUpGKoXKxQ57yffEGmPwtYA3DEXwu/<0;1>/*),"
    "a:pkh([d3a80c8b/48h/0h/0h/"
    "758h]xpub6FKYY6y3oVi7ihSCszFKRSeZj5SzrfSsUFXhKqjMV4iigrLhxwMX3mrjioNyL"
    "TZ5iD3u4wU9S3tyzpJGxhd5geaXoQ68jGz2M6dfh2zJrUv/<0;1>/*)),"
    'after(432))))", "devices": [{"type": "other", "label": "PK1"}, '
    '{"type": "other", "label": "PK2"}, {"type": "other", "label": "PK3"}, '
    '{"type": "other", "label": "PAK1"}, {"type": "other", '
    '"label": "PAK2"}, {"type": "other", "label": "PAK3"}, '
    '{"type": "other", "label": "SAK"}, {"type": "other", "label": "RK1"}, '
    '{"type": "other", "label": "RK2"}, {"type": "other", "label": "RK3"}]}'
)

# each psbt, and the descriptor of the coin it spends
_PSBTS = {
    "MINIS_P2WSH_PSBT_B64": (MINIS_P2WSH_PSBT_B64, WSH_MINISCRIPT),
    "SIGNED_MINIS_P2WSH_PSBT_B64": (SIGNED_MINIS_P2WSH_PSBT_B64, WSH_MINISCRIPT),
    "MINIS_TR_PSBT_B64": (MINIS_TR_PSBT_B64, TR_MINISCRIPT),
    "IN_KEY_SIGNED_MINIS_TR_PSBT_B64": (IN_KEY_SIGNED_MINIS_TR_PSBT_B64, TR_MINISCRIPT),
    "RECOV_M_TR_PSBT_B64": (RECOV_M_TR_PSBT_B64, TR_MINISCRIPT),
    "TAP_TREE_SIGNED_RECOV_PSBT_B64": (TAP_TREE_SIGNED_RECOV_PSBT_B64, TR_MINISCRIPT),
    "EXP_TR_MINIS_PSBT_B64": (EXP_TR_MINIS_PSBT_B64, TR_EXP_MULTI_MINISCRIPT),
    "SIGNED_EXP_TR_MINIS_PSBT_B64": (
        SIGNED_EXP_TR_MINIS_PSBT_B64,
        TR_EXP_MULTI_MINISCRIPT,
    ),
}

# the type of PSBT_IN_TAP_KEY_SIG, as a key of the input map
_TAP_KEY_SIG = b"\x13"


def _signer(mnemonic: str) -> SoftwareSigner:
    """Return the signer of a mnemonic of Krux's tests, on testnet."""
    return SoftwareSigner(bip39.mxprv_from_mnemonic(mnemonic, "", "testnet"))


def _signed(psbt_b64: str, mnemonic: str) -> Psbt:
    """Return the psbt signed by our signer of the mnemonic."""
    psbt = Psbt.b64decode(psbt_b64)
    # a taproot signature commits to every amount spent, and a psbt Krux
    # signs carries no previous transaction
    return _signer(mnemonic).sign_psbt(psbt, require_non_witness_utxo=False)


def _assert_spends(psbt: Psbt) -> None:
    """Run the finalized psbt's spend through the script engine."""
    tx = psbt.tx
    tx.vin[0].script_witness = psbt.inputs[0].final_script_witness
    verify_transaction(prevouts(psbt), tx)


@pytest.mark.parametrize("name", _PSBTS)
def test_each_psbt_reads_back_with_krux_pairs(name: str) -> None:
    """Parse each psbt, and write it back with the pairs Krux wrote.

    But one: Krux returns its key path spend finalized, and keeps the
    signature beside the final witness. We read both, and write the
    final witness alone, as a finalizer does.
    """
    psbt_b64, _ = _PSBTS[name]
    psbt = Psbt.b64decode(psbt_b64)
    krux = psbt_maps(psbt_b64)
    if name == "IN_KEY_SIGNED_MINIS_TR_PSBT_B64":
        (signature,) = psbt.inputs[0].final_script_witness.stack
        assert krux[1].pop(_TAP_KEY_SIG) == signature
    assert psbt_maps(psbt.b64encode()) == krux


@pytest.mark.parametrize("name", _PSBTS)
def test_the_descriptor_derives_the_coin_of_its_psbt(name: str) -> None:
    """Derive the coin each psbt spends from Krux's descriptor of it.

    Without its checksum: Bitcoin Core v32.1's `getdescriptorinfo`
    computes another checksum for each of the three descriptors, as we do.
    """
    psbt_b64, descriptor = _PSBTS[name]
    text, _, checksum = descriptor.partition("#")
    assert add_checksum(text) != f"{text}#{checksum}"
    with pytest.raises(BTClibValueError, match="^invalid descriptor checksum$"):
        multipath_descriptors(descriptor, "testnet")
    (spent,) = prevouts(Psbt.b64decode(psbt_b64))
    receive, _ = (parse(d, "testnet") for d in multipath_descriptors(text, "testnet"))
    scripts = [receive.script_pub_key(index).script for index in range(4)]
    assert spent.script_pub_key.script in scripts


@pytest.mark.parametrize("name", _PSBTS)
def test_a_ledger_restored_from_the_descriptor_watches_the_coin(
    name: str, tmp_path: Path
) -> None:
    """Restore a ledger from Krux's descriptor, its checksum fixed.

    The ledger watches the coin the psbt spends, on the receive branch.
    """
    psbt_b64, descriptor = _PSBTS[name]
    account = {"descriptor": add_checksum(descriptor.partition("#")[0])}
    restored, _ = Ledger.restore_policy(
        bip139.serialize([account], "testnet"),
        tmp_path / "restored.sqlite",
        "testnet",
        FakeChain(),
    )
    (spent,) = prevouts(Psbt.b64decode(psbt_b64))
    with restored:
        position = restored.position_of(spent.script_pub_key)
        assert position is not None
        assert position[:2] == (0, 0)


# (the psbt a coordinator made, the psbt Krux signed, the mnemonic)
_SIGNATURES = {
    "wsh, the primary key": (
        MINIS_P2WSH_PSBT_B64,
        SIGNED_MINIS_P2WSH_PSBT_B64,
        TEST_MNEMONIC,
    ),
    "tr, the internal key": (
        MINIS_TR_PSBT_B64,
        IN_KEY_SIGNED_MINIS_TR_PSBT_B64,
        TEST_MNEMONIC,
    ),
    "tr, the recovery leaf": (
        MINIS_TR_PSBT_B64,
        TAP_TREE_SIGNED_RECOV_PSBT_B64,
        TEST_MNEMONIC_BIP85_I0,
    ),
    "tr, both leaves": (
        EXP_TR_MINIS_PSBT_B64,
        SIGNED_EXP_TR_MINIS_PSBT_B64,
        TEST_MNEMONIC,
    ),
}


@pytest.mark.parametrize("case", _SIGNATURES)
def test_our_signer_signs_what_krux_signed(case: str) -> None:
    """Sign the coordinator's psbt with Krux's key, as Krux signed it.

    The ECDSA signature is Krux's, both being deterministic. A Schnorr
    signature of either takes auxiliary random bytes, so there the keys
    and leaves are compared, and the next test verifies each signature.
    """
    unsigned, signed, mnemonic = _SIGNATURES[case]
    ours = _signed(unsigned, mnemonic).inputs[0]
    krux = Psbt.b64decode(signed).inputs[0]
    assert ours.partial_sigs == krux.partial_sigs
    assert set(ours.taproot_script_spend_signatures) == set(
        krux.taproot_script_spend_signatures
    )
    assert bool(ours.taproot_key_spend_signature) == bool(
        krux.taproot_key_spend_signature
    )


@pytest.mark.parametrize("case", _SIGNATURES)
def test_each_signature_verifies(case: str) -> None:
    """Verify each signature ours and Krux's add to the coordinator's psbt.

    Krux's psbt comes back trimmed, so it is combined with the
    coordinator's first; its key path spend comes back finalized, and the
    script engine checks that.
    """
    unsigned, signed, mnemonic = _SIGNATURES[case]
    request = Psbt.b64decode(unsigned)
    assert_signatures_only(request, _signed(unsigned, mnemonic))
    krux = Psbt.b64decode(signed)
    if krux.inputs[0].final_script_witness.stack:
        _assert_spends(krux)
    else:
        assert_signatures_only(request, combine([request, krux]))


def test_krux_wsh_signature_finalizes_once_combined() -> None:
    """Combine the ``wsh()`` psbt Krux signed with the coordinator's, and spend.

    Krux's psbt alone names no key of the ``pkh()`` its script holds: the
    origins are in the coordinator's psbt, and without one the witness
    script cannot be read, as `miniscript_solver` says.
    """
    signed = Psbt.b64decode(SIGNED_MINIS_P2WSH_PSBT_B64)
    message = "input 0: no public key for a hash160 the witness script holds"
    with pytest.raises(BTClibValueError, match=f"^{message}$"):
        finalize(signed, solver=miniscript_solver)
    combined = combine([Psbt.b64decode(MINIS_P2WSH_PSBT_B64), signed])
    _assert_spends(finalize(combined, solver=miniscript_solver))


def test_krux_key_path_spend_is_a_valid_spend() -> None:
    """Run the key path spend Krux finalized itself."""
    _assert_spends(Psbt.b64decode(IN_KEY_SIGNED_MINIS_TR_PSBT_B64))


def test_the_recovery_leaf_signed_before_its_timelock_does_not_finalize() -> None:
    """Krux signs the recovery leaf of a psbt whose sequence opens no timelock.

    Its sequence disables the relative lock, so ``older()`` is never met.
    Combined with the coordinator's psbt, which holds the leaf script that
    Krux's psbt drops, the signature is there and the lock is not.
    """
    signed = Psbt.b64decode(TAP_TREE_SIGNED_RECOV_PSBT_B64)
    assert signed.tx.vin[0].sequence & 1 << 31
    combined = combine([Psbt.b64decode(MINIS_TR_PSBT_B64), signed])
    message = "no satisfaction with the signatures, preimages and lock times given"
    with pytest.raises(BTClibValueError, match=f"^{message}$"):
        finalize(combined, solver=miniscript_solver)


def test_our_recovery_signature_finalizes_once_the_timelock_opens() -> None:
    """Sign the recovery psbt, at the sequence its leaf asks, and spend it."""
    signed = _signed(RECOV_M_TR_PSBT_B64, TEST_MNEMONIC_BIP85_I0)
    _assert_spends(finalize(signed, solver=miniscript_solver))


def test_the_expanding_multisig_finalizes_with_both_signatures() -> None:
    """Combine Krux's signatures with the second signer's, and spend.

    Each signs both leaves its key is in, so the psbt has signatures on
    two leaves, of which the one without a timelock is complete.
    """
    second = _signed(EXP_TR_MINIS_PSBT_B64, TEST_MNEMONIC_BIP85_I0)
    combined = combine([Psbt.b64decode(SIGNED_EXP_TR_MINIS_PSBT_B64), second])
    _assert_spends(finalize(combined, solver=miniscript_solver))


def _specter(wallet_file: str) -> tuple[str, int]:
    """Return the descriptor and the birth height of a Specter wallet file."""
    wallet = json.loads(wallet_file)
    return wallet["descriptor"], wallet["blockheight"]


def test_a_specter_file_is_a_bip139_account() -> None:
    """Its descriptor and its birth height are BIP139's, and its label is not.

    `bip139` writes and reads them back, the checksum Specter wrote
    included. It carries no `name`, BIP139's field for a label.
    """
    wallet_file = SPECTER_MINISCRIPT_SINGLE_INHERITANCE_WALLET_DATA
    descriptor, birth = _specter(wallet_file)
    assert len(multipath_descriptors(descriptor, "mainnet")) == 2
    account = {"descriptor": descriptor, "birth_block": birth}
    text = bip139.serialize([account], "mainnet")
    assert bip139.parse(text) == {"network": "mainnet", "accounts": [account]}
    label = json.loads(wallet_file)["label"]
    with pytest.raises(BTClibValueError):
        bip139.serialize([{**account, "name": label}], "mainnet")


def test_a_specter_checksum_core_refuses_is_refused() -> None:
    """Refuse the expanding multisig's checksum, and read it without one.

    Bitcoin Core v32.1's `getdescriptorinfo` refuses it too, and computes
    the one we do.
    """
    descriptor, birth = _specter(SPECTER_MINISCRIPT_EXPANDING_MULTISIG_WALLET_DATA)
    with pytest.raises(BTClibValueError, match="^invalid descriptor checksum$"):
        multipath_descriptors(descriptor, "mainnet")
    text = descriptor.partition("#")[0]
    assert add_checksum(text) == f"{text}#3u2lfd8m"
    account = {"descriptor": add_checksum(text), "birth_block": birth}
    text = bip139.serialize([account], "mainnet")
    assert bip139.parse(text) == {"network": "mainnet", "accounts": [account]}


def test_a_specter_descriptor_repeating_a_key_is_refused() -> None:
    """Refuse the joint custody descriptor: it names one key twice.

    One xpub stands under several origins, so the script holds one public
    key more than once, which is not sane. Bitcoin Core v32.1's
    `getdescriptorinfo` refuses it as not sane too.
    """
    descriptor, _ = _specter(SPECTER_MINISCRIPT_3_KEY_JOINT_CUSTODY_WALLET_DATA)
    message = "a sub-expression is not sane: it repeats a public key"
    with pytest.raises(BTClibValueError, match=f"^{message}$"):
        multipath_descriptors(descriptor, "mainnet")


# the Specter files whose descriptor reads, its checksum fixed
_RESTORABLE = {
    "single inheritance": SPECTER_MINISCRIPT_SINGLE_INHERITANCE_WALLET_DATA,
    "expanding multisig": SPECTER_MINISCRIPT_EXPANDING_MULTISIG_WALLET_DATA,
}


@pytest.mark.parametrize("name", _RESTORABLE)
def test_each_wallet_file_restores(name: str, tmp_path: Path) -> None:
    """Restore a ledger from a Specter file's BIP139 account.

    The restored ledger watches the first receive address of the file's
    descriptor.
    """
    descriptor, birth = _specter(_RESTORABLE[name])
    text = add_checksum(descriptor.partition("#")[0])
    account = {"descriptor": text, "birth_block": birth}
    restored, _ = Ledger.restore_policy(
        bip139.serialize([account], "mainnet"),
        tmp_path / "restored.sqlite",
        "mainnet",
        FakeChain(),
    )
    receive, _ = (parse(d, "mainnet") for d in multipath_descriptors(text, "mainnet"))
    with restored:
        assert restored.position_of(receive.script_pub_key(0)) == (0, 0, 0)
