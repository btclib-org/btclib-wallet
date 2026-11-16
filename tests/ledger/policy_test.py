# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A `Ledger`'s policy backup: `export_policy` and `restore_policy`.

The module docstring of `ledger`, *The policy backup*, says what the text
holds and what is refused. A restored ledger is compared with the one it
was exported from after a sync of each over the same `FakeChain`.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.fee import FeeRate
from btclib.tx import TxOut

from btclib_wallet import bip139
from btclib_wallet.bip32 import fingerprint
from btclib_wallet.descriptors import add_checksum, normalized, parse
from btclib_wallet.ledger import MAX_LOOKAHEAD, Ledger, TxState
from btclib_wallet.ledger import ledger as ledger_module
from btclib_wallet.wallet import DescriptorWallet
from tests.ledger import (
    Alias,
    ClaimsStr,
    Conforming,
    ConformingStr,
    ObjectClaimingStr,
    Twin,
    TwinStr,
)
from tests.ledger.conftest import LOOKAHEAD, XPRV, FakeChain, script_of, source
from tests.refused_value_test import KEY, SPELLINGS
from tests.secret_free import assert_secret_free

# the master fingerprint of every key of `source`
FINGERPRINT = fingerprint(XPRV).hex()
NAMES = {0: {FINGERPRINT: {"alias": "Alice", "role": "main"}}}
# a secret a caller's text may hold, which no refusal prints
SECRET = KEY.hex()
SECRETS = [*SPELLINGS, XPRV]
TEMPLATE = "wpkh({}/84h/1h/0h/{}/*)"
TR_TEMPLATE = "tr({}/86h/1h/0h/{}/*)"
# one address on each branch, at index 7
FIXED_TEMPLATE = "wpkh({}/84h/1h/1h/{}/7)"
HARDENED_TEMPLATE = "wpkh({}/84h/1h/0h/{}/*h)"


def _new(chain: FakeChain, path: Path) -> Ledger:
    """Return a ledger over the chain with no source, every capability on."""
    return Ledger.create(
        path,
        "regtest",
        chain,
        broadcaster=chain,
        fee_estimator=chain,
        relay_fee_reader=chain,
        fallback_fee_rate=FeeRate.from_sats_per_vbyte(2),
    )


def _restored(chain: FakeChain, text: str, path: Path) -> Ledger:
    """Return the ledger restored from `text`, with the tests' lookahead."""
    ledger, _ = Ledger.restore_policy(text, path, "regtest", chain, lookahead=LOOKAHEAD)
    return ledger


def _branches(*branches: int) -> DescriptorWallet:
    """Return a wallet of `TEMPLATE` at each branch, labelled by it."""
    prv_keys: dict[str, str] = {}
    descriptors = {
        branch: parse(TEMPLATE.format(XPRV, branch), "regtest", prv_keys)
        for branch in branches
    }
    return DescriptorWallet(descriptors, prv_keys)


def _public(template: str, branch: int = 0) -> str:
    """Return the text `export_policy` writes of a template's branch."""
    wallet = source(template, (branch,))
    return add_checksum(str(normalized(wallet.descriptor(0), wallet.prv_keys)))


def _foreign() -> str:
    """Return an address of nobody the ledgers here hold."""
    return source("wpkh({}/84h/1h/9h/{}/*)", (0,)).address(0, 0)


def _pay(chain: FakeChain, ledger: Ledger, *addresses: str) -> None:
    """Pay each address from outside, mine, and sync the ledger."""
    payment = chain.pay([TxOut(50_000, script_of(address)) for address in addresses])
    chain.mine([payment])
    ledger.sync()


def _used(chain: FakeChain, path: Path) -> Ledger:
    """Return a ledger of three sources, paid, spent from and labelled.

    Source 0 receives and takes change, source 1 is a taproot one of
    branch 0 alone, and source 2 one address. A payment past the window
    of source 0 moves it on.
    """
    ledger = _new(chain, path)
    ledger.add_source(source(), lookahead=LOOKAHEAD)
    ledger.add_source(source(TR_TEMPLATE, (0,)), lookahead=LOOKAHEAD)
    ledger.add_source(source(FIXED_TEMPLATE, (0,)), lookahead=LOOKAHEAD)
    rent = ledger.new_address(label="rent")
    _pay(chain, ledger, rent, ledger.new_address(), ledger.new_address(1, label="tr"))
    far = ledger.sources[0].address(0, LOOKAHEAD + 1)
    _pay(chain, ledger, far, ledger.new_address(2), ledger.new_change_address())
    ledger.set_label(_foreign(), "friend")
    ledger.spend(
        [TxOut(30_000, script_of(_foreign()))], comment="for", comment_to="the rent"
    )
    chain.mine(list(chain.mempool.values()))
    ledger.sync()
    return ledger


def _found(ledger: Ledger) -> tuple[Any, ...]:
    """Return what a sync answers, whatever order it saw transactions in.

    `seq` is the order the ledger first saw each transaction in, and the
    comments are the ledger's own, which the export does not write.
    """
    return (
        ledger.balances(),
        sorted(ledger.utxos(0), key=lambda u: (u.outpoint.tx_id, u.outpoint.vout)),
        {
            info.wallet_tx.tx.id: replace(
                info.wallet_tx, seq=0, comment=None, comment_to=None
            )
            for info in ledger.transactions
        },
        ledger.tip,
        ledger.labels(),
        {label: ledger.addresses_by_label(label) for label in ledger.labels()},
        ledger.address_groupings,
    )


def _policy(accounts: list[dict[str, Any]]) -> str:
    """Return a regtest policy of the accounts, as `bip139` writes it."""
    return bip139.serialize(accounts, "regtest")


def test_the_export_of_a_restore_is_the_export(
    chain: FakeChain, path: Path, tmp_path: Path
) -> None:
    """Export, restore, export: the same text, after a sync and a load too.

    The key names come back as they were passed.
    """
    with _used(chain, path) as ledger:
        text = ledger.export_policy(NAMES)
    target = tmp_path / "restored.sqlite"
    restored, names = Ledger.restore_policy(
        text, target, "regtest", chain, lookahead=LOOKAHEAD
    )
    with restored:
        assert names == NAMES
        assert restored.export_policy(names) == text
        restored.sync()
        assert restored.export_policy(names) == text
    with Ledger.load(target, "regtest", chain) as loaded:
        assert loaded.export_policy(names) == text


def test_the_export_holds_each_source_as_an_account(
    chain: FakeChain, path: Path
) -> None:
    """Descriptors with no private key, indexes, birth, keys, labels."""
    with _used(chain, path) as ledger:
        text = ledger.export_policy(NAMES)
        sources = ledger.sources
    assert XPRV not in text
    assert "prv" not in text
    parsed = bip139.parse(text)
    assert parsed["network"] == "regtest"
    first, second, third = parsed["accounts"]
    assert first["descriptor"] == _public(TEMPLATE)
    assert first["change_descriptor"] == _public(TEMPLATE, 1)
    # the payment past the window marks its index handed out
    assert first["receive_index"] == LOOKAHEAD + 1
    assert first["change_index"] == 1
    assert first["birth_block"] == 0
    assert first["keys"] == NAMES[0]
    assert second["descriptor"] == _public(TR_TEMPLATE)
    assert "change_descriptor" not in second
    assert second["receive_index"] == 0
    assert "change_index" not in second
    assert "keys" not in second
    assert third["descriptor"] == _public(FIXED_TEMPLATE)
    assert third["receive_index"] == 0
    assert "labels" not in third
    # each label on the account that handed out its address, and the
    # foreign address's on the first; the "" `new_address` set on index 1
    # is written, and the index the payment past the window reached,
    # whose "" no call set, has no record
    assert first["labels"] == sorted(
        (
            {"type": "addr", "ref": address, "label": label}
            for address, label in (
                (sources[0].address(0, 0), "rent"),
                (sources[0].address(0, 1), ""),
                (_foreign(), "friend"),
            )
        ),
        key=lambda record: script_of(record["ref"]).script,
    )
    assert second["labels"] == [
        {"type": "addr", "ref": sources[1].address(0, 0), "label": "tr"}
    ]


def _records(*labelled: tuple[str, str]) -> list[dict[str, str]]:
    """Return address and label pairs as records, in an export's order."""
    return sorted(
        (_label(address, label) for address, label in labelled),
        key=lambda record: script_of(record["ref"]).script,
    )


def test_a_label_set_is_written_and_the_one_none_set_gives_is_not(
    chain: FakeChain, path: Path, tmp_path: Path
) -> None:
    """A label "" a call set is written; the "" *Labels* gives is not.

    `new_address` sets "" on index 0, and `set_label` on a change address
    and on a foreign one. A payment to index 3 hands out indexes 2 and 3
    with no label set. The restored ledger answers each address as the
    original does.
    """
    with _new(chain, path) as ledger:
        ledger.add_source(source(), lookahead=LOOKAHEAD)
        wallet = ledger.sources[0]
        ledger.new_address()
        ledger.new_address(label="kept")
        written = [wallet.address(0, 0), ledger.new_change_address(), _foreign()]
        for address in written[1:]:
            ledger.set_label(address, "")
        _pay(chain, ledger, wallet.address(0, 3))
        assert ledger.label_of(wallet.address(0, 2)) == ""
        text = ledger.export_policy()
        assert bip139.parse(text)["accounts"][0]["labels"] == _records(
            (wallet.address(0, 1), "kept"), *((address, "") for address in written)
        )
        with _restored(chain, text, tmp_path / "r.sqlite") as restored:
            assert restored.export_policy() == text
            for index in range(4):
                address = wallet.address(0, index)
                assert restored.label_of(address) == ledger.label_of(address)
            for address in written:
                assert restored.label_of(address) == ledger.label_of(address)
            for purpose in (None, "receive", "send"):
                assert restored.labels(purpose) == ledger.labels(purpose)


def _shared_sources(chain: FakeChain, path: Path, first: int, second: int) -> Ledger:
    """Return a ledger of two sources sharing branch 0's scripts.

    Source 0 watches `first` indexes and source 1 `second`, and source 1
    hands out eight addresses with no label given, so `new_address` sets
    "" on each.
    """
    ledger = _new(chain, path)
    ledger.add_source(source(), lookahead=first)
    ledger.add_source(source(TEMPLATE, (0,)), lookahead=second)
    for _ in range(8):
        ledger.new_address(1)
    return ledger


@pytest.mark.parametrize("first, second, restored_lookahead", [(5, 5, 20), (20, 5, 5)])
def test_the_label_new_address_sets_survives_any_lookahead(
    chain: FakeChain,
    path: Path,
    tmp_path: Path,
    first: int,
    second: int,
    restored_lookahead: int,
) -> None:
    """Whatever the lookahead of each source, and of the restore.

    Which source the ledger reads a shared script as depends on the
    lookahead, and so does whether *Labels* gives it "" with none set:
    each "" `new_address` set is written, on account 1, which handed the
    addresses out.
    """
    with _shared_sources(chain, path, first, second) as ledger:
        text = ledger.export_policy()
        addresses = [ledger.sources[1].address(0, index) for index in range(8)]
        accounts = bip139.parse(text)["accounts"]
        assert "labels" not in accounts[0]
        assert accounts[1]["labels"] == _records(*((a, "") for a in addresses))
        restored, _ = Ledger.restore_policy(
            text,
            tmp_path / "r.sqlite",
            "regtest",
            chain,
            lookahead=restored_lookahead,
        )
        with restored:
            assert restored.export_policy() == text
            for address in addresses:
                assert restored.label_of(address) == ledger.label_of(address) == ""


def test_the_export_derives_no_script_for_a_label_nobody_watches(
    chain: FakeChain, path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A foreign label is on the first account with no script derived.

    Every index handed out is watched, so the export does not look for a
    script it does not watch, and its own read of the text takes the
    accounts it computed: it derives a handful of scripts, not one for
    each index handed out.
    """
    account = {
        "descriptor": _public(TEMPLATE),
        "change_descriptor": _public(TEMPLATE, 1),
        "birth_block": 0,
        "receive_index": 200,
        "change_index": 200,
        "labels": [_label(_foreign(), "friend")],
    }
    text = _policy([account])
    derived: list[int] = []
    script_pub_key = DescriptorWallet.script_pub_key

    def counted(wallet: DescriptorWallet, branch: int = 0, index: int = 0) -> Any:
        derived.append(index)
        return script_pub_key(wallet, branch, index)

    with _restored(chain, text, path) as restored:
        monkeypatch.setattr(DescriptorWallet, "script_pub_key", counted)
        assert restored.export_policy() == text
    assert len(derived) < 10


def test_each_label_is_on_the_first_account_that_handed_out_its_address(
    chain: FakeChain, path: Path, tmp_path: Path
) -> None:
    """Whatever each source watches: a restore watching less exports the same.

    Sources 0 and 1 share the scripts of branch 0. A label of an address
    only source 1 handed out is on account 1, and on account 0 once source
    0 hands it out too. The one address of a branch that is not ranged
    counts as handed out. A label of an address watched and not handed
    out, the one after the last that source 2 handed out, is on account 0.
    """
    with _new(chain, path) as ledger:
        ledger.add_source(source(), lookahead=LOOKAHEAD)
        ledger.add_source(source(TEMPLATE, (0,)), lookahead=LOOKAHEAD)
        ledger.add_source(source(TR_TEMPLATE, (0,)), lookahead=LOOKAHEAD)
        ledger.add_source(source(FIXED_TEMPLATE, (0,)), lookahead=LOOKAHEAD)
        shared = ledger.new_address(1, label="shared")
        tr = ledger.new_address(2, label="tr")
        far = ledger.sources[2].address(0, 1)
        fixed = ledger.sources[3].address(0, 0)
        ledger.set_label(far, "far")
        ledger.set_label(fixed, "fixed")
        text = ledger.export_policy()
        accounts = bip139.parse(text)["accounts"]
        assert accounts[0]["labels"] == _records((far, "far"))
        assert accounts[1]["labels"] == _records((shared, "shared"))
        assert accounts[2]["labels"] == _records((tr, "tr"))
        assert accounts[3]["labels"] == _records((fixed, "fixed"))
        restored, _ = Ledger.restore_policy(
            text, tmp_path / "r.sqlite", "regtest", chain, lookahead=0
        )
        with restored:
            assert restored.position_of(script_of(far)) is None
            assert restored.export_policy() == text
        assert ledger.new_address(label="shared") == shared
        accounts = bip139.parse(ledger.export_policy())["accounts"]
        assert accounts[0]["labels"] == _records((far, "far"), (shared, "shared"))
        assert "labels" not in accounts[1]


def test_a_restored_ledger_finds_the_funds_and_the_next_addresses(
    chain: FakeChain, path: Path, tmp_path: Path
) -> None:
    """After a sync it answers what the original answers, and hands out on.

    The restore reads no backend: before the sync it holds no
    transaction, and the sync reads each source from its birth height.
    """
    ledger = _used(chain, path)
    restored = _restored(chain, ledger.export_policy(), tmp_path / "restored.sqlite")
    with ledger, restored:
        assert restored.transactions == ()
        assert restored.tip is None
        assert all(wallet.is_watch_only for wallet in restored.sources)
        chain.reads.clear()
        restored.sync()
        assert chain.reads[0] == 0
        assert _found(restored) == _found(ledger)
        for source_id, branch in ((0, 0), (0, 1), (1, 0), (2, 0)):
            assert restored.new_address(source_id, branch) == ledger.new_address(
                source_id, branch
            )
        # payments past the restored window are found as the original
        # finds them, each one moving the window on
        far = ledger.sources[0].address(0, 2 * LOOKAHEAD)
        last = ledger.sources[0].address(0, 3 * LOOKAHEAD - 1)
        _pay(chain, ledger, far)
        _pay(chain, ledger, last)
        restored.sync()
        assert _found(restored) == _found(ledger)


def test_the_export_leaves_out_comments_purposes_and_the_lookahead(
    chain: FakeChain, path: Path, tmp_path: Path
) -> None:
    """A restore reads them again: no comment, the purpose of what it watches.

    A label set on an address before the ledger watched it keeps the
    purpose `send`; restored, the address is watched, and the label is a
    `receive` one. A restore takes the lookahead its caller gives.
    """
    ledger = _used(chain, path)
    later = ledger.sources[0].address(0, 2 * LOOKAHEAD + 3)
    ledger.set_label(later, "later")
    while ledger.position_of(script_of(later)) is None:
        ledger.new_address()
    text = ledger.export_policy()
    assert "for" not in text
    assert "the rent" not in text
    restored, _ = Ledger.restore_policy(text, tmp_path / "r.sqlite", "regtest", chain)
    with ledger, restored:
        assert "later" in ledger.labels("send")
        assert "later" in restored.labels("receive")
        assert "later" not in restored.labels("send")
        restored.sync()
        assert {i.wallet_tx.comment for i in ledger.transactions} == {None, "for"}
        assert {i.wallet_tx.comment for i in restored.transactions} == {None}
        assert {i.wallet_tx.comment_to for i in restored.transactions} == {None}
        # the default lookahead watches past what the original watched
        end = ledger.sources[0].script_pub_key(0, 3 * LOOKAHEAD + 3)
        assert ledger.position_of(end) is None
        assert restored.position_of(end) is not None


def test_a_policy_holds_no_private_key(
    ledger: Ledger, tmp_path: Path, chain: FakeChain
) -> None:
    """The export of a ledger of private keys, and of it encrypted, locked.

    Both write the same text, which holds none of the keys.
    """
    pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    prv_keys = list((ledger.sources[0].prv_keys or {}).values())
    assert prv_keys
    text = ledger.export_policy()
    for secret in (XPRV, *prv_keys):
        assert secret not in text
    ledger.encrypt("passphrase")  # pragma: allowlist secret
    assert ledger.export_policy() == text
    with _restored(chain, text, tmp_path / "r.sqlite") as restored:
        assert restored.sources[0].is_watch_only


@pytest.mark.parametrize(
    "wallets, err_msg",
    [
        (
            lambda: [_branches(0, 2)],
            "^source 0: BIP139 carries a branch 0 and a branch 1 beside it, no other$",
        ),
        (
            lambda: [source(), _branches(1)],
            "^source 1: BIP139 carries a branch 0 and a branch 1 beside it, no other$",
        ),
        (
            lambda: [source(), source(HARDENED_TEMPLATE)],
            (
                "^a descriptor needs a private key at every index: a policy backup,"
                " which holds no private key, cannot carry source 1$"
            ),
        ),
    ],
)
def test_a_source_the_export_cannot_write_is_refused(
    chain: FakeChain,
    path: Path,
    wallets: Callable[[], list[DescriptorWallet]],
    err_msg: str,
) -> None:
    """No branch 0, a branch past 1, a hardened wildcard: no text at all."""
    with _new(chain, path) as ledger:
        held = wallets()
        for wallet in held:
            ledger.add_source(wallet)
        with pytest.raises(BTClibValueError, match=err_msg) as caught:
            ledger.export_policy()
    keys = [key for wallet in held for key in (wallet.prv_keys or {}).values()]
    assert_secret_free(caught.value, [*SECRETS, *keys])


def test_a_ledger_with_no_source_is_refused(chain: FakeChain, path: Path) -> None:
    """BIP139 asks for an account, and the ledger says why there is none."""
    with (
        _new(chain, path) as ledger,
        pytest.raises(BTClibValueError, match="^no source: add one before the export$"),
    ):
        ledger.export_policy()


# `isinstance` reads `__class__`, so this is believed to be a dict
_claims_dict: Any = property(lambda _self: dict)


class _ClaimsMapping:
    """An object that is no mapping, whose `__class__` claims dict."""

    __class__ = _claims_dict


@pytest.mark.parametrize(
    "key_names, kind, err_msg",
    [
        ([], BTClibTypeError, "^invalid key_names type: list$"),
        (_ClaimsMapping(), BTClibTypeError, "^invalid key_names type: _ClaimsMapping$"),
        ({"0": {}}, BTClibTypeError, "^invalid source type: str$"),
        ({True: {}}, BTClibTypeError, "^invalid source type: bool$"),
        ({7: {}}, BTClibValueError, "^no source an int of 3 bits$"),
        ({Twin(0): {}, Twin(0): {}}, BTClibValueError, "^source 0 named twice$"),
        ({0: [FINGERPRINT]}, BTClibTypeError, "^invalid keys type: list$"),
        ({0: {b"0c5f9a1e": {}}}, BTClibTypeError, "^invalid fingerprint type: bytes$"),
        (
            {0: {ObjectClaimingStr(): {}}},
            BTClibTypeError,
            "^invalid fingerprint type: ObjectClaimingStr$",
        ),
        (
            {0: {TwinStr(FINGERPRINT): {}, TwinStr(FINGERPRINT): {}}},
            BTClibValueError,
            "^a fingerprint named twice$",
        ),
        (
            {0: {FINGERPRINT: {}, FINGERPRINT.upper(): {}}},
            BTClibValueError,
            r"^accounts\[0\]\.keys entry 1: a fingerprint named twice$",
        ),
        ({0: {FINGERPRINT: SECRET}}, BTClibTypeError, "^invalid key names type: str$"),
        (
            {0: {FINGERPRINT: {1: SECRET}}},
            BTClibTypeError,
            "^invalid key field type: int$",
        ),
        (
            {0: {FINGERPRINT: {TwinStr("alias"): SECRET, TwinStr("alias"): "B"}}},
            BTClibValueError,
            "^a key field named twice$",
        ),
        (
            {0: {FINGERPRINT: {"alias": ClaimsStr(KEY)}}},
            BTClibTypeError,
            "^invalid key name type: ClaimsStr$",
        ),
        (
            {0: {"deadbeef": {"alias": SECRET}}},
            BTClibValueError,
            r"^accounts\[0\]\.keys entry 0: a key the descriptor does not name$",
        ),
        (
            {0: {SECRET: {}}},
            BTClibValueError,
            r"^accounts\[0\]\.keys entry 0: not a fingerprint$",
        ),
        (
            {0: {FINGERPRINT: {SECRET: "Alice"}}},  # pragma: allowlist secret
            BTClibValueError,
            r"^accounts\[0\]\.keys entry 0: no BIP139 key field: a value of 64",
        ),
        (
            {0: {FINGERPRINT: {"alias": SECRET, "role": SECRET}}},
            BTClibValueError,
            r"^accounts\[0\]\.keys entry 0\.role: not one of ROLES$",
        ),
    ],
)
def test_key_names_are_refused_naming_no_value(
    ledger: Ledger, key_names: Any, kind: type[Exception], err_msg: str
) -> None:
    """Each type decides, and the codec checks what the names say."""
    with pytest.raises(kind, match=err_msg) as caught:
        ledger.export_policy(key_names)
    assert_secret_free(caught.value, SECRETS)


def test_key_names_are_read_by_the_values_they_hold(
    chain: FakeChain, path: Path
) -> None:
    """A subclass's own methods are not read: its source and texts are.

    `Alias(1)` hashes and compares as 0 and holds 1, so its names are the
    second source's. A text None is left out, as `bip139` leaves it.
    """
    with _new(chain, path) as ledger:
        ledger.add_source(source())
        ledger.add_source(source("wpkh({}/84h/1h/2h/{}/*)"))
        plain = ledger.export_policy({1: {FINGERPRINT: {"alias": "Bob"}}})
        held: Mapping[int, Mapping[str, Mapping[str, str | None]]] = {
            Alias(1): {
                ConformingStr(FINGERPRINT): {
                    ConformingStr("alias"): ConformingStr("Bob"),
                    "role": None,
                }
            }
        }
        assert ledger.export_policy(held) == plain
        assert ledger.export_policy({Conforming(1): {FINGERPRINT: {}}}) == (
            ledger.export_policy({1: {FINGERPRINT: {}}})
        )
    accounts = bip139.parse(plain)["accounts"]
    assert "keys" not in accounts[0]
    assert accounts[1]["keys"] == {FINGERPRINT: {"alias": "Bob"}}


def test_a_multipath_descriptor_restores_as_two_branches(
    chain: FakeChain, tmp_path: Path
) -> None:
    """BIP389's ``<0;1>`` is branches 0 and 1, written back as two."""
    multipath = _public(TEMPLATE).split("#")[0].replace("/0/*", "/<0;1>/*")
    text = _policy([{"descriptor": multipath, "receive_index": 2, "change_index": 0}])
    with _restored(chain, text, tmp_path / "r.sqlite") as restored:
        assert restored.sources[0].branches == (0, 1)
        account = bip139.parse(restored.export_policy())["accounts"][0]
        assert account["descriptor"] == _public(TEMPLATE)
        assert account["change_descriptor"] == _public(TEMPLATE, 1)
        assert (account["receive_index"], account["change_index"]) == (2, 0)
        assert restored.new_address() == restored.sources[0].address(0, 3)
        assert restored.new_change_address() == restored.sources[0].address(1, 1)


def test_a_restore_reads_each_source_from_its_birth(
    chain: FakeChain, path: Path, tmp_path: Path
) -> None:
    """A birth the ledger held is written; an account with none is read from 0.

    A source added with no birth height after a sync is born at the tip.
    """
    chain.mine(count=4)
    with _new(chain, path) as ledger:
        ledger.add_source(source())
        ledger.sync()
        ledger.add_source(source(TR_TEMPLATE, (0,)), None)
        ledger.add_source(source(FIXED_TEMPLATE, (0,)), 3)
        text = ledger.export_policy()
    births = [a["birth_block"] for a in bip139.parse(text)["accounts"]]
    assert births == [0, 4, 3]
    born = _policy([{"descriptor": _public(TR_TEMPLATE), "birth_block": 4}])
    with _restored(chain, born, tmp_path / "born.sqlite") as restored:
        chain.reads.clear()
        restored.sync()
        assert chain.reads[0] == 4
    unborn = _policy([{"descriptor": _public(TR_TEMPLATE)}])
    with _restored(chain, unborn, tmp_path / "unborn.sqlite") as restored:
        chain.reads.clear()
        restored.sync()
        assert chain.reads[0] == 0
        assert bip139.parse(restored.export_policy())["accounts"][0]["birth_block"] == 0


def test_a_restore_takes_the_text_and_the_lookahead_a_subclass_holds(
    chain: FakeChain, tmp_path: Path
) -> None:
    """Neither the text's nor the lookahead's own methods are read.

    Before any sync the ledger watches the lookahead past the index the
    text hands out.
    """
    text = _policy([{"descriptor": _public(TEMPLATE), "receive_index": 1}])
    restored, _ = Ledger.restore_policy(
        ConformingStr(text),
        tmp_path / "r.sqlite",
        "regtest",
        chain,
        lookahead=Conforming(LOOKAHEAD),
    )
    with restored:
        assert restored.export_policy() == _policy(
            [{"descriptor": _public(TEMPLATE), "birth_block": 0, "receive_index": 1}]
        )
        wallet = restored.sources[0]
        last = wallet.script_pub_key(0, 1 + LOOKAHEAD)
        assert restored.position_of(last) == (0, 0, 1 + LOOKAHEAD)
        assert restored.position_of(wallet.script_pub_key(0, 2 + LOOKAHEAD)) is None


def test_a_text_another_wallet_wrote_restores(chain: FakeChain, tmp_path: Path) -> None:
    """What BIP139 says to discard is discarded, and a fingerprint lowercased.

    A field of the registry this does not carry, one of the application's
    own and a null are read as `bip139.parse` reads them.
    """
    text = json.loads(_policy([{"descriptor": _public(TEMPLATE)}]))
    text["accounts"][0] |= {
        "name": "savings",
        "change_index": None,
        "keys": {
            FINGERPRINT.upper(): {
                "key": FINGERPRINT.upper(),
                "alias": "Alice",
                "key_type": "hardware",
            }
        },
        "proprietary": {"example": {"x": 1}},
    }
    restored, names = Ledger.restore_policy(
        json.dumps(text), tmp_path / "r.sqlite", "regtest", chain
    )
    with restored:
        assert names == {0: {FINGERPRINT: {"alias": "Alice"}}}
        assert restored.sources[0].branches == (0,)
        assert restored.new_address() == restored.sources[0].address(0, 0)


_ADDRESS = source(TEMPLATE, (0,)).address(0, 0)
_TR_ADDRESS = source(TR_TEMPLATE, (0,)).address(0, 0)


def _label(ref: str, label: str = SECRET, kind: str = "addr") -> dict[str, Any]:
    """Return a BIP329 record of a ref, labelled with a secret by default."""
    return {"type": kind, "ref": ref, "label": label}


_REFUSED: list[tuple[Callable[[], str], str]] = [
    (
        lambda: _policy(
            [
                {
                    "descriptor": _public(TEMPLATE)
                    .split("#")[0]
                    .replace("/0/*", "/<0;1;2>/*")
                }
            ]
        ),
        (
            r"^accounts\[0\]\.descriptor: more than two paths, which an export cannot"
            " write back$"
        ),
    ),
    (
        lambda: _policy([{"descriptor": _public(TEMPLATE), "change_index": 0}]),
        r"^accounts\[0\]\.change_index: no change descriptor$",
    ),
    (
        lambda: _policy([{"descriptor": _public(TEMPLATE), "receive_index": 10**6}]),
        (
            r"^accounts\[0\]\.receive_index: not below 1000000, the range Core's"
            " importdescriptors takes$"
        ),
    ),
    (
        lambda: _policy([{"descriptor": _public(FIXED_TEMPLATE), "receive_index": 1}]),
        (
            r"^accounts\[0\]\.receive_index: past the one address of a descriptor that"
            " is not ranged$"
        ),
    ),
    (
        lambda: _policy(
            [
                {
                    "descriptor": _public(TEMPLATE),
                    "change_descriptor": _public(FIXED_TEMPLATE, 1),
                    "change_index": 1,
                }
            ]
        ),
        (
            r"^accounts\[0\]\.change_index: past the one address of a descriptor that"
            " is not ranged$"
        ),
    ),
    (
        lambda: _policy(
            [{"descriptor": _public(TEMPLATE), "change_descriptor": _public(TEMPLATE)}]
        ),
        "^branches 0 and 1 share a script",
    ),
    (
        lambda: _policy(
            [{"descriptor": _public(TEMPLATE).split("#")[0].replace("/0/*", "/0/*h")}]
        ),
        "^invalid hardened derivation from public key$",
    ),
    (
        lambda: _policy(
            [
                {
                    "descriptor": _public(TEMPLATE),
                    "labels": [_label(_ADDRESS, "a"), _label("00" * 32, kind="tx")],
                }
            ]
        ),
        (
            r"^accounts\[0\]\.labels\[1\]: a label of type tx, which a ledger does"
            " not hold$"
        ),
    ),
    (
        lambda: _policy(
            [
                {
                    "descriptor": _public(TEMPLATE),
                    "labels": [
                        _label(_ADDRESS)
                        | {"origin": f"wpkh([{FINGERPRINT}/84h/1h/0h])"}
                    ],
                }
            ]
        ),
        (
            r"^accounts\[0\]\.labels\[0\]\.origin: an origin, which a ledger does not"
            " hold$"
        ),
    ),
    (
        lambda: _policy(
            [
                {"descriptor": _public(TEMPLATE), "labels": [_label(_ADDRESS)]},
                {
                    "descriptor": _public(TR_TEMPLATE),
                    "labels": [_label(_ADDRESS, "other")],
                },
            ]
        ),
        r"^accounts\[1\]\.labels\[0\]: an address labelled twice$",
    ),
    (
        lambda: _policy(
            [
                {"descriptor": _public(TEMPLATE), "receive_index": 3},
                {
                    "descriptor": _public(TR_TEMPLATE),
                    "labels": [_label(_ADDRESS, "*")],
                },
            ]
        ),
        r"^accounts\[1\]\.labels\[0\]\.label: the name \*, which a ledger refuses$",
    ),
    (
        lambda: _policy(
            [
                {"descriptor": _public(TEMPLATE)},
                {"descriptor": _public(TR_TEMPLATE), "labels": [_label(_foreign())]},
            ]
        ),
        (
            r"^accounts\[1\]\.labels\[0\]: on another account than accounts\[0\],"
            " where an export writes it$"
        ),
    ),
    (
        lambda: _policy(
            [
                {"descriptor": _public(TEMPLATE), "labels": [_label(_TR_ADDRESS)]},
                {"descriptor": _public(TR_TEMPLATE), "receive_index": 0},
            ]
        ),
        r"^accounts\[0\]\.labels\[0\]: on another account than accounts\[1\],",
    ),
    (
        lambda: _policy(
            [
                {"descriptor": _public(TEMPLATE), "receive_index": 0},
                {
                    "descriptor": _public(TR_TEMPLATE),
                    "receive_index": 2,
                    "labels": [_label(source(TR_TEMPLATE, (0,)).address(0, 3))],
                },
            ]
        ),
        r"^accounts\[1\]\.labels\[0\]: on another account than accounts\[0\],",
    ),
    (
        lambda: _policy([{"descriptor": _public(TEMPLATE)}]).replace(
            '"regtest"', '"signet"'
        ),
        "^the policy's network, signet, is not the ledger's, regtest$",
    ),
    (lambda: "{}", "^version: missing$"),
]


@pytest.mark.parametrize(
    "record",
    [
        {"type": "spscan", "ref": SECRET, "label": "scan"},
        {"type": "unknown", "ref": SECRET, "label": "elsewhere"},
        {"type": "tx", "ref": "00" * 32},
    ],
)
def test_a_record_the_codec_discards_is_neither_restored_nor_refused(
    chain: FakeChain, path: Path, record: dict[str, str]
) -> None:
    """`bip139.parse` drops it, so the restore never sees it.

    A labelled ``spscan`` record, a labelled record of a type BIP329 does
    not define, and a record of a `type` and a `ref` alone: the restore
    holds the rest of the text, and the next export writes none of them.
    """
    beside = _label(_ADDRESS, "kept")
    text = _policy([{"descriptor": _public(TEMPLATE), "labels": [beside]}])
    document = json.loads(text)
    document["accounts"][0]["labels"].insert(0, record)
    with _restored(chain, json.dumps(document), path) as restored:
        assert bip139.parse(restored.export_policy())["accounts"][0]["labels"] == [
            beside
        ]
        assert restored.labels() == ("kept",)


def test_a_transaction_the_backend_no_longer_serves_is_not_restored(
    chain: FakeChain, path: Path, tmp_path: Path
) -> None:
    """A restore's sync reads again only what the backend still serves.

    A payment whose block a reorganization dropped, and which no mempool
    holds, stays in the original as inactive; the restored ledger never
    hears of it. The balances and the next addresses agree.
    """
    with _new(chain, path) as ledger:
        ledger.add_source(source(), lookahead=LOOKAHEAD)
        _pay(chain, ledger, ledger.new_address())
        chain.invalidate(chain.tip.height)
        chain.mine()
        ledger.sync()
        assert [i.wallet_tx.state for i in ledger.transactions] == [TxState.INACTIVE]
        target = tmp_path / "restored.sqlite"
        with _restored(chain, ledger.export_policy(), target) as restored:
            restored.sync()
            assert restored.transactions == ()
            assert restored.balances() == ledger.balances()
            assert restored.new_address() == ledger.new_address()


@pytest.mark.parametrize("policy, err_msg", _REFUSED)
def test_what_a_ledger_cannot_hold_is_refused_before_any_file(
    chain: FakeChain, path: Path, policy: Callable[[], str], err_msg: str
) -> None:
    """All that `bip139.parse` reads or nothing: no file, no value printed."""
    with pytest.raises(BTClibValueError, match=err_msg) as caught:
        Ledger.restore_policy(policy(), path, "regtest", chain)
    assert not path.exists()
    assert_secret_free(caught.value, SECRETS)


def test_an_index_is_restored_below_the_range_core_imports(
    chain: FakeChain, path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The last index below the bound is restored, the bound itself refused.

    The bound is set low, so that no test derives a million scripts.
    """
    monkeypatch.setattr(ledger_module, "_RESTORED_INDEXES", 3)
    account = {
        "descriptor": _public(TEMPLATE),
        "change_descriptor": _public(TEMPLATE, 1),
        "receive_index": 2,
    }
    with pytest.raises(
        BTClibValueError, match=r"^accounts\[0\]\.change_index: not below 3, the"
    ):
        Ledger.restore_policy(
            _policy([account | {"change_index": 3}]), path, "regtest", chain
        )
    assert not path.exists()
    with _restored(chain, _policy([account | {"change_index": 2}]), path) as restored:
        assert restored.new_address() == restored.sources[0].address(0, 3)
        assert restored.new_change_address() == restored.sources[0].address(1, 3)


def test_an_export_writes_no_index_its_restore_refuses(
    chain: FakeChain, path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The last index below the bound is written, one at it refused.

    The bound is set low, as the test above says, on each branch. The
    refusal is the restore's, as the export reads its text back.
    """
    monkeypatch.setattr(ledger_module, "_RESTORED_INDEXES", 3)
    with _new(chain, path) as ledger:
        ledger.add_source(source(), lookahead=LOOKAHEAD)
        for _ in range(3):
            ledger.new_address()
            ledger.new_change_address()
        account = bip139.parse(ledger.export_policy())["accounts"][0]
        assert (account["receive_index"], account["change_index"]) == (2, 2)
        ledger.new_change_address()
        err_msg = r"^accounts\[0\]\.change_index: not below 3, the range Core's"
        with pytest.raises(BTClibValueError, match=err_msg):
            ledger.export_policy()
        ledger.new_address()
        err_msg = r"^accounts\[0\]\.receive_index: not below 3, the range Core's"
        with pytest.raises(BTClibValueError, match=err_msg):
            ledger.export_policy()


def test_a_restore_refuses_a_wrong_argument_and_a_file_at_its_path(
    chain: FakeChain, path: Path
) -> None:
    """The types first, then the file `create` refuses, left as it is.

    Each argument is refused before the text is read: `unread` is refused
    where it is read.
    """
    text = _policy([{"descriptor": _public(TEMPLATE)}])
    unread = "{}"
    refused: list[tuple[Callable[[], object], type[Exception], str]] = [
        (
            lambda: Ledger.restore_policy(text.encode(), path, "regtest", chain),  # type: ignore[arg-type]
            BTClibTypeError,
            "^invalid policy type: bytes$",
        ),
        (
            lambda: Ledger.restore_policy(ClaimsStr(KEY), path, "regtest", chain),  # type: ignore[arg-type]
            BTClibTypeError,
            "^invalid policy type: ClaimsStr$",
        ),
        (
            lambda: Ledger.restore_policy(unread, 1, "regtest", chain),  # type: ignore[arg-type]
            BTClibTypeError,
            "^invalid path type: int$",
        ),
        (
            lambda: Ledger.restore_policy(unread, path, "nonet", chain),
            BTClibValueError,
            "network",
        ),
        (
            lambda: Ledger.restore_policy(
                unread,
                path,
                "regtest",
                chain,
                fallback_fee_rate=2,  # type: ignore[arg-type]
            ),
            BTClibTypeError,
            "^invalid fallback_fee_rate type: int$",
        ),
        (
            lambda: Ledger.restore_policy(
                unread,
                path,
                "regtest",
                chain,
                lookahead="5",  # type: ignore[arg-type]
            ),
            BTClibTypeError,
            "^invalid lookahead type: str$",
        ),
        (
            lambda: Ledger.restore_policy(unread, path, "regtest", chain, lookahead=-1),
            BTClibValueError,
            "^negative lookahead: ",
        ),
        (
            lambda: Ledger.restore_policy(
                unread, path, "regtest", chain, lookahead=MAX_LOOKAHEAD + 1
            ),
            BTClibValueError,
            "^lookahead above MAX_LOOKAHEAD, 100000: ",
        ),
    ]
    for call, kind, err_msg in refused:
        with pytest.raises(kind, match=err_msg) as caught:
            call()
        assert_secret_free(caught.value, SECRETS)
    assert not path.exists()
    path.write_bytes(b"held")
    with pytest.raises(BTClibValueError, match="^the ledger file exists$"):
        Ledger.restore_policy(text, path, "regtest", chain)
    assert path.read_bytes() == b"held"


def test_a_restore_that_fails_after_making_its_file_removes_it(
    chain: FakeChain, path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An interrupt while the labels are written leaves no file."""
    text = _policy(
        [{"descriptor": _public(TEMPLATE), "labels": [_label(_ADDRESS, "a")]}]
    )

    def interrupted(*_args: object) -> None:
        raise KeyboardInterrupt

    with monkeypatch.context() as patched:
        patched.setattr(Ledger, "_write_label", interrupted)
        with pytest.raises(KeyboardInterrupt):
            Ledger.restore_policy(text, path, "regtest", chain)
    assert not path.exists()
    with _restored(chain, text, path) as restored:
        assert restored.label_of(_ADDRESS) == "a"
