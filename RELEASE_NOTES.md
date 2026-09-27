# Release notes

Notable changes are documented here.
[CHANGELOG.md](./CHANGELOG.md) is the record behind them: this file says
what a user has to act on, that one says what changed.

Versions are *[calendar versions](https://calver.org/)*, `YYYY.M.D`: the
number says when a release was cut, and promises nothing about
compatibility, so a breaking change is announced in this file — read it
before upgrading, rather than a digit.

## v2026.10 (work in progress, not released yet)

A binary-string entropy passed as `bytes` is refused with a
`BTClibTypeError` by `mnemonic.entropy`'s functions taking one, which
read it as the digits it spells; pass the `str` instead. A mnemonic that
is not a `str` is refused with a `BTClibTypeError` rather than a bare
`TypeError` or `AttributeError`.

`mnemonic.slip39.master_secret_from_mnemonics` and `mxprv_from_mnemonics`
refuse shares passed as an iterable that is not a sequence -- a set, a
generator, an iterator, `dict.keys()` -- with a `BTClibTypeError`, where
they read it; pass a `list` or a `tuple` instead.

`mnemonic.slip39.mnemonics_from_master_secret` refuses with a
`BTClibTypeError` a `groups` passed as a set or a dict, and a bool as a
threshold, a member count or the iteration exponent, where it read them;
pass a `list` or a `tuple` of integer pairs, and integers.
`mnemonic.entropy.bin_str_entropy_from_rolls` refuses the same way rolls
passed as a set or a generator and a bool as a roll or as `bits`.

`mnemonic.slip39.Share` refuses with a `BTClibTypeError` a `value` that is
not `bytes` -- a `bytearray` or a list of ints included -- and a bool as
an integer field or a non-bool as `extendable`, where it held them; pass
`bytes`, integers and a bool. `mxprv_from_mnemonics` refuses a falsy
passphrase of another type, `0`, `[]` or `b""`, where it read the empty
passphrase; pass `None` or `""`. `mnemonics_from_master_secret` refuses
an `entropy_source` answering anything but `bytes` or a `bytearray` of
the length asked -- a 1-of-1 backup read a list, a `memoryview` or a
draw of another length; return exactly that.

`fetch.BitcoinCoreFetcher` and `fetch.BitcoinCoreRestFetcher` refuse with a
`BTClibTypeError` a `client` that is not a `BitcoinCoreRpcClient` or a
`BitcoinCoreRestClient` respectively, where a stand-in answering the
methods they call worked; pass an instance of that class or a subclass.
`fetch.ElectrumFetcher` refuses a `timeout` that is no number, a bool,
not positive, or above `threading.TIMEOUT_MAX`, which it handed as given
to a transport of the caller's; pass a positive number of seconds. `fetch.EsploraFetcher`
refuses a `base_url` carrying a user or a password, or without a host,
which a transport of the caller's received; pass the url without them,
and let that transport add the credentials.

`tx_builder.build_psbt`, `coin_selection.select_coins`, `knapsack` and
`single_random_draw` require `change_script_pub_key`: a call that left it
out, and so sent every leftover satoshi to the fee, raises a `TypeError`;
pass the change script, or `None` for a sweep.

`tx_builder.build_psbt` refuses with a `BTClibValueError` a fee above
`max_fee`, 0.10 BTC unless raised, and an output being paid below its
dust threshold. It refuses a non-zero `lock_time` too when every input's
sequence is final: set a non-final `PsbtIn.sequence`, such as
`0xfffffffe`, on an input for the lock time to bind.

`psbt.sign` refuses with a `BTClibValueError` a psbt paying a silent payment
it used to sign: one whose silent payment output has no script yet -- run
`psbt.silent_payments.set_input_share` or `set_global_share`, then
`set_output_scripts`, before signing -- one with an input's sighash other
than `SIGHASH_ALL`, and one whose shares, scripts or modifiable flags
`psbt.silent_payments.assert_as_valid` refuses. `psbt.extract_tx` refuses
what that function refuses, and a silent payment output with no script;
`check_validity=False` extracts as before. `psbt.combine` refuses two psbts
carrying different scripts for one silent payment output.

`tx_builder.build_psbt` also refuses with a `BTClibValueError` a fee above
what `max_fee_rate`, 0.10 BTC/kvB unless raised, asks of the estimated
virtual size, however far below `max_fee` it is; pass a higher
`max_fee_rate` where such a fee is meant.

A psbt with an input whose `witness_utxo` is not, in amount and script,
the output of its `non_witness_utxo` the outpoint names is refused with a
`BTClibValueError` by `Psbt.assert_valid`, and so by `Psbt.parse` and
every function validating the psbt, where it was accepted and the
`witness_utxo` read; set it to that output, or drop it.
`bip322.assert_as_valid` refuses a proof of funds in which it contradicts
the transaction an earlier input carries.

`psbt.estimated_input_sizes` refuses with a `BTClibValueError` a
`psbt_in` whose `non_witness_utxo` is not the transaction the `tx_in`'s
outpoint names, and one whose `witness_utxo` differs from the output that
outpoint names, where it answered an estimate; pass the
`TxIn` the input is spent by, and a `witness_utxo` equal to that output.

`psbt_signer.request_signatures` refuses a psbt paying a silent payment that
`psbt.sign` would refuse, before the signer is asked, where it sent it on.
`psbt.silent_payments` counts an input by the script it spends, and refuses
with a `BTClibValueError` a counted input whose key the psbt does not carry
where it left the input out: give every p2wpkh, p2pkh and p2sh-p2wpkh input
a `PSBT_IN_BIP32_DERIVATION` whose key the script commits to, and a p2sh
input its redeem script. A taproot input whose internal key is BIP341's NUMS
point is counted unless `PSBT_IN_TAP_MERKLE_ROOT` or a control block proves
it. `set_output_scripts` refuses until every counted input has a share, where
it derived the scripts from the shares there were.

`hwi.HwiSigner.sign_psbt` called directly refuses such a psbt the same way,
before `hwi` runs, where it sent it to the device; and it refuses a request
that is no `Psbt` with a `BTClibTypeError` rather than an `AttributeError`.

`psbt.combine` refuses with a `BTClibValueError` psbts whose merge
`Psbt.assert_valid` refuses, where it returned that psbt; drop from the
copies the field that contradicts the others -- a `witness_utxo` differing
from another copy's `non_witness_utxo` output -- before combining.
It refuses with a `BTClibTypeError` a `psbts` that is not a sequence -- a
generator, an iterator -- where it read it; pass a `list` or a `tuple`.

`psbt.join` refuses with a `BTClibTypeError` a `psbts` that is not a
sequence -- a `dict` view, any container that is only iterable -- where it
joined it; pass a `list` or a `tuple`.

`descriptors.KeyExpression` refuses with a `BTClibValueError` an extended
private key as `xkey`, where it held it; pass its xpub, and the xprv under
that xpub in `prv_keys` where a hardened step needs it.

`descriptors.KeyExpression`'s `xkey` holds an extended public key of a
version btclib decodes, a wallet-policy placeholder `wallet_policy` writes
-- `@N`, `@N/**`, `@N/<M;N>/*`, `musig(@N,...)` with one of those suffixes,
`K` -- or nothing. Any other `str` is refused with a `BTClibValueError` and
any other type with a `BTClibTypeError`, where they were held; pass an xpub.

`silent_payments.keys_from_address` refuses with a `BTClibValueError` a
mixed-case address and one holding a character outside ASCII, where it read
the address the string lowers to; pass the address all lower case or all
upper case. For such a spelling of an address a wallet handed out,
`address in wallet` answers `False` and `Wallet.address_info` raises, where
both found the address.

`silent_payments.keys_from_address` and `silent_payments.output_keys`,
which reads each address through it, `BIP32KeyData.b58decode` and what
reads an extended key through it, `bip32.derive` among them,
`bip322.Sig.b64decode`, `bip322.verify` and `assert_as_valid` for the
signature, `Psbt.b64decode`, `tx_or_psbt.tx_or_psbt_from_any`,
`BIP32KeyOrigin.from_description` and `bip32.str_from_der_path`'s
fingerprint strip only space, tab, newline, carriage return, vertical tab
and form feed. Text padded with U+00A0, U+3000, U+2028, U+0085 or another
character outside ASCII that `str.isspace` counts is refused with a
`BTClibValueError`, where it was read as the value it wraps, and so is
text padded with U+001C to U+001F, except by `Psbt.b64decode`
(issue #108). `BIP32KeyOrigin.from_description` still accepts either
padding after the path (issue #107). For such a spelling of an address a
wallet handed out, `address in wallet` answers `False` and
`Wallet.address_info` raises. Strip that padding before passing the text.

## v2026.9.24

The first release of `btclib-wallet`, whose modules leave `btclib`
(issue btclib-org/btclib#2129). A caller importing one of them from
`btclib` installs this package and imports it from `btclib_wallet`
instead, the path below the package unchanged: `btclib.bip32` becomes
`btclib_wallet.bip32`, `btclib.mnemonic.bip39` becomes
`btclib_wallet.mnemonic.bip39`.

`CHANGELOG.md`'s own `v2026.9.24` section has the rest.
