# Release notes

Notable changes are documented here.
[CHANGELOG.md](./CHANGELOG.md) is the record behind them: this file says
what a user has to act on, that one says what changed.

Versions are *[calendar versions](https://calver.org/)*, `YYYY.M.D`: the
number says when a release was cut, and promises nothing about
compatibility, so a breaking change is announced in this file — read it
before upgrading, rather than a digit.

## v2026.10 (work in progress, not released yet)

- **Verifying a release's attestation names a new signer and the tag.**
  `gh attestation verify` takes
  `--signer-workflow btclib-org/.github/.github/workflows/reusable-build.yml@refs/heads/main`
  and `--source-ref refs/tags/v<version>`; SECURITY.md has the command.
  Earlier releases keep `reusable-attest.yml`.
- **`descriptors.parse` refuses a key of another network.** A WIF or an
  extended key whose prefix is not the `network`'s raises
  `BTClibValueError` there, where the WIF was accepted and the extended key
  was refused only by `script_pub_keys()`. A caller that parses a descriptor
  for a network its keys are not of has to pass the right `network`.

- **`bip39.mxprv_from_mnemonic` and `electrum.mxprv_from_mnemonic` refuse
  a falsy passphrase of another type.** An empty `bytes`, `0`, `False` or
  `[]` derived the wallet without a passphrase; pass `None` or `""` for that.

- **A miniscript repeating a public key is refused under different
  spellings of it.** `descriptors.parse` does so as Bitcoin Core does, except
  for a key with a hardened step.

- **A malleable miniscript keeps neither "s", "f" nor "e".**
  `Miniscript.properties` drops them, and `is_signature_required` is false for
  it.

- **`join` empties the signatures of a version 0 psbt, and `sign` updates a
  version 2 psbt's modifiable flags.** Sign the joined psbt again. `join`
  refuses a version 2 psbt signed with anything but SIGHASH_NONE|ANYONECANPAY.

- **`extract_tx` verifies by default.** It runs every input's scripts and
  checks that the outputs do not exceed the inputs, so it raises on a psbt it
  extracted before: one with a bad signature, a missing utxo or outputs above
  the inputs. Pass `verify_scripts=False` to extract without the check.

- **`Miniscript.has_duplicate_keys`, `is_sane`, `is_sane_subexpression` and
  `insane_sub` are methods.** Call them with parentheses; without them,
  `if node.is_sane:` is always true, and mypy reports it as `truthy-function`.
  Pass `prv_keys`, the mapping `parse` fills, to derive a hardened step:
  `descriptors.parse` refuses `wsh(or_i(pk(XPRV/1h),pk(<the key it derives>)))`.
  Without its private key, a key with a hardened step is still compared as
  written.

## v2026.9.30

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
text padded with U+001C to U+001F. For such a spelling of an address a
wallet handed out, `address in wallet` answers `False` and
`Wallet.address_info` raises. Strip that padding before passing the text.

`mnemonic.entropy.bin_str_entropy_from_int` refuses with a
`BTClibValueError` a string entropy that is not ASCII digits -- binary after
`0b`, hex after `0x`, decimal otherwise -- once space, tab, newline,
carriage return, vertical tab and form feed are stripped around it, where
`int` read `0x1_0`, `1_6`, `+16` and fullwidth or Arabic-Indic digits as 16
and U+00A0 or U+3000 was stripped too. The functions reading a binary-string
entropy, `bin_str_entropy_from_str`, `bytes_entropy_from_str` and
`bin_str_entropy_from_entropy` among them, refuse one holding anything but
ASCII `0` and `1` -- a sign, `0b`, whitespace, an underscore -- which `int`
read as binary; `bytes_entropy_from_str` raised a bare `OverflowError` on a
leading `-`. Pass ASCII digits alone. The refusals read `invalid entropy:
what follows 0x is not ASCII hex digits` and `invalid entropy: not ASCII
decimal digits`, where they said `not a base 16 number` and `not a base 10
number`, and a negative entropy's reads `negative entropy`, without the
number. `bin_str_entropy_from_wordlist_indexes` and
`bin_str_entropy_from_rolls` name the range and not the value of an index or
a roll outside it: `invalid index: not in [0, 2048)`, `invalid roll: not in
[1-6]`. Match `invalid entropy`, `negative entropy`, `invalid index` and
`invalid roll` alone.

`descriptors.parse` refuses with a `BTClibValueError` a bare `multi()` or
`sortedmulti()` of more than three keys, one inside `sh()` whose redeem script
is over 520 bytes -- sixteen compressed keys are 547 -- and one of more than
twenty keys anywhere, where it parsed them; put the keys of the first two
inside `wsh()` or `sh(wsh())` instead. `wallet_policy_descriptor` refuses the
same, the descriptor it builds being read by `parse`.

`Psbt.b64decode` refuses with a `BTClibValueError` text holding a
character outside the base64 alphabet -- a line break, a space, U+001C,
`!` -- anywhere past the ASCII whitespace it strips from either end,
where it decoded the psbt the rest of the text spells. Remove the line
breaks from a wrapped psbt, or pass it to
`tx_or_psbt.tx_or_psbt_from_any`, which removes them.

`bip32.indexes_from_der_path`, `hardenings_from_der_path`,
`int_from_index_str` and every function reading a path string through
them, `bip32.derive` and `BIP32KeyOrigin.from_description` among them,
refuse with a `BTClibValueError` a step whose number is not ASCII decimal
digits -- `1_0`, `+1`, `-0`, fullwidth or Arabic-Indic digits -- or that is
padded with anything but space, tab, newline, carriage return, vertical tab
and form feed, where it was read as the number. With `bip380_enforced=True`
they refuse a step padded at all, and so `descriptors.parse` refuses a
step with a space around it. `BIP32KeyOrigin.from_description` refuses text
whose ninth character is not `/`, where it dropped that character and read
`deadbeef0/1` as `deadbeef/1`. `int_from_index_str` refuses a step that is
not a `str` with a `BTClibTypeError`, and reads a step with ASCII whitespace
after its symbol, `"0h "`, which it refused. Pass each step as ASCII digits.
The refusals read `invalid derivation index: not ASCII decimal digits` and
`invalid index: not below 2**31`, where they quoted the step or its number;
match those. `bip85`'s functions write their index into a path string, and
refuse a negative one with the first and one of 2**31 or more with the
second.

`descriptors.parse` and `miniscript.parse` refuse with a `BTClibValueError`
a `/` followed by no path step, in a key origin, after an extended key or
after a `musig()` -- `[deadbeef/]`, `xpub.../`, `xpub...//*`,
`musig(...)/` -- where they read the key expression as though that `/`
were absent. Remove the `/`; the refusal reads `invalid derivation index`.
`BIP32KeyOrigin.from_description`, whose reading of a path is the lenient
one, reads `deadbeef/` as `deadbeef`.

`Psbt.b64decode`, `bip322.Sig.b64decode`, and `bip322.verify` and
`assert_as_valid` for the signature, refuse with a `BTClibValueError`
base64 that is not the text `base64.b64encode` writes for its bytes, where
they read those bytes: a bit set in what the last character leaves over,
`YR==` read as `YQ==`, and on CPython and PyPy 3.11 an `=` after a whole
group. The refusal reads `invalid base64 encoding: not canonical`, and
`bip322.verify` raises it for a legacy signature so encoded, where it
answered `False`. `tx_or_psbt.tx_or_psbt_from_any` refuses such a `str` as
`neither hex nor base64`, and reads such bytes as a raw transaction, where
both were read as the psbt. Pass the text `base64.b64encode` writes, which
is the text Bitcoin Core writes and the only text it reads.

A refusal in `mnemonic` no longer quotes secret material, so its text
changed: an unknown word reads `unknown '<lang>' word at position <n>`,
where it was `unknown '<lang>' word: '<word>'`, and a SLIP-0039 one
`not in the SLIP-0039 word-list: words at positions [<n>, ...]`. A BIP39
checksum reads `invalid checksum: <n> words`, a SLIP-0039 padding
`invalid padding: must be all zeros`, and an unrecognized Electrum
sentence `unknown electrum mnemonic version; not in [...]`. Match the
new text if you match these. `mnemonic.mnemonic_from_indexes` refuses an
index outside the word-list, a negative one included, which read from
the end of the list; pass indexes in `[0, len(wordlist))`.
`WordLists.langs_of_words` refuses a lone `str`, which it read one
character at a time; pass the list of words.

`mnemonic.mnemonic_from_indexes` and `WordLists.langs_of_words` refuse
with a `BTClibTypeError` an iterable that is not a sequence -- a
generator, a set, an iterator -- where they read it; pass a `list` or a
`tuple`. `mnemonic_from_indexes` refuses too an index that is a bool or
an integer of a type other than `int`, `numpy.int64` or an object with
`__index__` included, where it read it; pass `int`s.
`dispatch.seed_type_from_mnemonic` and `all_seed_types_from_mnemonic`
refuse a `lang` that is not a `str` with a `BTClibTypeError`, where they
answered `""` and `[]`; pass the language code.

The BIP39, SLIP39 and Electrum mnemonic schemes are
[btclib-mnemonics](https://github.com/btclib-org/btclib-mnemonics)', a
dependency of this package, and `btclib_wallet.mnemonic` keeps what
builds a key from their seed: `bip39.mxprv_from_mnemonic`,
`slip39.mxprv_from_mnemonics`, `electrum.mxprv_from_mnemonic` and
`electrum.old_master_pub_key_from_mnemonic`. Every path below stops
resolving, and nothing re-exports it; import the name from
`btclib_mnemonics` instead. A refusal those four functions pass on from
`btclib_mnemonics`, of a mnemonic, a share or a passphrase, is that
package's own `BTClibMnemonicsTypeError` or `BTClibMnemonicsValueError`,
a `TypeError` or a `ValueError` and no `BTClibException`, where it was a
`BTClibTypeError` or a `BTClibValueError`; catch `TypeError` and
`ValueError`. `electrum.mxprv_from_mnemonic` still refuses a `2fa`, a
`2fa_segwit` or an `old` mnemonic with its own `BTClibValueError`, and for
an `old` one that refusal now ends `use old_master_pub_key_from_mnemonic`,
where it named `old_master_prv_key_from_mnemonic`. The paragraphs above
that name a function that moved describe it as it is under
`btclib_mnemonics`, where each `BTClibTypeError` or `BTClibValueError`
they name for it is a `BTClibMnemonicsTypeError` or a
`BTClibMnemonicsValueError`, and where the entropy conversions they name
are private.

- `btclib_wallet.mnemonic.dispatch` is `btclib_mnemonics.dispatch`.
- `btclib_wallet.mnemonic.entropy` is `btclib_mnemonics.entropy`, less the
  functions the bullets below make private.
- `btclib_wallet.mnemonic.mnemonic` is `btclib_mnemonics.mnemonic`.
- `btclib_wallet.mnemonic`'s `BinStr` is `btclib_mnemonics.entropy.BinStr`.
- `btclib_wallet.mnemonic`'s `Entropy` is `btclib_mnemonics.entropy.Entropy`.
- `btclib_wallet.mnemonic`'s `bin_str_entropy_from_random` is
  `btclib_mnemonics.entropy.bin_str_entropy_from_random`.
- `btclib_wallet.mnemonic`'s `bin_str_entropy_from_rolls` is
  `btclib_mnemonics.entropy.bin_str_entropy_from_rolls`.
- `btclib_wallet.mnemonic`'s `collect_rolls` is
  `btclib_mnemonics.entropy.collect_rolls`.
- `btclib_wallet.mnemonic`'s `Mnemonic` is
  `btclib_mnemonics.mnemonic.Mnemonic`.
- `btclib_wallet.mnemonic`'s `WORDLISTS` is
  `btclib_mnemonics.mnemonic.WORDLISTS`.
- `btclib_wallet.mnemonic`'s `indexes_from_mnemonic` is
  `btclib_mnemonics.mnemonic.indexes_from_mnemonic`.
- `btclib_wallet.mnemonic`'s `mnemonic_from_indexes` is
  `btclib_mnemonics.mnemonic.mnemonic_from_indexes`.
- `btclib_wallet.mnemonic`'s `normalize_mnemonic` is
  `btclib_mnemonics.mnemonic.normalize_mnemonic`.
- `btclib_wallet.mnemonic`'s `bin_str_entropy_from_bytes` is gone, private in
  `btclib_mnemonics`: pass the bytes to the scheme's `mnemonic_from_entropy`,
  which reads them.
- `btclib_wallet.mnemonic`'s `bin_str_entropy_from_entropy` is gone, private
  in `btclib_mnemonics`: pass the entropy to the scheme's
  `mnemonic_from_entropy`, which reads it.
- `btclib_wallet.mnemonic`'s `bin_str_entropy_from_int` is gone, private in
  `btclib_mnemonics`: pass the integer to the scheme's
  `mnemonic_from_entropy`, which reads it.
- `btclib_wallet.mnemonic`'s `bin_str_entropy_from_str` is gone, private in
  `btclib_mnemonics`: pass the binary string itself.
- `btclib_wallet.mnemonic`'s `bin_str_entropy_from_wordlist_indexes` is gone,
  private in `btclib_mnemonics`: use
  `btclib_mnemonics.mnemonic.mnemonic_from_indexes` and the scheme's
  `entropy_from_mnemonic`.
- `btclib_wallet.mnemonic`'s `bytes_entropy_from_str` is gone, private in
  `btclib_mnemonics`: `int(entropy, 2).to_bytes(len(entropy) // 8, "big")` is
  the conversion.
- `btclib_wallet.mnemonic`'s `wordlist_indexes_from_bin_str_entropy` is gone,
  private in `btclib_mnemonics`: use the scheme's `mnemonic_from_entropy` and
  `btclib_mnemonics.mnemonic.indexes_from_mnemonic`.
- `btclib_wallet.mnemonic.bip39`'s `entropy_from_mnemonic` is
  `btclib_mnemonics.bip39.entropy_from_mnemonic`.
- `btclib_wallet.mnemonic.bip39`'s `lang_from_mnemonic` is
  `btclib_mnemonics.bip39.lang_from_mnemonic`.
- `btclib_wallet.mnemonic.bip39`'s `mnemonic_from_entropy` is
  `btclib_mnemonics.bip39.mnemonic_from_entropy`.
- `btclib_wallet.mnemonic.bip39`'s `seed_from_mnemonic` is
  `btclib_mnemonics.bip39.seed_from_mnemonic`.
- `btclib_wallet.mnemonic.electrum`'s `ELECTRUM_WORDLISTS` is
  `btclib_mnemonics.electrum.ELECTRUM_WORDLISTS`.
- `btclib_wallet.mnemonic.electrum`'s `entropy_from_mnemonic` is
  `btclib_mnemonics.electrum.entropy_from_mnemonic`.
- `btclib_wallet.mnemonic.electrum`'s `hex_seed_from_old_mnemonic` is
  `btclib_mnemonics.electrum.hex_seed_from_old_mnemonic`.
- `btclib_wallet.mnemonic.electrum`'s `lang_from_mnemonic` is
  `btclib_mnemonics.electrum.lang_from_mnemonic`.
- `btclib_wallet.mnemonic.electrum`'s `mnemonic_from_entropy` is
  `btclib_mnemonics.electrum.mnemonic_from_entropy`.
- `btclib_wallet.mnemonic.electrum`'s `old_master_prv_key_from_mnemonic` is
  `btclib_mnemonics.electrum.old_master_prv_key_from_mnemonic`.
- `btclib_wallet.mnemonic.electrum`'s `old_mnemonic_from_hex_seed` is
  `btclib_mnemonics.electrum.old_mnemonic_from_hex_seed`.
- `btclib_wallet.mnemonic.electrum`'s `version_from_mnemonic` is
  `btclib_mnemonics.electrum.version_from_mnemonic`.
- `btclib_wallet.mnemonic.slip39`'s `Share` is
  `btclib_mnemonics.slip39.Share`.
- `btclib_wallet.mnemonic.slip39`'s `master_secret_from_mnemonics` is
  `btclib_mnemonics.slip39.master_secret_from_mnemonics`.
- `btclib_wallet.mnemonic.slip39`'s `mnemonic_from_share` is
  `btclib_mnemonics.slip39.mnemonic_from_share`.
- `btclib_wallet.mnemonic.slip39`'s `mnemonics_from_master_secret` is
  `btclib_mnemonics.slip39.mnemonics_from_master_secret`.
- `btclib_wallet.mnemonic.slip39`'s `share_from_mnemonic` is
  `btclib_mnemonics.slip39.share_from_mnemonic`.

The bound on a `timeout` that `fetch.ElectrumFetcher` refuses is
`fetch.transport.MAX_TIMEOUT`, 2147483 seconds, where the paragraph above
names `threading.TIMEOUT_MAX`; pass at most that many seconds.

`fetch.EsploraFetcher` refuses at construction, with a `BTClibTypeError`
or a `BTClibValueError`, a `timeout` that is no number, a bool, not
positive, or above `fetch.transport.MAX_TIMEOUT`, 2147483 seconds, where
its first fetch raised a `FetchError` and a timeout above that bound
reached a transport of the caller's. `fetch.transport.TlsLineTransport`
refuses a timeout above that bound with a `BTClibValueError`, where it
waited with one up to what the platform's socket took and failed past
it, with an `OverflowError` or, where the socket's wait refused it, a
`FetchError`; its refusals read `non-numeric timeout: <type>` and
`timeout is not a positive number of seconds up to 2147483`, where they
quoted the value. Pass a positive number of seconds up to that bound.

`CHANGELOG.md`'s own `v2026.9.30` section has the rest.

## v2026.9.24

The first release of `btclib-wallet`, whose modules leave `btclib`
(issue btclib-org/btclib#2129). A caller importing one of them from
`btclib` installs this package and imports it from `btclib_wallet`
instead, the path below the package unchanged: `btclib.bip32` becomes
`btclib_wallet.bip32`, `btclib.mnemonic.bip39` becomes
`btclib_wallet.mnemonic.bip39`.

`CHANGELOG.md`'s own `v2026.9.24` section has the rest.
