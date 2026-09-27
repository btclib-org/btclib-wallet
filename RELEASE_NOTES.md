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

## v2026.9.24

The first release of `btclib-wallet`, whose modules leave `btclib`
(issue btclib-org/btclib#2129). A caller importing one of them from
`btclib` installs this package and imports it from `btclib_wallet`
instead, the path below the package unchanged: `btclib.bip32` becomes
`btclib_wallet.bip32`, `btclib.mnemonic.bip39` becomes
`btclib_wallet.mnemonic.bip39`.

`CHANGELOG.md`'s own `v2026.9.24` section has the rest.
