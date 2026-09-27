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

## v2026.9.24

The first release of `btclib-wallet`, whose modules leave `btclib`
(issue btclib-org/btclib#2129). A caller importing one of them from
`btclib` installs this package and imports it from `btclib_wallet`
instead, the path below the package unchanged: `btclib.bip32` becomes
`btclib_wallet.bip32`, `btclib.mnemonic.bip39` becomes
`btclib_wallet.mnemonic.bip39`.

`CHANGELOG.md`'s own `v2026.9.24` section has the rest.
