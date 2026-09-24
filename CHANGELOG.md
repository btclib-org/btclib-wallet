# Changelog

<!-- markdownlint-configure-file
  {
    // MD024/no-duplicate-heading - every release repeats the same few
    // headings, which is what keeps the page readable scrolling down it;
    // only a duplicate under the same release heading would be the
    // accident this rule looks for
    "MD024": { "siblings_only": true }
  }
-->

An entry for anything a reader would notice: what changed, and the issue
it answers. That is section 9 of [the organization standard][std], and it
is narrower than "every change" — a comment reworded inside a workflow
changes nothing a reader of this repository meets, and lands without an
entry. [RELEASE_NOTES.md](./RELEASE_NOTES.md) has the release notes,
which say what a user has to act on; this file is the record behind them.

[std]: https://github.com/btclib-org/.github

Neither file states how many entries it holds: a stated number is a line
every open branch has to edit, and the two files carry a union merge
driver that would keep both sides' numbers.

## v2026.10 (work in progress, not released yet)

### `README.md` carries the OpenSSF Best Practices badge

It follows the Scorecard badge, where section 2 of the organization
standard places it for a tree section 10's `scorecard` entry names; the
project is bestpractices.dev's 14813 (issue btclib-org/.github#350).

### A release's version is the date it is cut

`RELEASING.md` dates a release `YYYY.M.D` of the day it is cut, not the
placeholder's month with the day added (closes #5).

### The suite the sdist ships is run from the unpacked sdist

`test.yml`'s `dist` job unpacks the sdist it built and runs the suite
there, gated at 100% coverage (closes #3).

### `sdist-rebuild.yml` stops passing `attest-signer`

The called workflow verifies against `reusable-attest.yml` alone, so the
input decides nothing (issue btclib-org/.github#1315).

### The type aliases only the wallet uses are defined in the wallet

`BIP44ScriptType`, `BlockCipherF`, `EmbeddedScriptType`, `KeyOrder`,
`MnemonicLang` and `ValidSigHashType` are published by this package's own
modules, not imported from `btclib.alias` (issue btclib-org/btclib#2244).

### `input_validation_test.py` checks this package's own aliases too

An alias a public parameter takes, from btclib's `alias.py` or this package,
is driven or exempted with a reason, and the walk drives `Entropy`; `BinStr`
and `Mnemonic` wait on their functions' validation (closes #12, issue #15).

### A mnemonic or a binary-string entropy of another type is refused

The functions taking one refuse any other type with a `BTClibTypeError`,
bytes included, and `input_validation_test.py` drives `BinStr` and
`Mnemonic` (closes #15).

## v2026.9.24

### The wallet layer is a package of its own, `btclib-wallet`

The modules above btclib's primitives leave `btclib` for this package,
each at the same path under `btclib_wallet` (issue btclib-org/btclib#2129).

### `btclib-wallet` imports only btclib's public names

The floor is `btclib>=2026.9.24`, the first btclib release publishing
every name imported here, and the `secp256k1` extra names the bindings
this package imports directly (issue btclib-org/btclib#2242).

### Python 3.11 and up

`requires-python` is `>=3.11`, and the classifiers start at 3.11.

### The interpreters this package claims are the ones it runs on

`tests/interpreters_test.py` refuses a floor, a classifier list and a
platform sweep that disagree on which Pythons this package supports.

### The PSBT, descriptor, BIP32 and BIP322 parsers are fuzzed weekly

`fuzz.yml` runs a ClusterFuzzLite target for each parser that reads a
stranger's octets or text, seeded from the vectors the suite already holds.

### The sdist leaves out the tests that read `.github` or `fuzz/`

Those tests fail when run from an unpacked sdist, which carries neither
directory, and `tests/source_exclude_test.py` refuses one not in
`source-exclude` (closes #1).

### `REPOSITORY.md` records what each read-back answers

Each read-back carries what it answered on 2026-09-24, and the one for the
repository's switches asks for `.default_branch` by its field
(issue btclib-org/btclib#2129).
