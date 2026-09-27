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

### SLIP-0039's list of shares is refused when it is not one

`master_secret_from_mnemonics` and `mxprv_from_mnemonics` refuse anything
but a sequence of mnemonics, a lone mnemonic included, with a
`BTClibTypeError` (closes #17).

### `codeql-passed` and `test-passed` no longer skip while draft

A skipped required check reads as passing, so both aggregates now fail
a first step on the draft flag instead of skipping on it (issue
btclib-org/.github#1327).

### CPython 3.15 is the interpreter pinned and a version claimed

`.python-version` names 3.15, its release candidate counting as a
release, and the classifiers and the sweeps gain it; `requires-python`
stays at 3.11 (issue btclib-org/.github#1324).

### pre-commit.ci skips `uv-lock`

Its image lacks the interpreter `.python-version` names and has no
network to download it; the lint workflow still runs the hook (issue
btclib-org/.github#1348).

### The rebuild of a release names the interpreter its tag pinned

`RELEASING.md`'s *Rebuild a release from its tag* reads it from the tag's
`.python-version` rather than naming one (issue btclib-org/.github#1349).

### The rebuild of a release runs in a worktree of its tag

`RELEASING.md`'s *Rebuild a release from its tag* builds in a worktree of
the tag, clean by construction, and drops the `git archive` export, which
has no `.git` for its git commands (issue btclib-org/.github#1352).

### A drift line names both commits whole

`check_vendored_vectors.py` prints the pinned commit and upstream's tip as
full shas, in its output and in the tracking issue, so two commits alike in
their first twelve characters print as two (issue btclib-org/.github#1343).

### `ARCHITECTURE.md` and `ASSURANCE_CASE.md` join the root

The architecture moves there from `CLAUDE.md`, which points at it; the
assurance case cites the tree for every claim (issue
btclib-org/.github#1321).

### The rebuild of a release builds under the release's own uv

`RELEASING.md`'s *Rebuild a release from its tag* builds under the uv
the published wheel names and verifies the sdist first: a wheel that
disagrees stops the chain after it (issue btclib-org/btclib-node#1063).

### The publishing environments' required reviewer is any of the owners

`RELEASING.md` and `REPOSITORY.md` name `fametrano`, `giacomocaironi` and
`pmazzocchi` as the `pypi` and `testpypi` reviewers, not `fametrano` alone
(issue btclib-org/.github#1355).

### `CONTRIBUTING.md` and `README.md` link `GOVERNANCE.md` and `ROADMAP.md`

Both point a contributor at the organization's one copy of each, in
`btclib-org/.github` (issue btclib-org/.github#1359).

### `tests.no_bindings` finds the dispatch from `set_libsecp256k1_serving`

It refuses the bindings held by the module the switch's `__module__` names,
`ellipticcurves.curves.curve` under a btclib re-exporting that switch, and
`no_bindings_anywhere` walks `ellipticcurves` too (closes #52).

### `bip32_test` and `key_wallet_test` find what they patch from a public name

The `mod_sqrt_var` patch and the counted key derivation land in the module
`CurveGroup`'s and `bytes_from_prv_key_int`'s `__module__` names, which
holds under a btclib re-exporting ellipticcurves (closes #55).

### The suite refuses a dispatch switch the installed btclib ignores

`py_arm_authority_test.py`'s measurement sets `BTCLIB_NO_LIBSECP256K1`
and `ELLIPTICCURVES_NO_LIBSECP256K1`; a run with either set while
libsecp256k1 still serves exits 4 rather than measure it (closes #53).

### A refusal of ellipticcurves' own leaves as that package's class

The contract's tests accept its classes beside btclib's, never a bare built-in;
a psbt or `musig()` key it refuses is a `BTClibValueError`, and `bip322.verify`
answers False to its runtime error (closes #54).

### The curve package is `btclib_ecc`

Where the entries above spell it `ellipticcurves`, it is `btclib_ecc`, with
`BTClibEcc*` classes and `BTCLIB_ECC_NO_LIBSECP256K1`; a name btclib leaves
unbound while delegating to it fails the suite (issue btclib-org/btclib#2282).

### `REVIEWING.md` lets a filed issue carry its fix

An issue filed from a review may say the fix where one is known: *What is
filed, and what is not* dropped its "no fix", the filing bar standing as it
was (issue btclib-org/.github#1378).

### A mistyped mnemonic or SLIP-0039 share is no longer echoed whole

`bip39.py`, `electrum.py` and `slip39.py` reported the sentence in the
exception raised over an unrecognized language or a bad checksum; each
now reports the word count instead (closes #38).

### `slip39.Share`'s `repr` no longer prints `value`

`value` is the (encrypted) master secret, and the frozen dataclass's
default `repr` printed it; `BIP32KeyData.__repr__` masks its key material
for the same reason (closes #39).

### The ClusterFuzzLite base image is pinned by digest

`.clusterfuzzlite/Dockerfile`'s `FROM` names a `sha256` digest, and
`.github/dependabot.yml` carries a `docker` ecosystem entry on
`/.clusterfuzzlite` to move it forward (closes #32).

### The ClusterFuzzLite build installs from `uv.lock`, not the index

`.clusterfuzzlite/build.sh` installs a hashed `uv export --locked`
requirements file with `pip3 install --require-hashes` before installing
the package itself `--no-deps` (closes #33).

### SLIP-0039 generation refuses an argument of another type

`slip39.mnemonics_from_master_secret` refuses one with a `BTClibTypeError`,
`groups` included, and a bool where an integer belongs (closes #43).

### Dice rolls are shuffled as a copy, and refused unless integers

`bin_str_entropy_from_rolls` leaves the caller's rolls in order, reads a
tuple, and refuses with a `BTClibTypeError` what is no sequence of
integers (closes #47).

### `TlsLineTransport`'s default context sets TLS 1.2 as its floor

The context it builds when given none has `minimum_version` set to
`TLSv1_2`: PyPy's `ssl.create_default_context()` leaves it at
`MINIMUM_SUPPORTED`, where CPython's already answers `TLSv1_2` (closes #46).

### `EsploraFetcher` and `ElectrumFetcher` check their constructor arguments

A `base_url` that is no http(s) url with a host, a `timeout` that is no
positive finite number, or a `transport` that is not callable is refused
at construction, as a `BTClibTypeError` or `BTClibValueError` (closes #44).

### `EsploraFetcher` refuses a `base_url` carrying credentials

A url with a user or a password is a `BTClibValueError` that does not echo
it, since the `HttpError` of a status other than 200 quotes the url
(closes #65).

### A SLIP-0039 share, and its passphrase, refuse a value of another type

`slip39.Share`, `mnemonic_from_share` and an entropy source's draws are
type-checked, and `mxprv_from_mnemonics` reads only `None` as the empty
passphrase, refusing a falsy value of another type (closes #63) (closes #66).

### `BitcoinCoreFetcher` and `BitcoinCoreRestFetcher` check their client

A `client` of another class is a `BTClibTypeError` at construction, and so
is an `estimate_mode` that is no string; a string that is none of the modes
Core takes, in any ASCII case, is a `BTClibValueError` (closes #64).

### A timeout past `threading.TIMEOUT_MAX` is a `BTClibValueError`

`TlsLineTransport`, `EsploraFetcher` and `ElectrumFetcher` share one check,
`transport.valid_timeout`, bounded where a socket still waits; past it, a
timeout left the transport's call as a bare `OverflowError` (closes #70).

### The change script is a required argument

`tx_builder.build_psbt`, `coin_selection.select_coins`, `knapsack` and
`single_random_draw` take `change_script_pub_key` with no default, a sweep
passing `None`; `branch_and_bound` keeps its default (closes #36).

### `build_psbt` refuses a lock time that final sequences void

A non-zero `lock_time` where every input's sequence is `0xffffffff` is a
`BTClibValueError`, consensus ignoring the lock time of such a
transaction (closes #37).

### `build_psbt` refuses an output below the dust threshold

An output being paid worth less than `dust_threshold` for its script, at
the `dust_fee_rate` the change is created against, is a
`BTClibValueError` (closes #42).

### `build_psbt` refuses a fee above `max_fee`

The keyword defaults to `DEFAULT_MAX_FEE`, Bitcoin Core's `-maxtxfee`
default of 0.10 BTC, and a larger fee is a `BTClibValueError`
(closes #48).

### `psbt.sign` runs BIP375's Signer checks on a silent payment

Before any key is asked, it refuses what `psbt.silent_payments.assert_as_valid`
refuses, a sighash other than `SIGHASH_ALL` among it, and a silent payment
output with no script yet (closes #34).

### `psbt.extract_tx` runs BIP375's Extractor check on a silent payment

`check_validity` also runs `psbt.silent_payments.assert_as_valid`, which
reads a finalized input's key from its final scripts, and refuses a silent
payment output with no script (closes #35).

### `psbt.combine` merges a silent payment output's script

The script is taken from whichever psbt carries it, and two different ones
are refused with a `BTClibValueError` rather than one kept (closes #50).

### `build_psbt` refuses a fee above what `max_fee_rate` asks

The keyword defaults to `DEFAULT_MAX_FEE_RATE`, Bitcoin Core's
`-maxfeerate` default of 0.10 BTC/kvB, applied to the estimated vsize;
a larger fee is a `BTClibValueError` (closes #73).

### The suite refuses a constant default entropy in BIP39 and SLIP-0039

`bip39_test` and `slip39_test` generate twice or more with no entropy given
and assert the mnemonics, the SLIP-0039 identifiers and the share values
differ, and that a default BIP39 entropy is 128 bits (closes #41).

### `HwiSigner` keeps caller text off HWI's options, and the psbt off argv

A message, a policy name or a registration starting with `-` reaches HWI
as a value (closes #45), a psbt goes to its standard input rather than to
a size-capped argv (closes #51), and a NUL in an argument is refused.

### A psbt input's witness utxo has to be the output its non-witness utxo names

`Psbt.assert_valid` refuses one differing in amount or script, and the
spent output is read from `non_witness_utxo` as Bitcoin Core reads it;
`bip322` does both against an earlier input's transaction (closes #40).

### `estimated_input_sizes` checks the utxo against the outpoint

A `non_witness_utxo` not the transaction the `TxIn` names, or without the
output it names, is a `BTClibValueError`, as is a `witness_utxo` differing
from that output, no longer read in its place (closes #80).

### `request_signatures` runs BIP375's Signer checks before a signer is asked

A psbt paying a silent payment is refused as `psbt.sign` refuses it before
`sign_psbt` is called, so a signer asked through it sees none (closes #74).

### Which inputs a silent payment sums is decided by the script they spend

A counted input without a key its script commits to is refused, not left out,
and `set_output_scripts` waits for every counted input's share (closes #76).

### `HwiSigner.sign_psbt` runs BIP375's Signer checks before `hwi` runs

A psbt `psbt.sign` would refuse is refused on a direct call too, not only
through `request_signatures`, and a request that is no psbt is a
`BTClibTypeError` (closes #82).

### `psbt.combine` validates the psbt it returns

Copies valid alone whose merge is not, such as one's `witness_utxo`
contradicting another's `non_witness_utxo`, are a `BTClibValueError`
(closes #81).

### `psbt.combine` refuses no psbts and what is not a psbt

An empty sequence is a `BTClibValueError`, and a `psbts` that is no sequence
or holds an element that is no `Psbt` a `BTClibTypeError` (closes #88).

### `psbt.join` refuses no psbts and what is not a psbt

An empty sequence is a `BTClibValueError`, and a `psbts` that is no sequence
or holds an element that is no `Psbt` a `BTClibTypeError` (closes #89).

### `CLAUDE.md` names three failures a session met in this tree

The union seam in `RELEASE_NOTES.md` that no hook reports, the
`.secrets.baseline` conflict on `generated_at` that costs a review round,
and the `timeout` macOS does not ship.

### `integration-hwi.yml` installs bitcoind with `.github`'s script

It runs `install_bitcoind.py`, as the reusable workflow that
`integration-bitcoind.yml` calls does, and the tree's own `install-bitcoind`
action is dropped (issue btclib-org/.github#1373).

### `codeql.yml`, `REPOSITORY.md` and `dependabot.yml` follow sections 10 and 11

The aggregate accepts `analyze`'s lagging rows (issue btclib-org/.github#1395),
signatures and SHA pinning are read back (issue btclib-org/.github#1409), and
`pre-commit` is an ecosystem left unused (issue btclib-org/.github#1391).

### A malformed descriptor's refusal no longer echoes its private keys

`descriptors.parse` and `wallet_policy_descriptor` name what is wrong without
quoting the descriptor text around it, a WIF or an xprv included (closes #49);
btclib's bech32 decoder can still quote an `addr()` argument (issue #94).

### `KeyExpression` refuses an extended private key as `xkey`

With a `BTClibValueError` that does not quote it, so no `KeyExpression` holds
an xprv for its `str`, or a wallet-policy refusal quoting it, to echo
(closes #95).

### `KeyExpression`'s `xkey` is an xpub, a placeholder or nothing

Other text is refused without being quoted: an xprv damaged by a character
decodes as no key, and where only its checksum changed it still spells the
key (closes #97).

### A mixed-case or non-ASCII address is not read as the one it lowers to

`silent_payments.keys_from_address` refuses both, and a wallet lowers only an
ASCII all-uppercase spelling: neither a mixed-case string nor U+212A KELVIN
SIGN in place of `K` is found as the address it lowers to (closes #99).

### `descriptors_test` matches the refusal of a non-script without its quote

`test_index_of_refuses_what_it_could_only_answer_none_for` matches
`neither a script nor an address` alone, which a btclib carrying
btclib-org/btclib#2350 raises without the string it refused (closes #101).

### The regtest job exempts the HWI skips by their message

`integration-bitcoind.yml` passes `skip-reason-prefix: "set BTCLIB_HWI"` for
`exclude-classname: hwi`: an HWI testcase skipping for another reason fails
the check that the node's tests ran (issue btclib-org/.github#1419).

### Address, key and base64 readers strip ASCII whitespace alone

`str.strip()` also takes U+00A0, U+3000 and the rest of what `str.isspace`
counts; `string.whitespace` is Bitcoin Core's `IsSpace`. `tx_or_psbt_from_any`
refuses non-ASCII text with `BTClibValueError`, not `ValueError` (closes #102).

### `mnemonic.entropy` reads a string entropy in ASCII digits alone

`int` read `0x1_0`, `1_6`, `+16`, non-ASCII digits and U+3000 padding as 16,
`collect_rolls` read `+2` and those digits, and a binary string took `-`, `0b`
or `_`. No refusal quotes the entropy, an index or a roll (closes #103).

### `descriptors.parse` refuses a multisig where Bitcoin Core refuses it

A bare `multi()` of more than three keys, a redeem script inside `sh()` over
520 bytes and more than twenty keys anywhere are refused, as Bitcoin Core
refuses them; the `sh()` one gave an unspendable address (closes #109).

### `Psbt.b64decode` refuses a character outside the base64 alphabet

Past the ASCII whitespace stripped from either end, a line break or a U+001C
is refused with `BTClibValueError`, as Bitcoin Core's `DecodeBase64PSBT`
refuses it, where the decoder dropped it and read the rest (closes #108).

### A derivation path's step is ASCII digits, padded with ASCII whitespace

A step spelled `1_0`, `+1`, `-0` or in non-ASCII digits, or padded with U+3000,
is refused without being quoted, and so is a ninth character other than `/` in
`BIP32KeyOrigin.from_description`, where each was read as a path (closes #107).

### `codeql-passed` reads a lagging row again and fails on a failed `analyze`

An unfinished `analyze` row is read again up to three times, 10 s apart, before
it is accepted (issue btclib-org/.github#1416), and an `analyze` result other
than `success` or `skipped` fails the check (issue btclib-org/.github#1424).

### A `/` in a key expression is followed by a path step

`descriptors.parse` and `miniscript.parse` refuse `[deadbeef/]`, `xpub.../`,
`xpub...//*` and `musig(...)/`, as Bitcoin Core refuses the empty step, where
each was read as though that `/` were absent (closes #116).

### The base64 readers read the canonical encoding alone

`YR==`, which decoded as `YQ==`, and an `=` after a whole group, which CPython
and PyPy 3.11 decoded, are refused as Bitcoin Core's `DecodeBase64` refuses
them; `bip322.Sig.b64decode` does not quote a non-ASCII character (closes #114).

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
