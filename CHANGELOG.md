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

### `RELEASING.md`'s griffe step searches `src`

`griffe check` takes `-s . -s src`, the pair `release.yml`'s `public-api`
job passes, where it answered `ModuleNotFoundError` for the previous
release (issue btclib-org/.github#1447).

### `pypi-install.yml` installs the version the release published

The install names `btclib-wallet==<version>` from the tag `release.yml` passes,
where a bare name let a lagging index serve the release before it
(issue btclib-org/.github#1456).

### `CONTRIBUTING.md` points a newcomer at `good first issue`

An issue carrying the label is small and self-contained: *The issue
tracker* says so, and links the organization-wide search for the open
ones (issue btclib-org/.github#1362).

### The OpenSSF Baseline badge

`README.md`'s badge row ends with the OpenSSF Baseline badge, beside the
Best Practices badge, section 2 of the organization standard admitting it
on the same property (issue btclib-org/.github#1460).

### `pypi-install.yml` retries the install of the version the release published

Each install cell runs `pip install btclib-wallet==<version>` through
btclib-org/.github's `install_published_release.py`, which retries only while
the installer says the pin is not resolvable (issue btclib-org/.github#1458).

### The release's attestation bundle is attached as `*.intoto.jsonl`

`RELEASING.md`'s verification and recovery commands name the bundle
`<tag>.intoto.jsonl`, the name `reusable-github-release.yml` attaches it under
(issue btclib-org/.github#1468).

### `codeql.yml`'s aggregate runs `check_run_jobs.py`

The aggregate's step runs `check_run_jobs.py`, which reads the run's jobs
listing again up to a deadline while a row of `analyze` is unfinished
(issue btclib-org/.github#1463).

### `generate_sbom.py` carries a not-affected list into the bill of materials

`generate_sbom.py` reads `.github/vex.toml`, where the tree lists the
vulnerabilities its release is not affected by, into the document's
`vulnerabilities`; no list, no key (issue btclib-org/.github#1469).

### `SECURITY.md` promises a response time

`SECURITY.md` says a report is acknowledged within 7 days, and a fix or a
published advisory within 90 (issue btclib-org/.github#1460).

### `parse` refuses impossible multisignature thresholds

`descriptors.parse` refuses a `multi()` or `sortedmulti()` threshold of zero
or more than its key count, instead of storing a descriptor that cannot
produce a script (closes #160).

### `parse` refuses an impossible `multi_a()`

`descriptors.parse` refuses a `multi_a()` or `sortedmulti_a()` threshold of
zero or more than its key count (closes #172), and more than 999 keys
(closes #173).

### `release.yml` audits the lock before it publishes

The `audit` job calls btclib-org/.github's `reusable-audit.yml`, which runs
`uv audit` over what the wheel declares, and both publish jobs wait for its
success (issue btclib-org/.github#1466).

### `generate_sbom.py` is btclib-org/.github's

The `dist` job writes the bill of materials with btclib-org/.github's
`generate_sbom.py`, served from `main`, and the tree keeps no copy of it
(issue btclib-org/.github#1478).

### `CLAUDE.md` carries the organization's shared section on the primary checkout

Its section *The primary checkout is the maintainer's* is the organization's
shared text, and `ARCHITECTURE.md` points the libsecp256k1 dispatch at
btclib-ecc's `SECURITY.md` (issue btclib-org/.github#1494).

### `Dependency review` is a required check

- **`REPOSITORY.md` reads `lint / Dependency review` back with the other
  required checks** (issue btclib-org/.github#1465).

### `[tool.uv] required-version` is `>=0.12.18`

- **`required-version` reads `>=0.12.18`, not `>=0.12.19`** (issue
  btclib-org/.github#1482): the Dependabot service refused `0.12.19` with
  `tool_version_not_supported`.

### `SECURITY.md` names the latest security review

`SECURITY.md` gives the date of the latest security review and links the issue
that records it (issue btclib-org/.github#1362).

### A `Signed-off-by:` trailer on every commit of a pull request

*Pull requests* says every commit of a pull request carries a
`Signed-off-by:` trailer, and how to add it (issue
btclib-org/.github#1467).

### The primary-checkout section uses one form for the checkout

- **The section writes the checkout as `"${checkout:?}"` throughout, says
  what `<scratchpad>` is and names the pull** (issue
  btclib-org/.github#1500).

### The `python` inventory has a copy kept in the tree

`docs/source/_inventories/python.inv` is read when `docs.python.org` fails,
so an outage of that site no longer fails the `-n -W` docs build (issue
btclib-org/.github#1508).

### `public-api` is red for a break `RELEASE_NOTES.md` does not name

`release.yml` and `RELEASING.md` say that a red `public-api` means
`RELEASE_NOTES.md` misses a name (issue btclib-org/.github#1517).

### The release's attestation is signed by `reusable-build.yml`, at SLSA Build L3

`release.yml` calls `reusable-build.yml`, which signs the files before the
publish jobs wait for approval (issue btclib-org/.github#1506).

### `CONTRIBUTING.md` says the maintainer self-merges while the bot review is off

*The review* says no ack of record exists while `claude-review.yml` is off,
and that a local review of a named sha, by a reviewer other than the author,
stands in (issue btclib-org/.github#1527).

### `dependabot.yml` does not say that every workflow passes `--locked`

`.github/dependabot.yml` says the workflows install from `uv.lock` with
`--locked`, bar the jobs that re-lock, install a published or built package
or install a hash-pinned export (issue btclib-org/.github#1538).

### `REPOSITORY.md` reads back the web sign-off setting

`REPOSITORY.md` reads `web_commit_signoff_required` back, the organization
setting section 11 of the standard states (issue btclib-org/.github#1540).

### `descriptors.parse` refuses a key of another network

`parse` raises `BTClibValueError` for a WIF or an extended key of another
network, as Core does; `KeyExpression.wif_prefix` holds the WIF's version
byte for it (closes #180).

### A `musig()` participant that is also a plain taproot key keeps its leaf hashes

`TrDescriptor`'s taproot derivations list every leaf of such a key whose plain
spelling has an origin, in either order; a participant written after the plain
key replaced its entry with an empty list (closes #185).

### `SilentPaymentOutput`'s repr leaves out `prv_key_tweak`

The tweak is a secret, so a logged output does not carry it (closes #161).

### `mxprv_from_mnemonic` takes only `None` or `""` as the empty passphrase

In `bip39` and `electrum`, `b""`, `0`, `False` and `[]` are refused with
`btclib_mnemonics`' `BTClibMnemonicsTypeError`, as `slip39` refuses them,
where they derived the wallet without a passphrase (closes #162).

### A malleable miniscript keeps neither `s`, `f` nor `e`

`Miniscript.properties` drops "s", "f" and "e" from an expression without "m",
as BIP379 asks, and `is_signature_required` is false there (closes #190).

### The duplicate-key check compares derived public keys

`Miniscript.has_duplicate_keys` compares the public keys the KEY expressions
derive at index 0, as Bitcoin Core does. A key with a hardened step is
compared by its extended key and its path (issue #193).

### The `Sign-off` check is required

`CONTRIBUTING.md`'s shared half says a pull request whose commits lack the
`Signed-off-by:` trailer cannot merge, and `REPOSITORY.md` lists
`lint / Sign-off` among the required checks (issue btclib-org/.github#1550).

### The suite imports btclib_ecc's exception classes from `btclib_ecc`

`tests/exception_family_test.py` imports them from `btclib_ecc.exceptions`,
since `btclib.exceptions` binds them only up to btclib 2026.9.29
(closes #166).

### `integration-hwi.yml` installs HWI and Speculos from hashed locks

`.github/integration-hwi/` holds hashed locks of both, installed with
`--require-hashes`, and the Ledger app is fetched by the commit that tag
2.5.0 names (closes #167).

### The assurance case names every direct call into libsecp256k1

`ASSURANCE_CASE.md` also says `verify_network` runs before a fetcher's first
answer, `EsploraFetcher.text` excepted, and names btclib-ecc's dispatch
(closes #163).

### The fuzz inventory covers the text parsers the threat model names

`tests/fuzz_test.py` drives the BOLT11, silent-payment address, BIP38,
minikey, derivation-path and transaction-or-PSBT parsers (closes #164).

### The assurance case states the scope of mutation testing

`ASSURANCE_CASE.md` says a module no `.github/mutation/` profile lists
rests on coverage alone (closes #165).

### `sign` updates `PSBT_GLOBAL_TX_MODIFIABLE` of a version 2 psbt

Each signature added clears Inputs Modifiable unless it is ANYONECANPAY,
clears Outputs Modifiable unless it is NONE, and sets Has SIGHASH_SINGLE
where it is SINGLE, as BIP370 asks of the Signer (closes #194).

### `join` clears the signatures of a version 0 psbt's inputs

`partial_sigs`, the final scriptSig and witness, and the taproot and MuSig2
signature fields are emptied, so the joined psbt can be signed again
(closes #195).

### `extract_tx` verifies the scripts and the amounts by default

`extract_tx` runs every input's scripts under the consensus rules and checks
that the outputs do not exceed the inputs. `verify_scripts=False` extracts
without them. `bip322` passes it, running the scripts itself (closes #191).

### The parsers refuse a long number as a `BTClibValueError`

A derivation index, a multisignature or `thresh()` threshold, an `older()` or
`after()` number and a wallet-policy `@N` of over ten significant digits are
refused, where `int()` raised `ValueError` past 4300 digits (closes #158).

### A miniscript parse stops at its script size and at 1000 `thresh()` arguments

A parse refuses once the fragments it has built pass the context's script
size, before it analyses the `thresh()` they are arguments of. A `thresh()`
of more than 1000 arguments is refused, a limit of this library (closes #159).

### `Bolt11Invoice.from_invoice` refuses a long amount as a `BTClibValueError`

An amount of more than 20 digits, leading zeros apart, is refused, where
`int()` raised the built-in `ValueError` past 4300 digits (closes #205).

### `CONTRIBUTING.md` says the ack of record is a bot's

*The review* says the maintainer lands their own pull requests through the
bypass, and that the OpenSSF criterion `two_person_review` is unmet because
the ack of record is a bot's (issue btclib-org/.github#452).

### The bypass is for emergencies, in `CONTRIBUTING.md` and this tree's prose

`CONTRIBUTING.md` and `REVIEWING.md` say every pull request, the maintainer's
included, lands with an approving review from somebody other than its author;
the bypass is for emergencies (issue btclib-org/.github#1362).

### Earlier entries on how a pull request lands

Entries above that have the maintainer landing without another person's approval
describe the rule before issue btclib-org/.github#1362 (issue
btclib-org/.github#1569).

### A PSBT's global unsigned transaction is read as Core reads it

It is read as `TX_NO_WITNESS`, so a PSBT with no input is read. The floors are
`btclib` 2026.10.3, the first release with `Tx.parse_without_witness`, and
`btclib-ecc` 2026.10.2, the one that release declares (closes #196).

### A `musig()` participant with an origin keeps the leaf hashes of its plain key

`TrDescriptor`'s taproot derivations give a key that is a plain leaf key and a
`musig()` participant the leaf hashes of its plain leaves, whichever spelling
has the origin (closes #198).

### `join` refuses to change the lock time or tx version of a signed version 2 psbt

`join` refuses to change the lock time or the tx version of a version 2 psbt
with a signed input, whose signatures commit to both. It kept signatures that
no longer verified (closes #211).

### `Miniscript`'s duplicate-key and sanity checks are methods

`has_duplicate_keys`, `is_sane`, `is_sane_subexpression` and `insane_sub`
were properties. They are methods taking `prv_keys` (issue #199).

### The duplicate-key check derives a hardened step

A key with a hardened step is compared by the public key it derives where
the descriptor holds its private key, not by its extended key and path. A
key not derived is compared as written (closes #199) (closes #193).

### The release publishes the files the build job built

The publish jobs, `github-release` and `test.yml`'s `dist` job on a release
stop where the `dist` they download differs from the digests
`reusable-build.yml` outputs (issue #168).

### The verification command pins the tag for every signer

SECURITY.md and RELEASING.md said a release signed by `reusable-attest.yml`
took no `--source-ref`; it takes the tag (issue #168).

### The weekly vendored-vectors check compares bytes

`check_vendored_vectors.py` hashes each vendored file against the blob
`tests/_data/README.md` records, and that blob against upstream's at the
pinned commit, failing the run on a mismatch (issue #168).

### A non-mapping `prv_keys` is a `BTClibTypeError`

The methods taking `prv_keys` and `descriptors.normalized` check it as `parse`
does, where a string left as an `AttributeError`; a test finds every such
callable (closes #215).

### btclib 2026.10.4 and btclib-secp256k1 0.8.0.10 are the floors

They fix GHSA-9fr5-46w5-5f9r, which stalled `bip322.verify` on a crafted
tapscript witness, and GHSA-8h6f-34jj-7p6c, in `silentpayments.scan_outputs`.

### `sign` and `partial_sign` refuse a sig_hash type the caller did not allow

So does `SoftwareSigner.sign_psbt`: any type but ALL or DEFAULT needs
`allowed_sig_hash_types`, and a legacy SINGLE input past the last output is
never signed (GHSA-qq38-77mp-j6wr).

### `ecdsa_sig_hash` refuses a legacy SIGHASH_SINGLE past the last output

So does `PsbtView.ecdsa_sig_hash`: the hash is the constant 1, which no
allow-list makes signable (GHSA-qq38-77mp-j6wr).

### An input with no sig_hash type takes ECDSA signatures of SIGHASH_ALL alone

`finalize`, `assert_signed` and `assert_signatures_only`, which
`request_signatures` runs, refuse another type there (GHSA-qq38-77mp-j6wr).

### `sign` refuses an input without its `non_witness_utxo`

`Psbt.assert_signable`, `sign` and `SoftwareSigner.sign_psbt` refuse an input
without its `non_witness_utxo` unless every input is taproot and none asks for
ANYONECANPAY; `require_non_witness_utxo=False` accepts it (GHSA-v4gq-j2v2-c4jp).

## v2026.9.30

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

### `Bip21.parse` hands the amount to btclib as a `Decimal`

`amount=1.`, `amount=.5` and `amount=01` parse under a btclib carrying
btclib-org/btclib#2378, which refuses them as text. Too many decimals are
refused quoting `Decimal`'s `1E-9`, not the URI's `0.000000001` (closes #122).

### `bip85` names the path reader as what refuses too many sides or rolls

The comment above `_MIN_SIDES` names `indexes_from_der_path`, not
`str_from_index_int`, which neither value passes through, and the suite pins
the refusal of `2**31` sides or rolls (closes #123).

### The vendored psbt BIPs' pins move to upstream's tip

BIP375's tip adds an invalid vector, a wrong-length
`PSBT_OUT_SP_V0_LABEL` field, which `tests/psbt/bip375_test.py` now
refuses beside the other field-shape rules (closes #128).

### The pinned `btclib-org/.github` rev is allowlisted inline

detect-secrets reads the pinned sha as a secret, and the baseline recorded
only the previous one: a `# pragma: allowlist secret` on the `rev:` line
holds for any sha, and the stale entry goes.

### The curve arithmetic and the schemes are imported from `btclib_ecc` directly

`btclib.curves`, `btclib.ecc` less `bms`, `btclib.kdf` and `btclib.number_theory`
become `btclib_ecc`'s own modules; btclib's own floor moves to the release
binding its own objects, and `btclib-ecc` joins `dependencies` (closes #127).

### A `PSBT_IN_TAP_LEAF_SCRIPT` record with an odd leaf version is skipped

BIP341 makes a leaf version's low bit always 0; the Signer excludes such a
record from what it proves and what it signs, matching Bitcoin Core, rather
than raising or masking the bit away (closes #126).

### `[tool.uv]`'s floor rises to the `uv` `dependabot-core` bundles

`required-version` reads `>=0.12.19`, the pin in `dependabot-core`'s
`uv/Dockerfile`: the old floor admitted a `uv` older than the one the updater
writes `uv.lock` with (issue btclib-org/.github#1438).

### The mnemonic calls that leaked a builtin `TypeError` refuse as btclib

`bip39.seed_from_mnemonic`'s passphrase, `WordLists.index` and the other
calls the issue lists refuse a wrong type by the parameter's name (closes #134).

### A mnemonic `lang` of another type is refused as a type

`WordLists.load_lang`, which every function taking a `lang` reaches,
refuses one with a `BTClibTypeError`, and so does `dispatch`, which answered
`""` for it (closes #136).

### `bip85.mnemonic_from_root_key` refuses a `lang` of another type as a type

A hashable one was refused as an unnumbered language, and an unhashable one
left as a builtin `TypeError` from the table lookup (closes #138).

### A mnemonic refusal quotes no word, checksum, padding or hash prefix

An unknown word is named by its position, a word-list index out of range
is refused by its position, and the rest by what they are (closes #135,
closes #137).

### `RELEASING.md`'s bundle verification names the signer workflow

The `--bundle` form of *Verify the provenance of an asset* passes
`--signer-workflow "$signer"`, without which `gh attestation verify` refuses
a good release (issue btclib-org/.github#1446).

### An `addr()` argument is not echoed by btclib's bech32 refusals

From 2026.9.29, the floor `dependencies` holds, btclib's bech32 decoder quotes
nothing it refuses, so the `addr()` exception the `#49` entry makes no longer
holds: `descriptors.parse` does not repeat a key written there (closes #94).

### The bindings floor is the one btclib's `secp256k1` extra declares

`btclib-secp256k1`, named in the `secp256k1` extra and the `bindings` group,
takes btclib's `>=0.8.0.9` (closes #105).

### The mnemonic schemes are `btclib-mnemonics`', a new dependency

`btclib_wallet.mnemonic` keeps what builds a key from a BIP39, SLIP39 or
Electrum seed; the schemes up to the seed are `btclib_mnemonics`', and
no module here re-exports them (closes #30).

### A timeout is bounded by what a socket waits for on every platform

`transport.MAX_TIMEOUT`, the whole seconds within `INT_MAX` milliseconds,
bounds `valid_timeout`, where `threading.TIMEOUT_MAX` let through one a
Windows socket or a PyPy one refuses (closes #146).

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
