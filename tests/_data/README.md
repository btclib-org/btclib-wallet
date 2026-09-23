# Vendored test vectors

This file is about `tests/**/_data/`, plus the shipped data this package
holds that nothing else pins: `src/btclib_wallet/mnemonic/_data/wordlist.txt`,
SLIP-0039's word list, and `src/btclib_wallet/bolt9.py`, BOLT9's feature table
transcribed into python mappings. A word list is the most load-bearing
vendored file there is -- every share ever written with it decodes through
it -- and unlike `english.txt` it has no byte-identical copy under `tests/`
for an entry to name instead. The package's other word lists have no entry
because each is already pinned somewhere else or not at all:
`english.txt` through the test copy below, `electrum_old_english.txt` and
`electrum_portuguese.txt` through the pins
`src/btclib_wallet/mnemonic/electrum.py` carries beside the constants naming
them, and the other BIP39 lists nowhere, which is a gap rather than a
statement about them.

The files of `tests/**/_generated_files/` are the opposite kind of thing
and have no entry here: they are this package's own output, `to_dict()`
over fixed input, committed as golden files so that a change to a
serialized form fails a test instead of passing unnoticed. Nothing
upstream to pin, and nothing to compare against but ourselves.

This file follows btclib's own `tests/_data/README.md`, which the entries
below were taken from with the files they describe: an entry pins where a
file came from and whether our copy still matches it, and a test module
names its upstream and points here for the revision. A citation that
names the wrong upstream is corrected in the module; this file is not
where that correction lives.

## Naming

A vendored file carries the name its upstream publishes it under, wherever
upstream publishes a file at all. A name of our own has no upstream name
to be compared against, so the citation in the module that loads it can
drift to a path upstream never had and nobody catches it -- the byte
comparison below is the only check the naming cannot fool.

The files that keep a name of their own do so because there is no upstream
file whose name they could take, or because the upstream name is taken:

- `bip32_test_vectors.json`, `bip32_invalid_keys.json`,
  `bip174_test_vectors.json`, `bip370_test_vectors.json`,
  `bip371_test_vectors.json`, `bip373_test_vectors.json` and
  `bip85_test_vectors.json` are transcribed from mediawiki prose.
  `bip375_test_vectors.json` beside them is the exception that shows the
  rule holds: BIP375 does publish a file, and its name is that one.
- `bip39_test_vectors.json` is trezor's `vectors.json` byte for byte, and
  keeps a name of its own anyway: `vectors.json` is taken in the very same
  directory, by SLIP-0039's own file of that name.
- `descriptor_checksums.json` is composed from prose, and
  `electrum_test_vectors.json`, `electrum_language_vectors.json`,
  `btclib_test_vectors.json` and `fakeenglish.txt` are btclib's own: no
  upstream file for any of them, so no upstream name to take.
- the files under `tests/fetch/_data/` are response bodies, and a
  response has no name at all. Each takes the rpc method or the endpoint
  path that produces it.

The prefix of a psbt vector file names the authority the cases answer to
-- `bip174_`, `bip370_`, `bip371_`, `bip373_`, `bip375_`, and `btclib_`
for the ones btclib composed, which no BIP publishes and no refresh will
ever reach.

## Reading an entry

Where an entry pins to a commit, it gives the upstream repository, the
path in it, and the commit. A `blob` line, where the entry carries one,
gives the git blob SHA-1 of what that entry pins; what it pins, and
whether it was compared byte for byte, is the entry's own to say. Most
entries close on a verdict; one with nothing upstream to compare against
says so in prose instead. The verdicts used:

- **identical** -- our file and the upstream blob are the same bytes.
- **reformatted** -- same parsed JSON value, different whitespace.
- **transcribed** -- there is no file compared byte for byte. Over prose
  (a BIP, a BOLT) the check is that every value in our copy appears
  verbatim in the pinned text; over a source file the check is the
  entry's own to state.
- **composed locally**, **recorded** -- there is nothing upstream to
  compare, so the entry says what stands in for one. *composed locally*
  is a case written here, naming the third implementation that answered
  it; *recorded* is one reply a program gave, kept verbatim, naming the
  program and the calls that ask it again.

`pulled` is the date of the btclib commit that put the current content in
btclib's tree, from `git log --follow --diff-filter=A` there: the files
came here with the entries, unchanged. `behind` counts upstream revisions
of that path since the pin. It is a staleness figure, not a defect: a
vector file is a fixed set of cases and refreshing it is a decision, not a
chore. `ref` names the branch a pin's path lives on, where that is not the
repository's own default branch.

A vector this package fails is vendored anyway and marked `xfail`, never
left out: an absent vector hides the defect it would have shown, and
`xfail_strict` turns the marker red the day the defect is fixed.

## Re-checking a pin

The commit stands in a fence of its own, sitting inside the API path
rather than at the end of the command; the fence below reads it as
`${commit:?}`, the shell's must-be-set form, so a paste of that fence
alone fails naming the variable.

```shell
commit=<the pin the entry gives>
```

```shell
git hash-object tests/psbt/_data/bip375_test_vectors.json
gh api "repos/bitcoin/bips/git/trees/${commit:?}:bip-0375" \
    --jq '.tree[] | select(.path == "bip375_test_vectors.json") | .sha'
```

The comparison is on git blob SHA-1, not sha256: it is what a tree entry
already carries, so nothing has to be downloaded, and `git hash-object`
reproduces it locally.

## bitcoin/bips

### `tests/mnemonic/_data/english.txt`

```text
repo    bitcoin/bips
path    bip-0039/english.txt
commit  ce1862ac6bcffa1dd20aad858380e51e66e949ea  2014-02-07
blob    942040ed50f7205cafc465496229128ba4f78e75
pulled  2018-06-01
behind  0 revisions; that commit is the only one to touch the path
```

Verdict: **identical**. The BIP39 English wordlist has never been
changed, so this is the one pin that cannot go stale.

### `tests/_data/send_and_receive_test_vectors.json`

```text
repo    bitcoin/bips
path    bip-0352/send_and_receive_test_vectors.json
commit  c2ac36f48f71615984087fd151f410457edfed72  2026-04-16
blob    3a189757ddbc90e5ec538d643f7ac238a51704e8
pulled  2026-08-13
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. All 28 cases, both halves of each: one sending
sub-test and one receiving sub-test per case, except "use silent payments
for sender change", which has two receiving sub-tests -- the change output
and the payment.

The revision matters more here than the pin usually does. This file used
to publish the inputs and the final outputs and nothing between, and the
2026 revision added `input_private_key_sum`, `shared_secrets`, `tweak` and
`input_pub_key_sum`: an implementation can now be held to the value at
each step rather than told that its output was wrong.
`tests/silent_payments_test.py` asserts every one of them, which is why an
outpoint sorted wrongly, a missed taproot negation and a wrong label are
three different failures there instead of one.

Two of the 28 publish a null where a value would be: the sending half of
"input keys sum up to zero" has no private key sum, and the K_MAX case has
a sum and then a null shared secret, sending having failed before one was
derived. Both are the file saying that the step was never reached, and the
test reads them that way.

The K_MAX case is the largest by far and worth naming: 2324 recipients
sharing one scan key, which is one more than BIP352 allows, so sending
fails and the receiving half finds 2323 of the 2324 outputs -- the file
counting them with `n_outputs` rather than listing them, and it is the
only case that does.

Three BIP352 rules have no vector here and are covered by the test module
instead: the address versions (v31 refused, v1 through v30 read as far as
v0 defines them), the 1023-character bound, and the label range. The
vectors are all v0 addresses on mainnet.

### `tests/bip32/_data/bip32_test_vectors.json`

```text
repo    bitcoin/bips
path    bip-0032.mediawiki
commit  c0644a054fd1568ecbfc9c2b656ad5200b16ff74  2026-03-05
pulled  2020-05-08, vector 4 added 2021-08-25, re-pinned to the tip 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**. BIP32 ships its vectors as prose, so there is
no upstream file and no byte comparison to make. All four seeds and all
34 extended keys of test vectors 1 to 4 appear verbatim in the pinned
text, and the derivation counts match: 6, 6, 2, 3.

The original pin was the commit that *added* test vector 4 rather than
the one current when btclib transcribed it: the earliest revision
holding all 34 keys, the parent holding 28, which made that pin checkable
rather than merely plausible. Re-checked against the tip on 2026-07-30
and again on 2026-08-06 — both times still test vectors 1 to 5 and no
sixth, every extended key in it one of ours, 48 matching the key
pattern: our 34 valid plus 14 of the 16 invalid, the other 2 being the
zero-prefix keys of test vector 5, which serialize outside it — the pin
above is now that tip, so the weekly automated check can carry it.

### `tests/bip32/_data/bip32_invalid_keys.json`

```text
repo    bitcoin/bips
path    bip-0032.mediawiki
commit  c0644a054fd1568ecbfc9c2b656ad5200b16ff74  2026-03-05
pulled  2020-05-16, error strings last changed 2026-07-30, re-pinned to
        the tip 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**. All 16 invalid extended keys are exactly the 16
of BIP32 test vector 5 — no omissions, no local additions — both at the
pinned commit and on master today.

btclib is the upstream here, not the consumer: commit ee2e0598, "added
invalid extended keys vectors", is Ferdinando Ametrano's, and is what
first put these 16 keys into the BIP. The pin above is the tip of the
same path rather than that commit, so the weekly automated check can
carry it too; the second column of the file is btclib's own regardless —
it holds btclib error messages, which the BIP does not and should not
carry, and which change when the messages change. Refreshing from
upstream means refreshing the keys, never the messages.

### `tests/psbt/_data/bip174_test_vectors.json`

```text
repo    bitcoin/bips
path    bip-0174.mediawiki
commit  8c369ac8e60629ac6c032ffe21bb5ec5b35213d7  2026-07-16
pulled  2020-11-15, extended 2021-08-03, refreshed 2026-07-30
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, complete for the cases. The BIP's Test Vectors
section is 34 `* Case:` entries — 20 invalid, 10 valid, 4 signer check
failures — and all 34 are here, each with the base64 the prose gives and
cross-checked against the hex the prose gives beside it. What is not
vendored, deliberately, is the role walk-through: the creator, updater,
signer, combiner, finalizer and extractor psbts of the worked example,
which are prose steps rather than cases. Five of them are the raw
material of `btclib_test_vectors.json` below, which is a different claim:
not that they are cases, but that a case can be built out of one.

The `description` and `encoded psbt` of each entry are upstream's. The
`error message` of a signer check failure is **not**: the BIP says only
that these four psbts must fail the check, so that field is btclib's own
expectation of btclib's own message, and correcting a message means
correcting it here too.

### `tests/psbt/_data/bip371_test_vectors.json`

```text
repo    bitcoin/bips
path    bip-0371.mediawiki
commit  24e96e870fffaa257b465ce1f0370c14aac588e8  2026-01-12
pulled  2023-07-07, re-pinned to the tip 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, complete. All 17 psbts in the pinned text are
in our file and all 17 of ours are in the text — 11 invalid, 6 valid, the
same 17 on 2026-07-30 and again on 2026-08-06 when re-checked against the
tip. The two "PSBT_KEY_PATH_SIG" cases were renamed
"PSBT_IN_TAP_KEY_SIG" between the original pin and the tip, matching the
field's own name; the `description` of both is updated to match, the
`encoded psbt` of every case unchanged throughout.

### `tests/psbt/_data/bip370_test_vectors.json`

```text
repo    bitcoin/bips
path    bip-0370.mediawiki
commit  e3874ca825bcd2d0975ffaffb97f1194b3661ad6  2026-04-07
pulled  2026-08-03
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, complete. Every psbt of the Test Vectors
section is here: 24 invalid, 14 valid, and the 10 of the timelock
determination algorithm, which keep the value that algorithm must
compute beside them — `null` for the one whose two kinds of locktime
cannot be reconciled. 48 base64 strings for 47 cases, one valid case
publishing two serializations of itself.

The base64 was taken and the hex checked against it, `b64decode(base64)
== bytes.fromhex(hex)` for all of them but one: the "1 input, 2 output
updated PSBTv2" case spells its label `Bytes in HEx`, so the pair cannot
be found by the name the other 46 use. A refresh should read the labels
case-insensitively rather than trust the count.

The `error message` of an invalid case is btclib's own, as in the two
files above, and here each names what the BIP says is wrong with the
case: half of the 24 are a version 0 psbt carrying one of BIP370's
twelve fields, refused by the name of the field, and the other half are
version 2 psbts refused for the unsigned transaction version 2 excludes,
for one of the seven fields it requires, or for a required locktime
outside the range that makes it one kind of locktime.

The valid ones are read and written back byte for byte, and the ten
locktime cases are asserted against the value the algorithm publishes
for each — the `null` one by the refusal it gets, its two kinds of
locktime having no single `nLockTime` to agree on.

### `tests/psbt/_data/bip373_test_vectors.json`

```text
repo    bitcoin/bips
path    bip-0373.mediawiki
commit  24e96e870fffaa257b465ce1f0370c14aac588e8  2026-01-12
pulled  2026-08-03
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, complete. Every psbt of the Test Vectors
section is here: 10 invalid and 14 valid, the valid ones being four
spend cases in three variants each — participant pubkeys only, then the
pubnonces, then the partial signatures — and two receiving cases, which
are the ones carrying the output field. The base64 was taken and the hex
checked against it, `b64decode(base64) == bytes.fromhex(hex)` for all
24.

Two of the ten invalid psbts are **the same bytes**: "PSBT with x-only
aggregate pubkey in output participant pubkeys keydata" and "PSBT with an
x-only output participant pubkey" both carry the x-only key in the key
data, so the second condition — an x-only key inside the value, which the
input pair does distinguish — is named upstream and carried by nothing.
Both are vendored as published, duplicate included, and
`test_an_output_participant_list_is_a_whole_number_of_keys` is the case
they do not make: the same shortening applied to the output map of the
BIP's own receiving psbt.

The `error message` of an invalid case is btclib's own, as in the three
files above. Each of the ten is a length — an x-only key where BIP373
requires a compressed one, or a nonce or partial signature whose value is
the wrong size — so a length is what each message names. Nothing here
pins the check Bitcoin Core makes beyond the length, `IsFullyValid` on
every key of every one of these fields: no vector of the BIP carries a
key of the right size that is on no curve, and
`test_a_musig2_key_must_be_a_point_and_not_merely_33_bytes` is where that
one is.

### `tests/psbt/_data/bip375_test_vectors.json`

```text
repo    bitcoin/bips
path    bip-0375/bip375_test_vectors.json
commit  e726d13ade44e2184635935c84a83d4082da3a63  2026-08-13
blob    38511f65b4f100c4f56ac12371ebe4d8888f1e0d
pulled  2026-08-25
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical** -- upstream's file ends on a newline after its
closing brace, so `end-of-file-fixer` leaves it untouched as it is staged
and our blob matches the one above. `script_assets_test.json` and
`vectors.json` are the files that still document the "identical but for a
trailing newline" exception.

The only psbt vector file here that has an upstream file at all -- the
other five are transcribed from mediawiki prose -- so the `bip375_` prefix
is upstream's own name and this repository's naming rule at once, which is
the one place the two coincide. 42 psbts, 22 invalid and 20 valid, the
valid ones split between "can finalize" and "in progress".

Each case carries a `supplementary` object of private keys, public keys
and prevouts, and upstream's own notes say it is "for diagnostics and
should not be used for validation". `tests/psbt/bip375_test.py` does not
read it: what it reads is the psbt, and what it compares each field
against is the raw map entry the field came out of.

**Not compared byte for byte**, unlike every other psbt vector here, and
the reason is the file rather than btclib: the generator that produced it
writes the keys of a map in an order of its own -- PSBT_GLOBAL_VERSION
first where BIP370's psbts put it last, and an input map's outpoint fields
ahead of the rest -- while a psbt map has no normative order at all,
BIP174 requiring only that a key not repeat. So the comparison is one
level up: the maps read out of upstream's bytes and the maps read out of
btclib's hold the same set of pairs, and btclib's own bytes are stable
under a second parse. Measured on all 37 psbts that parse.

All 22 invalid psbts are refused and all 20 valid ones pass, and it takes
two test modules to say so: `tests/psbt/bip375_test.py` holds the codec to
the file -- the field shapes, which is five of the six "PSBT Structure"
cases -- and `tests/psbt/silent_payments_test.py` holds the two roles to
it, which is the other seventeen. Each invalid case's category is read off
its own description, so a psbt refused by the wrong check fails there
rather than counting as a pass; a valid case can carry a `checks` field of
its own instead, naming the one check it isolates itself to -- one case
does, "input eligibility: bare OP_2 script is not a segwit v2 witness
program".

**The file and the BIP disagree about one rule, and the file wins here.**
BIP375 says the codes of one scan key are sorted lexicographically to
determine the ordering of `k`; the vectors' output scripts are the ones
*output index* order derives. The case that decides it is published as
valid -- "two sp outputs - output 0 uses label=3 / output 1 uses label=1"
-- and its two spend keys are in descending order, so the two rules assign
`k` the other way round and only one of them reproduces the scripts the
file carries. Neither reading of "the codes" rescues the prose: sorting
the 66-byte info fields and sorting the bech32m address strings both order
that pair the same wrong way. Upstream's own
`bip-0375/validator/validate_psbt.py` walks index order too, so two of its
three artefacts agree and the prose is the outlier.
`test_the_k_ordering_is_the_output_index` pins that in both directions, so
a revision settling it the other way fails rather than passing quietly.

### BIP322 (signed messages): files under `tests/_data/`

The files of `bip-0322/`, vendored whole and under upstream's own
names: `basic-test-vectors.json` and `generated-test-vectors.json`. One
commit added both and one has touched them since — `3ab70c98`
(2026-04-10, "BIP-0322: turn test vectors into JSON, add more") and
`d77863fb` (2026-05-06, "BIP-0322: update test vectors"), which is the
tip of both paths — and each is pinned below in its own entry all the
same, a shared placeholder path being what kept the BIP327 files out of
the weekly check.

Between them they are what `tests/bip322_test.py` runs: three
transaction hashes, eight *simple* signatures, ten *full*, three
*proof of funds*, and 36 error cases, with nothing left out and nothing
marked `xfail`. Two of the three proof-of-funds vectors were, until
issue btclib-org/btclib#513: their psbts carry a funding transaction
whose input is a null tx_id with vout 0, which `OutPoint.assert_valid`
refused and Bitcoin Core's `CheckTransaction` accepts.

### `tests/_data/basic-test-vectors.json`

```text
repo    bitcoin/bips
path    bip-0322/basic-test-vectors.json
commit  d77863fb9e9be7829ad8bb51694b9ba80a786766  2026-05-06
blob    f32a5bf45ae8b19ca33d0763669f5718879c82f4
pulled  2026-08-08
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for the final newline** — upstream ends without
one and `end-of-file-fixer` adds it, so our blob is `2aefe430` rather
than the one above. The same case as `bip340_test_vectors.csv` and its
line endings: a hook that fixes in place makes the byte comparison
disagree in a way the entry has to record rather than hide.

The file is UTF-8 rather than ASCII, one of its three messages running
from Latin-1 accents through CJK to an astral-plane emoji, and
`tests/__init__.py`'s `load` is asked for that encoding.

### `tests/_data/generated-test-vectors.json`

```text
repo    bitcoin/bips
path    bip-0322/generated-test-vectors.json
commit  d77863fb9e9be7829ad8bb51694b9ba80a786766  2026-05-06
blob    4677eea4544b9fef4814c85640ff109a4d887264
pulled  2026-08-08
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for the final newline**, as above: our blob is
`1c061893`. Generated by
[btcd's BIP322 implementation](https://github.com/btcsuite/btcd/pull/2521),
which the BIP names as their source.

### `tests/_data/bip85_test_vectors.json`

```text
repo    bitcoin/bips
path    bip-0085.mediawiki
commit  6209768676bf85d7ef5ffb4055543d6286d79b96  2026-08-03
pulled  2026-08-25
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, complete. Every value in our copy appears
verbatim in the pinned text, and every vector the BIP publishes is in
our copy: the master root key, the two entropy cases of the
specification's own section with the derived key of each, the 80-byte
BIP85-DRNG read, the three BIP39 mnemonics, the hdseed WIF, the xprv,
the 64 hex bytes, the base64 and base85 passwords, the ten dice rolls,
and the three Nostr nsecs of application 128002'. `tests/bip85_test.py`
runs all of them.

RSA (828365') is the one application with no vector here, because the
BIP publishes none for it: it defines the path and says the key
generator should read BIP85-DRNG, leaving how the primes are found to
whatever library generates the key. `btclib_wallet.bip85` stops at the same
place, so there is nothing further to compare against.

Two of the BIP's fields are not what their name reads as, and
`tests/bip85_test.py` asserts them as the BIP prints them rather than as
the name reads: the DERIVED ENTROPY of application 32' is the second half
of the 64 bytes, the private key of the xprv, and that of 39' is already
truncated to what the sentence encodes.

### Not vendored as a file: BIP387's `multi_a()` vectors

```text
repo    bitcoin/bips
path    bip-0387.mediawiki
commit  24e96e870fffaa257b465ce1f0370c14aac588e8  2026-01-12
pulled  2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, and cited inline rather than vendored: they are
descriptors and scripts read where they are used, in
`tests/descriptors/descriptors_test.py`'s `BIP387_VECTORS` and
`BIP387_INVALID`. Every descriptor of the BIP's Test Vectors section is
there with the scriptPubKey it produces, at each index the BIP lists, and
every invalid one with the message btclib refuses it with — two of those
refusals answering the uncompressed key before the threshold the BIP was
illustrating, which the entries say. Each value was matched against the
pinned text on 2026-08-06.

### Not vendored as a file: BIP390's `musig()` vectors

```text
repo    bitcoin/bips
path    bip-0390.mediawiki
commit  7517a8b2ac8fdb13e586d0e139a7f5b87ceab994  2026-08-06
pulled  2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, complete for both lists and cited inline, in
`tests/descriptors/descriptors_test.py`'s `BIP390_VECTORS` and
`BIP390_INVALID`: the six valid descriptors with the scripts they produce
at each index listed, and all fourteen invalid ones with the message each
is refused with. Five further invalid cases there are btclib's own, for
what the BIP states in prose rather than listing — no nesting, no key
origin in front of one, at least one participant, no x-only participant,
and a `musig()` where a tree leaf belongs.

The pin is the tip and it is the day it was taken: that commit is
`bip390: fix missing parenthesis in test vector`, which closed the last
invalid descriptor's brackets, so a copy taken a day earlier would hold a
descriptor upstream no longer publishes. Ours is the fixed one.

One of the fourteen is refused for a reason of btclib's own rather than
the BIP's, and the entry in the module says so: a multipath `musig()`
holding multipath participants is refused because `parse` takes no `<a;b>`
step at all, `multipath_descriptors` being what expands them textually as
BIP389 defines.

### Not vendored as a file: BIP388's wallet-policy vectors

```text
repo    bitcoin/bips
path    bip-0388.mediawiki
commit  cfff9719405fa35113cab637958809824873750f  2026-04-15
pulled  2026-09-02
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, complete and cited inline in
`tests/descriptors/descriptors_test.py`'s `BIP388_VECTORS`: every valid
policy of the Test Vectors section, its template, its key-information
vector and the multipath descriptor the two compile to, checked branch by
branch against `wallet_policy_descriptor` and `wallet_policy_address`
rather than restated as an address of its own -- `multipath_descriptors`
and `parse` already answer for what a branch of that descriptor is. The
same vectors are read the other way too, in
`test_wallet_policy_reconstructs_bip388s_own_vectors`: `wallet_policy`,
given the receive and change `Descriptor` `multipath_descriptors` splits
that same descriptor into, rebuilds the vector's own template and
key-information vector, byte for byte. Four
of the Invalid policies section's nine are checked too, in
`test_bip388_invalid_templates`: the no-path, explicit-path,
cardinality-above-two and derivation-before-aggregation ones, each a
property of the template text alone. The other five are not:
out-of-order and skipped placeholders are a canonicalization
`wallet_policy_descriptor` does not need to enforce to compute one
address correctly; repeated keys and non-disjoint multipath steps for the
same placeholder need the two occurrences compared against each other,
which nothing here does across an `re.subn` callback; and a non-KP key
present in a template position is refused anyway, but by `parse`'s own
"use multipath_descriptors first" -- a coincidence of the raw `<0;1>`
text reaching it unconsumed, not a check this module makes. That one is
in the module too, as what it is.

### Not vendored as a file: BIP328's synthetic xpub vectors

```text
repo    bitcoin/bips
path    bip-0328.mediawiki
commit  24e96e870fffaa257b465ce1f0370c14aac588e8  2026-01-12
pulled  2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, complete: all three aggregate keys, the
synthetic xpub each becomes and the participant keys each aggregates, in
`tests/bip32/bip32_test.py`'s `BIP328_VECTORS`. The keys of those vectors
aggregate **as written**, unsorted, which is what makes them worth holding
beside BIP390's: sorting before aggregation is BIP390's rule and not
BIP328's, and a `key_sort` applied here reaches none of the three
published keys. Matched against the pinned text on 2026-08-06.

### `tests/ecc/_data/bip445/sign_verify_vectors.json`

The one BIP445 file this package reads: `tests/psbt/frost_test.py` takes
its group of participants from it. btclib vendors the BIP445 files whole,
and its entry for them says why they sit in a subdirectory and why each
carries a `ref`: the BIP is a draft, `bitcoin/bips#2070`, whose path lives
on the pull request's own branch rather than on `bitcoin/bips`' default.

```text
repo    siv2r/bips
path    bip-0445/python/vectors/sign_verify_vectors.json
ref     bip-frost-signing
commit  8e25d57911c33f1daadcadb0161a60a56ef7145a  2026-08-26
blob    622d859bcd742e9caf37e1541bf2409aa7c6c333
pulled  2026-09-17
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for a trailing newline** -- our blob is that one
plus the `\n` the `end-of-file-fixer` hook added, so our blob is
`ead53ab1`.

## bitcoin/bitcoin

### `tests/_data/descriptor_checksums.json`

```text
repo    bitcoin/bitcoin
path    doc/descriptors.md
commit  0f38524c31da4cf69d8e904569fe56292e4325b9  2022-10-30
pulled  2023-07-12
```

Verdict: **composed locally**, not vendored. Descriptors appear
verbatim in the pinned document; none of their checksums does, because
Core's document does not list them. They were computed with a third
implementation, `bdk`'s `descriptor::checksum::get_checksum`, as
`tests/descriptors/descriptors_test.py` records — which is the point of
the file: the checksums are an independent oracle, so recomputing them
with btclib would void the test.

Nothing to refresh from upstream. A new descriptor needs a checksum from
somewhere other than btclib.

Checked again on 2026-07-30, against the current document rather than the
pin: ours are still all in it, and it still carries no checksum at
all — not one `descriptor#checksum` pair in the file. It has grown
concrete descriptors we do not hold (a `tr(musig(...))`, a
`wsh(sortedmulti(...))` and a `wsh(thresh(...))`, the rest of what it shows
being syntax templates like `sh(SCRIPT)`), and each would need a checksum
computed by something that is not btclib. That is a decision to take with
a tool at hand, not a refresh.

### `tests/_data/miniscript_fixed_tests.json`

```text
repo    bitcoin/bitcoin
path    src/test/miniscript_tests.cpp
commit  e8691056c0140f8fa850fc6837dde915ebeb22cc  2026-08-03
blob    d593fc3bf813ac27dce422d596ae9bf4b8b9e777
pulled  2026-08-25
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, mechanically. One json object per `Test()` call
of the `fixed_tests` case, with the fields that call passes: the
miniscript, the script it compiles to under P2WSH and under tapscript, the
`TESTMODE_*` flags split into booleans, and the ops, stack, witness-size
and execution-stack numbers where the call gives them. The regex that
produced it is not committed -- a one-off pass over C++ source is not a
tool -- and what re-derives the file is reading those calls again.

The pin between here and the commit this file was previously pinned to
(`128456b62d5e`) touches none of those calls: every changed line is
`BOOST_CHECK(a && b && c)` split into one `BOOST_REQUIRE`/`BOOST_CHECK` per
condition, inside the "Misc unit tests" block below `fixed_tests`'s own
vectors, not inside a `Test(...)` call. The vendored JSON is unchanged.

Not vendored as the file itself because there is no data file upstream:
the vectors are arguments to a C++ function. The blob above is that source
file, so the weekly re-check still reports a case added to it.

Four of the calls are not here, being loops rather than literals: the
`multi_a()` of twenty-one keys, the three `and_b()` chains that pass the
p2wsh ops, stack and script-size limits, and the two nestings that reach a
thousand elements on the stack. `tests/descriptors/miniscript_test.py`
builds those from Core's own key set instead, and asserts the same
formulas its calls pass -- which is why they are missing here rather than
untested.

Also not here: `random_tests`, which generates expressions from a seeded
RNG and checks the satisfier against the script interpreter. Satisfaction
is not implemented (issue btclib-org/btclib#187), so there is nothing yet
for those to measure.

### Not vendored as a file: Core's descriptor derivation vectors

```text
repo    bitcoin/bitcoin
path    src/test/descriptor_tests.cpp
commit  51ddab532cb38213e2258c24c492bc8a392ffc90  2026-09-14
pulled  2026-09-21, rawtr() added 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, a subset by design.
`tests/descriptors/descriptors_test.py` holds the `Check(prv, pub, ...)`
cases of the `descriptor_test` case as `CORE_VECTORS` — the descriptor in
both spellings and the scriptPubKey each expands to, at every index the
case lists — plus the public spellings of those Core expands from the
private form alone, which are `HARDENED_PUBLIC` there, and the `rawtr()`
cases, which no BIP publishes and only this file has.

Not vendored as a file because there is no file: the values are literals
in C++ source, so a copy of it would be a copy of a test program. What
this pin buys instead is the upstream re-check: a case added to that
function moves the commit, and the weekly run says so.

The subset is deliberate and is what a refresh would revisit: Core's file
also holds `CheckUnparsable` cases, which this module has as `UNPARSABLE`
with btclib's own messages, and `musig()` cases. Those BIP390 publishes
are transcribed from the BIP itself above rather than from here; those it
does not -- `rawtr(musig(...))` among them -- are transcribed from
neither. Matched against the file as it stood on 2026-08-06.

The cases upstream added after that comparison are not here, and
[ISS 1334](https://github.com/btclib-org/btclib/issues/1334) is where
they were weighed: it measured btclib against both defects they cover --
a `musig()` duplicate-key check that reads distinct participants as the
same key when neither of them derives, and a key origin prepended once
per expression rather than once per participant -- and found neither in
this tree, so none of those cases is owed here.

The revision this refresh crosses is bitcoin/bitcoin#35819, *test: add
coverage for untested descriptor parse error paths*: new lines, almost
all new `CheckUnparsable` cases -- already outside the transcribed
subset for the reason above -- and one new `Check(...)`-shaped case
asserting that a taptree of exactly 128 nesting levels parses.
`CORE_VECTORS` gains nothing from it.

## bitcoin-core/HWI

Nothing is vendored from HWI and nothing is imported from it: `btclib_wallet.hwi`
runs its JSON command line as a subprocess, which is what keeps its
`hidapi`, `libusb1`, `cbor2`, `pyserial`, `noiseprotocol` and `protobuf`
out of btclib's dependencies. What is pinned here is therefore not a file
but an *interface*, and the two entries are the two halves of it: the
commands and flags a caller sends, and the numbers it gets back.

Which makes these pins do something the others do not. A vector file is
refreshed or it is not; an interface that moves is code here that stops
working against the next release somebody installs — so the weekly
re-check is the alignment, and `tests/hwi_test.py` carries the
transcription it is checked against.

Both pins are read against `master`, and
`.github/workflows/integration-hwi.yml` installs the release its
`HWI_VERSION` names, so two interfaces are in play and each entry below
says what the release does not carry. `tests/hwi_test.py` answers from a
stand-in it writes itself and is green against either; the weekly jobs
are what run the release.

### Not vendored as a file: the commands and flags of HWI's JSON CLI

```text
repo    bitcoin-core/HWI
path    hwilib/_cli.py
commit  6f44e48980bf610a57195f43a74027f4dc20e385  2026-08-24
pulled  2026-09-02
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, and a subset by design. `tests/hwi_test.py`
holds the commands `btclib_wallet.hwi` runs — `enumerate`, `getxpub`,
`signtx`, `signmessage`, `displayaddress`, `registerdescriptor` — with
the positional arguments of each, the global flags it passes
(`--chain`, `--fingerprint`, `--emulators`), the `--desc` of
`displayaddress`, the chains `--chain` takes, and the keys read out of
each answer. Not every chain it transcribes is one btclib sends:
testnet4 goes out as `test`, and `btclib_wallet.hwi`'s `_HWI_CHAIN` says why.

What the parser declares and `btclib_wallet.hwi` leaves alone, under the reason
each is left alone for. `setup`, `wipe`, `restore`, `backup`,
`promptpin`, `togglepassphrase` and `sendpin` are the device lifecycle,
which issue btclib-org/btclib#381 keeps out of the signing surface deliberately.
`getdescriptors`, `getkeypool` and `getmasterxpub` are what btclib
computes for itself, on its own types, in
`descriptors.account_descriptors` and `btclib_wallet.core_import`.
`installudevrules` talks to no device -- it copies HWI's udev rules onto
the host -- and it is the one subcommand of the pin above that the
parser registers behind a platform guard,
`sys.platform.startswith("linux")`.

`displayaddress`'s BIP388 policy mode -- `--registration`, `--index`,
`--multipath-index` -- is `HwiSigner.display_policy_address`
(`btclib_wallet.hwi`'s module docstring, "Wallet policies", issue
btclib-org/btclib#1588), and
`psbt_signer.WalletPolicyAddressDisplay`/`display_policy_address` are
the protocol and the check beside `AddressDisplay`/`display_address`:
`descriptors.wallet_policy_address` computes the address a policy
describes at an index and a multipath index, and `display_policy_address`
compares it with what the device answers. Its own argv is checked in
`tests/hwi_test.py` directly rather than through the shared
`HWI_COMMAND_FLAGS` table above, `displayaddress`'s two modes taking
disjoint flags.

Not transcribed on purpose: `--change`, `displayaddress`'s alias for
`--multipath-index 1` -- `HwiSigner.display_policy_address` always
sends `--multipath-index` and never reaches for the alias -- and
`--registration` on `signtx`, which nothing here sends: a registration
travels with `displayaddress`'s policy mode only, and `signtx`'s answer
keys (`psbt`, `signed`) are unaffected by one being passed alongside
the transaction regardless.

Not in a release: `registerdescriptor` and its `registration` answer
key, and the BIP388 policy arguments named above -- `--index`,
`--multipath-index`/`--change`, and `--registration` on either command.
All of them entered upstream in 2026-08, after 3.2.0 shipped, so the
weekly jobs cannot reach `HwiSigner.register_descriptor` at all and
would refuse those flags. Raising `HWI_VERSION` to the first release
whose `hwilib/_cli.py` adds them is what makes the two interfaces one.

The parser has only ever grown, and only additively, since 2021:
`--emulators` in 2024, `--chain` and `--expert` on enumerate in 2022,
`registerdescriptor` and the BIP388 policy arguments on `displayaddress`
in 2026-08, and `--registration` on `signtx` in this pin. `signtx`
gained a second answer key, `signed`, in 2021 — which is how this pin
earned itself: btclib read only `psbt` until the surface was written
down, and now checks the two against each other.

### Not vendored as a file: HWI's error codes

```text
repo    bitcoin-core/HWI
path    hwilib/errors.py
commit  bbbc8a65db960bcd08be63362657dfcac72359dd  2026-08-20
pulled  2026-09-02
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**. The pin now carries the same commit
`INVALID_POLICY` (-19) had already been checked in from ahead of, and the
`UNKNWON_DEVICE_TYPE` misspelling this commit fixes upstream — keeping
the old name as a compat alias with the same code, -4 — is why
`tests/hwi_test.py`'s table now reads `UNKNOWN_DEVICE_TYPE`;
`pyproject.toml`'s typos exception for the old spelling stays, for
`CHANGELOG.md`'s own narration of it. Every number `master` defines,
under the name it gives, in `tests/hwi_test.py`, and one test per number
that a `{"error": …, "code": …}` answer arrives as an
`exceptions.SignerError` carrying it. The numbers are what a caller acts
on — -14 is somebody pressing the button that says no, -3 is a cable, -9
is a model that will never do it — so an adapter that dropped them would
leave a caller matching on the text of a message.

Not in a release: `INVALID_POLICY` (-19). The rest of the table is in
3.2.0, where -4 carries the misspelling this pin's commit corrects — a
name that differs and a number that does not, and the number is what
`tests/hwi_test.py` asserts on.

## Other projects

### `tests/mnemonic/_data/bip39_test_vectors.json`

```text
repo    trezor/python-mnemonic
path    vectors.json
commit  b57a5ad77a981e743f4167ab2f7927a55c1e82a8  2024-08-27
blob    d362a5d4eb1ba800a52aec30116915cd4576e1fd
pulled  2018-06-01, refreshed 2026-08-02
behind  0 revisions
```

Verdict: **identical**. All twelve language arrays, in order and value
for value, at the indentation upstream writes them with, so
`git hash-object` on our copy answers the blob id above and a refresh is
the fetch itself:

```shell
gh api -H 'Accept: application/vnd.github.raw' \
    '/repos/trezor/python-mnemonic/contents/vectors.json?ref=master' \
    > tests/mnemonic/_data/bip39_test_vectors.json
```

Upstream generates the file with its own `tools/generate_vectors.py`
rather than maintaining it by hand, which is what makes that one command
the whole of a refresh -- and why nothing of btclib's is inside it. The
one case that is ours, the last English vector with tabs, newlines,
doubled spaces and a form feed through the mnemonic, is a `pytest.param`
in `tests/mnemonic/bip39_test.py` beside the ones the file feeds: in the
array it would have to be re-added by hand at every refresh, and would
go missing the once nobody remembered.

Two `pulled` dates because the `english` array was here on its own for
as long as english was the only BIP39 language btclib read; that array
has not changed in any revision, so the earlier pull and this one hold
the same file for it, and `behind 0 revisions` is now about the whole of
the file rather than about one array of it.

The name is btclib's rather than upstream's, which the naming rule above
allows for one reason and this is it: `vectors.json` is taken in this
very directory, by SLIP-0039's own file of that name, which is a
different upstream's. The blob id is what checks the file behind the
name.

### `tests/mnemonic/_data/test_JP_BIP39.json`

```text
repo    bip32JP/bip32JP.github.io
path    test_JP_BIP39.json
commit  360c05a6439e5c461bbe5e84c7567ec38eb4ac5f  2017-08-20
blob    6d8c40b19e5d4b899f9f3c2addbf994d150b245b
pulled  2026-08-02
behind  0 revisions
```

Verdict: **reformatted**. 24 vectors, JSON-equal; upstream's indentation
wanders by a space or two and ours is what `json.dumps(indent=4)` writes.

bip-0039 cites this file by URL in its own Test vectors section, beside
the reference implementation's, for the case that file does not cover:
"Japanese wordlist test with heavily normalized symbols as passphrase".
The passphrase is one string in NFC and another in NFKD, and the
sentences are published composed against word-lists published
decomposed, so these are the vectors that fail when normalisation is
skipped anywhere.

### `tests/mnemonic/_data/electrum_language_vectors.json`

btclib's own, and the second file here cross-checked against an
application rather than copied from a project. Electrum's `make_seed`
run with `randrange` patched to a constant, once per language, which is
the same starting point `mnemonic_from_entropy` takes: what it returned
is the mnemonic, and `mnemonic_to_seed` of it is the seed. Electrum
publishes no vector of that kind — its own `SEED_TEST_CASES` are
sentences to read, not entropies to generate from — so there is nothing
upstream to pin or to refresh against; regenerate them from electrum's
`mnemonic.py` if they are ever doubted.

The two Portuguese sentences beside them answer electrum's
`bip39_is_checksum_valid` yes and no, over its own 1626-word list.

In a file rather than inline like every other electrum vector in
`tests/mnemonic/electrum_test.py`, and the reason is this directory: the
lint gate's two spell checkers read a python source and skip `_data`, and
`typos` runs with `--write-changes`. Measured, it corrected a word of the
Portuguese sentence into the English word it is one letter away from.

Pulled 2026-08-02.

### `src/btclib_wallet/mnemonic/_data/wordlist.txt`

```text
repo    satoshilabs/slips
path    slip-0039/wordlist.txt
commit  1524583213f1392321109b0ff0a91330836ecb32  2019-03-02
blob    5673e7ca7f20ed7a5e70b3a7fa5e6df277ee29ab
pulled  2026-08-02
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. SLIP-0039's 1024 words, ten bits each, and the
only word list it defines: the SLIP supports no localization, so there
is no second language to leave out and no decision behind shipping one.

`tests/mnemonic/slip39_test.py` re-checks the criteria the SLIP states
for the list -- 1024 words, none shorter than four letters or longer
than eight, and all 1024 four-letter prefixes distinct -- which is what
turns a corrupted copy into a red test rather than into shares nobody
can read. Not the whole of `slip-0039/test_wordlist.sh`, which also
measures Damerau-Levenshtein distance: that is a property of the list
upstream chose, not of our copy of it.

### `tests/mnemonic/_data/vectors.json`

```text
repo    trezor/python-shamir-mnemonic
path    vectors.json
commit  1525df19df504b1f69b49179140119959f317f24  2024-05-14
blob    d98c387aa1feb32ca9e6e4410cff870dfc6fb358
pulled  2026-08-02
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for a trailing newline** -- our 22,412 bytes
are that blob's 22,411 plus the `\n` the `end-of-file-fixer` hook added,
so our blob is `2e6da291`. 45 quadruples -- description, mnemonics,
master secret, BIP32 root extended private key -- of which 15 are valid
and 30 have an empty master secret, meaning combining those mnemonics
must fail. All 45 are exercised, the 30 included: an invalid vector left
out is a check nobody makes.

The reference implementation rather than the SLIP: SLIP-0039's own "Test
vectors" section carries no file, it links to this one. The pin is the
commit that added the extendable backup flag and the four vectors for
it, which is also the tip of the path.

Four of the 15 valid vectors are checked in both directions. They are
the 1-of-1 shares, whose value is the encrypted master secret itself and
therefore involves no randomness the vector does not record, so btclib
regenerates each of the four mnemonics word for word from the master
secret. The other 11 are recovery only, a 2-of-3 share being random by
construction.

### `tests/_data/bolt11_test_vectors.json`

```text
repo    lightning/bolts
path    11-payment-encoding.md
commit  14901bdcacee53d95b46dc276b0f09c85d7d71fd  2026-03-09
pulled  2026-09-03
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, off the document's own "Examples" and
"Examples of Invalid Invoices" sections. Every invoice string is copied
verbatim; every field the valid cases assert -- network, amount,
timestamp, payment hash, payee, description or its hash, a fallback
address, a routing hop, the feature bits -- is checked against that same
example's own "Breakdown" in the document, not derived from btclib's own
decoder. `tests/bolt11_test.py` reads both halves.

Both sections are transcribed whole, the invalid case adding "unknown
feature 100" included: what refuses that one is `btclib_wallet.bolt9`'s
assignment table, which `Bolt11Invoice.assert_valid` reads.

### `src/btclib_wallet/bolt9.py`

```text
repo    lightning/bolts
path    09-features.md
commit  35e79db504560b9d3494a0ed07bf1e8379c3663a  2026-07-27
pulled  2026-09-03
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, off the document's own assignment table: the
even bit of each assigned pair with the name that table gives it, as
`FEATURE_NAMES`, and its Dependencies column as `FEATURE_DEPENDENCIES`.
There is no blob to compare, the table being markdown inside the
document.

Source rather than a data file, and pinned here for what the table
decides: `Bolt11Invoice.assert_valid` refuses an invoice setting an even
bit the table does not carry, so a pair assigned upstream after this
commit is one a reader at upstream's tip accepts and btclib refuses. The
module points here for the revision and carries none of its own, which
is what puts the pin where the weekly workflow reads it.

## Chain data, not a repository

These are consensus bytes. There is no upstream repository to pin and no
commit to name: the authority is the chain, and any node or block
explorer settles a dispute. The identifier is the block hash, which is
what `Block.parse` recomputes from the bytes, so the first entry
verifies itself. The second is chain data inside an envelope:
bodies a node and an explorer send, carrying bytes the first entry
already holds.

### `tests/block/_data/block_*.bin`

```text
block_170.bin     height 170, 490 bytes
  00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee
block_200000.bin  height 200000, 247,533 bytes
  000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf
block_481824_complete.bin
  height 481824, 989,323 bytes
  0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893
```

Pulled 2020-06-08, except `block_200000.bin`, 2020-06-09.

Verdict: **recorded**. `bitcoin-cli getblock <hash> 0` returns each of
them. `tests/psbt/psbt_size_test.py` reads `block_200000.bin` and
`block_481824_complete.bin` for the inputs whose sizes it checks, the
fetch fixtures below are read out of `block_170.bin` and
`block_481824_complete.bin`, and btclib holds the same files for its own
block tests.

### `tests/fetch/_data/*` — response bodies

```text
getrawtransaction.json          594 bytes
getblockcount.json               48
getbestblockhash.json           108
getblockhash.json               108
getblockheader.json             204
getrawtransaction_error.json    216
esplora_tx_hex.txt              551
esplora_blocks_tip_height.txt     7
esplora_blocks_tip_hash.txt      65
esplora_block_height_hash.txt    65
esplora_block_header.txt        161
rest_tx.bin                     275
rest_chaininfo.json             191
rest_blockhashbyheight.bin       32
rest_headers.bin                 80
pulled  2026-08-02, and 2026-09-03 for the two get*header* pairs and the
        four rest_* files
```

Verdict: **composed locally**, and the distinction between the envelope
and what it carries is the whole of the entry.

**The envelopes are not recorded.** They are what bitcoind and Esplora
send, written here from the source that writes them rather than captured
from a node: `JSONRPCReplyObj` in Core's `src/rpc/request.cpp` puts
`jsonrpc`, `result` and `id` in that order, compact, and `WriteReply`
appends the newline, which is why these files are one line each and why
`pretty-format-json` must not touch them — the exclusion by directory
already covers them. The error object of
`getrawtransaction_error.json` is Core's too, code `-5` with the message
`src/rpc/rawtransaction.cpp` builds for a node running without
`-txindex`, verbatim including the trailing sentence `JSONRPCError`
appends. Nothing here was invented; nothing here was captured either, and
a node's answer is what settles a disagreement.

**What they carry is chain data, and it verifies itself.** The hex in
`getrawtransaction.json` and in `esplora_tx_hex.txt` is transaction 1 of
block 170 —

```text
txid  f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
      275 bytes, 1 input, 2 outputs of 10 and 40 BTC
```

— the first bitcoin payment between two people, and it is not fetched
from anywhere: it is read out of `tests/block/_data/block_170.bin`,
already vendored above, so the two copies can be compared without a
network and `Tx.parse` recomputes the id from the bytes on every run.
The height and hash the rest carry are block 481824,

```text
0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893
```

which is `tests/block/_data/block_481824_complete.bin`, so that pair is
checkable here too — `BlockHeader.parse(...).hash` against the hash, the
height against the BIP34 number in the coinbase. `getblockheader.json`
and `esplora_block_header.txt` carry the first eighty bytes of that same
block, which are its header in either serialization —
`BlockHeader.parse` recomputes the same hash from them, and
`assert_valid_pow` accepts them, being a real header of a real block.

The `.txt` files end in a newline that Esplora does not send: the
`end-of-file-fixer` hook adds it, as it did to `script_assets_test.json`
above, and `EsploraFetcher.text` strips whitespace for the same reason a
deployment behind a proxy may add some.

The `rest_*` files carry no envelope at all, `-rest` answering `.bin` and
`.json` alike with the body and nothing wrapped around it: `rest_tx.bin`
is the same 275 bytes as the hex in `getrawtransaction.json` and
`esplora_tx_hex.txt`, decoded rather than re-derived, and
`rest_headers.bin` the same eighty bytes as `getblockheader.json` and
`esplora_block_header.txt`. `rest_blockhashbyheight.bin` is the one
exception to "the same bytes another fixture already carries": Core's
`.bin` answers a block hash in its internal byte order, the reverse of
every hash `getblockhash.json` and the `esplora_block*` files carry
in display order, so this file is `TIP_ID`'s bytes reversed rather than
its hex decoded — `BitcoinCoreRestFetcher.get_block_header`'s docstring
is where that reversal is checked against `uint256::GetHex()`.
`rest_chaininfo.json` is the one member of this group with nothing to
verify against a vendored block: `blocks` and `bestblockhash` are the
same height and hash as every other fixture here, and the members beside
them are what a real `-rest` reply carries and this fetcher does not
read.

Regenerating one of these is reading the two block files: the Core and
Esplora fixtures take the envelope their backend wraps around what comes
out, the `rest_*` files take those bytes unwrapped, and
`rest_chaininfo.json` is composed rather than read. Nothing upstream will
refresh any of them, and nothing should.

## Not vendored from anywhere

### `tests/mnemonic/_data/electrum_test_vectors.json`

**Unresolved, and probably unresolvable.** These 12-word mnemonics with
their root keys and addresses are in no upstream repository: a GitHub
code search for the first mnemonic returns btclib and one fork of btclib,
and they are not in spesmilo/electrum's `tests/`. They were produced by
running Electrum, and no record says which version.

So they are btclib's, cross-checked against an application rather than
copied from a project. Treat them as ours: nothing upstream will ever
refresh them.

They are no longer the only Electrum vectors, and that is what makes the
paragraph above bearable: `tests/mnemonic/electrum_test.py` now carries
spesmilo/electrum's own, inline — the `SEED_TEST_CASES` seeds and the
`Test_seeds` seed-type table of its `tests/test_mnemonic.py`, and the
`UNICODE_HORROR` passphrase of its `tests/test_wallet_vertical.py`. Not
vendored as files here: each block is small enough to read, and a
citation two lines above the values is one that gets checked.

`SEED_VECTORS`' five passphrase-bearing rows each carry the
`passphrase_hex` field upstream's own `SeedTestCase` publishes beside
them where it publishes one — `spesmilo/electrum`'s
`300b986782c754be462788a30e0355301683c0ed` (2024-06-10, the tip of
`tests/test_mnemonic.py`) and, for the japanese row's
`UNICODE_HORROR_HEX`, `b57327fb3e6d62941b833f8ce9b3b91c34c9ec76`
(2026-07-01, the tip of `tests/test_wallet_vertical.py`) — and
`test_seed_vectors` asserts `passphrase.encode("utf8") ==
bytes.fromhex(passphrase_hex)` before either reaches the seed
computation, the way upstream's own `test_mnemonic_to_seed` does.
`english_with_passphrase` publishes no such field upstream, its
passphrase being plain ASCII, so that row's stays `None`. The check
found the spanish row's passphrase composed rather than decomposed — a
precomposed ñ, í, ó, é and á where upstream's own literal holds the
accent as a separate combining character — invisible to the seed
assertion, since `_seed_from_mnemonic` normalizes either form to the
same NFKD before hashing, and caught only by comparing raw bytes. The
fix was to match upstream's bytes, not to drop the check.

The pre-2.0 scheme is the same arrangement and four more of upstream's
values, added for issue btclib-org/btclib#208. The scheme has no
specification — it predates the BIPs — so a vector btclib generated
would be testing btclib against itself, and each of these is a value
published by spesmilo/electrum:

- the mnemonic-to-hex pair of `Test_OldMnemonic.test`, in
  `tests/test_mnemonic.py`, which is the only published pair and the only
  thing that pins the encoder;
- the mnemonic, hex seed and master public key of
  `test_electrum_seed_old`, and the mnemonic and master public key of
  `test_sending_offline_old_electrum_seed_online_mpk`, both in
  `tests/test_wallet_vertical.py`;
- the hex seed and `master_public_key` of the pre-2.0 wallet file in
  `tests/test_storage_upgrade.py`.

The word-list they run over has no entry here, and being outside
`tests/` is not the reason -- `wordlist.txt` is outside it and has one.
`src/btclib_wallet/mnemonic/_data/electrum_old_english.txt` is pinned where it is
used: it is shipped code, transcribed from the `_words` tuple of
`electrum/old_mnemonic.py`, and `src/btclib_wallet/mnemonic/electrum.py` carries
that pin beside the constant that names the file.

Pulled 2018-06-11; the pre-2.0 values 2026-08-02.

### `tests/mnemonic/_data/fakeenglish.txt`

Verdict: **composed locally**. btclib's own, and deliberately broken:
`english.txt` with the first word,
`abandon`, deleted — 2047 words, so that `WORDLISTS.load_lang` raises
"invalid wordlist length". Not vendored, nothing to pin; regenerate it
from `english.txt` if that ever changes, which it has not since 2014.

Pulled 2018-06-01.

### `tests/psbt/_data/btclib_test_vectors.json`

Verdict: **composed locally**, not vendored. Cases that no BIP
publishes: each is a psbt btclib must refuse, and what it must say. There
is no upstream URL to give, because there is no upstream — inventing one
is the failure mode this entry exists to prevent.

What they are made of is upstream, and it is the half of BIP174 the entry
above deliberately leaves out. The starting psbts are five steps of the
BIP's "2-of-3 Multisig Workflow" walk-through — prose steps rather than
`* Case:` entries, which is why `bip174_test_vectors.json` does not
vendor them — taken at the same pin as that file,
`8c369ac8e60629ac6c032ffe21bb5ec5b35213d7` (2026-07-16), where all five
appear verbatim; the two version 2 cases start instead from the first
valid psbt of `bip370_test_vectors.json`, at the pin recorded there.
Every case is one of those plus one edit:

- the **creator**'s psbt with a `PSBT_GLOBAL_VERSION` of 1, and with the
  `0xff` of its magic bytes replaced — the two `invalid psbts`, which
  `Psbt.b64decode` must refuse. The second is refused for the header and
  not for anything narrower, which is the case rather than a shortfall of
  it: that `0xff` is the fifth byte of `PSBT_MAGIC_BYTES` and not a field
  of its own, so losing it is the header being wrong;
- the **creator**'s psbt with a `script_sig` written into the first
  input of its unsigned transaction, which BIP174 requires to be
  unsigned. It is bytes like every other case here, where the three
  cases this replaces were a psbt plus the name of an edit: those
  described a psbt whose input maps and unsigned transaction disagreed,
  and under BIP370 the maps *are* the transaction, so dropping a map
  drops an input rather than leaving two counts to differ;
- two version 2 psbts, BIP370's first valid one with its
  `PSBT_GLOBAL_OUTPUT_COUNT` one too high and one too low. That count is
  how a version 2 parse knows how many maps follow, so a wrong one is a
  psbt that ends too early or has bytes left over — and it is the one
  place where those disagreeing counts *can* be written down;
- the **first signer**'s psbt with its `lock_time` flipped, beside the
  **second signer**'s unedited, as the one `invalid combination`;
- the **combiner**'s psbt with the partial signatures of its first input
  removed, as the one `unfinalizable psbt`. Its second input keeps its
  own, so what the case pins is that a Finalizer refuses the psbt for the
  one input it cannot finalize rather than finalizing what it can.

The `error message` of every case is btclib's own, as it is for the
signer check failures of `bip174_test_vectors.json`: the BIP says nothing
about the wording, so correcting a message means correcting it here too.
Nothing upstream will ever refresh this file, and a bumped BIP174 pin
does not touch it — the five psbts are fixed bytes, and the edits are
btclib's.

Composed 2026-08-02.

## What is not pinned, and why

- **`tests/mnemonic/_data/electrum_test_vectors.json`** has no upstream.
  Stated above rather than guessed at.
- **`tests/mnemonic/_data/electrum_language_vectors.json`** has none
  either, and for a reason that will not change: electrum publishes no
  vector for the sentence it *generates* from a given entropy. Ours were
  produced by running its code, which is a procedure to repeat rather
  than a revision to pin, and the entry above gives it.
- **The transcribed files** are pinned to a prose revision, or, where the
  upstream is a source file rather than a document, to that file's blob;
  neither makes "identical" a claim that can be made about them. What was
  checked is stated in each entry.
- **`tests/psbt/_data/btclib_test_vectors.json`** pins the prose revision
  its raw material came from, which is not the same as having an
  upstream: the cases are btclib's, so the pin says where the psbts were
  read and nothing about the cases built on them.
- **Nothing here is enforced by the suite.** No hook re-fetches an
  upstream and no test compares a blob, and that is a deliberate stopping
  point: a network call in the test suite would trade a documented drift
  for a flaky one.

## Summary

No count here, and no count in front of the lists below: a count is a
line every open branch has to edit, and branches moving it to the same
new number merge with nothing to decide, into a number that is wrong. The
lists *are* the fact the number summarized, and the tree answers
whenever the number is wanted:

```shell
git ls-files 'tests/_data/*' 'tests/*/_data/*' \
    src/btclib_wallet/mnemonic/_data/wordlist.txt | grep -cv 'README.md'
```

Against a pinned upstream blob:

- identical byte for byte: `english.txt`, `wordlist.txt`,
  `bip39_test_vectors.json`, `send_and_receive_test_vectors.json` and
  `bip375_test_vectors.json`.
- identical but for a trailing newline: `vectors.json`,
  `sign_verify_vectors.json` and the BIP322 vector files.
- JSON-equal, reformatted: `test_JP_BIP39.json`.

Not checked byte for byte against one:

- transcribed, every value matched either in the pinned text or, for a
  source file, by the check the entry itself states:
  `bip32_test_vectors.json`, `bip32_invalid_keys.json`,
  `bip174_test_vectors.json`, `bip370_test_vectors.json`,
  `bip371_test_vectors.json`, `bip373_test_vectors.json`,
  `bip85_test_vectors.json`, `miniscript_fixed_tests.json`,
  `bolt11_test_vectors.json`, `bolt9.py`.
- chain data, identified by block hash: the blocks under
  `tests/block/_data/`.
- response bodies under `tests/fetch/_data/`, whose envelopes are
  composed from Core's and Esplora's own source and whose payload is
  chain data the entry above already holds.
- not vendored: `electrum_test_vectors.json`,
  `electrum_language_vectors.json`, `fakeenglish.txt`,
  `descriptor_checksums.json` and `btclib_test_vectors.json` (btclib's
  own). `descriptor_checksums.json`, `fakeenglish.txt` and
  `btclib_test_vectors.json` are composed rather than recorded:
  `descriptor_checksums.json`'s checksums come from a third
  implementation run over Core's own descriptors, `fakeenglish.txt` is
  `english.txt` with one word deleted, and `btclib_test_vectors.json`'s
  cases were built here, out of psbts BIP174 prints as prose.

### Left for a maintainer to decide

- **Descriptors of Core's `doc/descriptors.md` are not vendored**,
  and cannot be without a checksum from a third implementation. See that
  entry.
