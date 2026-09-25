# Assurance case

[SECURITY](./SECURITY.md) states what a user can and cannot expect of
btclib-wallet in terms of security. This page argues why those
expectations hold: the threat model, the trust boundaries, how secure
design principles are applied, and how common implementation weaknesses
are countered. Each argument below names the file, the test or the
workflow that supports it; where SECURITY.md already states a fact, this
page points at it instead of repeating it. The components named here are
the ones [ARCHITECTURE](./ARCHITECTURE.md) describes.

## What is claimed

- **A derivation, a parse, a signature and a broadcast agree with the
  reference each is defined by.** BIP32, BIP39, SLIP39 and SLIP132
  against the vectors their own authors publish, an output descriptor
  and a PSBT against BIP380 and BIP174/BIP370, and, over a real device
  or a real node, `tests/integration/hwi_device_test.py` against a
  pinned Trezor emulator and a pinned Ledger under Speculos
  (`.github/workflows/integration-hwi.yml`) and
  `tests/integration/regtest_test.py` against a disposable regtest
  `bitcoind` (`.github/workflows/integration-bitcoind.yml`).
  `tests/_data/README.md` pins every vendored vector to the upstream
  commit it was copied from and says whether the two still match, and
  `.github/workflows/vendored-vectors.yml` re-checks that weekly.
- **Malformed input is refused the way the library says it is.** A
  public function handed an argument it cannot use raises
  `BTClibTypeError` or `BTClibValueError`, as btclib's own contract
  requires (`tests/input_validation_test.py`,
  `tests/integer_policy_test.py`).
- **Parsing octets from outside costs what the protocol allows.** A
  length or a count read from a descriptor, a PSBT or an extended key is
  checked against a bound before anything is built from it
  (`tests/parse_contract_test.py`), and a parser fails the way the
  library says it fails on anything else, never with a bare `IndexError`
  or `OverflowError` (`tests/fuzz_test.py`).
- **Where a secret meets the curve, the protection is the one
  SECURITY.md's *Where constant time ends* states, and no more.** Signing
  and verification run where btclib runs them; BIP32's private
  derivation and BIP352's key agreement are the two calls this package
  makes into the libsecp256k1 bindings directly; the sum this package
  builds for BIP352 and the EC-multiply factor BIP38 builds are Python
  integer arithmetic, variable in time with the operands, whichever
  install is in use.
- **A published distribution is what this tree built.** SECURITY.md's
  *Supported versions* states how that is verified.

## Threat model

btclib-wallet is a library in its caller's process, like btclib, with two
differences ARCHITECTURE.md's own sections name: it runs a subprocess
(`hwi.py`, Bitcoin Core's HWI) when a caller asks it to reach a hardware
device, and it opens client sockets of its own (`fetch/`) when a caller
asks it to reach a node, an explorer or an Electrum server. Neither
happens on import, and neither happens unless the caller constructs the
object that does it. The command below lists the top-level name of every
module `src/` imports, at any depth and in any spelling of the statement.

```shell
python3 - <<'EOF'
import ast, pathlib
names = set()
for p in pathlib.Path("src").rglob("*.py"):
    for n in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
        if isinstance(n, ast.Import):
            names.update(a.name.split(".")[0] for a in n.names)
        elif isinstance(n, ast.ImportFrom) and n.level == 0:
            names.add(n.module.split(".")[0])
print(sorted(names))
EOF
```

Beside this package's imports of its own modules, its dependencies
`btclib`, `bitcoin_core_rpc` and `typing_extensions`, and btclib's
`btclib_secp256k1`, what it lists is the standard library: `subprocess`
is `hwi.py`'s alone, `socket` and `ssl` are `fetch.transport`'s,
`urllib` is `bip21.py`'s percent-encoding of a payment URI, and `random`
is `coin_selection.py`'s shuffle, marked `# noqa: S311` at both call
sites because what it orders is which of the caller's own utxos is spent
first, never a key or a nonce.

**What is defended.**

- Private keys, extended private keys, mnemonics, seeds and the shared
  secrets BIP352 and BIP38 compute, against recovery from what this
  package returns or raises, and from the timing of the one call each
  makes into libsecp256k1 or the general dispatch reaches.
- The correctness of every answer: a derived key, a parsed descriptor or
  PSBT, an address, a fee estimate, a selection of coins, and the psbt or
  transaction a build or a sign produces.
- The caller's process, against a descriptor, a PSBT, a mnemonic or an
  extended key built to make a parser raise an exception this package
  does not document, or allocate without bound.
- A wallet's own ledger, against a change output imported as a receiving
  one or the reverse — `core_import.account_import_requests` marks a
  change chain `internal` for that reason, a mistake there being invisible
  until a balance is wrong.
- The signing boundary, against a psbt or a transaction sent to
  `psbt_signer` for a party who did not ask for it, and against a
  fingerprint mismatch when several devices of the same vendor are
  present (`hwi.py`'s own `--fingerprint` selection).

**The adversaries.**

- A party handing this package a descriptor, a PSBT, a mnemonic sentence,
  an extended key, a BIP21 URI or a BOLT11 invoice built to exploit a
  parser rather than to be spent.
- A co-signer in MuSig2 or FROST, or the other side of BIP352's key
  agreement, choosing what it contributes after seeing what this package
  already committed to.
- A backend `fetch/` talks to — a node, an explorer, an Electrum server —
  answering a question about the chain with something false; SECURITY.md's
  *A backend is trusted, and not every backend alike* states which
  answers are checked and which rest on the backend's word.
- A device or an HWI subprocess this package drives, returning a
  fingerprint, a signature or a derived key that does not belong to the
  request it was asked to answer — the reason
  `psbt_signer_contract.assert_psbt_signer` exists, for an implementer
  who has no other way to ask.
- A party tampering with a distribution between this tree and the user.

**What is not defended**, each stated in SECURITY.md's *Where constant
time ends* and *A backend is trusted, and not every backend alike*:

- side channels on the Python arithmetic btclib runs, and on the
  Python integer arithmetic this package computes itself for BIP352's
  input-key sum and BIP38's EC-multiply factor
- memory disclosure: secret material in a Python object is not zeroized,
  and `bip32._cached_base58_decode` keeps a decoded extended key
  reachable from its own cache past whatever reference the caller
  released
- a chosen-ciphertext attack on `bip38.decrypt`, which carries no MAC and
  cannot tell a wrong password from a right one before decrypting
- the resistance to side channels of whatever cipher a caller passes
  `btclib_wallet.bip38`, which takes AES-256 as two callables
- the privacy of a lookup against `EsploraFetcher`, `BitcoinCoreRestFetcher`
  or `ElectrumFetcher`: each learns every txid and outpoint asked of it
- the operating system, the interpreter, or the HWI binary or hardware
  device this package's caller names

Nor is the network transport a caller's own `Fetcher`, `Broadcaster` or
`FeeEstimator` substitute opens: `tests/fetch/` exercises the ones this
package ships, and a caller's own implementation is the caller's to
secure.

## Trust boundaries

**The caller and the public API.** Arguments cross from the caller into
btclib-wallet at every public function, and each is validated there.
CONTRIBUTING.md's *The public surface* states the rule and names the
tests that drive it — `tests/input_validation_test.py`,
`tests/bool_contract_test.py`, `tests/built_object_contract_test.py`,
`tests/curve_parameter_test.py` — and `tests/serialization_boundary_test.py`
drives it again where an object meets octets, text or json.
`check_validity=False` is a caller's explicit choice to defer validation
on an already-built object, never an exemption from it
(`tests/check_validity_test.py`).

**btclib-wallet and btclib.** Every primitive crosses this boundary
rather than being reimplemented — the curve arithmetic, a signature
scheme, a script, a transaction's own serialization. This package imports
btclib and re-exports none of it, which `tests/all_test.py`'s
`REEXPORTED` holds, and btclib does not depend on this package. A
flaw in a primitive is btclib's to fix, and reported through
[its own security policy](https://github.com/btclib-org/btclib/blob/main/SECURITY.md).

**Descriptors and PSBTs from outside.** `descriptors.parse` and
`Psbt.parse`/`Psbt.b64decode` are where a stranger's own text or bytes
cross in — a descriptor pasted, read from a file or returned by
`listdescriptors`; a psbt from another wallet, a coordinator or a QR
code. `tests/parse_contract_test.py` holds every `parse` in the package
to btclib's own contract: a field is as long as its encoding says, a
complete octet string is one whole object, a caller's stream is the
caller's. `descriptors.miniscript.parse` and `Psbt.parse` are BIP379's
and BIP174's own recursive grammars over that input, and
`fuzz/fuzz_descriptor.py` and `fuzz/fuzz_psbt.py` drive both under
ClusterFuzzLite (`.github/workflows/fuzz.yml`); `fuzz/fuzz_bip32.py`
does the same for an extended key's Base58Check and `fuzz/fuzz_bip322.py`
for a BIP322 signature, and `tests/fuzz_corpus_test.py` checks that every
seed in their corpora still parses.

**Mnemonics and passwords.** A sentence or a password only the user holds
crosses in through `mnemonic/` and `bip38.py`, against the module-level
`WORDLISTS` this package ships; a wordlist for a language `WORDLISTS`
does not carry is the one place *Files* below names a caller's own path
crossing in instead.

**The signing boundary.** `psbt_signer.PsbtSigner` is where a signer's
own answer crosses back in: a fingerprint, a derived key, a signed psbt
or transaction, checked by `psbt_signer_contract.assert_psbt_signer`
against what the request asked for before a caller trusts it. `hwi.py`
is the one place this
boundary is also a process boundary: `subprocess.Popen` runs `hwi` with
an argument list this package built, never a caller-supplied string
passed to a shell (`hwi.py`'s own `# noqa: S603`, the exec vector
`S602`'s `shell=True` would open, not taken).

**The network.** `fetch/` is where a backend's own reply crosses in — a
transaction, a block header, a fee estimate, a UTXO's existence.
SECURITY.md's *A backend is trusted, and not every backend alike* is the
full statement of what is checked at that boundary and what is not:
a transaction id is recomputed and refused unless it matches, a header's
proof of work is checked, and a height or a tip hash rests on the
backend's word except through `ElectrumFetcher`'s own merkle proof.
`TlsLineTransport` verifies the server's certificate and host name by
default. `Broadcaster.broadcast` checks that the backend named the txid
this package computed and nothing checks that the transaction went on to
propagate.

**Files.** The one place a caller's own path crosses in is
`mnemonic.WordLists`: its `language_files` constructor argument and its
`load_lang` method let a caller point a language at any file, which is
how `electrum.py` loads a wordlist that is not BIP39's — every other
caller reaches the module-level `WORDLISTS` singleton, loaded from this
package's own `_data/` files. Every other read under `src/` is this
package's own package data (`bip44.py`'s purposes table,
`mnemonic/electrum.py`'s old wordlist), and nothing under `src/` writes a
file at all.

## Secure design principles

Saltzer and Schroeder's principles, over the layering ARCHITECTURE.md
describes.

- **Economy of mechanism.** One protocol, `psbt_signer.PsbtSigner`, is
  what every signer implementation is checked against rather than a
  test suite per adapter, and one function,
  `psbt_signer_contract.assert_psbt_signer`, is where that check lives.
  `btclib_wallet/__init__.py`'s `__all__` is the one
  place the public tree is declared, and nothing is imported eagerly, so
  a module's own import graph is what `tests/imports_test.py` walks
  rather than whatever the package root happened to pull in first.
- **Fail-safe defaults.** `fetch`'s `verify_network` runs by default on
  every backend construction, so a caller who does not choose gets the
  check; `check_validity` defaults to `True` the same way btclib's own
  dataclasses do (`tests/check_validity_test.py`). A hardware device is
  selected by fingerprint, never by "the first one found"
  (`hwi.py`'s own argument against HWI's `--device-type`).
- **Complete mediation.** Every public function validates its inputs,
  and where it defers the work to a private twin, the twin trusts its
  inputs because its callers checked them — `bip32.derive` and
  `bip32._derive` is the shape CONTRIBUTING.md names to copy.
- **Open design.** The code, the vendored vectors and the corpus under
  `fuzz/` are published, `tests/_data/README.md` says where every
  vendored file came from, and SECURITY.md states what is not defended.
- **Least privilege.** `fetch/__init__.py`'s own docstring is the
  argument in full: the codec a server would need sits outside this
  package, and importing `fetch` pays for a client's dependencies —
  `urllib`, `ssl`, `socket` — only because a caller asked for one, never
  because a caller only wanted to parse. `core_import.py` builds the
  request Bitcoin Core's `importdescriptors` takes and opens no RPC
  connection to send it.
- **Psychological acceptability.** A parser refuses with
  `BTClibTypeError` or `BTClibValueError` rather than an opaque
  exception, and `assert_psbt_signer` raises on the first breach with
  what was expected and what came back, because the first breach is the
  one an implementer has to fix.
- **Layering.** btclib does not import this package, and this package
  does not reimplement a primitive btclib already defines
  (`tests/imports_test.py`). `descriptors/`'s own three modules import
  only the ones before them; `fetch`'s own codec sits in `btclib.p2p`
  and `btclib.electrum`, outside this package, for the reason above.

**Where this package reaches past btclib's own dispatch, it says so.**
`bip32/bip32.py` and `silent_payments.py` are the two modules calling the
libsecp256k1 bindings directly rather than through btclib's general
predicate, and each is one call for one fixed operation — a private-key
tweak, an ECDH shared secret — rather than a copy of the dispatch logic
itself, keeping the one place a caller has to read for "does this call
reach the bindings" to `curves.curve._libsecp256k1_serves` plus these two
named exceptions.

## Common implementation weaknesses

Weaknesses from MITRE's CWE list that a package of this kind is exposed
to, and what counters each.

- **Improper input validation (CWE-20).** The trust boundaries above, and
  `tests/integer_policy_test.py`, which refuses a `bool` where an integer
  field — a derivation index, an account number — is expected.
- **Uncaught exceptions on hostile input (CWE-248, CWE-755).**
  `tests/fuzz_test.py`'s contract — `BTClibValueError`, `BTClibTypeError`
  or `BTClibRuntimeError`, and nothing else — driven by Hypothesis over
  every declared parser and by the harnesses under `fuzz/` running under
  ClusterFuzzLite. `tests/fuzz_corpus_test.py` checks that every seed of
  their corpus still parses.
- **Race conditions on shared state (CWE-362).** The module-level
  `WORDLISTS` singleton is reachable from any thread a caller runs, and
  `WordLists`'s own lock is what keeps a second thread arriving mid-load
  from reading the empty list the constructor put there before the words
  landed — `tests/mnemonic/mnemonic_test.py`'s
  `test_load_lang_is_not_a_race` forces that interleaving and asserts the
  second reader waits rather than seeing zero words.
- **Uncontrolled resource consumption (CWE-400, CWE-770).**
  `tests/parse_contract_test.py`'s bound, read before anything is built,
  covers a descriptor, a PSBT map and an extended key the same way
  btclib's own parsers are covered.
- **Observable timing (CWE-208).** SECURITY.md's *Where constant time
  ends* states which of this package's own operations run on Python
  integers regardless of which arithmetic btclib itself is using.
- **Weak randomness (CWE-330, CWE-338).** Randomness for a key, a seed
  or a nonce comes from `secrets` (SECURITY.md), and ruff's
  flake8-bandit family, selected whole in `pyproject.toml`, flags a bare
  `random` call under `src/`; `coin_selection.py`'s two uses are the
  exception, each carrying a `# noqa: S311` naming why the choice need
  not be unpredictable to an adversary — which of the caller's own
  utxos is spent first, not a secret.
- **Improper verification of a signature or a derivation (CWE-347).**
  Checked against the BIPs' and SLIPs' own vectors, and, over a real
  device or a real node rather than only this package's own suite,
  `tests/integration/hwi_device_test.py` and
  `tests/integration/regtest_test.py` under the workflows named in *What
  is claimed*.
- **Exposure of sensitive information (CWE-209).** `bip38.py`'s own
  design is the sharpest instance and SECURITY.md states it: `decrypt`
  cannot tell a wrong password from a right one before running the
  cipher, so nothing here reports which of the two happened beyond the
  final address check.
- **Deserialization of untrusted data (CWE-502).** `descriptors.parse`
  and `Psbt.parse`/`Psbt.b64decode` are this package's own parsers, not a
  generic deserializer; the census under *Threat model* lists neither
  `pickle` nor `marshal` nor `shelve`. `.github/workflows/codeql.yml`
  analyses the code and the workflows.
- **OS command injection (CWE-78).** `hwi.py`'s `subprocess.Popen` takes
  an argument list this package built from a caller's own typed
  parameters, never a shell string interpolated from them —
  `noqa: S603` is scoped to that one call, and `shell=True`, the vector
  `S602` guards, is not used anywhere under `src/`.
- **Type confusion (CWE-843).** mypy runs with `strict = true`
  (`pyproject.toml`) over the package and the suite, as a hook of the
  lint gate in `.pre-commit-config.yaml`.
- **Code that is wrong and still passes.** Line and branch coverage of
  the package and of the suite is held at 100% by `fail_under` in
  `pyproject.toml`, and mutation testing, profiled per subsystem under
  `.github/mutation/` and run by `.github/workflows/mutation.yml`, asks
  whether the suite notices a wrong line — `signer.toml`'s own header
  states why the signing boundary is mutated apart from parsing or
  encoding: a wrong decision there is a signature over somebody else's
  transaction.
- **Supply chain.** SECURITY.md's *Supported versions* describes the
  attestations and the bill of materials. `uv.lock` pins every
  dependency, and CONTRIBUTING.md's *The environment and the gates*
  states that the suite and the lint gate install with `--locked`;
  `deps-latest.yml` and `deps-oldest.yml` resolve fresh on a schedule
  instead, so a break in what the pin hides is caught rather than never
  seen. Every third-party action is pinned to a commit sha; `actionlint`,
  `zizmor` and `detect-secrets` run as hooks in `.pre-commit-config.yaml`.

**Upstream.** `tests/_data/README.md` pins every vendored file to the
upstream commit it was copied from and to a git blob hash, and states
whether the two still match; a vector that disagrees with the rule it
tests is kept byte for byte, so that its pin still compares, rather than
edited to pass.
