# Contributing

What this repository holds in common with the others of the organization
— the toolchain, the lint gate, the tool tables behind it, the workflow
set and the branch rules — is stated once in the
[btclib-org repository standard](https://github.com/btclib-org/.github),
each rule with the alternative it was decided against. It binds this
repository, so a change departing from it is a divergence, and one filed
as an issue in that repository rather than here: a difference between two
repositories belongs to neither of them.

**This file is the same in every repository of the organization up to
its last section.** What is true of one tree only — the commands that
build its environment, the gates it runs, which of its workflows decide
a merge — is under that heading, and the comparison stops there.

## The issue tracker

Where an issue is filed, and what an alignment finding has to name, is
[the standard's *What this repository is*][s-what]: an issue spanning
repositories, or whose subject is the standard, goes to
[btclib-org/.github](https://github.com/btclib-org/.github/issues), and
one about this tree alone stays here.

A finding noticed while doing something else goes where `REVIEWING.md`'s
*What is filed, and what is not* says, for an author as much as for a
reviewer: a pull request answering two questions cannot be accepted for
either.

## Documentation and comments

[Section 9 of the standard][s9] is the prose style, and it governs the
prose this tree ships — comments, docstrings and markdown. It is not
restated here: a second wording is the one that goes stale, which is
that section's own *One fact in one place*.

A commit message is prose this tree ships too, though section 9 does not
say so: [the only merge method the rule accepts][s11] puts it on `main`
as the landing commit's body, so what is written in one is read there
long after the branch is gone.

## Pull requests

What `main` accepts, and what it refuses to everyone, is [section 11 of
the standard][s11]. Run the gates locally before opening anything —
the last section of this file says which they are — because CI runs
exactly them, so a red run there is a local run that was not done.

What a pull request's title and description have to say about the issues
it closes, and why a manual link in the Development panel is a trap
neither of them shows, is [the standard's *What a pull request says it
is*][s-title]. Read it before opening one; it is the rule most often
found broken after the fact.

**Before it is opened, the branch's own commit subjects and bodies are
read against that same rule.** The description does not exist yet to
disagree with them, and [the standard][s-title] has the command that
scans the branch's own commit text for a verb in front of a reference.

**The two spellings are named here as well as there, against [section 9's
*One fact in one place*][s9]**, the paragraph above naming the section
and not the forms, which are the half a citation is got wrong in:
`(closes #N)` cites an issue the change closes, wherever the citation
sits — the title, the commit subject where [*Merge method*][s11] makes
that the thing that lands, and a `CHANGELOG.md` entry — and `(issue #N)`
cites, in those same places, an issue the change advances and does *not*
close. One token holds one meaning whichever file it sits in, so the
pair is chosen by what is true of the change rather than by which file
is being written, and a tree's own landed subjects are not what to copy
it from: nothing already landed is rewritten, so what a repository wrote
before the rule stays where it is.

`REVIEWING.md` is the standard a review is written against, and is this
file's other half. Read before opening a pull request, it is what the
pull request will be answered against.

`CHANGELOG.md` gets an entry for anything a reader would notice, and the
release notes move only for something a user has to *act* on, in the
repositories that publish.

Where that entry goes is [section 9][s9]'s — the end of the open
section — and no gate reads it: `check-changelog` is handed the file and
no base, so it cannot tell which entry the branch wrote. The open
section's headings, in the order the file holds them, a branch's own
last:

```shell
awk '/^## /{n++} n==1 && /^### /' CHANGELOG.md
```

`n==1` takes the open section, from the first `##` heading to the next,
and the scan is `/^## /` rather than `/^## v/`: a section headed
`## Unreleased` is no match for `/^## v/`, which counts from the first
release heading instead and prints a released section's entries — or
nothing, where the tree has released nothing — while reading as a
check that passed.

### One subject, opened as soon as it is written

A pull request answers one question. Issues that share a subject are one
pull request, closing each of them; issues that do not are one pull
request each, however small either of them is.

It is opened the moment it is written and verified — not held for the
previous one to be reviewed or to land, and not batched with the next. A
batch arrives as one reviewing job with several subjects, which is the
shape that costs the most to read; a finished pull request held back is
review that could have started and did not.

Working this way stacks branches, which is fine and costs one rule: a
child whose base was amended is moved with the old base named,

```shell
git rebase --onto <new-base> <old-base-sha> <child>
```

because a plain rebase replays the base's old commit inside the child,
and the forge then shows the base's old text as additions with nothing
red anywhere. Read the child's diff afterwards rather than trusting the
rebase, and retarget each child onto `main` as its parent lands.

### The landing queue

Where more than one pull request is open against this repository, only
one is carried to `main` at a time: rebased onto the tip, reviewed on
that head, and landed, while every other one waits, untouched, for its
turn. This governs which of several *already open* pull requests reaches
`main` next; *One subject, opened as soon as it is written* above governs
the moment before that, when a finished one is opened — the two do not
conflict, since a pull request is still opened without delay and still
waits its turn once several are open.

The reason is CI throughput, not the ack a waiting pull request keeps —
`REVIEWING.md`'s *The verdict* states what an ack belongs to, and
*Landing it* below states which rebase voids one. Every rebase queues
this repository's whole check matrix against the organization's ceiling
on concurrent jobs, so rebasing every waiting pull request after each
landing spends that capacity on runs the next landing invalidates
anyway, and delays the one pull request that is actually next: work
spent on a pull request that is not next is work that delays the one
that is. The ceiling's figure is `REPOSITORY.md`'s, under *Plan-gated
settings*, beside the command that re-derives it.

Order is cheapest and least contended first, most invasive last, so that
a large change does not sit at the head blocking everything behind it.

The maintainer may declare a bounded exception — several pull requests in
flight against one repository, for a named piece of work — trading the
cost above for throughput; it is recorded as a comment in
[btclib-org/.github](https://github.com/btclib-org/.github/issues), by
*The issue tracker* above, and holds only for the work it names.

### The review

A review is given promptly and on local evidence. It does not wait for
CI, does not report a check as a finding, and does not discuss a run at
all: whether CI is green is the author's business, once, at landing time.

The exchange is anchored to a sha rather than to a branch, a branch being
free to move under a review:

- the author hands off by naming the sha pushed and the evidence run
  against it, then leaves that head alone;
- the reviewer answers with findings — where, what is wrong, how they
  know it, and whether each is blocking;
- the author accepts what is reasonable, declines the rest with a reason
  in the thread, and pushes the answer without waiting for CI;
- the reviewer resolves the threads they opened, that being what says a
  finding is closed, and re-reviews the delta rather than the branch.

**What ends the loop is the ack of record**, and the author does not
supply their own. A reading that says what it found and delivers no
verdict is a review too and ends nothing; [the standard's *Review*][s-rev]
has which is which, and `REVIEWING.md` has how each is written. A
disagreement that survives a second exchange goes to the maintainer
instead of into a third round.

### Landing it

CI is read once, and this is where. Rebase onto `main`'s tip, push that
head so the checks run on the tree that will land, and only then wait for
them: checks read before a rebase describe a tree nobody is landing. A
rebase that moved nothing but the base leaves the ack standing; one that
resolved a conflict does not, that resolution being a change no reviewer
has seen.

Then squash, [the only method the rule accepts][s11].

**The maintainer's bypass is not automatic — it has to be invoked, and
`gh pr merge` cannot invoke it**, refusing client-side before it asks
GitHub anything:

```text
Pull request is not mergeable: the base branch policy prohibits the merge
```

The merge endpoint applies it server-side, and it is the same endpoint
the merge button asks:

```shell
gh api -X PUT repos/{owner}/{repo}/pulls/<n>/merge \
  -f merge_method=squash -f sha=<the head the checks ran on>
```

**The `sha` is not optional.** Reading the ack and merging are two
calls, and the head is free to move between them — the push that would
move it comes out of the same round the verdict does. Unpinned, the
command takes whatever sits at the head when it runs; pinned, [the
endpoint answers `409` where the head has moved][gh-merge], and a round
lost that way is cheaper than a tree nobody has read reaching `main`.
*The review* above anchors the exchange to a sha and [section 11][s11]
has an ack name one: the pin is that rule reaching the call that
performs the landing.

**Verify what landed rather than trusting the answer**, the signature
[the standard asks for][s-sigs] being a valid one rather than a
particular signer's:

```shell
gh api repos/{owner}/{repo}/commits/main \
  --jq '.commit.verification | {verified, reason}'
```

**What it closed is read again here too, from the landed sha rather
than from the pull request**: [the standard's *What a pull request says
it is*][s-title] has the second read, and why the first alone does not
reach a squash subject composed after it runs.

The forge deletes the head branch itself, per the setting section 11
names. What is still yours is bringing every checkout sitting on `main`
up to date,
that being where the next session starts from and a stale one being where
a branch gets built on a base that has moved. `REPOSITORY.md` carries the
settings and why they are what they are.

[s-what]: https://github.com/btclib-org/.github#what-this-repository-is
[s11]: https://github.com/btclib-org/.github#11-github-settings
[s9]: https://github.com/btclib-org/.github#9-prose-comments-and-docstrings
[s-title]: https://github.com/btclib-org/.github#what-a-pull-request-says-it-is
[s-rev]: https://github.com/btclib-org/.github#review
[s-sigs]: https://github.com/btclib-org/.github#signatures
[gh-merge]: https://docs.github.com/en/rest/pulls/pulls#merge-a-pull-request

## This repository in particular

Everything above is the same file in every repository of the
organization; everything below is this one's, and the comparison stops at
this heading.

<!-- The toolchain badges are here rather than in the README because they
report no state: each names a choice, and this is the file that says how
the choice is enforced and what the command for it is. The README keeps
the badges that can turn red, the same split some sibling repositories
of the organization use. --> [![calendar versioning:
yyyy.m.d](<https://img.shields.io/badge/cal_ver-yyyy.m.d-1674b1.svg?logo=calver>)](<https://calver.org/>)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)
[![format:
ruff](https://img.shields.io/badge/format-ruff-yellowgreen.svg?logo=ruff)](https://docs.astral.sh/ruff/formatter/)
[![lint:
ruff](https://img.shields.io/badge/lint-ruff-yellowgreen.svg?logo=ruff)](https://docs.astral.sh/ruff/)
[![docstrings:
ruff](https://img.shields.io/badge/docstrings-ruff-yellowgreen.svg?logo=ruff)](https://docs.astral.sh/ruff/rules/#pydocstyle-d)
[![type check:
mypy](https://img.shields.io/badge/type_check-mypy-yellowgreen.svg?logo=mypy)](https://mypy-lang.org/)
[![lint:
markdownlint-cli2](https://img.shields.io/badge/lint-markdownlint--cli2-yellowgreen.svg?logo=markdown)](https://github.com/DavidAnson/markdownlint-cli2)
[![pre-commit
enabled](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit)](https://github.com/pre-commit/pre-commit)
[![GitHub repository:
btclib-org/btclib-wallet](https://img.shields.io/badge/GitHub-btclib--org%2Fbtclib--wallet-181717?logo=github)](https://github.com/btclib-org/btclib-wallet/)

To get an overview of the project, read the [README](./README.md) and
[CLAUDE.md](./CLAUDE.md)'s *Architecture*, which is where the layering
this package sits in is written down.

What a primitive does — a curve operation, a signature scheme, a script —
is btclib's, not this package's: a finding that reproduces with `btclib`
alone is an issue for
[its tracker](https://github.com/btclib-org/btclib/issues) rather than
this one.

### The one constraint

**This package is built on btclib and never the reverse.** It imports
`btclib` and re-exports nothing of it: a caller wanting one of btclib's
names imports it from `btclib`. `tests/imports_test.py` is what reads the
import graph. A name of `bitcoin_core_rpc` that `btclib_wallet.fetch`
publishes is a re-export, and `tests/all_test.py`'s `REEXPORTED` records
each such name.

### The public surface

**Every module and every package declares `__all__`**, at every depth of
the tree. A name is public here because a list says so, not because it
happens to lack a leading underscore. An empty list is a legitimate
answer, for a module with nothing public of its own; declaring nothing is
not. For a package the list is what the `__init__` publishes, submodules
included; for a module it is what the module itself defines, a name it
imported belonging to the module that defines it. `btclib_wallet.__all__`
is the root of that tree, written out rather than discovered, so that a
new module is published by somebody deciding to. `tests/all_test.py`
checks all of this and finds the modules rather than listing them: a
public name kept out of a list is recorded in its `UNEXPORTED` table, and
a name published from another module in its `REEXPORTED` table.

**Every public function validates its inputs.** Whatever it is handed — a
string, octets, or an object somebody built earlier — a name a caller can
reach checks it before acting on it, and a malformed argument leaves as a
`BTClibTypeError` or a `BTClibValueError`, which is what the callers of
this package are written to catch. A type the signature does not declare
is a `BTClibTypeError` even where the function answers a `bool`: the
`bool` is the answer to a well-typed question. The work itself may be
deferred to a private twin that does not validate, and that twin is what
the package composes internally. `btclib_wallet.bip32` is the shape to
copy: `derive` validates and calls `_derive`, which does not, and
`_key_data_from_bip32_key` is the one place a `BIP32Key` of any spelling
becomes a validated `BIP32KeyData`.

`tests/input_validation_test.py` drives that rule over every public
function whose required parameters are all library input types;
`tests/bool_contract_test.py`, `tests/built_object_contract_test.py` and
`tests/curve_parameter_test.py` drive it from fixtures where that walk
cannot reach.

**`check_validity=False` is not an exemption from this.** It says "do not
check *now*", not "this object is exempt from here on": these are
dataclasses whose validity at construction is not validity at use.
Passing it is supported — `tests/check_validity_test.py` exercises the
flag — so a public function that takes an already-built object and asks it
nothing is one a caller can reach with an object the package itself would
refuse. Every validating dataclass takes `check_validity` keyword-only.

**A `bool` parameter is a kind or a truth, and only the first is
type-checked.** A flag that decides *what is computed* refuses a non-bool;
a flag that decides only *whether a check runs* is read for its truth, and
its `True` is its conservative value. `tests/bool_parameter_test.py` is
the census of which each flag is.

**A name's prefix says what the call answers.** `assert_*` refuses and
returns `None`; `is_*` and `verify*` answer a `bool` and are total over
the declared types; `check_*` answers a `bool` and refuses what cannot be
an answer. A public function answering a `bool` carries one of the four or
is one of the English predicates `tests/name_contract_test.py` names, such
as `Psbt.inputs_modifiable`. A member that takes nothing but `self` is a
`@property`.

**A private function takes no default argument**, the value the call is
made with being at the call site, where it is read;
`tests/private_defaults_test.py` is the gate. **A trailing underscore is
public**, and marks the spelling whose input the caller has already
prepared; both names of such a pair are in `__all__`, and prepared is not
unchecked — `tests/integer_policy_test.py` holds the coercion policy.

### The environment and the gates

uv is the only tool that must be installed; it fetches interpreters,
linters and packaging tools itself. `uv sync` creates the environment.

```shell
uv sync
```

No test outside `tests/integration/` reaches the network or needs a node.
[tests/README.md](./tests/README.md) is where the suite, its switches and
the integration tests are described.

The gate is the suite, the hooks and the documentation build:

```shell
uv run pytest
uv run pre-commit run --all-files
uv run --locked --no-default-groups --group docs \
    sphinx-build -n -W -b html docs/source docs/build/html
```

`--cov` is in `addopts`, so the bare `pytest` above is the coverage gate
and `fail_under` is what it answers against — 100%, and coverage takes
that literally: a statement or a branch no test reaches fails it. A
selective run is reported and not gated, and `tests/conftest.py`'s
`coverage_fail_under` is what makes that difference.

The documentation build is the one to remember, because no hook reads
reStructuredText: a docstring docutils cannot parse fails it with every
hook green — a name ending in an underscore is a reference to a link
target, and the fix is double backticks around it. `-n` turns an
unresolved cross-reference into a warning for `-W` to fail on, and
`conf.py`'s `intersphinx_mapping` is what resolves a reference into the
standard library, btclib or bitcoin-core-rpc.

**Check exit codes, not filtered output.** `pre-commit run ... | grep -v
Passed` hides a failure, and `grep` finding nothing exits 1, which is not
the gate's answer to anything.

**The lint gate is not installed as a git hook.** `pre-commit install`
writes into the common git directory, which every worktree of this
repository shares: `git -C <worktree> rev-parse --git-path hooks` answers
with the primary checkout's `.git/hooks` from every one of them. So one
session installing it installs it for every other. Run the gate by hand
before committing — the `uv run pre-commit run --all-files` above.

**Prefix any `--python <version>` command with
`UV_PROJECT_ENVIRONMENT=.venv-<version>`, naming the interpreter that
command selects — `.venv-3.10` for `--python 3.10`, `.venv-pypy3.11` for
`--python pypy3.11`.** Without it, `uv run --python <version>` removes
`.venv`, builds it again on that interpreter and with that command's own
group set, and leaves it there. `uv sync` restores it.

### The editor

`.vscode/settings.json` and `.vscode/extensions.json` are tracked, and they
hold no preference: the recommended extensions are the tools
`.pre-commit-config.yaml` already runs, and the settings put the fixing ones
on save. Installing them is optional and changes nothing about what a local
run enforces.

Anything machine-local — an interpreter path, a telemetry answer, a theme —
belongs in the editor's own user settings instead, those two files being
read by every checkout of this repository.

### Reproducing what CI runs

Each command below is the one a CI job runs. Keep this section true when a
workflow changes.

`os-ubuntu.yml`, `os-macos.yml`, `os-windows.yml` and `deps-oldest.yml`,
the suite job of each — the suite, on one cell of a matrix. `--no-cov`
undoes the `--cov` addopts carries, the `coverage` job below being where
coverage is measured and gated:

```shell
uv run --locked --no-default-groups --group test pytest --no-cov
```

`test.yml`, the `coverage` job:

```shell
uv run --locked --no-default-groups --group test pytest
```

`test.yml`, the `dist` job — build the distribution files, check them and
install one. `release.yml`'s `test` job calls this workflow, and its
publish jobs download the `dist` artifact this job uploads, so what the
checks below judge is what an index ends up serving. `normalize_sdist.py`
is what puts the commit's own time into every member of the sdist, and
its docstring says why the backend's archive is not published as it
stands; `sha256sum` after it is the digest a rebuild from the tag is
compared against, per RELEASING.md's
[Rebuild a release from its tag](./RELEASING.md#rebuild-a-release-from-its-tag).
`generate_sbom.py` writes the CycloneDX bill of materials into `sbom/`,
which `release.yml`'s `attest` job signs beside the two files:

```shell
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
uv build
uv run --no-project --python 3.14 .github/scripts/normalize_sdist.py dist/
sha256sum dist/*
uv run --no-project --python 3.14 .github/scripts/generate_sbom.py dist/ sbom/
uv run --locked --only-group check twine check --strict dist/*
uv run --locked --only-group check check-wheel-contents dist/*.whl
uv run --locked --only-group check pyroma --min 10 dist/*.tar.gz
```

The job then installs the wheel it just built, alone, from an empty
directory, and derives an address with it:

```shell
tmp=$(mktemp -d)
cd "$tmp"
uv venv
uv pip install "$OLDPWD"/dist/*.whl
.venv/bin/python -c "
from importlib.metadata import requires, version
from btclib_wallet import bip44
from btclib_wallet.mnemonic import bip39

print(version('btclib-wallet'), requires('btclib-wallet'))
xprv = bip39.mxprv_from_mnemonic('abandon ' * 11 + 'about')
address = bip44.address_from_der_path(xprv, 'm/84h/0h/0h/0/0')
assert address == 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu', address
"
```

`lint.yml`, the `lint` job — this file *is* the lint gate, so there is no
second list of tools anywhere:

```shell
uv run --locked --only-group lint \
    pre-commit run --all-files --show-diff-on-failure
```

`docs.yml`, the `docs` job — the build, and then a read of the pages it
wrote:

```shell
uv run --locked --no-default-groups --group docs \
    sphinx-build -n -W -b html docs/source docs/build/html
if grep -rn 'href="#\.\.\?/' docs/build/html --include='*.html'; then
    echo "::error::the links above resolve to no page (unresolved relative path)"
    exit 1
fi
```

What myst renders for a destination it cannot resolve is an anchor to an
id no page has. `-W` reports it because `docs/source/conf.py` resolves the
links the included root files carry and suppresses no myst warning; the
`grep` is what still finds one the day a suppression goes back in.

`integration-bitcoind.yml`, the `regtest` job — a pinned Core release,
its published sha256 verified, and the regtest tests with the binary named
rather than found on `PATH`:

```shell
BTCLIB_INTEGRATION=1 BTCLIB_BITCOIND=/path/to/bitcoind \
    uv run --locked --no-default-groups --group test \
    pytest tests/integration --junitxml=integration.xml
```

A step after it reads that report and fails the job if a regtest test
skipped, pytest exiting 0 for a module that skipped itself. The HWI tests
skip there by design and are not counted.

`integration-hwi.yml` — the HWI tests against a Trezor emulator and
against a Ledger one under Speculos, each beside the same node. The
workflow's own header says what each job installs and pins; the Trezor
job runs:

```shell
BTCLIB_INTEGRATION=1 BTCLIB_HWI_SIGN=1 \
    BTCLIB_HWI="/path/to/hwi --emulators" \
    BTCLIB_BITCOIND=/path/to/bitcoind \
    uv run --locked --no-default-groups --group test \
    pytest tests/integration/hwi_device_test.py -n0 --junitxml=hwi.xml
```

It carries no `pull_request` trigger: a firmware release or an emulator
that stopped starting headless is the vendor's day rather than the
branch's. A branch touching `src/btclib_wallet/hwi.py` asks for it:

```shell
gh workflow run integration-hwi.yml --ref <branch>
```

`codeql.yml` has no line here: its jobs run `github/codeql-action` and no
command of this project's, so reproducing it locally means the CodeQL CLI
and a database rather than a `uv run`.

### What gates a merge, and what only reports

`lint.yml`, `test.yml`, `docs.yml` and `integration-bitcoind.yml` produce the
required checks, and `REPOSITORY.md` reads the rule back from the endpoint
rather than restating it. So a diff does not reach a review without having
passed them or passing them beside it on the same sha, which is the
reliance `REVIEWING.md` provides for.

| workflow | when | what it varies |
| --- | --- | --- |
| `test` | pull request, push | — |
| `lint`, `docs` | pull request, push | — |
| `integration-bitcoind` | pull request, push to main, weekly | — |
| `claude-review` | pull request, and `@claude` in a comment | — |
| `codeql` | pull request, push, and weekly | the languages |
| `os-ubuntu` | weekly, a release | images × interpreters |
| `os-macos` | weekly, a release | images × interpreters |
| `os-windows` | weekly, a release | images × interpreters |
| `deps-latest` | weekly | dependencies upgraded |
| `deps-oldest` | weekly | the floor interpreter, dependencies at their floors |
| `integration-hwi` | weekly, push to main | two emulators |
| `scorecard` | weekly, push to main | — |
| `links` | weekly | — |
| `mutation` | weekly | — |
| `vendored-vectors` | weekly | the pins in `tests/_data/README.md` |
| `pypi-install` | weekly, a release | what PyPI serves |
| `sdist-rebuild` | weekly | the latest release's sdist, rebuilt |
| `release` | a tag, and a rehearsal | the workflows it calls |

Which workflows that last row covers is
`grep -n 'uses: \./\.github/workflows/' .github/workflows/release.yml`,
not a list here. Which day each of the rest runs is section 10 of
[the organization standard](https://github.com/btclib-org/.github), and
not this file's to restate.

The gates run one image on one interpreter: `ubuntu-latest`, and the
version `.python-version` names. `claude-review` gates nothing: a review
that gates a merge would make a model's judgement a branch rule. Why so
little gates is the ceiling on concurrent jobs the plan puts on the whole
organization, and `REPOSITORY.md`'s *Plan-gated settings* is where that
lives.

### Mutation testing

`mutation.yml` asks the question coverage cannot: a line the suite executes
is not a line the suite checks. It gates nothing and runs weekly, through
`btclib-org/.github`'s `reusable-mutation.yml`; each file under
`.github/mutation/` is one session, its header saying what it mutates.
One session, by hand:

```shell
uv run --locked --no-default-groups --group test --group mutation \
    cosmic-ray baseline .github/mutation/bip32.toml
uv run --locked --no-default-groups --group test --group mutation \
    cosmic-ray init .github/mutation/bip32.toml bip32.sqlite
uv run --locked --no-default-groups --group test --group mutation \
    cr-filter-operators bip32.sqlite .github/mutation/bip32.toml
uv run --locked --no-default-groups --group test --group mutation \
    cosmic-ray exec .github/mutation/bip32.toml bip32.sqlite
uv run --locked --no-default-groups --group test --group mutation \
    cr-report --surviving-only --show-diff bip32.sqlite
```

The session writes each mutation into the source and restores it
afterwards, so nothing else may read the tree while it runs.

### The secrets baseline

`detect-secrets` reads `.secrets.baseline` to decide which findings have
already been reviewed. The test data of a wallet is keys and mnemonics,
published upstream as vectors, and adding one means regenerating it:

```shell
uvx detect-secrets scan --baseline .secrets.baseline
uv run --locked --only-group lint pre-commit run detect-secrets --all-files
```

Read the diff before committing it: a new entry is a finding somebody has
to have looked at, which is the whole point of a baseline over an
exclusion.
