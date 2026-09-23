# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working
with code in this repository.

How to work here — what the issue tracker takes, the prose style, and how
a pull request is opened and landed — is `CONTRIBUTING.md`, which is the
same file in every repository of the organization up to its last section,
which is this tree's and holds the commands and the gates. Repository
configuration is `REPOSITORY.md`: read it before changing a workflow, a
branch rule or a setting. Reviewing is `REVIEWING.md`, and `/review` is
that file as a command; read it before reviewing a pull request and
before opening one, since it is what the pull request will be answered
against.

## Architecture

The wallet side of btclib-org/btclib#2129's table, row 5: the package
`btclib_wallet`, under `src/btclib_wallet/`, sitting above `btclib` —
the protocol, row 4 — and depending on it and on `bitcoin-core-rpc`, row
6. Dependencies point one way, down that table: nothing in `btclib` or in
`bitcoin-core-rpc` imports this package, and this package re-exports
nothing of `btclib`'s. `btclib_wallet.fetch` publishes
`bitcoin-core-rpc`'s clients and transport under its own names, and
`tests/all_test.py`'s `REEXPORTED` records each of them. The
line between this package and `btclib` is Bitcoin Core's between
`src/consensus` and `src/wallet`: what places a module here is
everything from a seed to a signed, broadcast transaction, and every
module with a counterparty outside the process — a socket, a
subprocess, a node, a device — where the codec of a protocol stays
`btclib`'s and opens nothing.

- `bip32/` and `mnemonic/` derive keys, `slip132` and `bip44` turn them
  into addresses, and `bip85` derives another wallet's entropy from one
  root key, a BIP39 sentence being one of the formats it hands back
- `descriptors/` reads the BIP380 grammar and hands back the scripts a
  descriptor names, `descriptors.miniscript` reading BIP379's language;
  `psbt/` is BIP174 and BIP370 with the fields later BIPs add
- `wallet/` remembers which addresses it has handed out; `psbt_signer`
  is the contract an external signer answers and `hwi` that contract
  over Bitcoin Core's HWI; `core_import` writes what Bitcoin Core's
  `importdescriptors` takes
- `fetch/` is the one package that goes and asks — a node over
  `bitcoin-core-rpc`'s two clients, an Esplora instance, an Electrum
  server — and turns
  the answers into `btclib`'s `Tx` and `TxOut`
- what this package signs, it signs through `btclib.ecc`, so the dispatch
  to the libsecp256k1 bindings and where constant time ends are
  `btclib`'s, read in its `CLAUDE.md` and its `SECURITY.md`

## The primary checkout is the maintainer's

**Never work in it.** No edit, no `git add`, no commit, no branch
switch, no rebase, no `git stash` — the hooks fix files in place. It is a
local reference only, and it stays on `main`.

Reading it is fine, but `git fetch` moves `refs/remotes/origin/main` and
leaves the work tree where it was, so a `grep` or a `Read` against the
checkout answers for whenever it was last brought forward, not for now.
The read that cannot go stale is `git show origin/main:<path>`: it
answers from the ref `git fetch` just moved, never from the tree.

Where the checkout has to be current rather than merely readable, a
fast-forward of a clean `main` brings it up:

```shell
git fetch origin && git merge --ff-only origin/main
```

That writes no commit, switches no branch and runs no hook, so it is on
the permitted side of *never work in it*, not an exception to it. Stop
if the checkout is not on `main` or is not clean: that is no longer
bringing it forward.

**Every session works in a worktree**, its own, from the first edit, named
`wt-<tracker>-<issue>-<repo>-<role>` rather than after the issue alone, most
general part first: an issue filed in `btclib-org/.github`'s tracker is the key
and the repository is a detail of it — `btclib-org/.github#255` is one issue
owed by seven repositories, `btclib-org/.github#177` by two — so the repository
is what varies underneath an issue rather than the other way round, which is why
`repo` comes after `issue`. Naming it that way also sorts every worktree of one
issue together, which is what a port leaves behind.

Each of the four parts earns its place against a different collision,
and none of them is the same collision. `tracker` is the repository
whose issue tracker holds the issue: an issue number is unique only
within one tracker, so `btclib-org/.github#45` and
`btclib-org/btclib#45` are different issues that would otherwise name
the same worktree. `issue` is what prevents the collision that has
actually happened — two worktrees of different work sharing a generic
basename in one repository's own `.git`, keyed on its path's basename.
`repo` prevents a different collision, a *path* one rather than a `.git`
one: two repositories each keep their own `.git/worktrees/<basename>`
and cannot collide there, but the workers of one session share one
scratchpad directory, so a session carrying one issue into several
repositories computes the same target path for each of them, and `git
worktree add` refuses a directory that already exists — or worse, a
second worker reads the first one's tree. `role` covers the narrower
case of a coder and its reviewer holding a worktree at once, which the
ordinary sequence avoids by each removing its own.

An issue of `btclib-org/.github`'s tracker, worked in `btclib` by a coder, names
its worktree `wt-github-255-btclib-coder`. The environment is created in the
worktree, not the checkout, by whatever that tree's own `CONTRIBUTING.md` names
under *The environment and the gates*, and a session reads that section, not
this one, for the command. The editing, the gates and the commits all happen in
the worktree before the push.

```shell
WT=<scratchpad>/wt-<tracker>-<issue>-<repo>-<role>
git worktree add "$WT" origin/main -b <branch>
git -C "$WT" push origin HEAD:refs/heads/<branch>
```

`-b <branch>` sits after the path and the commit-ish so that the placeholder
ends the command, which is section 9 of `btclib-org/.github`'s rule. With the
placeholder ahead of `"$WT"`, its `<` and its `>` are redirections performed
left to right, so the `>` is reached only where the reader's own directory
already holds the name `branch`: there the `<` succeeds, the line runs, and the
`>` takes `"$WT"` as its target — a path with no directory at it is the file it
creates. Ordinarily nothing holds that name, so the `<` fails first (`no such
file or directory: branch`) and the line ends before the `>` opens anything.

The push names the worktree with `git -C "$WT"` because a `cd` binds the
shell that runs it: a session that runs each line as its own command
starts the next one in the directory it began in, the primary checkout,
so a push after a `cd` offers that checkout's `HEAD` instead of the
worktree's. `env -C <dir>` is the same binding for a command that takes
no `-C` of its own. Neither binding rescues the assignment above it: a
session that loses the `cd` loses `WT` with it, and `git -C ""` is
documented to leave the working directory unchanged, so that push lands
the same way, exit 0 and no diagnostic. That silence is `git`'s rather
than the binding's: the BSD `env` macOS ships documents no case for an
empty `-C` and refuses one — `cannot change directory to ''`, exit 125 —
so a line bound with `env -C` stops there instead of running against the
wrong tree. What the `-C` buys is a path that can be written out in
full; write it out.

Removing the worktree is part of finishing, and it stands in a block of
its own: the block above ends in a placeholder, and a shell that
discards that line as a parse error reads the next as a fresh command —
which, in one block, is this line against whatever `$WT` already held.
Standing alone it is a second fence, so `${WT:?}` is what it writes:
with `$WT` unset or empty the expansion fails and the removal does not
run. Those are the only cases it catches — a `$WT` an earlier session or
command left holding a path expands, and the removal runs against
whatever worktree that path names.

```shell
git worktree remove --force "${WT:?}"
```

**Never `git stash` in a worktree either: `refs/stash` is shared.** A
worktree isolates files, not refs, so `git stash push` pushes onto the
same stack every other session pops from. Commit to your own branch
instead.

**Do not rewrite `refs/heads/main`, and move it only onto
`origin/main`.** That name is the local branch's, and no ruleset reaches
it: a ruleset binds the forge's copy. The fast-forward above moves it
onto `origin/main` and is inside that, where a merge, a commit on `main`
or an `update-ref` to a branch tip leaves the ref somewhere
`origin/main` is not. Your own branch is what you push, and the pull
request is what moves `origin/main`.

## Model

The default model for this repository is Sonnet. Switch to Opus only
for architectural decisions with conflicting constraints -- design
choices with non-obvious trade-offs, refactors with unclear
dependencies, diagnosis where the symptom does not point to the
cause. Use `/model opus` for the session, then switch back to Sonnet.

Do not use Fable unless explicitly instructed.

## Non-obvious facts that will otherwise waste a session

- **A branch's CI run can be `cancelled` rather than green.** `test.yml`'s
  concurrency group is
  `test-${{ github.event.pull_request.number || github.ref }}` (plus a
  release-only suffix) with cancel-in-progress, so the next push kills
  the run for the previous commit. The local gates are the evidence;
  `cancelled` is not `failure`.
- **A draft pull request runs no CI at all**, every workflow carrying
  `if: ${{ !github.event.pull_request.draft }}`. Mark it ready to be
  checked: a required check that never reports blocks the merge rather
  than passing it.
- **mypy is a *local* hook shelling out to uv on purpose.** The
  mirrors-mypy hook injects `--ignore-missing-imports`, and it type
  checks in an isolated environment where the project is not installed —
  so `import btclib_wallet` in a test would be `Any` and every assertion
  about it would pass vacuously.
- **The version is declared once**, in `pyproject.toml`.
  `docs/source/conf.py` parses that file (not the metadata, which would
  need the package installed).
- **A change in `btclib` reaches this tree through `uv.lock` only.** A
  test here that fails after a `uv lock --upgrade-package btclib` and not
  before is a break in the protocol package's surface, and the question
  is asked of `btclib`'s `RELEASE_NOTES.md` before it is asked of this
  code.

## Conventions to match

Section 9 of `btclib-org/.github` is the prose style and section 10 its
workflow conventions, and neither is re-listed here, that section's own
*One fact in one place* being the reason. They govern the workflows and
the pre-commit config as much as the docstrings. `actionlint` and
`zizmor` read the workflows as hooks of the lint gate, so a finding from
either fails a commit rather than reporting one.

What is left to this file is what those cannot say, because it is about a
session rather than about the tree: the worktree rule, the model, the
failure modes in the section that names them, and what this tree is.

## Verifying

Run the command as documented before claiming it works, and read its exit
code rather than its filtered output, for the reason `CONTRIBUTING.md`'s
*This repository in particular* gives. Every claim in this file was
checked against the tree, and the tree changes.
