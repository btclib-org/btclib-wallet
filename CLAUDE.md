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

[ARCHITECTURE.md](./ARCHITECTURE.md) is the design: which module holds
what, the one dependency direction, every place a module crosses out of
the process it runs in, and whose libsecp256k1 dispatch this package signs
through. Read it before touching `src/btclib_wallet/`.

## The primary checkout is the maintainer's

Never work in it: no edit, no `git add`, no commit, no branch switch, no
rebase, no `git stash` — the hooks fix files in place. The one write
allowed there brings it forward, and only while it is on `main` and
`git status --porcelain` prints nothing; where it is not, stop:

```shell
checkout=<checkout>
```

```shell
git -C "${checkout:?}" pull --ff-only
```

Read it only after that, once this prints one sha twice:

```shell
git -C "${checkout:?}" rev-parse HEAD origin/main
```

A measurement that has to hold at a named revision reads
`git -C "${checkout:?}" show <sha>:<path>` instead.

Every session works in a worktree of its own, from its first edit, named
`wt-<tracker>-<issue>-<repo>-<role>` — `wt-github-255-btclib-writer` for
issue 255 of `btclib-org/.github`'s tracker, worked in `btclib` by a
writer. The environment is created there, with the command `CONTRIBUTING.md`
names under *The environment and the gates*. Every path is written out in
full, `<scratchpad>` being the session's scratch directory:

```shell
git worktree add \
  <scratchpad>/wt-<tracker>-<issue>-<repo>-<role> origin/main -b <branch>
```

Removing it is part of finishing:

```shell
git worktree remove --force <scratchpad>/wt-<tracker>-<issue>-<repo>-<role>
```

`refs/stash` and the local `main` are shared by every worktree: never
`git stash`, and move `main` only by the `git pull --ff-only` above.

## Model

Default model: Sonnet; Opus for design decisions with conflicting
constraints. Do not use Fable unless instructed.

## Non-obvious facts that will otherwise waste a session

- **A branch's CI run can be `cancelled` rather than green.** `test.yml`'s
  concurrency group is
  `test-${{ github.event.pull_request.number || github.ref }}` (plus a
  release-only suffix) with cancel-in-progress, so the next push kills
  the run for the previous commit. The local gates are the evidence;
  `cancelled` is not `failure`.
- **A draft pull request is checked by nothing but aggregates that
  fail to say it is a draft.** The jobs doing work decline a draft in
  their `if:`; `test: every job passed` and `codeql: every job passed`
  run anyway and fail on their first step, so the required one reads
  red rather than skipped. Mark the pull request ready to be checked.
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
- **The union seam in `RELEASE_NOTES.md` is reported by nothing.**
  `.gitattributes` has why a rebase eats the blank line above a branch's
  block, and `check-changelog` names that line in `CHANGELOG.md`, where
  the block opens with a heading. A release note is a bare paragraph, so
  the seam joins it to the one above into a single paragraph that every
  hook passes. After a rebase that replayed a release note, rebuild the
  file as the new base's copy with the branch's block spliced before the
  first released heading, and `cmp` it against the committed one.
- **Two branches that each touched `.secrets.baseline` conflict on its
  `generated_at`,** whatever else they changed. Keeping `main`'s value
  resolves it, and the check is that the baseline then differs from
  `main`'s by the branch's own changes alone. It is still a
  conflict resolved, so `REVIEWING.md`'s *Re-review* sends the pull
  request back for one more round on the resolution.

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
*This repository in particular* gives.
