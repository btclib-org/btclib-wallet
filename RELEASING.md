# Releasing btclib-wallet

Releases are published by GitHub Actions
([release.yml](./.github/workflows/release.yml)), not from a developer
machine. Pushing a `v<version>` tag runs the full test matrix, builds and
checks the distribution files, publishes them to PyPI, and creates the
GitHub release. There is no PyPI token anywhere: both indices are
configured to trust the workflow itself
([Trusted Publishing](https://docs.pypi.org/trusted-publishers/)).

The same workflow, started by hand instead of by a tag, is a full rehearsal
against TestPyPI. A rehearsal is never tagged.

**A workflow GitHub has not registered cannot be dispatched, and it
registers one only once its file has reached the default branch.** Any new
workflow therefore answers `gh: Not Found (HTTP 404)` to `gh workflow run`
until the pull request adding it is merged. What makes that more than a
nuisance is the set no commit and no pull request fires either, which is
otherwise never exercised before the merge at all: `release.yml`, whose
`push:` names tags and nothing else, and the workflows below.

```shell
grep -L -E '^  (push|pull_request):' .github/workflows/*.yml
```

It bites once, on the first release after any of them is written, and it
inverts the order below: the TestPyPI rehearsal that this file asks for
*before* the merge can only happen after it, still before the tag. It also
means such a workflow reaches `main` having never run.

## Which version string is which

Telling these apart is most of what can go wrong when cutting a release.

- **`pyproject.toml`'s own `version`** shifts shape over one cycle,
  never two at once: `2026.9`, month only, between releases — the
  placeholder "Open the next cycle" sets, so a checkout of `main` reports
  itself as work in progress rather than as a release it is not;
  `2026.8.6`, the date of release day — calendar versioning, `YYYY.M.D`
  — which is what gets published, its month that date's own and not
  necessarily the placeholder's; and `2026.8.6.1`, a fourth number added
  only if `2026.8.6` shipped broken and cannot be reuploaded (see "If
  something goes wrong"). All three are typed by hand. Three
  components is always the release day; four is always a patch on it. The
  day is never dropped in favour of a fourth digit standing in for it,
  which is what would make the two indistinguishable — and `version-check`
  refuses a tag on the placeholder shape for exactly that reason: two
  components reach the check and nothing past it, whichever one is
  declared. It does not tell three apart from four, both being a release
  it accepts
- **`v2026.8.6`**, the tag, carries no version of its own: it picks the
  index, PyPI rather than TestPyPI, and `version-check` exists to
  confirm it says what `pyproject.toml` says
- **`2026.8.6.dev701`** is a rehearsal, and nobody types it either half
  at a time: `.dev<run*100+attempt>` is the template `release.yml`
  appends to what `pyproject.toml` declares when `workflow_dispatch`
  starts it, `github.run_number` counted for that workflow alone and
  `github.run_attempt` counted for one dispatch of it, so the seventh
  such run's first attempt, rehearsing `2026.8.6`, produces exactly
  that. The multiplier is what makes a re-run a version of its own
  rather than a collision: a re-run keeps the run's own number and only
  raises the attempt, so the run number alone was identical across every
  re-run of one dispatch and PEP 440 could not tell them apart. Placing
  the attempt below the run number's own place value keeps a run's later
  attempts sorting after its earlier ones and before the next run's, the
  attempt therefore capped at two digits and the workflow refusing a
  hundredth rather than silently wrapping into the next run's range.
  Nothing writes it down, and no commit ever carries it
- **`2026.8.6rc1`**, and a `v2026.8.6rc1` tag, have no place in this
  scheme: there are no release candidates here, only a version not yet
  tagged. `version-check` refuses anything that is not digits and dots,
  which is what stops `2026.8.6rc1` before a tag is even pushed — and
  what a `v2026.8.6rc1` tag would otherwise pass, burning a pre-release
  on PyPI itself, where `--pre` installs would find it from then on

PEP 440 sorts `2026.8.6.dev7` before `2026.8.6`, so a rehearsal never
shadows the release it rehearses. `git tag` on its own does not read the
numbers the same way: measured, `v2026.10` lists before `v2026.7`,
alphabetically rather than chronologically. `git tag --sort=v:refname`
reads them as PEP 440 does.

## One-time setup

Neither index holds the project until an upload creates it, so both entries
below are added as *pending* publishers, on that same page: a publisher
attached to a project can only be added to a project that exists, and a
first upload has nothing else to authenticate with, there being no token
anywhere. The upload PyPI accepts turns its pending entry into an ordinary
one, and TestPyPI's rehearsal does the same there.

1. On [PyPI](https://pypi.org/manage/account/publishing/), add a trusted
   publisher: PyPI project name `btclib-wallet`, owner `btclib-org`,
   repository `btclib-wallet`, workflow `release.yml`,
   environment `pypi`.

1. On [TestPyPI](https://test.pypi.org/), add the same trusted publisher,
   with environment `testpypi`.

1. In the GitHub repository settings, create the `pypi` and `testpypi`
   environments. Both require a review from `fametrano`, so neither
   index is uploaded to without a human approving that run; `publish-pypi`
   and `publish-testpypi` are the only holders of `id-token: write` that
   carry one of these two environments, and this is the gate in front of
   them. `attest` holds `id-token: write` too, for its own Sigstore
   exchange, but no environment of its own — what gates it instead is
   `needs: [publish-pypi, publish-testpypi]`, so it never runs before one
   of the two reviewed jobs already has. `pypi` is additionally restricted
   to `v*` tags, which is the only ref its job runs on anyway — the
   restriction is what makes that true of the environment and not just
   of an `if:` in a file a pull request could change.

   Self-review stays allowed on purpose: the maintainer who pushes the
   tag is the reviewer, and forbidding it would deadlock a
   one-maintainer release. The approval is a confirmation step, not a
   second pair of eyes; it becomes one as soon as there is a second
   reviewer to add.

## Rehearse on TestPyPI

A rehearsal runs the identical pipeline — lint gate, test matrix, the
`dist` job's build, its packaging checks (twine, check-wheel-contents,
pyroma) and its wheel smoke test — and publishes the very files those
checks passed to
[TestPyPI](https://test.pypi.org/project/btclib-wallet/) instead of
PyPI, so what `release.yml` publishes and what `test.yml` checked are
the same files (issue btclib-org/btclib#1166).

**What it answers is whether the publish path still works**, so it earns
its run when that path or what travels it has moved: `release.yml` or a
workflow it calls, `pyproject.toml`'s packaging metadata — the build
backend and the patterns of `[tool.uv.build-backend]` above all —
`normalize_sdist.py`, the trusted publisher registration, or the addition
of a file the distribution has to carry. A cycle that changed the module
and the prose and nothing else is one the tag's own run judges as well,
every job up to `publish-pypi` being the same job — and skipping it is
the maintainer's call to make and to say out loud in the release pull
request, not a step to leave silently undone. What is given up either way
is the token exchange and the upload, which no rehearsal on `main` proves
for PyPI anyway: `pypi` and `testpypi` are two registrations, and only
the tag exercises the first.

1. On GitHub, Actions → release → Run workflow, and pick the branch to
   rehearse (usually `main`).

1. The workflow appends `.dev<run*100+attempt>` to whatever
   `pyproject.toml` declares on the branch dispatched — the outgoing
   cycle's placeholder if the version about to ship has not landed yet,
   which publishes something like `2026.9.dev401` and still tests the
   identical pipeline the tag will run; the number is not what is being
   asked about.
   Every rehearsal is unique on TestPyPI this way, re-runs included: a
   re-run raises only `github.run_attempt`, which the run number is
   multiplied by 100 to make room for, so re-running a failed or finished
   rehearsal mints its own version instead of colliding with the one it
   repeats. It sorts before the release it rehearses once that release's
   own version is the one declared, which is what the rehearsal after
   the merge below runs on; a placeholder naming a later month sorts
   after the day it rehearses instead, which costs nothing — `.dev` is a
   pre-release no plain install resolves, and the release itself never
   reaches TestPyPI.

1. Check the upload, and optionally install it, naming the `.dev`
   version the run published — its dependencies are PyPI's, and TestPyPI
   is the extra index that holds this one file:

   ```shell
   dev=<the version the rehearsal published>
   ```

   The assignment stands in a fence of its own, for the reason the
   tagging step below gives.

   ```shell
   uv run --isolated --no-project \
     --index https://test.pypi.org/simple/ \
     --index-strategy unsafe-best-match \
     --with "btclib-wallet==${dev:?}" \
     python -c "import btclib_wallet; print(btclib_wallet.__version__)"
   ```

1. Check that the `attest` job is green. It signs a rehearsal's files too,
   which is what it is here for: the release path attests after PyPI has
   the distribution files and the tag can no longer be moved, so a
   permission or an API that only works on release day is one this job
   would find there. What it produces here goes no further than an
   artifact of the run — no release is cut from a dispatch, so nothing is
   attached anywhere — and the attestation it records names a `.dev`
   version nothing resolves.

## A live node has already been asked

Whether Core accepts what this package builds is checked on every pull
request: `integration-bitcoind.yml` is a required check, and `release.yml`
calls it again on the tag. Nothing to dispatch here.

Dispatch it by hand only when a run needs repeating without a push:
Actions → integration-bitcoind → Run workflow. `integration-hwi.yml` is
not a required check and has no `pull_request` trigger, so a cycle that
touched `src/btclib_wallet/hwi.py` reads its last run on `main` before
the tag.

## Release to PyPI

**A release is a tag on `main`, and everything below that edits a file
does so on a branch of its own.** Nothing is pushed to `main` directly,
this release included: the steps that retitle the notes, open the next
cycle's sections and set the version are one pull request, the one that
sets the next cycle's version is another, and the tag names the commit
the first of them left behind.

`deps-latest` is worth dispatching before the tag rather than waiting for
its cron, because what it answers is cheaper to know before a version is
consumed than after. It gates nothing, so it will not stop you: reading it
is the point.

**Read it per job, not as a verdict**, and open the failure rather than
inferring it from a sibling. A release ships what `uv.lock` pins, so drift
against a newer version of some dependency does not make the release
wrong — it says the next bump is going to be work.

Whether to close that drift now — `uv lock --upgrade`, gated by nothing
here — or leave it for Dependabot's own pull requests is a decision
worth stating rather than defaulting by omission: silence at the tag
reads as "nobody looked", not as "looked and chose to leave it". State
the choice in the release pull request, next to `deps-latest`'s own
result.

1. Read what is open, and land first anything that fixes the release path
   itself:

   ```shell
   gh pr list --state open
   gh pr list --state open --search "release.yml OR pypi-install.yml"
   ```

   A pull request touching `release.yml`, anything under
   `.github/scripts/`, or any workflow `release.yml` calls is one the tag
   is about to run, so leaving it in review means running the defect it
   fixes on the release. What it calls is a list this file would only let
   rot, so read it from the file itself:

   ```shell
   grep -n 'uses: \./\.github/workflows/' .github/workflows/release.yml
   ```

   It is not caught anywhere else: every one of those workflows is
   green on the pull request that fixes it, which is what makes it look
   like something that can wait. `pypi-install.yml` is the case to watch,
   its own failures arriving after PyPI has already accepted the files.

   The reverse question is worth the same minute: a pull request that is
   *not* ready is one this release ships without, so what the notes claim
   is what landed rather than what is nearly landed.

1. Read the public API against the previous release, before the notes that
   describe it are declared final. [RELEASE_NOTES.md](./RELEASE_NOTES.md)
   promises that a breaking change is announced there, the calendar version
   promising nothing, and nothing else reads that promise: the suite judges the
   code, and a reviewer weighs what the prose says rather than what it leaves
   out. griffe reads both revisions and answers that second question — not
   whether the list is right, but whether it is complete:

   ```shell
   uv run --locked --with griffe griffe check btclib_wallet \
       -a v<previous version>
   ```

   The first release has no previous tag, and there is nothing for this
   step to read; `release.yml`'s `public-api` job skips its check for the
   same reason.

   It reports breakage only: a public object removed, a parameter that
   changed kind or default, an attribute whose value moved. An addition is
   silent, so the output is short and every line of it wants an entry —
   what the step asks is that nothing it names is missing from RELEASE_NOTES.md.
   The converse is not its to answer: an entry describing a break it did
   not find is a claim about the prose, which review still has to read.
   Not a hook and not a job of `lint.yml`, deliberately: the comparison is
   against the previous *release*, so a break lands on `main` on purpose and
   remains a finding until the release that announces it, leaving every
   pull request in between red for something no branch introduced. It exits
   1 on a finding, so the day that reasoning stops holding — a cycle that
   means to break nothing — making it a gate is one line.

   `release.yml` asks the same question again as its `public-api` job,
   and a red one there is the expected shape of a cycle with breaking
   changes in it: the job gates nothing, its own comment saying why, and
   every job behind it opens its `if:` with `always()` and names the
   results it does require, so a red `public-api` costs the release
   nothing. What it costs is the run's own badge, red while every job
   that matters is green, which is why the step after the approval below
   reads the run job by job rather than as a whole.

1. Retitle the work-in-progress sections of
   [RELEASE_NOTES.md](./RELEASE_NOTES.md) and [CHANGELOG.md](./CHANGELOG.md) to
   `## v<version>` — the heading must be the version alone, and the section
   must not be empty. `release.yml` checks both before anything is built,
   because PyPI never accepts a version's file names twice, even once the
   release is deleted.

   In the same pull request, open the next cycle's section in both files,
   above the one just retitled — `## v<next YYYY.M> (work in progress, not
   released yet)`, with nothing under it yet. That section is what the
   next release's notes are written into, one landed change at a time,
   and opening it here is what keeps the topmost heading of either file
   on `main` a work-in-progress heading at every commit. Opening the
   next cycle in a pull request of its own after this one, ahead of
   anything else landing, is the rejected alternative: until that pull
   request lands the topmost section of each file is the release's, so
   a branch landing in between files its entry under a release it is
   not in, and nothing reports it, the release commit having touched
   only the heading. `release.yml`'s check reads the `## v<version>`
   section alone, so a heading above it is nothing it sees, and it is
   not what the release publishes: the notes are lifted from the section
   whose heading is the tag's own.

1. Set the version in `pyproject.toml`, which is the one place it is
   declared, to the date the release is cut, `YYYY.M.D`, and re-lock so
   `uv.lock` agrees:

   ```shell
   uv lock
   ```

   The date replaces the placeholder rather than extending it. *Open the
   next cycle* below sets the month after the release's, so a second
   release in the same month, built by appending the day to the
   placeholder, names a day of the next month — a date in the future,
   which sorts above every release that next month cuts before that day.
   `version-check` compares the tag with the declared version and reads
   the shape, never the calendar, so nothing downstream refuses it, and
   PyPI never accepts that version's file names again, even once the
   release is deleted.

   **If `main` moves while the gates run, throw the branch away and redo
   these edits on top of it — never rebase it, and never merge `main` into
   it.** CHANGELOG.md and RELEASE_NOTES.md are `merge=union`, so a change that
   opened a `### Repository` group where this release opens its own is
   fused into one section carrying that heading twice, and the union driver
   reports no conflict for a reader to catch. Reset onto the new tip, then
   redo the retitle, the version and `uv lock`, and gate again:

   ```shell
   git fetch origin
   git reset --hard origin/main
   ```

   The retitle, the headings it opens and the version are a few lines;
   what is expensive to reconstruct is the entries, and those are
   already on `main` in the pull requests that landed them. `git diff
   --cached` at the landing step
   below is the second reading of the same hazard, not a substitute for
   this one: by then the fused headings are what is being committed.

1. Give the release pull request its title and its body, before merging it
   and not after. The title is the version; the body says what the release
   is — what moved, what did not, and which of the two a user would
   notice. A squash leaves one commit whose message is that title, so the
   pull request is where the rest stays, and where a reader arriving from
   that commit lands. A template left unfilled, or a bot's summary of the
   diff, is not a substitute — the summary can stay, but what the diff
   cannot say has to be written, and what a reader should not have to
   discover at the button belongs there too.

   The section of RELEASE_NOTES.md the retitle step renamed is what that
   body is written from, and the reason it is filled in one landed change
   at a time rather than reconstructed from the diff on release day.
   Check it against
   `git log v<previous version>..main --oneline` regardless of how current
   it looks, rather than trust that every line landed when it should have.
   Griffe's result and the integration run belong in the body too, each a
   line rather than a screenshot — both are steps nothing else enforces,
   and a pull request that never mentions them reads exactly like one that
   skipped them.

1. Run `uv run pre-commit run --all-files` and `uv run pytest --cov`
   before pressing anything, then verify the
   [read the docs](https://readthedocs.org/projects/btclib-wallet/builds/)
   build renders. Read the *builds* page and not only the rendered one: a
   site that answers 200 may be serving the last build that succeeded,
   the webhook having quietly refused every delivery since.

1. Merge it, with the button, the way every other pull request here
   lands.

   "Squash and merge" is the only method either the repository setting
   or the ruleset accepts, and auto-merge presses it once the review and
   the checks are in. Branch protection requires an approving review
   and GitHub does not let an author approve their own, which on a
   solo-maintainer repository would stop every merge — the
   `main-self-merge` bypass in `pull_request` mode is what answers that,
   and only that. There is no second landing to choose between: a direct
   push to `main` is refused for everyone.

   `gh pr merge <n> --squash` alone can still refuse this pull request —
   `the base branch policy prohibits the merge` — because a
   solo-maintainer repository never clears `REVIEW_REQUIRED`, and gh's
   client-side mergeable check declines before it asks the server.
   `--admin` is the flag that clears it — the pair REPOSITORY.md's
   "Branch protection" describes, `enforce_admins` `false` together with
   holding `admin`. Name the release commit's title and body explicitly
   when using it — `gh pr merge <n> --squash --admin --body-file <path>
   --subject <title>` — rather than leave them to
   `squash_merge_commit_message`'s repository default, which concatenates
   the branch's commit messages.

   That the commit is composed by GitHub and signed with its web-flow
   key rather than yours costs nothing. What `main-integrity` requires
   is a signature, not a signer, and it enforces that with no bypass
   actor at all: a verified signature, linear history, no force push and
   no branch deletion, for administrators too.

   ```shell
   pr=<the release pull request's number>
   ```

   Split for the reason the tagging step gives.

   ```shell
   gh pr view "${pr:?}" --json state,mergeCommit \
     --jq '{state, merged_as: .mergeCommit.oid}'
   ```

   `MERGED` is what it reads, its `Closes #N` closes the issue, and
   GitHub deletes the release branch itself.

   Then read `lint` and `test` on the commit `main` ends up at before
   tagging, rather than trust the pull request's own green run:

   ```shell
   gh run list --commit "$(git rev-parse origin/main)"
   ```

   a squash creates a commit that is not the one the pull request tested,
   and the merge fires both workflows again from their own `push`
   trigger — a run of its own, not the `pull_request` run already green a
   moment earlier. That trigger is the whole reason `main` keeps one, and
   the run to read is the `push` run on `main`.

1. Rehearse on TestPyPI (see above) from `main`, if this cycle touched the
   publish path — that section says which changes make it worth the run,
   and asks that a skip be stated in the release pull request rather than
   left to be inferred.

1. Tag the release commit on `main` and push the tag. **Name the
   commit**, and read the tag back before pushing it. The values stand
   in a fence of their own with nothing under them to reach, and the
   fence below writes each as `${name:?}` and chains. Both are needed:
   `:?` fails at run time, which the chain propagates, where a parse
   error takes its own `&&` with it. Section 9 of the organization
   standard is the rule.

   ```shell
   version=<the version being released>
   sha=<the sha of the release commit>
   ```

   ```shell
   git tag -s "v${version:?}" -m "release v${version:?}" "${sha:?}" &&
   git show "v${version:?}:pyproject.toml" | grep '^version' &&
   git push origin "v${version:?}"
   ```

   `git tag` with no commit tags whatever HEAD the shell is in, and every
   step above ran in a worktree while the primary checkout sits on another
   branch — so the argumentless form is one `cd` away from tagging the
   commit before the version bump. `version-check` would refuse it,
   comparing the declared version against the tag's and failing the run
   with nothing uploaded, which is the guard doing its job; the `git show`
   above is the same check one step earlier, where it costs nothing, and
   the chain is what makes the push wait on it.

1. Approve the `pypi` environment when the workflow asks. Up to here
   nothing is public and the tag can still be deleted; the upload that
   follows is the point of no return — the upload, and not the approval,
   the token exchange happening after it. A registration that does not
   match the claims fails there having uploaded nothing, and a version
   survives a failed exchange: delete the tag, fix the registration, tag
   again.

   A registration that matched once can still go stale on its own — a
   repository rename is enough — without anything here flagging it before
   the upload tries. Where only the token exchange failed, fixing the
   registration and running `gh run rerun <run id> --failed` republishes
   from the artifacts already there; retagging is the right answer only
   when the failure happened before those artifacts existed — see "If
   something goes wrong" below.

   A job that sits `queued` with no runner assigned for tens of minutes,
   on an ordinary `ubuntu-latest` label, past the point where the
   environment approval has already gone through, is not this repository's
   problem to fix: the org's GitHub Actions concurrency is shared across
   every `btclib-org` repository, and a burst of CI elsewhere in the
   organization is enough to queue this one behind it. Confirm
   there is nothing to fix rather than assume it — githubstatus.com green,
   no `pending_deployments` left on the run, no concurrency group of this
   repository's own blocking it — then wait; cancelling or re-dispatching
   a job that is merely queued, not failed, risks a second attempt racing
   the first one into `publish-pypi`.

1. Read the run job by job once it has ended, for `skipped` rather than
   for red. A failed job is loud; a skipped one carries no step, starts
   and completes in the same second, and leaves the run looking finished
   with a job missing from it, which is what a bare `needs:` behind a
   red `public-api` produces — section 12 of the organization standard
   has the rule, and the `github-release` case under "If something goes
   wrong" below is the same mechanism behind a skipped job rather than a
   failed one:

   ```shell
   run=<run id>
   ```

   The assignment stands in a fence of its own, and the fence below
   takes the pair the tagging step explains: inside quotes a placeholder
   is no parse error, so the fence is not its own guard.

   ```shell
   gh api --paginate \
     --jq '.jobs[] | [.conclusion, (.steps|length), .name] | @tsv' \
     "repos/btclib-org/btclib-wallet/actions/runs/${run:?}/jobs?per_page=100"
   ```

   On a tag `Publish to TestPyPI` is `skipped`, its trigger being the
   dispatch, and `public-api` is red on any cycle with breaking changes
   in it, being the griffe step above run again. Every other job reads
   `success`, the ones behind `public-api` included: each of them opens
   its `if:` with `always()` and names the results it does require, so a
   red `public-api` costs the release nothing, and a `skipped` among them
   is a defect in `release.yml` rather than a red to look past. A
   rehearsal is the mirror image, `Publish to PyPI` skipped and with it
   whatever is guarded on its success, and `documented` skipped on its
   own account, its guard being the push. `gh run rerun` does not reach a
   skipped job, `--failed` rerunning `failure` and `--job` refusing a skip
   outright, so what recovers one is doing by hand what it would have
   done: for `github-release` the script "If something goes wrong" gives,
   for `published` a dispatch of `pypi-install.yml`, which installs what
   the index serves at the time.

1. Install what was just published, in an environment of its own rather
   than one that may already hold it, and run something with it:

   ```shell
   uv run --isolated --no-project --with btclib-wallet \
     python -c "import btclib_wallet; print(btclib_wallet.__version__)"
   ```

   from a directory that belongs to no checkout of this project: run
   inside one, uv can answer from a cached build of the tree rather than
   from the index.

   then check the attestations — the JSON API answers `null` for
   `provenance` even where they exist; the
   [simple API](https://pypi.org/simple/btclib-wallet/) (`Accept:
   application/vnd.pypi.simple.v1+json`) carries the real link, under
   `/integrity/<project>/<version>/<filename>/provenance`, and
   `pypi-attestations verify pypi <file> --repository
   https://github.com/btclib-org/btclib-wallet` checks the
   signature rather than merely its presence.

1. Read the `published` job of the release run, which needs no dispatch:
   `release.yml` calls that workflow once PyPI has accepted the files, with
   the tag's version, and it waits for the index to serve that version
   before installing anything — so it cannot pass by testing the release
   before this one. It installs from PyPI on every image `os-ubuntu.yml`,
   `os-macos.yml` and `os-windows.yml` run between them, at the floor of
   the supported interpreter range and at its two newest interpreters,
   each of those beside its free-threaded build, and derives an address
   with it. From then on it runs weekly on
   its own, and a failure means the outside world moved, not this
   repository — a new
   runner image, an interpreter release, PyPI serving a file that does not
   match its own hash — which is why it is a workflow of its own rather
   than a job of this one.

1. Check the GitHub release the previous step's workflow run created —
   **ask for the release itself, not for the run's conclusion**, a
   skipped job being what a green run looks like from the Actions page:

   ```shell
   version=<the released version>
   ```

   Split for the reason the tagging step gives.

   ```shell
   gh release view "v${version:?}" --json name,assets,author
   ```

   `release not found` is the failure "If something goes wrong" ends with.
   `author` is the cheap second question: `github-actions` is the workflow
   having cut it, any other login a release recreated by hand. Its notes
   are the tag's section of RELEASE_NOTES.md, and the distribution files are
   attached, `<tag>.attestation.jsonl` and the bill of materials beside
   them. A run that logs
   `RELEASE_NOTES.md has no v<version> section` generated the notes from the
   merged pull requests instead — the fallback `version-check` exists to make
   unreachable, not a second way to write release notes — and they are worth
   replacing by hand if it ever fires.

1. Read the bill of materials attached to the release,
   `btclib_wallet-<version>.cdx.json`: a CycloneDX 1.6 document naming
   the distribution, its licence, the two files with their SHA-256, and
   one component per dependency the wheel's metadata declares. It is read
   out of the built wheel and not out of `pyproject.toml`, which is what
   lets a rehearsal describe the `.dev` version it actually built. A
   component that is not a dependency `pyproject.toml` declares is one
   this repository did not mean to ship. Attested with the distribution
   files, so `gh attestation verify` below covers it too.

1. Verify the provenance of an asset, which is the release's own and not
   the PEP 740 attestations checked two steps up: those cover the copies
   on the index, these the copies attached here. Both forms, the same
   signature read two ways:

   ```shell
   version=<the released version>
   ```

   ```shell
   gh release download "v${version:?}" --repo btclib-org/btclib-wallet &&
   wheel=btclib_wallet-${version:?}-py3-none-any.whl &&
   repo=btclib-org/btclib-wallet &&
   signer=btclib-org/.github/.github/workflows/reusable-attest.yml &&
   gh attestation verify "$wheel" --repo "$repo" \
     --signer-workflow "$signer" &&
   gh attestation verify "$wheel" --repo "$repo" \
     --bundle "v${version:?}.attestation.jsonl"
   ```

   the first asks the attestations API for the signed statement, the
   second reads it from the asset and asks nothing — which is what the
   bundle is attached for, mirroring the releases page being the case it
   answers. One attestation covers every asset the `attest` job was
   given, so the sdist and the bill of materials verify against the same
   bundle.

   `--signer-workflow` is the flag that makes the check say *which*
   workflow signed: without it a valid attestation from any workflow in
   the repository passes. The signing runs inside `btclib-org/.github`'s
   `reusable-attest.yml`, which `release.yml`'s `attest` job calls, so
   that is the workflow the certificate names, while `--repo` still names
   this repository. Neither form is offline on its own — the
   Sigstore trusted root comes over the network unless
   `gh attestation trusted-root > trusted_root.jsonl` fetched it earlier
   and `--custom-trusted-root` points at it.

1. Open the next cycle: set a generic next version without the day (e.g.
   after 2026.8.6, use 2026.9) in `pyproject.toml`, through a pull
   request like any other. That shape is the one nothing tagged can have,
   so a checkout of `main` between releases reports itself as work in
   progress rather than as a release it is not, and `version-check`
   refuses it should it ever reach a tag — which is a second guard behind
   the heading check, not a replacement for it. Re-lock so `uv.lock`
   agrees:

   ```shell
   uv lock
   ```

   The two "work in progress" sections are already there, the retitle
   step above having opened them in the release's own pull request. What
   stays here is the version, which cannot move earlier with them:
   `version-check` compares the tag against what `pyproject.toml`
   declares, so a tree already bumped would offer it the next cycle's
   month instead of the version being released.

## Rebuild a release from its tag

test.yml's `dist` job exports `SOURCE_DATE_EPOCH` from the commit date
and normalizes the sdist, so a rebuild of a released tag is the same
bytes as what was published — that job's own upload is what
`publish-pypi` publishes, unchanged, so "what was published" and "what
that job built" are the same files (issue btclib-org/btclib#1166).
Anyone can check that, and the check is one command short of the
provenance one above: verify the *rebuilt* file rather than a downloaded
one, and it can only pass if the digests agree.

```shell
version=<the released version>
```

The placeholder stands in a fence with nothing under it to reach, and the
fence below writes it `${version:?}` and chains, which is the pair the
tagging step of *Release to PyPI* describes. `SOURCE_DATE_EPOCH` is
exported rather than prefixed onto the build: a prefix binds one
command, and both scripts below read the variable out of their own
environment and refuse to run without it.

```shell
git worktree add --detach /tmp/btclib-wallet-rebuild "v${version:?}" &&
cd /tmp/btclib-wallet-rebuild &&
python=$(grep -Ev '^[[:space:]]*(#|$)' .python-version) &&
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct) &&
repo=btclib-org/btclib-wallet &&
signer=btclib-org/.github/.github/workflows/reusable-attest.yml &&
wheels=$(mktemp -d) &&
gh release download "v${version:?}" --repo "$repo" --dir "$wheels" \
  --pattern '*.whl' &&
gh attestation verify "$wheels"/*.whl \
  --repo "$repo" --signer-workflow "$signer" &&
uv_version=$(unzip -p "$wheels"/*.whl '*.dist-info/WHEEL' |
  sed -n 's/^Generator: uv //p') &&
[[ $uv_version =~ ^[0-9]+([.][0-9]+)*$ ]] &&
uvx "uv@$uv_version" build &&
uv run --no-project --python "$python" \
  .github/scripts/normalize_sdist.py dist/ &&
uv run --no-project --python "$python" \
  .github/scripts/generate_sbom.py dist/ sbom/ &&
gh attestation verify "dist/btclib_wallet-${version:?}.tar.gz" \
  --repo "$repo" --signer-workflow "$signer" &&
gh attestation verify "dist/btclib_wallet-${version:?}-py3-none-any.whl" \
  --repo "$repo" --signer-workflow "$signer" &&
gh attestation verify "sbom/btclib_wallet-${version:?}.cdx.json" \
  --repo "$repo" --signer-workflow "$signer"
```

`python` is the interpreter the tag's own `.python-version` pins, its
comment and blank lines dropped, and not the one `main` pins:
`normalize_sdist.py` writes the sdist again through the running
interpreter's `gzip`, so a rebuild under another pin is the published
bytes only where the two interpreters' zlib compress alike (issue
btclib-org/.github#1349).

`uv_version` is the uv the release job ran, read off the published
wheel once its attestation verifies, so that what is read is signed: its
`.dist-info/WHEEL` names it on the `Generator:` line, where the tag holds
only `[tool.uv] required-version`, a floor `setup-uv` resolves to the
newest uv at release time. The `[[ ]]` holds it to digits and dots
before `uvx` sees it, `uvx` taking a URL or a VCS reference in that
place and running what it fetches. That line is written by the
build, so a wheel built under another uv is another digest (issue
btclib-org/btclib-node#1063). The sdist is verified first, it being the
file the rebuild exists to reproduce: a wheel that still disagrees stops
the chain after that check rather than ahead of it.

The bill of materials is rebuilt with them and verified like them: its
timestamp is `SOURCE_DATE_EPOCH` and its serial number is derived from
the two digests, so it is the same bytes as the released copy — which is
the only reason a third `gh attestation verify` can pass at all. It is
no steadier than the files, though: any of the bounds below that moves a
distribution file's digest moves this document's serial number with it,
so the third command fails wherever the first two do.

Three things bound that guarantee, and each is worth knowing before
reading a mismatch as tampering:

- **the build reads the working directory, not git.** `uv_build` walks
  the tree through the glob patterns of `[tool.uv.build-backend]`, so an
  *untracked* file matching one of them is packed like any other and
  changes the digest. `tests/**` and `docs/**` are the patterns wide
  enough for that to happen by accident, and `source-exclude` beside them
  names what a linter or a type checker is known to leave there — but the
  rule is the directory, not the list. The worktree the command above
  adds is a clean tree whatever the reader's checkout holds: it has only
  the files the tag tracks, and `git worktree add` refuses a target that
  already holds files.
- **the build backend is the uv's own.** `[build-system] requires`
  names a range rather than a version, and for
  the uv the release ran, which the range admits, `uv build` uses the
  backend built into that uv rather than a `uv_build` resolved from the
  range. That is why the command above runs the release's uv rather than
  the reader's, and why it reproduces the wheel only while that uv can
  still be installed. The sdist's member metadata is `normalize_sdist.py`'s
  answer and not the backend's, which is why the command above runs that
  script and why a rebuild that skips it disagrees with the published
  archive on every member's `mtime`.
- **the rehearsal is a different version, by construction.** A TestPyPI
  dispatch appends `.dev<run*100+attempt>` to the version, so its files are not
  a second build of the release's — they are their own artifact, published
  where they say they are. The attestation the rehearsal writes covers
  those, and no digest is shared with the release.

## If something goes wrong

- The workflow failed before the `publish-pypi` job: nothing was
  uploaded. Delete the tag, fix, and tag again:

  ```shell
  git tag -d v<version>
  git push origin :refs/tags/v<version>
  ```

  Both lines, and the local one is the half that is easy to skip: a tag is
  per-repository where a branch is per-worktree, so deleting it in one
  worktree leaves it in every other, and the `git tag -s` that follows
  answers `fatal: tag 'v<version>' already exists` — from a checkout that
  looks uninvolved. Delete locally wherever it is, then re-create.

- `publish-pypi` itself ran and failed at the token exchange
  (`invalid-publisher`), after the matrix had already built everything:
  nothing was uploaded, but retagging would rebuild what was never at
  fault. Fix the registration and re-run the publish job alone against
  what is already built:

  ```shell
  run=<the release.yml run>
  ```

  Split for the reason the tagging step gives.

  ```shell
  gh run rerun "${run:?}" --failed
  ```

  a fresh approval of the `pypi` environment is still required, the
  protection applying per deployment attempt rather than once per run.
  This is a different case from the one above: there, the workflow never
  reached `publish-pypi`, so there is nothing to re-run and no artifact to
  re-run it against.

- The upload succeeded but the release is broken: PyPI never accepts a
  file name twice, even after deletion. Yank the bad release on PyPI and
  publish a new patch version, a fourth number on the day
  (`2026.8.6` → `2026.8.6.1`).

- Only the `github-release` job failed: the PyPI upload is already done;
  re-run the failed job, or recover by hand from the run's `dist`,
  `sbom` **and** `attestation` artifacts, not `dist` alone — the job
  downloads all three before it writes the release, and a release built
  from `dist` only would carry the wheel and the sdist with no signed
  statement beside them, leaving "Verify the provenance of an asset"
  above nothing to `--bundle` against, and no bill of materials for
  "Read the bill of materials attached to the release" to read. The
  by-hand recovery is the same script the `skipped` case spells out
  next; the difference between the two is only that `gh run rerun
  --failed` reaches a job the run marks *failed*, so it is worth trying
  first here and is not an option there at all.

- `github-release` shows **`skipped`** rather than failed, though both of
  its needs — `publish-pypi` and `attest` — report `success`. The run's own
  conclusion is `success` and no release exists, which is why the step
  above asks `gh release view` rather than reading the run. What produces
  it is a job the release path does not depend on and cannot see:
  `publish-testpypi` is skipped on a tag, `attest` needs it, and a job
  standing behind a skipped ancestor is skipped in turn unless its own
  condition opts out with `always()` — which `attest` does for itself and
  cannot do on behalf of what needs `attest`. Every job that crosses a
  skip has to say `always()`, so the answer is an explicit `if` on the job
  that shows the symptom, not on the one that caused it. Recovery is by
  hand: `gh run rerun --job` refuses a skipped job outright (`cannot be
  rerun`), unlike a failed one. Re-running the whole workflow is not the
  fix either: `publish-pypi` would attempt the upload a second time, and
  while PyPI would refuse the existing file names rather than accept a
  duplicate, the attempt itself asks for a fresh approval of the `pypi`
  environment and gates the run on nothing this repository controls. Skip
  the workflow entirely and do by hand exactly what the job's own script
  does, from the artifacts already sitting on the run:

  ```shell
  run=<run id>
  version=<the released version>
  ```

  The assignments stand in a fence of their own, and the fence below
  takes the same pair as the tagging step.

  ```shell
  gh run download "${run:?}" -n dist -D dist &&
  gh run download "${run:?}" -n sbom -D sbom &&
  gh run download "${run:?}" -n attestation -D attestation &&
  shasum -a 256 dist/* &&
  curl -s "https://pypi.org/pypi/btclib-wallet/${version:?}/json" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin)
  [print(u["filename"], u["digests"]["sha256"]) for u in d["urls"]]' &&

  git show "v${version:?}:RELEASE_NOTES.md" | awk -v tag="v${version:?}" '
    $0 ~ "^## " tag "( |$)" {found=1; next}
    /^## / && found {exit}
    found {print}
  ' > notes.md &&
  cp attestation/attestation.jsonl "v${version:?}.attestation.jsonl" &&
  gh release create "v${version:?}" dist/* sbom/* \
    "v${version:?}.attestation.jsonl" \
    --title "v${version:?}" --notes-file notes.md
  ```

  The digest comparison is not optional: it is what stands in for the
  provenance a second, unwanted publish attempt would otherwise have to
  establish, confirming the files a human is about to attach are the
  exact bytes the token exchange already accepted rather than a fresh
  local build that merely claims to be.
