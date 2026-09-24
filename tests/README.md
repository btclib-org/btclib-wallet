# Tests and code coverage

## The suite

```shell
uv sync
uv run pytest
```

`--cov` is in `addopts`, so the bare `pytest` is the coverage gate, the
same measurement the `coverage` job makes, and it answers against
`fail_under` in `pyproject.toml`. A run that selects a subset — a path
that leaves part of the suite behind, `-k`, `-m`, `--deselect`,
`--ignore`, `--ignore-glob` or `--lf` — prints the report without the
threshold: `coverage_fail_under` in `tests/conftest.py` is where that
happens, and section 8 of [the organization standard][std] names the
set.

```shell
uv run pytest --no-cov
```

runs the suite without measuring anything.

The suite writes nothing but for one deliberate exception, asked for by
name. A test comparing a `to_dict()` against a json file under
`tests/**/_generated_files/` fails on a change to the serialized form,
and when that change is the intended one

```shell
BTCLIB_REGENERATE_GOLDEN=1 uv run pytest
```

rewrites the files, and the diff it leaves is the review the change
wants.

## The integration tests, and why they are off by default

`tests/integration/` needs what this repository does not ship: a
`bitcoind` to talk to, an `hwi` to run, a device to press a button on.
Each test skips itself without the switch that asks for it, and says
which switch was off:

```shell
BTCLIB_INTEGRATION=1 uv run pytest tests/integration
```

That runs the regtest flow against a node of the session's own, in a
data directory under pytest's `tmp_path` and on ephemeral ports. Name a
binary with `BTCLIB_BITCOIND=/path/to/bitcoind`, or the one on `PATH`
is used.

The HWI tests need a device as well, and a second switch for the one
that asks it to sign:

```shell
BTCLIB_INTEGRATION=1 BTCLIB_HWI=hwi BTCLIB_HWI_SIGN=1 \
    uv run pytest tests/integration/hwi_device_test.py -n0
```

`BTCLIB_HWI` is the executable, split on spaces, so an emulator is
reached with `BTCLIB_HWI="hwi --emulators"`. `-n0` because there is one
device, and `addopts` passes `-n auto`.

These tests are outside the coverage ratchet, which `pyproject.toml`
says where it omits them. `integration-bitcoind.yml` and
`integration-hwi.yml` run them unattended, and each job fails if its
tests skipped rather than ran.

## Fuzzing, and replaying a crash it finds

`tests/fuzz_test.py` is Hypothesis over every parser of the public
surface, part of the ordinary `uv run pytest` above. Coverage-guided
fuzzing is a separate job: `fuzz.yml` runs every `fuzz/fuzz_*.py`
harness with `atheris` under ClusterFuzzLite, weekly and on
`workflow_dispatch`, never on `uv run pytest` and never inside the
coverage ratchet. Atheris 3.1.0 ships no wheel for macOS or aarch64, so
the machine writing the code cannot run a harness with `uv run` the way
the rest of the suite does; what it can still do is replay a crash the
workflow already found, in the same images the workflow used --
`base-builder-python` to build the harness, `base-runner` to run it --
which is what makes the missing wheel irrelevant to reproducing a
finding rather than blocking it.

A crash `fuzz.yml` finds is attached to that run as a GitHub Actions
artifact named `crashes-<fuzzer>` (`<fuzzer>` the crashing
`fuzz/fuzz_*.py` file's own stem), holding the input under a
sanitizer-named directory with a `.summary` beside it carrying the
stack trace. The run id is in the run's own URL, so the two are quoted
for the download call beside them and stand in an assignment block of
their own above it, unset being what an unfilled paste of that block
alone supplies:

```shell
run_id=<run-id>
fuzzer=<fuzzer>
```

```shell
gh run download "${run_id:?}" -n "crashes-${fuzzer:?}"
```

Replaying it needs a checkout of
[google/oss-fuzz](https://github.com/google/oss-fuzz), whose
`infra/helper.py` drives the same build `.clusterfuzzlite/Dockerfile`
describes -- `gcr.io/oss-fuzz-base/base-builder-python` -- for a
project outside its own `projects/` tree via `--external`
(`google/clusterfuzzlite`'s `docs/build_integration.md`, "Testing
locally", which is where `--external` is spelled;
`google/oss-fuzz`'s `docs/advanced-topics/reproducing.md` has the shape
of `reproduce` and not that flag):

```shell
btclib_wallet_checkout=<btclib-wallet-checkout>
fuzzer=<fuzzer>
crash_file=<path-to-crash-file>
```

`:?` in the commands below is what makes an unfilled paste stop: the
shell refuses to expand a variable left unset and the command never
runs. Filling the block above is what arms them; deleting the `:?`
disarms them.

```shell
git clone --depth=1 https://github.com/google/oss-fuzz.git
```

```shell
python3 oss-fuzz/infra/helper.py build_fuzzers \
    --external "${btclib_wallet_checkout:?}" --sanitizer address
```

```shell
python3 oss-fuzz/infra/helper.py reproduce \
    --external "${btclib_wallet_checkout:?}" "${fuzzer:?}" "${crash_file:?}"
```

`reproduce` forwards trailing arguments to the fuzzer's own libFuzzer
binary, which is where minimization comes from -- the crashing input
shrunk to what still reproduces it, written back to oss-fuzz's own
`build/out/` for this checkout, the directory `reproduce` mounts as
`/out`. Two things about the invocation are not obvious and both are
`helper.py`'s: `fuzzer_args` is declared `nargs='*'` rather than
`argparse.REMAINDER`, so a first token beginning with `-` is read as an
option to `helper.py` itself and refused -- `--` is what ends its own
arguments; and `reproduce_impl` prepends `-runs=100`, which is the
whole minimization budget unless a later `-runs` overrides it, libFuzzer
taking the last occurrence of a flag:

```shell
python3 oss-fuzz/infra/helper.py reproduce \
    --external "${btclib_wallet_checkout:?}" "${fuzzer:?}" "${crash_file:?}" \
    -- -minimize_crash=1 -runs=100000
```

What to do with the minimized input from there is `fuzz.yml`'s own
comment and `fuzz/fuzz_*.py`'s: a regression test naming it and the
exception the parser is expected to raise on it.

Not `fuzz/corpus/<name>/`, which is a seed corpus checked into the
tree and asserted still valid by `tests/fuzz_corpus_test.py`; `fuzz.yml`'s
own comment is where the reason a crash cannot live there is argued. The
corpus a batch run accumulates lives the same way a crash does, a GitHub
Actions artifact named `cifuzz-corpus-<fuzzer>`, `fuzz.yml` naming no
`storage-repo` to keep it in a git branch instead. The prefix is the
difference: `GithubActionsFilestore.upload_corpus` goes through
`_upload_directory`, which prepends `cifuzz-`, where `upload_crashes`
calls `_raw_upload_directory` and does not -- so the two names are not
the same shape, and a download asking for the wrong one answers
`no artifact matches any of the names or patterns provided`.

## Convention tests

Section 7 of [the organization standard][std] lists conventions a suite
can turn into a red test, and a repository needs the ones its own prose
states rather than all of them. So which of them this repository tests
is declared here, in two halves that together account for every one of
them: the table below and the "Not tested here" line under it. One row
per module, so a convention answered by more than one file is named once
per file, and `conventions_test.py` asserts the declaration is true.

| convention | tested in |
| --- | --- |
| the public surface | `all_test.py` |
| the copyright header | `copyright_test.py` |
| the documentation | `docs_test.py` |
| the import graph | `imports_test.py` |
| the changelog | `release_notes_test.py` |
| the calling convention | `keyword_only_test.py` |
| the calling convention | `name_contract_test.py` |
| the calling convention | `private_defaults_test.py` |
| input validation | `input_validation_test.py` |

Not tested here: the build system; the suite opens no socket.

[std]: https://github.com/btclib-org/.github/blob/main/README.md
