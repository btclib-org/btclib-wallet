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
