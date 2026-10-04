#!/bin/bash -eu
# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.
#
# Runs inside the container the Dockerfile beside this file builds, cwd
# at $SRC/btclib-wallet (the Dockerfile's WORKDIR). $CC, $CXX, $CFLAGS and
# $LIB_FUZZING_ENGINE are ClusterFuzzLite's own, exported before this
# script runs; the install below is what puts them in front of any
# extension a dependency compiles, which is why it has to happen inside
# this container and not in the Dockerfile. uv.lock pins btclib and every
# other runtime dependency; `uv export` reads it into a hashed
# requirements file so `pip3 install --require-hashes` resolves nothing
# of its own from the index, and the project installs `--no-deps` right
# after, its own dependencies already satisfied by that file.
#
# The three-line shape -- install, discover, compile -- is
# docs/build-integration/python_lang.md's own example build.sh for a
# Python project, and google/oss-fuzz's projects/idna/build.sh, a
# pure-Python parser of untrusted input the way this tree's parsers are.
uv export --locked --no-dev --no-emit-project -o requirements.txt
pip3 install --require-hashes -r requirements.txt
pip3 install --no-deps .

# compile_python_fuzzer forwards every extra argument straight to
# pyinstaller, ahead of the fuzzer's own path (base-builder's own
# compile_python_fuzzer script). A frozen onefile executable bundles no
# non-Python file PyInstaller cannot trace a reference to, and these
# packages read files under their own directory from a path built off
# `__file__`. --collect-data names the project's own package and every
# distribution requirements.txt pins, its name with `-` read as `_`.
# For a name that is a module, or is not the import name, PyInstaller
# warns and collects nothing.
collect=--collect-data=btclib_wallet
for dist in $(sed -n 's/^\([A-Za-z0-9_.-]*\)==.*/\1/p' requirements.txt); do
  collect="$collect --collect-data=$(echo "$dist" | tr '-' '_')"
done

# The same loop also zips each target's own seed corpus, one
# fuzz/corpus/<name>/ directory per fuzzer (google/fuzzing's glossary,
# "Seed Corpus": inputs "checked into source alongside fuzz targets"),
# under the name libFuzzer picks up next to a target's own binary with
# no configuration -- so a new fuzz_*.py with a corpus directory beside
# it is picked up here without a second list of names to keep in step
# with the first.
for fuzzer in $(find "$SRC/btclib-wallet/fuzz" -maxdepth 1 -name 'fuzz_*.py'); do
  compile_python_fuzzer "$fuzzer" $collect
  name=$(basename "$fuzzer" .py)
  if [ -d "fuzz/corpus/$name" ]; then
    zip -j "$OUT/${name}_seed_corpus.zip" "fuzz/corpus/$name"/*.bin
  fi
done
