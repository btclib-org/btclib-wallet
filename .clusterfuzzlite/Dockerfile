# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.
#
# The container `build.sh` runs in. `base-builder-python` is the image
# docs/build-integration/python_lang.md names for a Python project --
# atheris and its runtime dependencies are pre-installed there, which is
# why neither is listed here or in build.sh.
#
# ClusterFuzzLite copies the checked-out tree in rather than cloning it,
# unlike a plain OSS-Fuzz integration (docs/build_integration.md,
# "Prerequisites"): the workflow's own checkout step is what puts the
# source `docker build` sees on disk, so no `git clone` belongs here.
#
# Pinned by digest rather than the `latest` tag it otherwise carries, so
# a moved or compromised image does not change what a scheduled run
# builds with no diff here. Re-read the digest before bumping it rather
# than trusting the tag: the `Docker-Content-Digest` response header on
# `gcr.io/v2/oss-fuzz-base/base-builder-python/manifests/latest`.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:cfcc123c40d4ecab777ac0f32f868177cb752950bf9f5d880f55e452adda5106

COPY . $SRC/btclib-wallet
WORKDIR $SRC/btclib-wallet
COPY ./.clusterfuzzlite/build.sh $SRC/
