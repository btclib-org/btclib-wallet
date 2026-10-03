# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.
#
# uv, pinned by digest below the same way as the image build.sh runs in:
# build.sh reads uv.lock through it, and that image carries no uv of its
# own. astral-sh/uv's own docs, "Installing uv", name digest-pinning the
# distroless image as the practice over `latest` or a bare version tag.
FROM ghcr.io/astral-sh/uv@sha256:f513a91fc62fe7c17567eee97230dd198e43edb8a9fbecca843714a4358fe1bc AS uv

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

COPY --from=uv /uv /usr/local/bin/uv

COPY . $SRC/btclib-wallet
WORKDIR $SRC/btclib-wallet
COPY ./.clusterfuzzlite/build.sh $SRC/
