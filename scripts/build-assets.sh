#!/usr/bin/env bash
# Build the release archives for scripts/release.sh: one mcpscan binary per platform plus SHA256SUMS.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
version="${1:?usage: scripts/build-assets.sh vX.Y.Z}"
make dist VERSION="$version"
mkdir -p dist/release
mv dist/mcpscan_* dist/SHA256SUMS dist/release/
ls dist/release
