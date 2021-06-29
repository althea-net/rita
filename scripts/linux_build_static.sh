#!/bin/bash
# Usage: ./linux_build_static [--debug] [--release]
#
# This script builds a static Linux binaries.
#
# Options:
#   --debug (optional) Use debug profile
#   --release (optional) Use release profile (default)
#   --features (optional) List of features to build
#
# Note: You may need to disable or modify selinux, or add $USER to docker group
# to be able to use `docker`.
set -eux

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

# Parse command line arguments
source $DIR/build_common.sh
pushd $DIR/dockerfile
docker build -t cross-rita .
popd
pushd $DIR/../
cross build --target x86_64-unknown-linux-gnu --all ${PROFILE} --features rita/openssl
popd