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

RUST_TOOLCHAIN="stable"
CARGO_ROOT="$HOME/.cargo"
CARGO_GIT="$CARGO_ROOT/.git"
CARGO_REGISTRY="$CARGO_ROOT/registry"

docker pull ekidd/rust-musl-builder
RUST_MUSL_BUILDER="docker run --rm -it -v "$(pwd)":/home/rust/src -v $CARGO_GIT:/home/rust/.cargo/git -v $CARGO_REGISTRY:/home/rust/.cargo/registry ekidd/rust-musl-builder"
$RUST_MUSL_BUILDER sudo chown -R rust:rust /home/rust/.cargo/git /home/rust/.cargo/registry

$RUST_MUSL_BUILDER cargo build --all ${PROFILE} --features server,${FEATURES}
