#!/bin/bash
# You may need to disable or modify selinux
set -eux

RUST_TOOLCHAIN="stable"

RUST_MUSL_BUILDER="docker run --rm -it -v "$(pwd)":/home/rust/src ekidd/rust-musl-builder:$RUST_TOOLCHAIN"
$RUST_MUSL_BUILDER cargo build --all --release
