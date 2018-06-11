#!/bin/bash
# You may need to disable or modify selinux
set -eux
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BUILDER="docker run --rm -it -v $(pwd):/home/rust/src ekidd/rust-musl-builder"
pushd $DIR
cargo clean
$BUILDER cargo build --all --release
