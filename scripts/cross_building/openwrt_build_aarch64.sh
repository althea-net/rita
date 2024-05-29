#!/bin/bash
set -eux
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Parse command line arguments
source $DIR/build_common.sh

cargo install cross

cross build --target aarch64-unknown-linux-musl ${PROFILE} ${FEATURES} -p rita_bin --bin ${RITA_VERSION}
