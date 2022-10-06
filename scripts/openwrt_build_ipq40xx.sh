#!/bin/bash
set -eux
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Parse command line arguments
source $DIR/build_common.sh

# cargo install cross

cross build --target armv7-unknown-linux-musleabihf ${PROFILE} ${FEATURES} -p rita_bin --bin rita
