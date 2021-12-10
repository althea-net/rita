#!/bin/bash
set -eux
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo $DIR

pushd $DIR/../cross-builders/exit
docker build -t cross-with-clang-ssl .
cp Cross.toml ../..
popd
pushd $DIR/..
cross build --release --target x86_64-unknown-linux-gnu  -p rita_bin --bin rita_exit
rm Cross.toml
