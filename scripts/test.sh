#!/bin/bash
set -eux
RUST_TEST_THREADS=1 cargo test --all

modprobe wireguard
# cleanup docker junk or this script will quickly run you out of room in /
docker system prune -a

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DOCKERFOLDER=$DIR/../integration-tests/container/
REPOFOLDER=$DIR/..
tar --exclude $REPOFOLDER/target \
    --exclude $REPOFOLDER/**/target \
    --exclude $REPOFOLDER/integration-tests/althea_rs_a \
    --exclude $REPOFOLDER/integration-tests/althea_rs_b \
    --exclude $REPOFOLDER/integration-tests/target_a \
    --exclude $REPOFOLDER/integration-tests/target_b \
    --exclude $REPOFOLDER/integration-tests/deps \
    --exclude $REPOFOLDER/integration-tests/container/rita.tar.gz \
    --exclude $REPOFOLDER/scripts -czf $DOCKERFOLDER/rita.tar.gz $REPOFOLDER
#git archive -v -o $DOCKERFOLDER/rita.tar.gz --format=tar.gz HEAD
pushd $DOCKERFOLDER
docker build -t rita-test .
docker run --privileged -it rita-test
rm rita.tar.gz
popd
