#!/bin/bash
set -eux
NODES=${NODES:='None'}

RUST_TEST_THREADS=1 cargo test --all
cross test --target x86_64-unknown-linux-musl --verbose -p rita --bin rita -- --test-threads=1
cross test --target mips-unknown-linux-gnu --verbose -p rita --bin rita -- --test-threads=1
cross test --target mipsel-unknown-linux-gnu --verbose -p rita --bin rita -- --test-threads=1
cross test --target mips64-unknown-linux-gnuabi64 --verbose -p rita --bin rita -- --test-threads=1
cross test --target mips64el-unknown-linux-gnuabi64 --verbose -p rita --bin rita -- --test-threads=1
cross test --target aarch64-unknown-linux-gnu --verbose -p rita --bin rita -- --test-threads=1

if ! modprobe wireguard ; then
	echo "The container can't load modules into the host kernel"
	echo "Please install WireGuard https://www.wireguard.com/ and load the kernel module using 'sudo modprobe wireguard'"
	exit 1
fi

# cleanup docker junk or this script will quickly run you out of room in /
echo "Docker images take up a lot of space in root if you are running out of space select Yes"
docker system prune -a -f

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DOCKERFOLDER=$DIR/../integration-tests/container/
REPOFOLDER=$DIR/..
git archive --format=tar.gz -o $DOCKERFOLDER/rita.tar.gz --prefix=althea_rs/ HEAD
pushd $DOCKERFOLDER
time docker build -t rita-test --build-arg NODES=$NODES .
time docker run --privileged -it rita-test
rm rita.tar.gz
popd
