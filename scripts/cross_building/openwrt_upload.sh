#!/usr/bin/env bash
set -eux
export TARGET=ipq40xx
export TRIPLE=armv7-unknown-linux-musleabihf
export RITA_VERSION=rita_exit
export ROUTER_IP=192.168.10.1
#heartbeat-test-router
bash scripts/cross_building/openwrt_build_$TARGET.sh --features rita_bin/development
set +e
ssh root@$ROUTER_IP killall -9 $RITA_VERSION
set -e
scp -O target/$TRIPLE/release/$RITA_VERSION root@$ROUTER_IP:/tmp/$RITA_VERSION
ssh -L localhost:4877:localhost:4877 root@$ROUTER_IP NO_REMOTE_LOG=TRUE RUST_BACKTRACE=FULL RUST_LOG=TRACE /tmp/$RITA_VERSION --config=/etc/$RITA_VERSION.toml &> out.log
