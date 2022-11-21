#!/usr/bin/env bash
set -eux
export TARGET=ipq40xx
export TRIPLE=armv7-unknown-linux-musleabihf
export ROUTER_IP=192.168.10.1
bash scripts/cross_building/openwrt_build_$TARGET.sh --features rita_bin/development
set +e
ssh root@$ROUTER_IP killall -9 rita
set -e
scp -O target/$TRIPLE/release/rita root@$ROUTER_IP:/tmp/rita
ssh -L localhost:4877:localhost:4877 root@$ROUTER_IP NO_REMOTE_LOG=TRUE RUST_BACKTRACE=FULL RUST_LOG=TRACE /tmp/rita --config=/etc/rita.toml --platform=linux &> out.log
