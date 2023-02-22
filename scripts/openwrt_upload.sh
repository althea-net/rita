#!/usr/bin/env bash
set -eux
export TARGET=x86_64
export TRIPLE=x86_64-unknown-linux-musl
export ROUTER_IP=atl-woodland-building-d-bak
bash scripts/openwrt_build_$TARGET.sh
set +e
ssh root@$ROUTER_IP killall -9 rita
set -e
scp -O target/$TRIPLE/release/rita root@$ROUTER_IP:/tmp/rita
ssh root@$ROUTER_IP NO_REMOTE_LOG=TRUE RUST_BACKTRACE=FULL RUST_LOG=TRACE /tmp/rita --config=/etc/rita.toml --platform=linux &> out.log
