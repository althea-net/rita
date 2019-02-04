#!/usr/bin/env bash
set -eux
export TARGET=mips
export TRIPLE=mips-unknown-linux-musl
export ROUTER_IP=192.168.10.1
bash scripts/openwrt_build_$TARGET.sh $@
set +e
ssh root@$ROUTER_IP killall -9 rita
set -e
scp target/$TRIPLE/release/rita root@$ROUTER_IP:/tmp/rita
ssh root@$ROUTER_IP NO_REMOTE_LOG=true RUST_BACKTRACE=FULL RUST_LOG=TRACE /tmp/rita --config=/etc/rita.toml --platform=linux &> out.log
