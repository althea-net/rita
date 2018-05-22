#!/usr/bin/env bash
set -eux
export ROUTER_IP=$1
export OPENWRT_DIR=$2

bash scripts/openwrt_build.sh $OPENWRT_DIR
scp target/mips-unknown-linux-musl/debug/rita root@$ROUTER_IP:/tmp/rita
ssh root@$ROUTER_IP RUST_BACKTRACE=FULL RUST_LOG=TRACE /tmp/rita --config=/etc/rita.toml --platform=linux &> out.log
