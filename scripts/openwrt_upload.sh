#!/usr/bin/env bash
set -eux
export ROUTER_IP=192.168.1.1
bash scripts/openwrt_build.sh
scp target/mipsel-unknown-linux-musl/debug/rita root@$ROUTER_IP:/tmp/rita
ssh root@$ROUTER_IP RUST_BACKTRACE=FULL RUST_LOG=TRACE /tmp/rita --config=/etc/rita.toml --platform=linux &> out.log
