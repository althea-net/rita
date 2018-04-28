#!/usr/bin/env bash
set -eux
bash scripts/openwrt_build.sh
scp target/mipsel-unknown-linux-musl/debug/rita root@192.168.1.1:/tmp/rita
ssh root@192.168.1.1 RUST_BACKTRACE=FULL RUST_LOG=TRACE /tmp/rita --config /etc/rita.toml --platform linux &> out.log
