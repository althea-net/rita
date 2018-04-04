#!/usr/bin/env bash
set -eux
bash scripts/openwrt_build.sh
scp target/mipsel-unknown-linux-musl/debug/rita root@192.168.1.1:/tmp/rita
scp settings/default.toml root@192.168.1.1:/etc/rita-default.toml
scp scripts/rita-test.toml root@192.168.1.1:/etc/rita.toml
ssh root@192.168.1.1 RUST_BACKTRACE=FULL RUST_LOG=TRACE /tmp/rita --config /etc/rita.toml  --default /etc/rita-default.toml --platform openwrt
