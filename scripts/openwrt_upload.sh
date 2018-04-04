#!/usr/bin/env bash
set -eux
bash scripts/openwrt_build.sh
scp target/mipsel-unknown-linux-musl/debug/rita root@192.168.1.1:/tmp/rita
scp settings/default.toml root@192.168.1.1:/etc/rita-default.toml
ssh root@192.168.1.1 RUST_BACKTRACE=FULL RUST_LOG=INFO /tmp/rita --config /etc/rita-default.toml  --default /etc/rita-default.toml --platform openwrt
