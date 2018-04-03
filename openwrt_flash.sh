#!/usr/bin/env bash
bash openwrt_build.sh
scp target/mipsel-unknown-linux-musl/release/rita root@192.168.1.1:/tmp/rita
#RUST_BACKTRACE=FULL RUST_LOG=INFO /tmp/rita --config /etc/rita-default.toml  --default /etc/rita-default.toml --platform openwrt