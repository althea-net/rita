#!/usr/bin/env bash
bash openwrt_build.sh
scp target/mipsel-unknown-linux-musl/release/rita root@192.168.1.1:/tmp/rita