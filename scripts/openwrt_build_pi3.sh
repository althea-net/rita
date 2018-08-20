#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
if [[ ! -d $DIR/staging_dir ]]; then
    pushd $DIR
    wget -N https://updates.altheamesh.com/staging.tar.xz -O staging.tar.xz > /dev/null; tar -xf staging.tar.xz
fi

export TOOLCHAIN=toolchain-aarch64_cortex-a53_gcc-7.3.0_musl
export TARGET_CC=$DIR/staging_dir/$TOOLCHAIN/bin/aarch64-openwrt-linux-gcc
export TARGET_LD=$DIR/staging_dir/$TOOLCHAIN/bin/aarch64-openwrt-linux-ld
export TARGET_AR=$DIR/staging_dir/$TOOLCHAIN/bin/aarch64-openwrt-linux-ar
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=$TARGET_CC
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_AR=$TARGET_AR
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LD=$TARGET_LD
export SQLITE3_LIB_DIR=$DIR/staging_dir/target-aarch64_cortex-a53_musl/usr/lib/
export AARCH64_UNKNOWN_LINUX_MUSL_OPENSSL_DIR=$DIR/staging_dir/target-aarch64_cortex-a53_musl/usr/
export OPENSSL_STATIC=1
export PKG_CONFIG_ALLOW_CROSS=1
export RUSTFLAGS="-C link-arg=-lgcc"

rustup target add aarch64-unknown-linux-musl

cargo build --target aarch64-unknown-linux-musl -p rita --bin rita
