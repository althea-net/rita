#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Parse command line arguments
source $DIR/build_common.sh

if [[ ! -d $DIR/staging_dir ]]; then
    pushd $DIR
    wget -N https://updates.altheamesh.com/staging.tar.xz -O staging.tar.xz > /dev/null; tar -xf staging.tar.xz
fi

export TOOLCHAIN=toolchain-mips_24kc_gcc-7.3.0_musl
export TARGET_CC=$DIR/staging_dir/$TOOLCHAIN/bin/mips-openwrt-linux-gcc
export TARGET_LD=$DIR/staging_dir/$TOOLCHAIN/bin/mips-openwrt-linux-ld
export TARGET_AR=$DIR/staging_dir/$TOOLCHAIN/bin/mips-openwrt-linux-ar
export CARGO_TARGET_MIPS_UNKNOWN_LINUX_MUSL_LINKER=$TARGET_CC
export CARGO_TARGET_MIPS_UNKNOWN_LINUX_MUSL_AR=$TARGET_AR
export SQLITE3_LIB_DIR=$DIR/staging_dir/target-mips_24kc_musl/usr/lib/
export MIPS_UNKNOWN_LINUX_MUSL_OPENSSL_DIR=$DIR/staging_dir/target-mips_24kc_musl/usr/
export OPENSSL_STATIC=1

rustup target add mips-unknown-linux-musl

cargo build --target mips-unknown-linux-musl ${PROFILE} ${FEATURES} -p rita --bin rita
