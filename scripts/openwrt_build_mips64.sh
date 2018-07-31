#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
if [[ ! -d $DIR/staging_dir ]]; then
    pushd $DIR
    wget -N https://updates.altheamesh.com/staging.tar.xz -O staging.tar.xz > /dev/null; tar -xf staging.tar.xz
fi

export TOOLCHAIN=toolchain-mips64_octeon_64_gcc-7.3.0_glibc
export TARGET_CC=$DIR/staging_dir/$TOOLCHAIN/bin/mips64-openwrt-linux-gcc
export TARGET_LD=$DIR/staging_dir/$TOOLCHAIN/bin/mips64-openwrt-linux-ld
export TARGET_AR=$DIR/staging_dir/$TOOLCHAIN/bin/mips64-openwrt-linux-ar
export CARGO_TARGET_MIPS64_UNKNOWN_LINUX_GNUABI64_LINKER=$TARGET_CC
export CARGO_TARGET_MIPS64_UNKNOWN_LINUX_GNUABI64_AR=$TARGET_AR
export SQLITE3_LIB_DIR=$DIR/staging_dir/target-mips64_octeon_64_glibc/usr/lib/
export MIPS64_UNKNOWN_LINUX_GNUABI64_OPENSSL_DIR=$DIR/staging_dir/target-mips64_octeon_64_glibc/usr/
export OPENSSL_STATIC=1

rustup target add mips64-unknown-linux-gnuabi64

cargo build --target mips64-unknown-linux-gnuabi64 --release -p rita --bin rita --features "system_alloc"
