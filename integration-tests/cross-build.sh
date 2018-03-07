#!/bin/bash
wget https://updates.altheamesh.com/staging-mips.tar.gz > /dev/null; tar -xf staging-mips.tar.gz

export TARGET_CC=$PWD/staging_dir/toolchain-mips_24kc_gcc-5.5.0_musl/bin/mips-openwrt-linux-gcc
export TARGET_LD=$PWD/staging_dir/toolchain-mips_24kc_gcc-5.5.0_musl/bin/mips-openwrt-linux-ld
export TARGET_AR=$PWD/staging_dir/toolchain-mips_24kc_gcc-5.5.0_musl/bin/mips-openwrt-linux-ar
export CARGO_TARGET_MIPS_UNKNOWN_LINUX_MUSL_LINKER=$TARGET_CC
export CARGO_TARGET_MIPS_UNKNOWN_LINUX_MUSL_AR=$TARGET_AR
export SQLITE3_LIB_DIR=$PWD/staging_dir/target-mips_24kc_musl/usr/lib/
export MIPS_UNKNOWN_LINUX_MUSL_OPENSSL_DIR=$PWD/staging_dir/target-mips_24kc_musl/usr/

rustup target add mips-unknown-linux-musl

cargo build --target mips-unknown-linux-musl --release --all
