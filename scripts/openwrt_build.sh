#!/usr/bin/env bash
export OPENWRT_DIR=$1
export TOOLCHAIN=toolchain-mips_24kc_gcc-7.3.0_musl
export TARGET_NAME=target-mips_24kc_musl
export TARGET=mips-unknown-linux-musl
export CROSS_PREFIX=mips-openwrt-linux-musl
export HOST_CC=gcc
export HOST=x86_64-unknown-linux-gnu
export PKG_CONFIG_ALLOW_CROSS=1

export RUST_TRIPLE=$TARGET
export CROSS_COMPILE=$CROSS_PREFIX
export TARGET_CC=$OPENWRT_DIR/staging_dir/$TOOLCHAIN/bin/mips-openwrt-linux-musl-gcc
export TARGET_CCX=$OPENWRT_DIR/staging_dir/$TOOLCHAIN/bin/mips-openwrt-linux-musl-g++
export TARGET_LD=$OPENWRT_DIR/staging_dir/$TOOLCHAIN/bin/mips-openwrt-linux-musl-ld
export TARGET_AR=$OPENWRT_DIR/staging_dir/$TOOLCHAIN/bin/mips-openwrt-linux-musl-ar
export PATH=$PATH:$OPENWRT_DIR/staging_dir/$TOOLCHAIN/bin/
export OPENSSL_DIR=$OPENWRT_DIR/staging_dir/$TARGET_NAME/usr/
export LIBRARY_PATH=$OPENWRT_DIR/staging_dir/$TARGET_NAME/usr/lib/
export LD_LIBRARY_PATH=$OPENWRT_DIR/staging_dir/$TARGET_NAME/usr/lib/
export SQLITE3_LIB_DIR=$LIBRARY_PATH
export SQLITE3_LIB_DIR=$LIBRARY_PATH
export RUSTFLAGS="-C linker=$TARGET_CC -C ar=$TARGET_AR"
cargo build --all --target $RUST_TRIPLE
