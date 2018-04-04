#!/usr/bin/env bash
export OPENWRT_DIR=/home/justin/repos/althea-firmware/build
export TOOLCHAIN=toolchain-mipsel_24kc_gcc-7.3.0_musl
export TARGET_NAME=target-mipsel_24kc_musl
export TARGET=mipsel-unknown-linux-musl
export RUST_TRIPLE=$TARGET
export CROSS_PREFIX=mipsel-openwrt-linux-musl
export CROSS_COMPILE=$CROSS_PREFIX
export TARGET_CC=$OPENWRT_DIR/staging_dir/$TOOLCHAIN/bin/mipsel-openwrt-linux-musl-gcc
export TARGET_CCX=$OPENWRT_DIR/staging_dir/$TOOLCHAIN/bin/mipsel-openwrt-linux-musl-g++
export TARGET_LD=$OPENWRT_DIR/staging_dir/$TOOLCHAIN/bin/mipsel-openwrt-linux-musl-ld
export TARGET_AR=$OPENWRT_DIR/staging_dir/$TOOLCHAIN/bin/mipsel-openwrt-linux-musl-ar
export PATH=$PATH:$OPENWRT_DIR/staging_dir/$TOOLCHAIN/bin/
export HOST_CC=gcc
export HOST=x86_64-unknown-linux-gnu
export OPENSSL_DIR=$OPENWRT_DIR/staging_dir/$TARGET_NAME/usr/
export LD_LIBRARY_PATH=/home/ben/src/althea-firmware/build/staging_dir/target-mipsel_24kc_musl/usr/lib/
export LIBRARY_PATH=$OPENWRT_DIR/staging_dir/$TARGET_NAME/usr/lib/
export SQLITE3_LIB_DIR=$LIBRARY_PATH
export SQLITE3_LIB_DIR=$LIBRARY_PATH
export PKG_CONFIG_ALLOW_CROSS=1
export RUSTFLAGS="-C linker=$TARGET_CC -C ar=$TARGET_AR"
cargo build --all --target $RUST_TRIPLE --features "system_alloc"
#$OPENWRT_DIR/staging_dir/$TOOLCHAIN/bin/mipsel-openwrt-linux-musl-strip target/$RUST_TRIPLE/release/rita
