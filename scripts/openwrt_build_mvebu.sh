#!/bin/bash
set -eux
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Parse command line arguments
source $DIR/build_common.sh

if [[ ! -d $DIR/staging_dir ]]; then
    pushd $DIR
    wget -N https://updates.altheamesh.com/staging.tar.xz -O staging.tar.xz > /dev/null; tar -xf staging.tar.xz
fi

export TOOLCHAIN=toolchain-arm_cortex-a9+vfpv3_gcc-7.3.0_musl_eabi
export TARGET_CC=$DIR/staging_dir/$TOOLCHAIN/bin/arm-openwrt-linux-gcc
export TARGET_LD=$DIR/staging_dir/$TOOLCHAIN/bin/arm-openwrt-linux-ld
export TARGET_AR=$DIR/staging_dir/$TOOLCHAIN/bin/arm-openwrt-linux-ar
export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER=$TARGET_CC
export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_AR=$TARGET_AR
export SQLITE3_LIB_DIR=$DIR/staging_dir/target-arm_cortex-a9+vfpv3_musl_eabi/usr/lib/
export ARMV7_UNKNOWN_LINUX_MUSLEABIHF_OPENSSL_DIR=$DIR/staging_dir/target-arm_cortex-a9+vfpv3_musl_eabi/usr/
export OPENSSL_STATIC=1

rustup target add armv7-unknown-linux-musleabihf

cargo build --target armv7-unknown-linux-musleabihf ${PROFILE} ${FEATURES} -p rita --bin rita
