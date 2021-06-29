#!/bin/bash
set -eux
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Parse command line arguments
source $DIR/build_common.sh

if [[ ! -d $DIR/staging_dir ]]; then
    pushd $DIR
    wget -N https://updates.altheamesh.com/staging.tar.xz -O staging.tar.xz > /dev/null; tar -xf staging.tar.xz
fi



export TOOLCHAIN=toolchain-x86_64_gcc-7.5.0_musl
export TARGET_CC=$DIR/staging_dir/$TOOLCHAIN/bin/x86_64-openwrt-linux-gcc
export TARGET_LD=$DIR/staging_dir/$TOOLCHAIN/bin/x86_64-openwrt-linux-ld
export TARGET_AR=$DIR/staging_dir/$TOOLCHAIN/bin/x86_64-openwrt-linux-ar
export CARGO_TARGET_X86_64_UKNOWN_LINUX_MUSL_LINKER=$TARGET_CC
export CARGO_TARGET_X86_64_UKNOWN_LINUX_MUSL_LINKER_AR=$TARGET_AR
export SQLITE3_LIB_DIR=$DIR/staging_dir/target-x86_64_musl/usr/lib/
export X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_DIR=$DIR/staging_dir/target-x86_64_musl/usr/
export OPENSSL_STATIC=1
export STAGING_DIR=$DIR/staging_dir/

rustup target add x86_64-unknown-linux-musl

cargo build --target x86_64-unknown-linux-musl ${PROFILE} ${FEATURES} --all
