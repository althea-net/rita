# Actually execute a test against an already running background case
#!/bin/bash
TEST_TYPE=$1
set -eu

set +e
killall -9 tester
killall -9 babeld
killall -9 postgres
set -e
export TEST_TYPE
pushd /althea_rs
RUST_LOG=INFO RUST_BACKTRACE=1 cargo run --profile testrunner --manifest-path /althea_rs/test_runner/Cargo.toml