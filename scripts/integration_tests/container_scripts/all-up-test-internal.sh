#!/bin/bash
# the script run inside the container for all-up-test.sh
NODES=$1
TEST_TYPE=$2
set -eux

bash /althea_rs/scripts/integration_tests/container_scripts/setup-validators.sh $NODES

bash /althea_rs/scripts/integration_tests/container_scripts/run-testnet.sh $NODES $TEST_TYPE &

sleep 10

bash /althea_rs/scripts/integration_tests/container_scripts/integration-tests.sh $TEST_TYPE