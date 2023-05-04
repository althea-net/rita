#!/bin/bash
TEST_TYPE=$1
set -eu
CONTAINER_NAME="rita-integration-test-instance"

time docker exec --env TEST_TYPE=$TEST_TYPE --privileged -it $CONTAINER_NAME /bin/bash /althea_rs/scripts/integration_tests/container_scripts/integration-tests.sh $TEST_TYPE