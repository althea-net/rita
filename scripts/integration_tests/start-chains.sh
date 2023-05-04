# Starts the Althea chain in the background, useful to run multiple tests on the same chain state
#!/bin/bash
set -eux
CONTAINER_NAME="rita-integration-test"

# the directory of this script, useful for allowing this script
# to be run with any PWD
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Remove existing container instance
set +e
docker rm -f $CONTAINER_NAME-instance
set -e

NODES=3

pushd $DIR/../

# Run new test container instance
docker run --name $CONTAINER_NAME-instance --mount type=bind,source="$DIR/../../",target=/althea_rs --privileged -p 2345:2345 -p 9090:9090 -p 26657:26657 -p 1317:1317 -p 8545:8545 -it $CONTAINER_NAME /bin/bash /althea_rs/scripts/integration_tests/container_scripts/reload-code.sh $NODES