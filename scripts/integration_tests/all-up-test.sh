# bujilds the container (thus pulling in new code from git) and runs a test instance as a single action
#!/bin/bash
set -eux
# the directory of this script, useful for allowing this script
# to be run with any PWD
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# builds the container containing various system deps
# also builds the tester once in order to cache Rust deps, this container
# must be rebuilt every time you run this test because it pulls in the
# current repo state by reading the latest git commit during image creation
# if you want a faster solution use start chains and then run tests
# if you are running many tests on the same code set the NO_IMAGE_BUILD=1 env var
set +u
if [[ -z ${NO_IMAGE_BUILD} ]]; then
bash $DIR/build-container.sh
fi
set -u

CONTAINER_NAME="rita-integration-test"
# Remove existing container instance
set +e
docker rm -f $CONTAINER_NAME-all-up
set -e

NODES=3
set +u
TEST_TYPE=$1
set -u

docker run --name $CONTAINER_NAME-all-up --privileged -t $CONTAINER_NAME /bin/bash /althea_rs/scripts/integration_tests/container_scripts/all-up-test-internal.sh $NODES $TEST_TYPE
