# Build the rita-integration-test container, this build will pull in the latest code changes that are *checked in*
# changes that are not checked in will not be pulled in
#!/bin/bash
# Remove existing container instance
CONTAINER_NAME="rita-integration-test"
set +e
docker rm -f $CONTAINER_NAME
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DOCKERFOLDER=$DIR/../../integration_tests/container/
REPOFOLDER=$DIR/..
git archive --format=tar.gz -o $DOCKERFOLDER/rita.tar.gz --prefix=althea_rs/ HEAD
pushd $DOCKERFOLDER
time docker build -t $CONTAINER_NAME .
rm rita.tar.gz
