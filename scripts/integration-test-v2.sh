# Remove existing container instance
set +e
docker rm -f integration-test
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DOCKERFOLDER=$DIR/../integration_tests_v2/container/
REPOFOLDER=$DIR/..
git archive --format=tar.gz -o $DOCKERFOLDER/rita.tar.gz --prefix=althea_rs/ HEAD
pushd $DOCKERFOLDER
time docker build -t integration-test .
time docker run --name integration-test --privileged -it integration-test
popd

rm rita.tar.gz

