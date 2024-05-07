# bujilds the container (thus pulling in new code from git) and runs a test instance as a single action
#!/bin/bash
set -eux
# the directory of this script, useful for allowing this script
# to be run with any PWD
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

sudo apt-get update
sudo apt install -y sudo \
          iputils-ping \
          iproute2 \
          jq \
          vim \
          netcat-traditional \
          default-libmysqlclient-dev \
          libsqlite3-dev \
          postgresql-client-14 \
          postgresql-server-dev-14 \
          libpq-dev \
          python3-pip \
          bridge-utils \
          wireguard \
          linux-source \
          curl \
          git \
          libssl-dev \
          pkg-config \
          build-essential \
          ipset \
          python3-setuptools \
          python3-wheel \
          dh-autoreconf \
          procps \
          net-tools \
          iperf3 \
          babeld \
          make \
          locales-all \
          npm \
          linux-source linux-headers-$(uname -r) \
          build-essential
sudo modprobe wireguard

cargo install diesel_cli --force
pushd /var
sudo git clone -b master https://github.com/althea-mesh/babeld.git
pushd /var/babeld/
sudo make install
popd
popd

# Install Althea for Althea blockchain operations, also used to test eth blockchain operations
# but in that case the test runs entierly on the evm environment contained in the althea chain
sudo wget https://github.com/althea-net/althea-L1/releases/download/v1.1.0/althea-linux-amd64 -O /usr/bin/althea
sudo chmod +x /usr/bin/althea

NODES=3
set +u
TEST_TYPE=$1
set -u

sudo bash scripts/integration_tests/container_scripts/setup-validators.sh $NODES

sudo bash scripts/integration_tests/container_scripts/run-testnet.sh $NODES $TEST_TYPE &

sleep 10

pushd solidity/

npm install

npm run typechain

popd

set +e
killall -9 tester
killall -9 babeld
killall -9 postgres
set -e
export TEST_TYPE
cargo build --profile testrunner --manifest-path test_runner/Cargo.toml
sudo TEST_TYPE=$TEST_TYPE RUST_LOG=INFO RUST_BACKTRACE=1 ./target/testrunner/tester