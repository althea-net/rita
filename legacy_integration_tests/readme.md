This folder must be located in a folder containing the Althea projects being tested together:

Default virtual network topology:

Where 5 is the exit and 7 is the gateway

```
    5
    |
    7
   / \
  3   6
   \ / \
4 - 2   1
```

```
althea-mesh/
  |- integration-tests/   # This folder
  |- rita/                # Rita metering daemon
  |- babeld/              # Althea fork of babeld
```

## To run locally

Network lab needs to be installed using `bpkg`.

Example:

```
# use this or whatever package manager is available on your platform
sudo apt-get install -y libsqlite3-dev iperf3 python3-pip bridge-utils wireguard linux-source linux-headers-$(uname -r) curl git libssl-dev pkg-config build-essential ipset jq

cargo install diesel_cli --no-default-features --features sqlite
bpkg install sudomesh/network-lab
bash rita.sh
```

## To run in Docker

**The Docker version of this test _only_ tests files that are in git commits not changes in your working directory**

Example:

```
sudo modprobe wireguard # only needs to be run once on system reboot
bash scrips/test.sh
```

### Checking docker container logs

Logging into the docker container is useful when encountering errors when running integration tests. These error messages are usually not very descriptive, so to view the backtrace and
debugging lines (for instance 'info!' macro), we can view log files of rita instances, which we can access with docker container. Get docker running by following the instructions below.

```
# run the test using the command
bash scripts/test.sh
# once you have the test env running, open a new terminal and run:
docker exec -it rita-test /bin/bash
# once you are in the docker, navigate to
althea_rs/integration-tests
```

wait for the error and then check this directory for corresponding logs messages.
log files are of the format rita-n\*.log
When adding more info! macro debugging lines, make sure to commit these changes to see these in the logs.

### Observing net namespaces

This test uses net namespaces, these are conceptually similar to containers. A linux container is running on the same kernel as the host machine, but with a large number of changed
namespace variables. This is how container isolation is performed. Net namespaces are a way to use only the network routing table isolation part of the container system. For this test
we have a docker container (it's own net namespace, process namespace, filesystem namespace etc) that contains within it several more net namespaces. This separation allows us to run many
instances of Rita, each of which interact with and make significant adjustments to the routing table, without needing heavy duty virtual machiens for our tests.

Now that we have the theory out of the way, the real question you want to ask is "how do I run a simple command like `wg` and see the Wireguard tunnels for a particular virtual rita router?"

```
sudo ip netns exec netlab-5 wg
```

When run inside the container, or natively if you are running natively, this will run the command `wg` in the network namespace of rita-n5 instance
