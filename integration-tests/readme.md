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

Network lab needs to be installed using `bpkg`.

Example:

```
# use this or whatever package manager is available on your platform
sudo apt-get install -y libsqlite3-dev iperf3 python3-pip bridge-utils wireguard linux-source linux-headers-$(uname -r) curl git libssl-dev pkg-config build-essential ipset jq

cargo install diesel_cli --no-default-features --features sqlite
bpkg install sudomesh/network-lab
bash rita.sh
```



Running Docker to check logs:

Docker is useful when encountering errors when running integration tests. These error messages are usually not very descriptive, so to view the backtrace and 
debugging lines (for instance 'info!' macro), we can view log files of rita instances, which we can access with docker container. Get docker running by following the instructions below.

run the test using the command
    bash scripts/test.sh
once you have the test env running, open a new terminal and run:
  docker exec -it rita-test /bin/bash
once you are in the docker, navigate to 
    althea_rs/integration-tests

wait for the error and then check this directory for corresponding logs messages.
log files are of the format rita-n*.log
When adding more info! macro debugging lines, make sure to commit these changes to see these in the logs.



