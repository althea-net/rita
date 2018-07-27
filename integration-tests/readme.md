This folder must be located in a folder containing the Althea projects being tested together:

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
sudo apt-get install -y libsqlite3-dev iperf3 python3-pip bridge-utils wireguard linux-source linux-headers-$(uname -r) curl git libssl-dev pkg-config build-essential ipset

cargo install diesel_cli --no-default-features --features sqlite
bpkg install sudomesh/network-lab
bash rita.sh
```
