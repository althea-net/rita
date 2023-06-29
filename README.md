# Rita

## What is this repo?

Rita is one part of the 'Althea Telecom Stack' a system that allows home wifi routers to buy and sell bandwidth autnomously, technically this is very similar to how BGP functions in the internet exchange with the key difference that Rita settles payment for banwidth automatically on a blockchain payment backend and all routing setup is fully automated.

[This video](https://www.youtube.com/watch?v=G4EKbgShyLw) provides a good explanation of key concepts.

This repo contains 'Rita' the coordination, management, and billing software for the 'Althea Telecom Stack'. Rita is the glue that ties together the different components of the system.

Rita interacts with and manages an instance of the [Babeld](https://github.com/althea-net/babeld) routing protocol that implements the [price aware routing extension](https://github.com/althea-net/babel-drafts/blob/master/draft-ietf-babel-price-propagation/draft-ietf-babel-price-propagation.xml). This extention provides a cash price for bandwidth independent of the routing cost, which is usually determined by packet loss and optionally latency in Babeld.

Rita discovers peers on physical interfaces and uses [WireGuard](https://www.wireguard.com/) to build a network of authenticated tunnels. Rita keeps track of traffic on these tunnels to compute how much each neighbor is owed or owes. Rita then attaches Babeld on top of this network of WireGuard tunnels to provide an authenaticated path for traffic.

From there Rita communicates with an instance of Rita exit, the exit is a privacy protecting server of the users selection that peers their traffic out onto the internet. Preventing anyone along the path from spying on the users traffic while it automatically roams within the Babel routing layer to the route with the best ratio of price to quality.

Rita implements and performs all billing functionality expected in the pay per forward system defined by the price aware routing extension to Babeld. Providing a blockchain wallet, producing and signing transactions, and finally publishing these transactions and monitoring their status on the blockchain.

Finally Rita also contains [user dashboard](https://github.com/althea-net/rita-dash), monitoring, and remote assistance functions designed to assist organizations in operating networks at scale.

This is primarily an infrastructure repo, to get a working version of Althea for real world use you should look at [installer](https://github.com/althea-net/rita-installer) for desktop linux and [rita-firmware](https://github.com/althea-net/rita-firmware) for OpenWRT.

## Building

Debian:

    sudo apt-get install build-essential libssl-dev libsqlite3-dev pkg-config postgresql-server-dev-all automake liboping-dev libtool perl clang

Ubuntu:

    sudo apt-get install build-essential libssl-dev libsqlite3-dev pkg-config postgresql-server-dev-all automake liboping-dev libtool perl clang

Centos:

    sudo yum install gcc gcc-c++ openssl-devel sqlite-devel make postgresql-devel automake liboping-devel libtool perl clang

Fedora:

    sudo dnf install gcc gcc-c++ openssl-devel sqlite-devel make postgresql-devel automake liboping-devel libtool perl clang

Arch:

    sudo pacman -S gcc gcc-libs openssl sqlite postgressql perl clang

Finally install [Rust](https://www.rustup.rs/) and add Rustup to your PATH

You are now ready to build code from this Rust repository by running

    cargo build --all

If you want to build a development build that contains unsafe options that are not suitable for production usage:

    cargo build --all --features development

## Testing

Prior to running the tests, make sure you have the following installed: cross

```
    cargo install cross
```

If you wish to test a commit you are developing, or just see Rita in action locally run

    bash scripts/test.sh

This runs both the unit and integration tests you will need to have installed the depenencies listed in the Building section
as well as docker and have the [WireGuard](https://www.wireguard.com/install/) kernel module loaded for your operating system.

Due to a gotcha in the docker container build you will need to have your changes commited for the integration tests to work.

## Contributing

This codebase is formatted using rustfmt, you can format your commits manually with

    cargo +stable fmt

Or install our git hook to do it for you.

```sh
rustup component add rustfmt-preview --toolchain nightly
cd .git/hooks && ln -s ../../scripts/.git-hooks/pre-commit
```

## Cross building

Rita is designed to run on OpenWRT and other embedded devices, if you need to test your code on a router you can use the build scripts in the `scripts/` folder. These use the 'cross' docker container to build for the appropriate target architecture.

### Setting up a router

First download the latest [nightly firmware](https://github.com/althea-net/rita-firmware#is-this-where-i-get-althea) for your device. Follow the OpenWRT wiki link in the table for flashing instructions. If you have a pretty recent version of the firmware you should be fine, but upgrade if you see strange behavior.

Once you have a device running edit the `scripts/openwrt_upload.sh` script to match your device ip and target. Review the nightly firmware download table to determine the correct target name for other devices.

The router ip address is by default `192.168.10.1`, if your home network is on that same ip range you may have trouble reaching the router, plug into the device directly and disable wifi or connect to the Althea-Home wifi network to make sure there's no confusion about which device you are talking to.

Finally run `bash scripts/openwrt_upload.sh` Rust should take a few minutes to build and then Rita should start scrolling logs on your screen. The build will take longer than your normal debugging builds because the binary needs to be much smaller to fit on most embedded devices. If you have any problems refer to the [firmware debugging instructions](https://github.com/althea-mesh/althea-firmware#so-i-flashed-the-firmware-what-do-i-do-now). If that also proves unhelpful drop by our [Discord chat](https://discord.gg/hHx7HxcycF) and ask.
