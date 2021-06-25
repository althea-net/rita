# Althea_rs

## What is this repo?

This repo contains 'Rita' the core management and billing software for the Althea stack. Rita is the glue that ties together the different components of the Althea system.

Rita manages our price aware [Babeld](https://github.com/althea-net/babeld) implementation. Both Rita and Babel interact with the Linux kernel in different ways to create the Althea network.

Rita discovers peers on physical interfaces and uses [WireGuard](https://duckduckgo.com/?t=ffab&q=wireguard&ia=web) to build a network of authenticated tunnels. This authentication is used for billing purposes. Rita then attaches Babeld on top fo this network of WireGuard tunnels creating the internal routing network for the Althea mesh.

From there Rita communicates with an instance of Rita exit, the exit is a privacy protecting server of the users selection that peers their traffic out onto the internet. Preventing anyone along the path from spying on the users traffic.

Once this network is built Rita implements and performs all billing functionality expected in the pay per forward system. Providing a blockchain wallet, producing and signing transactions, and finally publishing these transactions and monitoring their status on the blockchain.

Finally Rita also contains user dashboard, monitoring, and remote assistance functions designed to assist organizations in operating Althea networks at scale.

This is primarily an infrastructure repo, to get a working version of Althea for real world use you should look at [installer](https://github.com/althea-mesh/installer) for desktop linux and [althea-firmware](https://github.com/althea-mesh/althea-firmware) for OpenWRT.

## Building

Debian:

    sudo apt-get install build-essential libssl-dev libsqlite3-dev pkg-config postgresql-server-dev-all automake liboping-dev libtool perl clang

Ubuntu:

    sudo apt-get install build-essential libssl-dev libsqlite3-dev pkg-config postgresql-server-dev-all autoamke liboping-dev libtool perl clang

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

Rita is designed to run on OpenWRT and other embedded devices, if you need to test your code on a router you can use the build scripts in the `scripts/` folder. These will download a pre-built cross-compiler toolchain from updates.altheamesh.com and then use that to build your local althea_rs repository for the specified architecture. If you wish to build the cross-compilation toolchain yourself see the [Althea firmware builder](https://github.com/althea-mesh/althea-firmware). Either way you need to be on Linux, or running Windows Linux compatibility layer.

### Setting up the router

First download the latest [nightly firmware](https://github.com/althea-mesh/althea-firmware#is-this-where-i-get-althea) for your device. Follow the OpenWRT wiki link in the table for flashing instructions. If you have a pretty recent version of the firmware you should be fine, but upgrade if see strange behavior.

Once you have a device running edit the `scripts/openwrt_upload.sh` script to match your device ip and target. If you have an n600 or n750 then the default settings are correct. Review the nightly firmware download table to determine the correct target name for other devices.

The router ip address is by default `192.168.10.1`, if your home network is on that same ip range (probable) you may have trouble reaching the router, plug into the device directly and disable wifi or connect to the Althea-Home wifi network to make sure there's no confusion about which device you are talking to.

Finally run `bash scripts/openwrt_upload.sh` Rust should take a few minutes to build and then Rita should start scrolling logs on your screen. The build will take longer than your normal debugging builds because the binary needs to be much smaller to fit on most embedded devices. If you have any problems refer to the [firmware debugging instructions](https://github.com/althea-mesh/althea-firmware#so-i-flashed-the-firmware-what-do-i-do-now). If that also proves unhelpful drop by our [matrix chat](https://riot.im/app/#/room/#althea:matrix.org) and ask.
