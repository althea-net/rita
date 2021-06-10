# Althea_rs

This contains many (although confusingly not all) of the Rust components for the Althea firmware. The only separated components are [guac_rs](https://github.com/althea-mesh/guac_rs) which we want to be easily used externally as a Rust Payment channel light client, [Clarity](https://github.com/althea-mesh/clarity) a lightweight transaction generation library for Ethereum, and [web30](https://github.com/althea-mesh/web30) a full node communication library.

The primary binary crate in this repo is 'rita' which produces two binaries 'rita' and 'rita_exit'
see the file headers for descriptions.

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

## Components

### Rita

The only binary output of this repo that ends up on routers and the 'main' Crate. The Rita binary is run as a daemon on the mesh nodes as well as the exit nodes in an Althea network.

Status:

- Discovering Peers: done
- Opening Wireguard tunnels with Peers: done
- Contacting the Exit server to negotiate credentials: done
- Opening a Wireguard tunnel to the exit: done
- Setting the user traffic route to the exit tunnel: Partially complete, needs ipv6
- Accepting commands from the user configuration dashboard and applying them: Done
- Accounts for bandwidth used and required payment: done
- Communicates with Babeld to get mesh info: done
- Communicates with Babeld to detect fraud: in progress
- Makes payments: done

### althea_kernel_interface

Handles interfacing with the kernel networking stack. Right now it does this by shelling out to common Linux commands like 'ip', 'iptables', 'ebtables', etc. This will some day be replaced with calls in the native Netlink api for greater stability.

Status: Feature Complete

### babel_monitor

Communicates with Babel's local configuration API to list routes along with their quality and price.

Status: Needs improvements to fraud detection, possibly rescue cases for crashes

### bounty_hunter

A separate daemon from Rita designed to be run by channel bounty hunters on the internet. In a production Alteha network mesh devices would periodically upload their channel states to a bounty hunter. The bounty hunter will then watch the blockchain state and publish these channel states if an attempt at fraud was made. Claiming a small bounty and preventing channel fraud even when a device is knocked offline.

Status: Needs Clarity integration and Blockchain watching

### clu

Manages things like exit tunnel setup, key generation, and other more using facing tasks.

Status: Feature complete

### Settings

Manages the settings file, including loading/saving and updating the file.

Status: Feature complete

## Cross building

Rita is designed to run on OpenWRT and other embedded devices, if you need to test your code on a router you can use the build scripts in the `scripts/` folder. These will download a pre-built cross-compiler toolchain from updates.altheamesh.com and then use that to build your local althea_rs repository for the specified architecture. If you wish to build the cross-compilation toolchain yourself see the [Althea firmware builder](https://github.com/althea-mesh/althea-firmware). Either way you need to be on Linux, or running Windows Linux compatibility layer.

### Setting up the router

First download the latest [nightly firmware](https://github.com/althea-mesh/althea-firmware#is-this-where-i-get-althea) for your device. Follow the OpenWRT wiki link in the table for flashing instructions. If you have a pretty recent version of the firmware you should be fine, but upgrade if see strange behavior.

Once you have a device running edit the `scripts/openwrt_upload.sh` script to match your device ip and target. If you have an n600 or n750 then the default settings are correct. Review the nightly firmware download table to determine the correct target name for other devices.

The router ip address is by default `192.168.10.1`, if your home network is on that same ip range (probable) you may have trouble reaching the router, plug into the device directly and disable wifi or connect to the Althea-Home wifi network to make sure there's no confusion about which device you are talking to.

Finally run `bash scripts/openwrt_upload.sh` Rust should take a few minutes to build and then Rita should start scrolling logs on your screen. The build will take longer than your normal debugging builds because the binary needs to be much smaller to fit on most embedded devices. If you have any problems refer to the [firmware debugging instructions](https://github.com/althea-mesh/althea-firmware#so-i-flashed-the-firmware-what-do-i-do-now). If that also proves unhelpful drop by our [matrix chat](https://riot.im/app/#/room/#althea:matrix.org) and ask.
