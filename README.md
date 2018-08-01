# Althea_rs

This contains many (although confusingly not all) of the Rust components for the Althea firmware. The only separated component is [guac_rs](https://github.com/althea-mesh/guac_rs) which we want to be easily used externally as a Rust Ethereum light client.

This is primarily an infrastructure repo, to get a working version of Althea you should look at [installer](https://github.com/althea-mesh/installer) for desktop linux and [althea-firmware](https://github.com/althea-mesh/althea-firmware) for OpenWRT.

## Building

Debian:

    sudo apt-get install build-essential libssl-dev libsqlite3-dev pkg-config

Ubuntu:

    sudo apt-get install build-essential libssl-dev libsqlite3-dev pkg-config

Centos:

    sudo yum install gcc gcc-c++ openssl-devel sqlite-devel make

Fedora:

    sudo dnf install gcc gcc-c++ openssl-devel sqlite-devel make

Arch:

    sudo pacman -S gcc gcc-libs openssl sqlite

Finally install [Rust](https://www.rustup.rs/) and add Rustup to your PATH

You are now ready to build code from this Rust repository by running

	cargo build --all

## Components

### Rita
The only binary output of this repo that ends up on routers and the 'main' Crate. The Rita binary is run as a daemon on the mesh nodes as well as the exit nodes in an Althea network.

Status:
 - Discovering Peers: done  (should maybe have a proper discovery packet instead of ebtables)
 - Opening Wireguard tunnels with Peers: done
 - Contacting the Exit server to negotiate credentials: done
 - Opening a Wireguard tunnel to the exit: done
 - Setting the user traffic route to the exit tunnel: Partially complete, needs ipv6
 - Accepting commands from the user configuration dashboard and applying them: Done 
 - Sends load stats to external stats server (if opted in): Untested
 - Accounts for bandwidth used and required payments: Needs more testing
 - Communicates with Babeld to get mesh info: done
 - Communicates with Babeld to detect fraud: in progress
 - Makes payments: in progress

### althea_kernel_interface
Handles interfacing with the kernel networking stack. Right now it does this by using common Linux commands like 'ip', 'iptables', 'ebtables', etc. This will some day be replaced with calls in the native Netlink api for greater stability than shelling out. 

Status: Feature Complete

### babel_monitor 
Communicates with Babel's local configuration API to list routes along with their quality and price. 

Status: Needs fraud detection implementation 

### bounty_hunter
 A separate daemon from Rita designed to be run by channel bounty hunters on the internet. In a production Alteha network mesh devices would periodically upload their channel states to a bounty hunter. The bounty hunter will then watch the blockchain state and publish these channel states if an attempt at fraud was made. Claiming a small bounty and preventing channel fraud even when a device is knocked offline. 
 
 Status: Needs Parity integration and real channel states (removed for now, adding back to guac_rs)
 
### clu
Manages things like exit tunnel setup, key generation, and other more using facing tasks. 

Status: Feature complete  

### kv-store
No longer used, should be removed

### num256

A 256bit number implementation for EVM compatibility. 

Status: Feature complete

### Settings
Manages the settings file, including loading/saving and updating the file. 

Status: Feature complete

## Cross building
Rita is designed to run on OpenWRT and other embedded devices, if you need to test your code on a router you can use the build scripts in the `scripts/` folder. These will download a pre-built cross-compiler toolchain from updates.altheamesh.com and then use that to build your local althea_rs repository for the specified architecture. If you wish to build the cross-compilation toolchain yourself see the [Althea firmware builder](https://github.com/althea-mesh/althea-firmware). Either way you need to be on Linux, or running Windows Linux compatiblity layer.

### Setting up the router
First download the latest [nightly firmware](https://github.com/althea-mesh/althea-firmware#is-this-where-i-get-althea) for your device. Follow the OpenWRT wiki link in the table for flashing instructions. If you have a pretty recent version of the firmware you should be fine, but upgrade if see strange behavior.

Once you have a device running edit the `scripts/openwrt_upload.sh` script to match your device ip and target. If you have an n600 or n750 then the default settings are correct. Review the nightly firmware download table to determine the correct target name for other devices.

The router ip address is by default `192.168.10.1`, if your home network is on that same ip range (probable) you may have trouble reaching the router, plug into the device directly and disable wifi or connect to the Althea-Home wifi network to make sure there's no confusion about which device you are talking to. 

Finally run `bash scripts/openwrt_upload.sh` Rust should take a few minutes to build and then Rita should start scrolling logs on your screen. The build will take longer than your normal debugging builds because the binary needs to be much smaller to fit on most embedded devices. If you have any problems refer to the [firmware debugging instructions](https://github.com/althea-mesh/althea-firmware#so-i-flashed-the-firmware-what-do-i-do-now). If that also proves unhelpful drop by our [matrix chat](https://riot.im/app/#/room/#althea:matrix.org) and ask. 
