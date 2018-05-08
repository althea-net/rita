# Althea_rs

This contains many (although confusingly not all) of the Rust components for the Althea firmware. The only separated component is [guac_rs](https://github.com/althea-mesh/guac_rs) which we want to be easily used externally as a Rust Etherium light client. 

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
 - Communicates with Babeld to detect fraud: not started
 - Makes payments: in progress

### althea_kernel_interface
Handles interfacing with the kernel networking stack. Right now it does this by using common Linux commands like 'ip', 'iptables', 'ebtables', etc. This will some day be replaced with calls in the native Netlink api for greater stability than shelling out. 

Status: Feature Complete

### babel_monitor 
Communicates with Babel's local configuration API to list routes along with their quality and price. 

Status: Needs fraud detection implementation 

### bounty_hunter
 A separate daemon from Rita designed to be run by channel bounty hunters on the internet. In a production Alteha network mesh devices would periodically upload their channel states to a bounty hunter. The bounty hunter will then watch the blockchain state and publish these channel states if an attempt at fraud was made. Claiming a small bounty and preventing channel fraud even when a device is knocked offline. 
 
 Status: Needs Parity integration and real channel states
 
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
