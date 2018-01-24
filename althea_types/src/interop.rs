use ::eth_address::EthAddress;
use std::net::{IpAddr};
use eui48::MacAddress;
use num256::{Uint256, Int256};

/// This is how nodes are identified. `mac_address` will soon be replaced with a 
/// Wireguard public key. This is because both of these things allow us to track a
/// neighbor's usage. The advantage of a wireguard public key is that we can be certain
/// that traffic was sent by a certain neighbor.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
pub struct Identity {
    pub ip_address: IpAddr,
    pub eth_address: EthAddress,
    pub mac_address: MacAddress,
}

/// This is a stand-in for channel updates. Completely insecure, but allows us to 
/// track how much people would be paying each other if channels were implemented.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PaymentTx {
    pub to: Identity,
    pub from: Identity,
    pub amount: Uint256,
}