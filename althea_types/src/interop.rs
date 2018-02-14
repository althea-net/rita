use ::eth_address::EthAddress;
use std::net::{IpAddr};
use eui48::MacAddress;
use num256::{Uint256, Int256};

/// This is how nodes are identified.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
pub struct Identity {
    pub mesh_ip: IpAddr,
    pub eth_address: EthAddress,
    pub wg_public_key: MacAddress,
}

/// This is all the data we need to give a local neighbor to open a wg connection
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
pub struct LocalIdentity {
    pub local_ip: IpAddr,
    pub wg_port: u16,
    pub global: Identity,
}


/// This is a stand-in for channel updates. Completely insecure, but allows us to 
/// track how much people would be paying each other if channels were implemented.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct PaymentTx {
    pub to: Identity,
    pub from: Identity,
    pub amount: Uint256,
}