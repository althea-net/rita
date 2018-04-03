use eth_address::EthAddress;
use std::net::IpAddr;
use eui48::MacAddress;
use num256::{Int256, Uint256};

#[cfg(feature = "actix")]
use actix::*;

/// This is how nodes are identified.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct Identity {
    pub mesh_ip: IpAddr,
    pub eth_address: EthAddress,
    pub wg_public_key: String,
}

impl Identity {
    pub fn new(mesh_ip: IpAddr, eth_address: EthAddress, wg_public_key: String) -> Identity {
        Identity {
            mesh_ip,
            eth_address,
            wg_public_key,
        }
    }
}

/// This is all the data we need to send to an exit
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct ExitClientIdentity {
    pub wg_port: u16,
    pub global: Identity,
}

/// This is all the data we need from an exit
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct ExitServerIdentity {
    pub own_local_ip: IpAddr,
    pub server_local_ip: IpAddr,
    pub netmask: IpAddr,
    pub wg_port: u16,
    pub global: Identity,
    pub price: u64,
}

#[cfg(feature = "actix")]
impl Message for Identity {
    type Result = ();
}

/// This is all the data we need to give a neighbor to open a wg connection
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct LocalIdentity {
    pub local_ip: IpAddr,
    pub wg_port: u16,
    pub global: Identity,
}

#[cfg(feature = "actix")]
impl Message for LocalIdentity {
    type Result = ();
}

/// This is a stand-in for channel updates. Completely insecure, but allows us to
/// track how much people would be paying each other if channels were implemented.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct PaymentTx {
    pub to: Identity,
    pub from: Identity,
    pub amount: Uint256,
}
