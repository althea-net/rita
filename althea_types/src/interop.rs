use ::eth_address::EthAddress;
use std::net::{IpAddr};
use eui48::MacAddress;
use num256::{Uint256, Int256};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
pub struct Identity {
    pub ip_address: IpAddr,
    pub eth_address: EthAddress,
    pub mac_address: MacAddress,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct PaymentTx {
    pub to: Identity,
    pub from: Identity,
    pub amount: Uint256,
}