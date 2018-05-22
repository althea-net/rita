use eth_address::EthAddress;
use num256::Uint256;
use serde;
use serde::Deserialize;
use serde::Deserializer;
use std::net::IpAddr;

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

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
pub struct ExitRegistrationDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zip_code: Option<String>,

    // ISO country code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

/// This is the state an exit can be in
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
pub enum ExitState {
    New,
    GotInfo,
    Pending,
    Registered,
    Denied,
    Disabled,
}

pub trait DeserializeWith: Sized {
    fn deserialize_with<'de, D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>;
}

impl DeserializeWith for ExitState {
    fn deserialize_with<'de, D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(de)?;

        match s.as_ref() {
            "New" => Ok(ExitState::New),
            "GotInto" => Ok(ExitState::GotInfo),
            "Pending" => Ok(ExitState::Pending),
            "Registered" => Ok(ExitState::Registered),
            "Denied" => Ok(ExitState::Denied),
            "Disabled" => Ok(ExitState::Disabled),
            _ => Err(serde::de::Error::custom(
                "error trying to deserialize ExitState config",
            )),
        }
    }
}

impl Default for ExitState {
    fn default() -> Self {
        ExitState::New
    }
}

/// This is all the data we need to send to an exit
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct ExitClientIdentity {
    pub wg_port: u16,
    pub global: Identity,
    pub reg_details: ExitRegistrationDetails,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct ExitDetails {
    pub server_internal_ip: IpAddr,
    pub netmask: u8,
    pub wg_exit_port: u16,
    pub exit_price: u64,
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct ExitClientDetails {
    pub client_internal_ip: IpAddr,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct ExitServerReply {
    pub details: Option<ExitClientDetails>,
    pub state: ExitState,
    pub message: String,
}

#[cfg(feature = "actix")]
impl Message for Identity {
    type Result = ();
}

/// This is all the data we need to give a neighbor to open a wg connection
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct LocalIdentity {
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

/// This contains all the info we need to send the the stats server
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Stats {
    pub proc_stat: String,
    pub proc_load_avg: String,
    pub devices: String,
    pub netstat: String,
    pub routes: String,
    pub snmp: String,
    pub wg: String,
    pub from: Identity,
}
