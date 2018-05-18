use eth_address::EthAddress;
use num256::Uint256;
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
