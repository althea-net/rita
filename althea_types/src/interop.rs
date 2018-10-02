use num256::Uint256;
use std::net::IpAddr;
use EthAddress;

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
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub email: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub email_code: Option<String>,
}

/// This is the state an exit can be in
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
#[serde(tag = "state")]
pub enum ExitState {
    New,
    GotInfo {
        general_details: ExitDetails,
        message: String,
        #[serde(default)]
        auto_register: bool,
    },
    Registering {
        general_details: ExitDetails,
        message: String,
    },
    Pending {
        general_details: ExitDetails,
        message: String,
        #[serde(default)]
        email_code: Option<String>,
    },
    Registered {
        general_details: ExitDetails,
        our_details: ExitClientDetails,
        message: String,
    },
    Denied {
        message: String,
    },
    Disabled,
}

impl Default for ExitState {
    fn default() -> Self {
        ExitState::New
    }
}

impl ExitState {
    pub fn general_details(&self) -> Option<&ExitDetails> {
        match self {
            &ExitState::GotInfo {
                ref general_details,
                ..
            } => Some(general_details),
            &ExitState::Registering {
                ref general_details,
                ..
            } => Some(general_details),
            &ExitState::Pending {
                ref general_details,
                ..
            } => Some(general_details),
            &ExitState::Registered {
                ref general_details,
                ..
            } => Some(general_details),
            _ => None,
        }
    }

    pub fn our_details(&self) -> Option<&ExitClientDetails> {
        match self {
            &ExitState::Registered {
                ref our_details, ..
            } => Some(our_details),
            _ => None,
        }
    }

    pub fn message(&self) -> String {
        match self {
            &ExitState::New => "New exit".to_string(),
            &ExitState::GotInfo { ref message, .. } => message.clone(),
            &ExitState::Registering { ref message, .. } => message.clone(),
            &ExitState::Pending { ref message, .. } => message.clone(),
            &ExitState::Registered { ref message, .. } => message.clone(),
            &ExitState::Denied { ref message, .. } => message.clone(),
            &ExitState::Disabled => "Exit disabled".to_string(),
        }
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
pub enum ExitVerifMode {
    Email,
    Off,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct ExitDetails {
    pub server_internal_ip: IpAddr,
    pub netmask: u8,
    pub wg_exit_port: u16,
    pub exit_price: u64,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub verif_mode: Option<ExitVerifMode>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct ExitClientDetails {
    pub client_internal_ip: IpAddr,
}

#[cfg(feature = "actix")]
impl Message for Identity {
    type Result = ();
}

/// This is all the data we need to give a neighbor to open a wg connection
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct LocalIdentity {
    pub wg_port: u16,
    pub have_tunnel: Option<bool>, // If we have an existing tunnel, None if we don't know
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
    pub routes: String,
    pub meminfo: String,
    pub cpuinfo: String,
}
