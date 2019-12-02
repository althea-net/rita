use crate::wg_key::WgKey;
use arrayvec::ArrayString;
use clarity::Address;
use failure::Error;
use num256::Uint256;
use std::fmt;
use std::fmt::Display;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[cfg(feature = "actix")]
use actix::{ActorFuture, ActorStream, Message};

/// This is how nodes are identified.
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct Identity {
    pub mesh_ip: IpAddr,
    pub eth_address: Address,
    pub wg_public_key: WgKey,
    pub nickname: Option<ArrayString<[u8; 32]>>,
}

impl Identity {
    pub fn new(
        mesh_ip: IpAddr,
        eth_address: Address,
        wg_public_key: WgKey,
        nickname: Option<ArrayString<[u8; 32]>>,
    ) -> Identity {
        Identity {
            mesh_ip,
            eth_address,
            wg_public_key,
            nickname,
        }
    }
}

// Comparison ignoring nicknames to allow changing
// nicknames without breaking everything
impl PartialEq for Identity {
    fn eq(&self, other: &Identity) -> bool {
        self.mesh_ip == other.mesh_ip
            && self.eth_address == other.eth_address
            && self.wg_public_key == other.wg_public_key
    }
}

// I don't understand why we need this
// docs insist on it though https://doc.rust-lang.org/std/cmp/trait.Eq.html
impl Eq for Identity {}

// Custom hash implementation that also ignores nickname
impl Hash for Identity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.mesh_ip.hash(state);
        self.eth_address.hash(state);
        self.wg_public_key.hash(state);
    }
}

#[derive(Debug, Serialize, Deserialize, Hash, Clone, Eq, PartialEq, Copy)]
pub enum SystemChain {
    Ethereum,
    Rinkeby,
    Xdai,
}

impl Display for SystemChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SystemChain::Ethereum => write!(f, "Ethereum"),
            SystemChain::Rinkeby => write!(f, "Rinkeby"),
            SystemChain::Xdai => write!(f, "Xday"),
        }
    }
}

impl Default for SystemChain {
    fn default() -> SystemChain {
        SystemChain::Ethereum
    }
}

fn default_system_chain() -> SystemChain {
    SystemChain::default()
}

impl FromStr for SystemChain {
    type Err = ();
    fn from_str(s: &str) -> Result<SystemChain, ()> {
        match s {
            "Ethereum" => Ok(SystemChain::Ethereum),
            "Rinkeby" => Ok(SystemChain::Rinkeby),
            "Xdai" => Ok(SystemChain::Xdai),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
pub struct ExitRegistrationDetails {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub email_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub phone_code: Option<String>,
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
        phone_code: Option<String>,
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
    pub low_balance: Option<bool>,
}

/// Wrapper for secure box containing an exit client identity
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct EncryptedExitClientIdentity {
    pub pubkey: WgKey,
    pub nonce: [u8; 24],
    pub encrypted_exit_client_id: Vec<u8>,
}

/// Wrapper for secure box containing an exit state
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct EncryptedExitState {
    pub nonce: [u8; 24],
    pub encrypted_exit_state: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ExitVerifMode {
    Phone,
    Email,
    Off,
}

fn default_verif_mode() -> ExitVerifMode {
    ExitVerifMode::Off
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct ExitDetails {
    pub server_internal_ip: IpAddr,
    pub netmask: u8,
    pub wg_exit_port: u16,
    pub exit_price: u64,
    #[serde(default = "default_system_chain")]
    pub exit_currency: SystemChain,
    pub description: String,
    #[serde(default = "default_verif_mode")]
    pub verif_mode: ExitVerifMode,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
pub struct ExitClientDetails {
    pub client_internal_ip: IpAddr,
}

#[cfg(feature = "actix")]
impl Message for Identity {
    type Result = ();
}

/// This is all the data we need to give a neighbor to open a wg connection
/// this is also known as a "hello" packet or message
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
pub struct LocalIdentity {
    pub wg_port: u16,
    pub have_tunnel: Option<bool>, // If we have an existing tunnel, None if we don't know
    pub global: Identity,
}

#[cfg(feature = "actix")]
impl Message for LocalIdentity {
    type Result = ();
}

/// This is all the data a light client needs to open a light client tunnel
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
pub struct LightClientLocalIdentity {
    pub wg_port: u16,
    pub have_tunnel: Option<bool>, // If we have an existing tunnel, None if we don't know
    pub global: Identity,
    pub tunnel_address: Ipv4Addr, // we have to replicate dhcp ourselves due to the android vpn api
}

#[cfg(feature = "actix")]
impl Message for LightClientLocalIdentity {
    type Result = ();
}

/// This is a stand-in for channel updates. representing a payment
/// when completed it contains a txid from a published transaction
/// that should be validated against the blockchain
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct PaymentTx {
    pub to: Identity,
    pub from: Identity,
    pub amount: Uint256,
    // populated when transaction is published
    pub txid: Option<Uint256>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum ReleaseStatus {
    Custom(String),
    ReleaseCandidate,
    PreRelease,
    GeneralAvailability,
}

impl FromStr for ReleaseStatus {
    type Err = Error;
    fn from_str(s: &str) -> Result<ReleaseStatus, Error> {
        match s {
            "rc" => Ok(ReleaseStatus::ReleaseCandidate),
            "pr" => Ok(ReleaseStatus::PreRelease),
            "ga" => Ok(ReleaseStatus::GeneralAvailability),
            "ReleaseCandidate" => Ok(ReleaseStatus::ReleaseCandidate),
            "PreRelease" => Ok(ReleaseStatus::PreRelease),
            "GeneralAvailability" => Ok(ReleaseStatus::GeneralAvailability),
            _ => {
                if !s.is_empty() {
                    Ok(ReleaseStatus::Custom(s.to_string()))
                } else {
                    Err(format_err!(
                        "Empty string can't possibly be a valid release!"
                    ))
                }
            }
        }
    }
}
