use crate::default_system_chain;
use crate::wg_key::WgKey;
use crate::{exits::identity::ExitIdentity, Identity, SystemChain};
use crypto_box::PublicKey;
use ipnetwork::IpNetwork;
use serde::Deserialize;
use serde::Serialize;
use std::hash::Hash;
use std::net::IpAddr;

pub mod encryption;
pub mod identity;
pub mod server_list_signatures;

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash, Default)]
pub struct ExitRegistrationDetails {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub email_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub phone_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sequence_number: Option<u32>,
}

/// This is the state an exit can be in
#[derive(Default, Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
#[serde(tag = "state")]
pub enum ExitState {
    /// the default state of the struct in the config
    #[default]
    New,
    Pending {
        message: String,
    },
    /// we are currently registered and operating, update this state
    /// incase the exit for example wants to assign us a new ip
    Registered {
        identity: Box<ExitIdentity>,
        general_details: ExitDetails,
        our_details: ExitClientDetails,
        message: String,
    },
    /// we have been denied
    Denied {
        message: String,
    },
}

impl ExitState {
    pub fn general_details(&self) -> Option<&ExitDetails> {
        match *self {
            ExitState::Registered {
                ref general_details,
                ..
            } => Some(general_details),
            _ => None,
        }
    }

    pub fn our_details(&self) -> Option<&ExitClientDetails> {
        match *self {
            ExitState::Registered {
                ref our_details, ..
            } => Some(our_details),
            _ => None,
        }
    }

    pub fn message(&self) -> String {
        match *self {
            ExitState::New => "New exit".to_string(),
            ExitState::Pending { ref message } => message.clone(),
            ExitState::Registered { ref message, .. } => message.clone(),
            ExitState::Denied { ref message, .. } => message.clone(),
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

/// Wrapper for secure box containing a list of ips
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct EncryptedExitList {
    pub nonce: [u8; 24],
    pub exit_list: Vec<u8>,
}

/// Struct returned when hitting exit_list endpoint TODO remote deprecated
#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct ExitList {
    pub exit_list: Vec<Identity>,
    // All exits in a cluster listen on same port
    pub wg_exit_listen_port: u16,
}

/// Struct returned when hitting exit_list_V2 endpoint TODO remote deprecated
#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct ExitListV2 {
    /// A list of exits currently active on this contract
    pub exit_list: Vec<ExitIdentity>,
}

impl ExitListV2 {
    pub fn into_identities(self) -> Vec<Identity> {
        self.exit_list.into_iter().map(|exit| exit.into()).collect()
    }
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
    pub internet_ipv6_subnet: Option<IpNetwork>,
}

/// Wrapper for secure box containing a Signed Exit Server List
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct EncryptedExitServerList {
    pub pubkey: WgKey,
    pub nonce: [u8; 24],
    pub encrypted_exit_server_list: Vec<u8>,
}
