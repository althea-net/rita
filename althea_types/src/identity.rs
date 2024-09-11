use crate::regions::Regions;
use crate::wg_key::WgKey;
use crate::SystemChain;
use arrayvec::ArrayString;
use clarity::Address;
use deep_space::Address as AltheaAddress;
use serde::Deserialize;
use serde::Serialize;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::fmt;
use std::fmt::Display;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;

/// This is all the data we need to give a neighbor to open a wg connection
/// this is also known as a "hello" packet or message
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
pub struct LocalIdentity {
    pub wg_port: u16,
    pub have_tunnel: Option<bool>, // If we have an existing tunnel, None if we don't know
    pub global: Identity,
}

/// Unique identifier for an Althea node
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct Identity {
    pub mesh_ip: IpAddr,
    pub eth_address: Address,
    pub wg_public_key: WgKey,
    pub nickname: Option<ArrayString<32>>,
}

impl Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.nickname {
            Some(nick) => {
                write!(
                f,
                "nickname: {}, mesh_ip: {}, eth_address: {}, althea_address: {:?}, wg_pubkey {}",
                nick, self.mesh_ip, self.eth_address, self.get_althea_address(), self.wg_public_key
            )
            }
            None => write!(
                f,
                "mesh_ip: {}, eth_address: {}, althea_address: {:?}, wg_pubkey {}",
                self.mesh_ip,
                self.eth_address,
                self.get_althea_address(),
                self.wg_public_key
            ),
        }
    }
}

pub const ALTHEA_PREFIX: &str = "althea";

impl Identity {
    pub fn new(
        mesh_ip: IpAddr,
        eth_address: Address,
        wg_public_key: WgKey,
        nickname: Option<ArrayString<32>>,
    ) -> Identity {
        Identity {
            mesh_ip,
            eth_address,
            wg_public_key,
            nickname,
        }
    }

    /// Returns true if this identity is converged, meaning the Althea address is
    /// derived from and is interchangeable with the ETH address. If false we have
    /// to avoid assumptions avoid these being the same private key
    pub fn get_althea_address(&self) -> AltheaAddress {
        AltheaAddress::from_slice(self.eth_address.as_bytes(), ALTHEA_PREFIX).unwrap()
    }

    pub fn get_hash(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }

    pub fn get_hash_array(&self) -> [u8; 8] {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        let bits = hasher.finish();
        bits.to_be_bytes()
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

/// This struct represents a single exit server. It contains all the details
/// needed to contact and register to the exit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitIdentity {
    /// This is the unique identity of the exit. Previously exit
    /// had a shared wg key and mesh ip, this struct needs to have unique
    /// meship, wgkey and ethaddress for each entry
    pub mesh_ip: IpAddr,
    pub wg_key: WgKey,
    pub eth_addr: Address,
    // The port the client uses to query exit endpoints
    pub registration_port: u16,
    // The port the clients uses for exit wg tunnel setup
    pub wg_exit_listen_port: u16,
    pub allowed_regions: HashSet<Regions>,
    pub payment_types: HashSet<SystemChain>,
}

// Custom hash implementation that also ignores nickname. There should be no collding exits with
// the same mesh, wgkey and ethaddr
impl Hash for ExitIdentity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.mesh_ip.hash(state);
        self.eth_addr.hash(state);
        self.wg_key.hash(state);
    }
}

impl From<ExitIdentity> for Identity {
    fn from(exit_id: ExitIdentity) -> Identity {
        Identity {
            mesh_ip: exit_id.mesh_ip,
            eth_address: exit_id.eth_addr,
            wg_public_key: exit_id.wg_key,
            nickname: None,
        }
    }
}

impl From<&ExitIdentity> for Identity {
    fn from(exit_id: &ExitIdentity) -> Identity {
        Identity {
            mesh_ip: exit_id.mesh_ip,
            eth_address: exit_id.eth_addr,
            wg_public_key: exit_id.wg_key,
            nickname: None,
        }
    }
}

pub fn exit_identity_to_id(exit_id: ExitIdentity) -> Identity {
    exit_id.into()
}
