//! The Settings crate handles settings for Rita, specifically it uses lazy_static to load and
//! deserialize the config file on system start. Once deserialized using Serde into internal data
//! structures it is then provided to Rita as a global static reference, this reference is locked
//! using a RwLock to allow multiple readers and writers throughout the code. If you hold a read
//! reference in a blocking function call or a read and write reference at the same time you will
//! cause a deadlock.
//!
//! This can be dependent on the behavior of the borrow checker since the lock
//! is released based on when the reference is dropped. Take care when using _mut to either
//! namespace or clone quickly to avoid deadlocks.

extern crate althea_types;
extern crate config;
extern crate eui48;
extern crate failure;
extern crate num256;
extern crate owning_ref;
extern crate toml;

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate log;

#[cfg(test)]
use std::sync::Mutex;

extern crate serde;
extern crate serde_json;

extern crate althea_kernel_interface;

use owning_ref::{RwLockReadGuardRef, RwLockWriteGuardRefMut};

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Write;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use althea_kernel_interface::KernelInterface;

#[cfg(not(test))]
use althea_kernel_interface::LinuxCommandRunner;
#[cfg(test)]
use althea_kernel_interface::TestCommandRunner;

use config::Config;

use althea_types::{EthAddress, ExitRegistrationDetails, ExitState, Identity};

use num256::Int256;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use failure::Error;

/// This is the network settings for rita and rita_exit which generally only applies to networking
/// _within_ the mesh or setting up pre hop tunnels (so nothing on exits)
#[cfg(test)]
lazy_static! {
    static ref KI: Box<KernelInterface> = Box::new(TestCommandRunner {
        run_command: Arc::new(Mutex::new(Box::new(|_program, _args| {
            panic!("kernel interface used before initialized");
        })))
    });
}

#[cfg(not(test))]
lazy_static! {
    static ref KI: Box<KernelInterface> = Box::new(LinuxCommandRunner {});
}

fn default_discovery_ip() -> Ipv6Addr {
    warn!("Add discovery_ip to network, removed in the next version!");
    Ipv6Addr::new(0xff02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x8)
}

fn default_tunnel_timeout() -> u64 {
    900 // 15 minutes
}

fn default_local_fee() -> u32 {
    500_000u32 // 500kWei per byte
}

fn default_metric_factor() -> u32 {
    1_900u32
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct NetworkSettings {
    /// The static IP used on mesh interfaces
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mesh_ip: Option<IpAddr>,
    /// Old name for mesh_ip, left in for back-compat, TODO: REMOVE IN ALPHA 11
    #[serde(skip_serializing_if = "Option::is_none")]
    pub own_ip: Option<IpAddr>,
    /// Mesh IP of bounty hunter (in fd00::/8)
    pub bounty_ip: IpAddr,
    /// Broadcast ip address used for peer discovery (in ff02::/8)
    #[serde(default = "default_discovery_ip")]
    pub discovery_ip: Ipv6Addr,
    /// Port on which we connect to a local babel instance (read-write connection required)
    pub babel_port: u16,
    /// Port on which rita starts the per hop tunnel handshake on (needs to be constant across an
    /// entire althea deployment)
    pub rita_hello_port: u16,
    /// Port on which rita contacts other althea nodes over the mesh (needs to be constant across an
    /// entire althea deployment)
    pub rita_contact_port: u16,
    /// Port over which the dashboard will be accessible upon
    pub rita_dashboard_port: u16,
    /// Port over which the bounty hunter will be contacted
    pub bounty_port: u16,
    /// The tick interval in seconds between rita hellos, traffic watcher measurements and payments
    pub rita_tick_interval: u64,
    /// Our private key, encoded with Base64 (what the `wg` command outputs and takes by default)
    /// Note this is the canonical private key for the node
    pub wg_private_key: String,
    /// Where our private key is saved (written to the path on every start) because wireguard does
    /// not accept private keys via stdin or command line args
    pub wg_private_key_path: String,
    /// The our public key, Base64 encoded
    pub wg_public_key: String,
    /// The starting port for per hop tunnels, is a range as we need a different wg interface for
    /// each neighbor to enable billing, and each wg interface needs an unique port.
    pub wg_start_port: u16,
    /// Interfaces on which we accept rita hellos
    pub peer_interfaces: HashSet<String>,
    /// List of URLs/IPs which we will manually send hellos to, used when neighbor detection fails,
    /// such as for connecting to external peers from gateways or to peer 2 althea nodes with a
    /// complex network in between
    pub manual_peers: Vec<String>,
    /// This is a route in the format of `ip route` which is set by default (assuming it will reach
    /// the internet), used to tunnel manual peers over a specific route
    pub default_route: Vec<String>,
    /// This is the NIC which connects to the internet, used by gateways/exits to find its
    /// globally routable ip
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_nic: Option<String>,
    /// This in memory variable specifies if we are a gateway or not
    #[serde(skip_deserializing, default)]
    pub is_gateway: bool,
    /// How long do we wait without contact from a peer before we delete the associated tunnel?
    #[serde(default = "default_tunnel_timeout")]
    pub tunnel_timeout_seconds: u64,
    /// The name of the device or router model
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        NetworkSettings {
            mesh_ip: None,
            own_ip: None,
            bounty_ip: "fd00::3".parse().unwrap(),
            discovery_ip: default_discovery_ip(),
            babel_port: 6872,
            rita_hello_port: 4876,
            rita_dashboard_port: 4877,
            rita_contact_port: 4875,
            bounty_port: 8888,
            rita_tick_interval: 5,
            wg_private_key: String::new(),
            wg_private_key_path: String::new(),
            wg_public_key: String::new(),
            wg_start_port: 60000,
            peer_interfaces: HashSet::new(),
            manual_peers: Vec::new(),
            external_nic: None,
            default_route: Vec::new(),
            is_gateway: false,
            tunnel_timeout_seconds: default_tunnel_timeout(),
            device: None,
        }
    }
}

// TODO change to false in alpha 11
fn default_logging() -> bool {
    true
}

// TODO change to warn in alpha 11
fn default_logging_level() -> String {
    "INFO".to_string()
}

fn default_logging_send_port() -> u16 {
    5044
}

fn default_logging_dest_port() -> u16 {
    514
}

/// Remote logging settings. Used to control remote logs being
/// forwarded to an aggregator on the exit. The reason there is
/// no general destination setting is that syslog udp is not
/// secured or encrypted, sending it over the general internet is
/// not allowed.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct LoggingSettings {
    #[serde(default = "default_logging")]
    pub enabled: bool,
    #[serde(default = "default_logging_level")]
    pub level: String,
    #[serde(default = "default_logging_send_port")]
    pub send_port: u16,
    #[serde(default = "default_logging_dest_port")]
    pub dest_port: u16,
}

impl Default for LoggingSettings {
    fn default() -> Self {
        LoggingSettings {
            enabled: true,
            level: "INFO".to_string(),
            send_port: 5044,
            dest_port: 514,
        }
    }
}

/// This struct is used by both rita and rita_exit to configure the dummy payment controller and
/// debt keeper
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PaymentSettings {
    /// The threshold above which we will kick off a payment
    pub pay_threshold: Int256,
    /// The threshold below which we will kick another node off (not implemented yet)
    pub close_threshold: Int256,
    /// This is used to control the amount of grace, as `total_payment/close_fraction` which we will
    /// give to a node
    pub close_fraction: Int256,
    /// The amount of billing cycles a node can fall behind without being subjected to the threshold
    pub buffer_period: u32,
    /// Our own eth address
    pub eth_address: EthAddress,
}

impl Default for PaymentSettings {
    fn default() -> Self {
        PaymentSettings {
            pay_threshold: 0.into(),
            close_threshold: (-10000).into(),
            close_fraction: 100.into(),
            buffer_period: 3,
            eth_address: 1.into(),
        }
    }
}

/// This struct is used by rita to store exit specific information
/// There is one instance per exit
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ExitServer {
    pub id: Identity,
    /// The port over which we will reach the exit apis on over the mesh
    pub registration_port: u16,
    #[serde(default)]
    pub description: String,
    /// The state and data about the exit
    #[serde(default, flatten)]
    pub info: ExitState,
}

/// This struct is used by rita to encapsulate all the state/information needed to connect/register
/// to a exit and to setup the exit tunnel
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ExitClientSettings {
    /// This stores a mapping between an identifier (any string) to exits
    #[serde(default)]
    pub exits: HashMap<String, ExitServer>,
    /// This stores the current exit identifier
    pub current_exit: Option<String>,
    /// This is the port which the exit wireguard tunnel will listen on
    /// NOTE: must be under `wg_start_port` in `NetworkSettings`
    pub wg_listen_port: u16,
    /// Details for exit registration
    pub reg_details: Option<ExitRegistrationDetails>,
    /// This controls which interfaces will be proxied over the exit tunnel
    pub lan_nics: HashSet<String>,
}

impl Default for ExitClientSettings {
    fn default() -> Self {
        ExitClientSettings {
            exits: HashMap::new(),
            current_exit: None,
            wg_listen_port: 59999,
            reg_details: Some(ExitRegistrationDetails {
                email: Some("1234@gmail.com".into()),
                email_code: Some("000000".into()),
            }),
            lan_nics: HashSet::new(),
        }
    }
}

impl ExitClientSettings {
    pub fn get_current_exit(&self) -> Option<&ExitServer> {
        Some(&self.exits[self.current_exit.as_ref()?])
    }
}

// in seconds
fn default_cache_timeout() -> u64 {
    600
}

fn default_dao_enforcement() -> bool {
    true
}

fn default_node_list() -> Vec<String> {
    vec!["http://sasquatch.network:9545".to_string()]
}

fn default_dao_address() -> Vec<EthAddress> {
    Vec::new()
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Default)]
pub struct SubnetDAOSettings {
    /// If we should take action based on DAO membership
    #[serde(default = "default_dao_enforcement")]
    pub dao_enforcement: bool,
    /// The amount of time an entry is used before refreshing the cache
    #[serde(default = "default_cache_timeout")]
    pub cache_timeout_seconds: u64,
    /// A list of nodes to query for blockchain data
    #[serde(default = "default_node_list")]
    pub node_list: Vec<String>,
    /// List of subnet DAO's to which we are a member
    #[serde(default = "default_dao_address")]
    pub dao_addresses: Vec<EthAddress>,
}

/// This is the main struct for rita
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Default)]
pub struct RitaSettingsStruct {
    payment: PaymentSettings,
    #[serde(default)]
    dao: SubnetDAOSettings,
    #[serde(default)]
    log: LoggingSettings,
    network: NetworkSettings,
    exit_client: ExitClientSettings,
    #[serde(skip)]
    future: bool,
    /// What we charge other nodes
    #[serde(default = "default_local_fee")]
    local_fee: u32,
    /// How much non-financial metrics matter compared to a route's cost. By default a 2x more
    /// expensive route will only be chosen if it scores more than 2x better in other metrics. The
    /// value is expressed in 1/1000 increments, i.e. 1000 = 1.0, 500 = 0.5 and 1 = 0.001
    #[serde(default = "default_metric_factor")]
    metric_factor: u32,
}

/// This is the network settings specific to rita_exit
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ExitNetworkSettings {
    /// This is the port which the exit registration happens over, and should only be accessable
    /// over the mesh
    pub exit_hello_port: u16,
    /// This is the port which the exit tunnel listens on
    pub wg_tunnel_port: u16,
    /// Price in wei per byte which is charged to traffic both coming in and out over the internet
    pub exit_price: u64,
    /// This is the exit's own ip/gateway ip in the exit wireguard tunnel
    pub own_internal_ip: IpAddr,
    /// This is the start of the exit tunnel's internal address allocation to clients, incremented
    /// by 1 every time a new client is added
    pub exit_start_ip: IpAddr,
    /// The netmask, in bits to mask out, for the exit tunnel
    pub netmask: u8,
}

impl Default for ExitNetworkSettings {
    fn default() -> Self {
        ExitNetworkSettings {
            exit_hello_port: 4875,
            wg_tunnel_port: 59999,
            exit_price: 10,
            own_internal_ip: "172.16.255.254".parse().unwrap(),
            exit_start_ip: "172.16.0.0".parse().unwrap(),
            netmask: 12,
        }
    }
}

fn default_email_subject() -> String {
    String::from("Althea Exit verification code")
}

fn default_email_body() -> String {
    // templated using the handlebars language
    // the code will be placed in the {{email_code}}, the [] is for integration testing
    String::from("Your althea verification code is [{{email_code}}]")
}

/// This is the settings for email verification
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Default)]
pub struct EmailVerifSettings {
    /// The email address of the from field of the email sent
    pub from_address: String,
    /// Min amount of time for emails going to the same address
    pub email_cooldown: u64,

    // templating stuff
    #[serde(default = "default_email_subject")]
    pub subject: String,

    #[serde(default = "default_email_body")]
    pub body: String,

    #[serde(default)]
    pub test: bool,
    #[serde(default)]
    pub test_dir: String,
    /// SMTP server url e.g. smtp.fastmail.com
    #[serde(default)]
    pub smtp_url: String,
    /// SMTP domain url e.g. mail.example.com
    #[serde(default)]
    pub smtp_domain: String,
    #[serde(default)]
    pub smtp_username: String,
    #[serde(default)]
    pub smtp_password: String,
}

/// Placeholder
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[serde(tag = "type", content = "contents")]
pub enum ExitVerifSettings {
    Email(EmailVerifSettings),
}

/// This is the main settings struct for rita_exit
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Default)]
pub struct RitaExitSettingsStruct {
    db_file: String,
    description: String,
    payment: PaymentSettings,
    dao: SubnetDAOSettings,
    network: NetworkSettings,
    exit_network: ExitNetworkSettings,
    /// Countries which the clients to the exit are allowed from, blank for no geoip validation.
    /// (ISO country code)
    #[serde(skip_serializing_if = "HashSet::is_empty", default)]
    allowed_countries: HashSet<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    mailer: Option<EmailVerifSettings>, // Legacy setting, TODO: remove in Alpha 13
    #[serde(skip_serializing_if = "Option::is_none")]
    verif_settings: Option<ExitVerifSettings>, // mailer's successor with new verif methods readiness
    #[serde(skip)]
    future: bool,
    /// What we charge other nodes
    #[serde(default = "default_local_fee")]
    local_fee: u32,
    /// How much non-financial metrics matter compared to a route's cost. By default a 2x more
    /// expensive route will only be chosen if it scores more than 2x better in other metrics
    #[serde(default = "default_metric_factor")]
    metric_factor: u32,
}

pub trait RitaCommonSettings<T: Serialize + Deserialize<'static>> {
    fn get_payment<'ret, 'me: 'ret>(&'me self) -> RwLockReadGuardRef<'ret, T, PaymentSettings>;
    fn get_payment_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, T, PaymentSettings>;

    fn get_dao<'ret, 'me: 'ret>(&'me self) -> RwLockReadGuardRef<'ret, T, SubnetDAOSettings>;
    fn get_dao_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, T, SubnetDAOSettings>;

    fn get_network<'ret, 'me: 'ret>(&'me self) -> RwLockReadGuardRef<'ret, T, NetworkSettings>;
    fn get_network_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, T, NetworkSettings>;

    fn merge(&self, changed_settings: Value) -> Result<(), Error>;
    fn get_all(&self) -> Result<serde_json::Value, Error>;

    // Can be None if the mesh ip was not configured yet
    fn get_identity(&self) -> Option<Identity>;

    fn get_future(&self) -> bool;
    fn set_future(&self, future: bool);

    fn get_local_fee(&self) -> u32;
    fn get_metric_factor(&self) -> u32;
}

/// This merges 2 json objects, overwriting conflicting values in `a`
fn json_merge(a: &mut Value, b: &Value) {
    match (a, b) {
        (&mut Value::Object(ref mut a), &Value::Object(ref b)) => {
            for (k, v) in b {
                json_merge(a.entry(k.clone()).or_insert(Value::Null), v);
            }
        }
        (a, b) => {
            *a = b.clone();
        }
    }
}

impl RitaCommonSettings<RitaSettingsStruct> for Arc<RwLock<RitaSettingsStruct>> {
    fn get_payment<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, PaymentSettings> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.payment)
    }

    fn get_payment_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, PaymentSettings> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| &mut g.payment)
    }

    fn get_dao<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, SubnetDAOSettings> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.dao)
    }

    fn get_dao_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, SubnetDAOSettings> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| &mut g.dao)
    }

    fn get_network<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, NetworkSettings> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.network)
    }

    fn get_network_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, NetworkSettings> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| &mut g.network)
    }

    fn merge(&self, changed_settings: serde_json::Value) -> Result<(), Error> {
        let mut settings_value = serde_json::to_value(self.read().unwrap().clone())?;

        json_merge(&mut settings_value, &changed_settings);

        match serde_json::from_value(settings_value) {
            Ok(new_settings) => {
                *self.write().unwrap() = new_settings;
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    fn get_all(&self) -> Result<serde_json::Value, Error> {
        Ok(serde_json::to_value(self.read().unwrap().clone())?)
    }

    fn get_identity(&self) -> Option<Identity> {
        Some(Identity::new(
            self.get_network().mesh_ip?.clone(),
            self.get_payment().eth_address.clone(),
            self.get_network().wg_public_key.clone(),
        ))
    }

    fn get_future(&self) -> bool {
        self.read().unwrap().future
    }

    fn set_future(&self, future: bool) {
        self.write().unwrap().future = future
    }

    fn get_local_fee(&self) -> u32 {
        self.read().unwrap().local_fee
    }

    fn get_metric_factor(&self) -> u32 {
        self.read().unwrap().metric_factor
    }
}

impl RitaCommonSettings<RitaExitSettingsStruct> for Arc<RwLock<RitaExitSettingsStruct>> {
    fn get_payment<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaExitSettingsStruct, PaymentSettings> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.payment)
    }

    fn get_payment_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaExitSettingsStruct, PaymentSettings> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| &mut g.payment)
    }

    fn get_dao<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaExitSettingsStruct, SubnetDAOSettings> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.dao)
    }

    fn get_dao_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaExitSettingsStruct, SubnetDAOSettings> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| &mut g.dao)
    }

    fn get_network<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaExitSettingsStruct, NetworkSettings> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.network)
    }

    fn get_network_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaExitSettingsStruct, NetworkSettings> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| &mut g.network)
    }

    fn merge(&self, changed_settings: serde_json::Value) -> Result<(), Error> {
        let mut settings_value = serde_json::to_value(self.read().unwrap().clone())?;

        json_merge(&mut settings_value, &changed_settings);

        match serde_json::from_value(settings_value) {
            Ok(new_settings) => {
                *self.write().unwrap() = new_settings;
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    fn get_all(&self) -> Result<serde_json::Value, Error> {
        Ok(serde_json::to_value(self.read().unwrap().clone())?)
    }

    fn get_identity(&self) -> Option<Identity> {
        Some(Identity::new(
            self.get_network().mesh_ip?.clone(),
            self.get_payment().eth_address.clone(),
            self.get_network().wg_public_key.clone(),
        ))
    }

    fn get_future(&self) -> bool {
        self.read().unwrap().future
    }

    fn set_future(&self, future: bool) {
        self.write().unwrap().future = future
    }

    fn get_local_fee(&self) -> u32 {
        self.read().unwrap().local_fee
    }

    fn get_metric_factor(&self) -> u32 {
        self.read().unwrap().metric_factor
    }
}

pub trait RitaClientSettings {
    fn get_exit_client<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, ExitClientSettings>;
    fn get_exit_client_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, ExitClientSettings>;
    fn get_exits<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, HashMap<String, ExitServer>>;
    fn get_exits_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, HashMap<String, ExitServer>>;
    fn get_log<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, LoggingSettings>;
    fn get_log_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, LoggingSettings>;
}

impl RitaClientSettings for Arc<RwLock<RitaSettingsStruct>> {
    fn get_exit_client<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, ExitClientSettings> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.exit_client)
    }
    fn get_exit_client_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, ExitClientSettings> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| &mut g.exit_client)
    }

    fn get_exits<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, HashMap<String, ExitServer>> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.exit_client.exits)
    }

    fn get_exits_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, HashMap<String, ExitServer>> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| &mut g.exit_client.exits)
    }

    fn get_log<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaSettingsStruct, LoggingSettings> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.log)
    }

    fn get_log_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaSettingsStruct, LoggingSettings> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| &mut g.log)
    }
}

pub trait RitaExitSettings {
    fn get_exit_network<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaExitSettingsStruct, ExitNetworkSettings>;
    fn get_verif_settings(&self) -> Option<ExitVerifSettings>;
    fn get_verif_settings_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaExitSettingsStruct, Option<ExitVerifSettings>>;
    fn get_mailer(&self) -> Option<EmailVerifSettings>;
    fn get_mailer_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaExitSettingsStruct, Option<EmailVerifSettings>>;
    fn get_db_file(&self) -> String;
    fn get_description(&self) -> String;
    fn get_allowed_countries<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaExitSettingsStruct, HashSet<String>>;
}

impl RitaExitSettings for Arc<RwLock<RitaExitSettingsStruct>> {
    fn get_exit_network<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaExitSettingsStruct, ExitNetworkSettings> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.exit_network)
    }
    fn get_db_file(&self) -> String {
        self.read().unwrap().db_file.clone()
    }
    fn get_description(&self) -> String {
        self.read().unwrap().description.clone()
    }
    fn get_allowed_countries<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaExitSettingsStruct, HashSet<String>> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.allowed_countries)
    }
    fn get_verif_settings(&self) -> Option<ExitVerifSettings> {
        self.read().unwrap().verif_settings.clone()
    }
    fn get_verif_settings_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaExitSettingsStruct, Option<ExitVerifSettings>> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| &mut g.verif_settings)
    }
    fn get_mailer(&self) -> Option<EmailVerifSettings> {
        self.read().unwrap().mailer.clone()
    }
    fn get_mailer_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaExitSettingsStruct, Option<EmailVerifSettings>> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| &mut g.mailer)
    }
}

pub trait FileWrite {
    fn write(&self, file_name: &str) -> Result<(), Error>;
}

fn spawn_watch_thread<'de, T: 'static>(
    settings: Arc<RwLock<T>>,
    file_path: &str,
) -> Result<(), Error>
where
    T: serde::Deserialize<'de> + Sync + Send + std::fmt::Debug + Clone + Eq + FileWrite,
{
    let file_path = file_path.to_string();

    thread::spawn(move || {
        let old_settings = settings.read().unwrap().clone();
        loop {
            thread::sleep(Duration::from_secs(5));

            let new_settings = settings.read().unwrap().clone();

            if old_settings != new_settings {
                trace!("writing updated config: {:?}", new_settings);
                match settings.read().unwrap().write(&file_path) {
                    Err(e) => warn!("writing updated config failed {:?}", e),
                    _ => (),
                }
            }
        }
    });

    Ok(())
}

impl RitaSettingsStruct {
    pub fn new(file_name: &str) -> Result<Self, Error> {
        let mut s = Config::new();
        s.merge(config::File::with_name(file_name).required(false))?;
        let settings: Self = s.try_into()?;

        Ok(settings)
    }

    pub fn new_watched(file_name: &str) -> Result<Arc<RwLock<Self>>, Error> {
        let mut s = Config::new();
        s.merge(config::File::with_name(file_name).required(false))?;
        let settings: Self = s.clone().try_into()?;

        let settings = Arc::new(RwLock::new(settings));

        trace!("starting with settings: {:?}", settings.read().unwrap());

        spawn_watch_thread(settings.clone(), file_name).unwrap();

        Ok(settings)
    }

    pub fn get_exit_id(&self) -> Option<Identity> {
        Some(self.exit_client.get_current_exit().as_ref()?.id.clone())
    }
}

impl RitaExitSettingsStruct {
    pub fn new(file_name: &str) -> Result<Self, Error> {
        let mut s = Config::new();
        s.merge(config::File::with_name(file_name).required(false))?;
        let settings: Self = s.try_into()?;
        Ok(settings)
    }

    pub fn new_watched(file_name: &str) -> Result<Arc<RwLock<Self>>, Error> {
        let mut s = Config::new();
        s.merge(config::File::with_name(file_name).required(false))?;
        let settings: Self = s.clone().try_into()?;

        let settings = Arc::new(RwLock::new(settings));

        trace!("starting with settings: {:?}", settings.read().unwrap());

        spawn_watch_thread(settings.clone(), file_name).unwrap();

        Ok(settings)
    }
}

impl<T> FileWrite for T
where
    T: Serialize,
{
    fn write(&self, file_name: &str) -> Result<(), Error> {
        let ser = toml::Value::try_from(self.clone())?;
        let ser = toml::to_string(&ser)?;
        let mut file = File::create(file_name)?;
        file.write_all(ser.as_bytes())?;
        file.flush().unwrap();
        file.sync_all().unwrap();
        drop(file);
        KI.fs_sync()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_settings_example() {
        RitaSettingsStruct::new("example.toml").unwrap();
    }

    #[test]
    fn test_settings_default() {
        RitaSettingsStruct::new("default.toml").unwrap();
    }

    #[test]
    fn test_exit_settings_default() {
        RitaExitSettingsStruct::new("default_exit.toml").unwrap();
    }

    #[test]
    fn test_exit_settings_example() {
        RitaExitSettingsStruct::new("example_exit.toml").unwrap();
    }

}
