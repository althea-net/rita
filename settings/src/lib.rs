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
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use althea_kernel_interface::KernelInterface;

#[cfg(not(test))]
use althea_kernel_interface::LinuxCommandRunner;
#[cfg(test)]
use althea_kernel_interface::TestCommandRunner;

use config::Config;

use althea_types::{
    DeserializeWith, EthAddress, ExitClientDetails, ExitDetails, ExitRegistrationDetails,
    ExitState, Identity,
};

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

// TODO: remove in alpha 5
fn default_rita_contact_port() -> u16 {
    4874
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct NetworkSettings {
    /// Our own mesh IP (in fd00::/8)
    pub own_ip: IpAddr,
    /// Mesh IP of bounty hunter (in fd00::/8)
    pub bounty_ip: IpAddr,
    /// Port on which we connect to a local babel instance (read-write connection required)
    pub babel_port: u16,
    /// Port on which rita starts the per hop tunnel handshake on (needs to be constant across an
    /// entire althea deployment)
    pub rita_hello_port: u16,
    /// Port on which rita contacts other althea nodes over the mesh (needs to be constant across an
    /// entire althea deployment)
    #[serde(default = "default_rita_contact_port")] // TODO: remove in alpha 5
    pub rita_contact_port: u16,
    /// Port over which the dashboard will be accessible upon
    pub rita_dashboard_port: u16,
    /// Port over which the bounty hunter will be contacted
    pub bounty_port: u16,
    /// The tick interval in seconds between rita hellos, traffic watcher measurements and payments
    #[serde(default = "default_rita_tick_interval")] // TODO: remove in alpha 5
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
}

impl Default for NetworkSettings {
    fn default() -> Self {
        NetworkSettings {
            own_ip: "fd00::1".parse().unwrap(),
            bounty_ip: "fd00::3".parse().unwrap(),
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
    /// This stores information which the exit gives us from registration, and is specific to this
    /// particular node (such as local ip on the exit tunnel)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub our_details: Option<ExitClientDetails>,
    /// This stores information on the exit which is consistent across all nodes which the exit
    /// serves (for example the exit's own ip/gateway ip within the exit tunnel)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub general_details: Option<ExitDetails>,
    /// The state the exit is in, used to control if/when/how to poll the exit
    #[serde(default, deserialize_with = "ExitState::deserialize_with")]
    pub state: ExitState,
    /// The message returned from the exit from registration
    #[serde(default)]
    pub message: String,
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
                zip_code: Some("1234".into()),
                email: Some("1234@gmail.com".into()),
                country: Some("Althea".into()),
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

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Default)]
pub struct StatsServerSettings {
    pub stats_address: String,
    pub stats_port: u16,
    pub stats_enabled: bool,
}

/// This is the main struct for rita
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Default)]
pub struct RitaSettingsStruct {
    payment: PaymentSettings,
    network: NetworkSettings,
    exit_client: ExitClientSettings,
    #[serde(skip_serializing_if = "Option::is_none")]
    stats_server: Option<StatsServerSettings>,
    #[serde(skip)]
    future: bool,
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

/// This is the main settings struct for rita_exit
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Default)]
pub struct RitaExitSettingsStruct {
    db_file: String,
    description: String,
    payment: PaymentSettings,
    network: NetworkSettings,
    exit_network: ExitNetworkSettings,
    #[serde(skip_serializing_if = "Option::is_none")]
    stats_server: Option<StatsServerSettings>,
    /// Countries which the clients to the exit are allowed from, blank for no geoip validation.
    /// (ISO country code)
    #[serde(skip_serializing_if = "HashSet::is_empty", default)]
    allowed_countries: HashSet<String>,
    #[serde(skip)]
    future: bool,
}

pub trait RitaCommonSettings<T: Serialize + Deserialize<'static>> {
    fn get_payment<'ret, 'me: 'ret>(&'me self) -> RwLockReadGuardRef<'ret, T, PaymentSettings>;
    fn get_payment_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, T, PaymentSettings>;

    fn get_network<'ret, 'me: 'ret>(&'me self) -> RwLockReadGuardRef<'ret, T, NetworkSettings>;
    fn get_network_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, T, NetworkSettings>;

    fn get_stats_server_settings<'ret, 'me: 'ret>(
        &'me self,
    ) -> Option<RwLockReadGuardRef<'ret, T, StatsServerSettings>>;

    fn merge(&self, changed_settings: Value) -> Result<(), Error>;
    fn get_all(&self) -> Result<serde_json::Value, Error>;

    fn get_identity(&self) -> Identity;

    fn get_future(&self) -> bool;
    fn set_future(&self, future: bool);
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

    fn get_stats_server_settings<'ret, 'me: 'ret>(
        &'me self,
    ) -> Option<RwLockReadGuardRef<'ret, RitaSettingsStruct, StatsServerSettings>> {
        if self.read().unwrap().stats_server.is_some() {
            Some(
                RwLockReadGuardRef::new(self.read().unwrap()).map(|g| match g.stats_server {
                    Some(ref stat_server) => stat_server,
                    None => panic!("exit client not set but needed"),
                }),
            )
        } else {
            None
        }
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

    fn get_identity(&self) -> Identity {
        Identity::new(
            self.get_network().own_ip.clone(),
            self.get_payment().eth_address.clone(),
            self.get_network().wg_public_key.clone(),
        )
    }

    fn get_future(&self) -> bool {
        self.read().unwrap().future
    }

    fn set_future(&self, future: bool) {
        self.write().unwrap().future = future
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

    fn get_stats_server_settings<'ret, 'me: 'ret>(
        &'me self,
    ) -> Option<RwLockReadGuardRef<'ret, RitaExitSettingsStruct, StatsServerSettings>> {
        if self.read().unwrap().stats_server.is_some() {
            Some(
                RwLockReadGuardRef::new(self.read().unwrap()).map(|g| match g.stats_server {
                    Some(ref stat_server) => stat_server,
                    None => panic!("exit client not set but needed"),
                }),
            )
        } else {
            None
        }
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

    fn get_identity(&self) -> Identity {
        Identity::new(
            self.get_network().own_ip.clone(),
            self.get_payment().eth_address.clone(),
            self.get_network().wg_public_key.clone(),
        )
    }

    fn get_future(&self) -> bool {
        self.read().unwrap().future
    }

    fn set_future(&self, future: bool) {
        self.write().unwrap().future = future
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
}

pub trait RitaExitSettings {
    fn get_exit_network<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaExitSettingsStruct, ExitNetworkSettings>;
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
                info!("writing updated config: {:?}", new_settings);
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
