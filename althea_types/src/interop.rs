use crate::wg_key::WgKey;
use crate::{ClientExtender, WifiDevice};
use arrayvec::ArrayString;
use babel_monitor::structs::Neighbor;
use babel_monitor::structs::Route;
use clarity::Address;
use deep_space::Address as AltheaAddress;
use ipnetwork::IpNetwork;
use num256::Uint256;
use serde::Serialize;
use serde::{Deserialize, Deserializer, Serializer};
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::fmt::Display;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

/// This is how nodes are identified.
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

#[derive(PartialEq, Eq, Hash, Clone, Debug, Serialize, Deserialize)]
pub struct Denom {
    /// String representation of token, ex, ualthea, wei, from athea chain will be some unpredictable ibc/<hash>
    pub denom: String,
    /// This value * 1 denom = 1 unit of token. For example for wei, decimal is 10^18. So 1 wei * 10^18 = 1 eth
    /// u64 supports upto a 10^19 decimal
    pub decimal: u64,
}

#[derive(Default, Debug, Hash, Clone, Eq, PartialEq, Copy)]
pub enum SystemChain {
    Ethereum,
    Sepolia,
    #[default]
    Xdai,
    AltheaL1,
}

impl Display for SystemChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SystemChain::Ethereum => write!(f, "Ethereum"),
            SystemChain::Sepolia => write!(f, "Sepolia"),
            SystemChain::Xdai => write!(f, "Xdai"),
            SystemChain::AltheaL1 => write!(f, "Althea"),
        }
    }
}

fn default_system_chain() -> SystemChain {
    SystemChain::default()
}

impl FromStr for SystemChain {
    type Err = String;
    fn from_str(s: &str) -> Result<SystemChain, String> {
        match s {
            "Ethereum" => Ok(SystemChain::Ethereum),
            "ethereum" => Ok(SystemChain::Ethereum),
            "eth" => Ok(SystemChain::Ethereum),
            "ETH" => Ok(SystemChain::Ethereum),
            "Rinkeby" => Ok(SystemChain::Sepolia),
            "rinkeby" => Ok(SystemChain::Sepolia),
            "Sepolia" => Ok(SystemChain::Sepolia),
            "sepolia" => Ok(SystemChain::Sepolia),
            "Testnet" => Ok(SystemChain::Sepolia),
            "Test" => Ok(SystemChain::Sepolia),
            "testnet" => Ok(SystemChain::Sepolia),
            "test" => Ok(SystemChain::Sepolia),
            "Xdai" => Ok(SystemChain::Xdai),
            "xDai" => Ok(SystemChain::Xdai),
            "xDAI" => Ok(SystemChain::Xdai),
            "xdai" => Ok(SystemChain::Xdai),
            "GnosisChain" => Ok(SystemChain::Xdai),
            "gnosischain" => Ok(SystemChain::Xdai),
            "Gnosis" => Ok(SystemChain::Xdai),
            "gnosis" => Ok(SystemChain::Xdai),
            "Althea" => Ok(SystemChain::AltheaL1),
            "AltheaL1" => Ok(SystemChain::AltheaL1),
            "altheal1" => Ok(SystemChain::AltheaL1),
            "altheaL1" => Ok(SystemChain::AltheaL1),
            _ => Err("Unknown chain".to_string()),
        }
    }
}

impl Serialize for SystemChain {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for SystemChain {
    fn deserialize<D>(deserializer: D) -> Result<SystemChain, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

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
    /// we have successfully contacted the exit and gotten basic info
    GotInfo {
        general_details: ExitDetails,
        message: String,
    },
    /// We are awaiting user action to enter the phone or email code
    Pending {
        general_details: ExitDetails,
        message: String,
        #[serde(default)]
        email_code: Option<String>,
        phone_code: Option<String>,
    },
    /// we are currently registered and operating, update this state
    /// incase the exit for example wants to assign us a new ip
    Registered {
        general_details: ExitDetails,
        our_details: ExitClientDetails,
        message: String,
    },
    /// we have been denied
    Denied { message: String },
}

impl ExitState {
    pub fn general_details(&self) -> Option<&ExitDetails> {
        match *self {
            ExitState::GotInfo {
                ref general_details,
                ..
            } => Some(general_details),
            ExitState::Pending {
                ref general_details,
                ..
            } => Some(general_details),
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
            ExitState::GotInfo { ref message, .. } => message.clone(),
            ExitState::Pending { ref message, .. } => message.clone(),
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

/// Struct returned when hitting exit_list endpoint
#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct ExitList {
    pub exit_list: Vec<Identity>,
    // All exits in a cluster listen on same port
    pub wg_exit_listen_port: u16,
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

/// This is all the data we need to give a neighbor to open a wg connection
/// this is also known as a "hello" packet or message
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
pub struct LocalIdentity {
    pub wg_port: u16,
    pub have_tunnel: Option<bool>, // If we have an existing tunnel, None if we don't know
    pub global: Identity,
}

/// This represents a generic payment that may be to or from us
/// it contains a txid from a published transaction
/// that should be validated against the blockchain
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub struct PaymentTx {
    pub to: Identity,
    pub from: Identity,
    pub amount: Uint256,
    // txhash of the payment this could either be on Ethereum or Althea as both are 256 bit integers
    pub txid: Uint256,
}

// Ensure that duplicate txid are always treated as the same object
impl Hash for PaymentTx {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.txid.hash(state);
    }
}

/// This represents a generic payment that may be to or from us, it does not contain a txid meaning it is
/// unpublished
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct UnpublishedPaymentTx {
    pub to: Identity,
    pub from: Identity,
    pub amount: Uint256,
}

impl UnpublishedPaymentTx {
    pub fn publish(&self, txid: Uint256) -> PaymentTx {
        PaymentTx {
            to: self.to,
            from: self.from,
            amount: self.amount,
            txid,
        }
    }
}

/// This enum contains information about what type of update we need to perform on a router initiated from op tools.
/// This can either be a sysupgrade with a url to a firmware image, or an opkg update with a url to a opkg feed
#[derive(Serialize, Deserialize, Hash, Clone, Debug, Eq, PartialEq)]
pub enum UpdateType {
    Sysupgrade(SysupgradeCommand),
    Opkg(Vec<OpkgCommand>),
}

static FEED_NAME: &str = "althea";
impl From<UpdateTypeLegacy> for UpdateType {
    fn from(legacy: UpdateTypeLegacy) -> Self {
        match legacy {
            UpdateTypeLegacy::Sysupgrade(command) => UpdateType::Sysupgrade(command),
            UpdateTypeLegacy::Opkg(legacy_opkg) => {
                let mut commands = Vec::new();
                for item in legacy_opkg.command_list {
                    match item.opkg_command {
                        OpkgCommandTypeLegacy::Install => {
                            if item.packages.is_none() {
                                continue;
                            }
                            commands.push(OpkgCommand::Install {
                                packages: item.packages.unwrap(),
                                arguments: item.arguments.unwrap_or_default(),
                            })
                        }
                        OpkgCommandTypeLegacy::Update => commands.push(OpkgCommand::Update {
                            feed: legacy_opkg.feed.clone(),
                            feed_name: FEED_NAME.to_string(),
                            arguments: item.arguments.unwrap_or_default(),
                        }),
                    }
                }
                UpdateType::Opkg(commands)
            }
        }
    }
}

/// This enum defines which opkg command we are performing during a router update
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum OpkgCommand {
    Install {
        packages: Vec<String>,
        arguments: Vec<String>,
    },
    Remove {
        packages: Vec<String>,
        arguments: Vec<String>,
    },
    Update {
        feed: String,
        feed_name: String,
        arguments: Vec<String>,
    },
}

///This enum contains information about what type of update we need to perform on a router initiated from op tools.
/// This can either be a sysupgrade with a url to a firmware image, or an opkg update with a url to a opkg feed
#[derive(Serialize, Deserialize, Hash, Clone, Debug, Eq, PartialEq)]
pub enum UpdateTypeLegacy {
    Sysupgrade(SysupgradeCommand),
    Opkg(OpkgCommandListLegacy),
}

#[derive(Serialize, Deserialize, Hash, Clone, Debug, Eq, PartialEq)]
///This struct contains info required for a sysupgrade command
pub struct SysupgradeCommand {
    pub url: String,
    pub flags: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Hash, Clone, Debug, Eq, PartialEq)]
/// This struct contains the feed and a vector of opkg commands to run on an update
pub struct OpkgCommandListLegacy {
    pub feed: String,
    pub command_list: Vec<OpkgCommandLegacy>,
}

/// This struct contains alls the information need to perfom an opkg command, i.e, install/update, list of arguments, and flags
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct OpkgCommandLegacy {
    pub opkg_command: OpkgCommandTypeLegacy,
    pub packages: Option<Vec<String>>,
    pub arguments: Option<Vec<String>>,
}

/// This enum defines which opkg command we are performing during a router update
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum OpkgCommandTypeLegacy {
    Install,
    Update,
}

#[derive(Serialize, Deserialize, Hash, Clone, Debug, Eq, PartialEq)]
pub enum ReleaseStatus {
    Custom(String),
    ReleaseCandidate,
    PreRelease,
    GeneralAvailability,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq, Hash)]
pub struct WifiChannel {
    pub radio: String,
    pub channel: u16,
}
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq, Hash)]
pub struct WifiSsid {
    pub radio: String,
    pub ssid: String,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq, Hash)]
pub struct WifiPass {
    pub radio: String,
    pub pass: String,
}
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct WifiSecurity {
    pub radio: String,
    pub encryption: String,
}
#[derive(Clone, Debug)]
pub struct WifiDisabledReturn {
    pub needs_reboot: bool,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq, Hash)]
pub struct WifiDisabled {
    pub radio: String,
    pub disabled: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum WifiToken {
    WifiChannel(WifiChannel),
    WifiSsid(WifiSsid),
    WifiPass(WifiPass),
    WifiDisabled(WifiDisabled),
    WifiSecurity(WifiSecurity),
}

/// Settings for the bandwidth shaper
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub struct ShaperSettings {
    pub enabled: bool,
    /// The speed the bandwidth shaper will start at, keep in mind this is not the maximum device
    /// speed as all interfaces start at 'unlimited' this is instead the speed the shaper will deploy
    /// when it detects problems on the interface and a speed it will not go above when it's increasing
    /// the speed after the problem is gone
    pub max_speed: usize,
    /// this is the minimum speed the shaper will assign to an interface under any circumstances
    /// when the first bad behavior on a link is experienced the value goes from 'unlimited' to
    /// max_shaper_speed and heads downward from there. Set this value based on what you think the
    /// worst realistic performance of any link in the network may be.
    pub min_speed: usize,
}

/// This struct is sent up to op to display info related to a routers connect exit there
#[derive(Default, Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub struct CurExitInfo {
    pub cluster_name: Option<String>,
    pub instance_name: Option<String>,
    pub instance_ip: Option<IpAddr>,
}

/// This struct is sent up to op to display info related to a current exit connection
/// This includes exit deatails, client ipv6 address, etc
#[derive(Default, Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub struct ExitConnection {
    pub cur_exit: Option<CurExitInfo>,
    pub client_pub_ipv6: Option<IpNetwork>,
}

/// The message and exit sends to the operator server to checkin, this allows us to customize
/// the operator checkin response to the device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorExitCheckinMessage {
    pub id: Identity,
    /// This is a password that operator tools uses to verify that the one
    /// making a request is an exit. Exits are started with this password
    /// in their config, and ops verifies this pass with the one they store
    pub pass: String,
    /// This is to keep track of the rita exit uptime for debugging purposes
    pub exit_uptime: Duration,
    /// Number of users online
    pub users_online: Option<u32>,
}

/// Operator update that we get from the operator server during our checkin
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OperatorExitUpdateMessage {
    /// List of routers for this exit to register
    pub to_register: Vec<ExitClientIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// A set of info derived from /proc/ and /sys/ about the recent
/// load on the system
pub struct HardwareInfo {
    /// the number of logical processors on the system, derived
    /// by parsing /proc/cpuinfo and counting the number of instances
    /// of the word 'processor'
    pub logical_processors: u32,
    /// The load average of the system over the last 1 minute please
    /// see this reference before making decisions based on this value
    /// http://www.brendangregg.com/blog/2017-08-08/linux-load-averages.html
    /// parsed from /proc/loadvg
    pub load_avg_one_minute: f32,
    /// The load average of the system over the last 5 minutes please
    /// see this reference before making decisions based on this value
    /// http://www.brendangregg.com/blog/2017-08-08/linux-load-averages.html
    /// parsed from /proc/loadavg
    pub load_avg_five_minute: f32,
    /// The load average of the system over the last 15 minutes please
    /// see this reference before making decisions based on this value
    /// http://www.brendangregg.com/blog/2017-08-08/linux-load-averages.html
    /// parsed from /proc/loadavg
    pub load_avg_fifteen_minute: f32,
    /// Available system memory in kilobytes parsed from /proc/meminfo
    pub system_memory: u64,
    /// Allocated system memory in kilobytes parsed from /proc/meminfo
    pub allocated_memory: u64,
    /// The model name of this router which is inserted into the config
    /// at build time by the firmware builder. Note that this is an Althea
    /// specific identifying name since we define it ourselves there
    pub model: String,
    /// An array of sensors data, one entry for each sensor discovered by
    /// traversing /sys/class/hwmon
    pub sensor_readings: Option<Vec<SensorReading>>,
    /// A 64 bit float representing the system uptime located in /proc/uptime
    /// This is provided by the linux kernel and is generated on the fly in
    /// a tuple format with no commas in the following format.
    /// (Up time of system in seconds               Time of each core idling)
    #[serde(default)]
    pub system_uptime: Duration,
    /// The linux kernel version of this router will be inserted into the hard-
    /// structure allowing us to upload into the dashboard what version we're
    /// running. The format will be a string as it's the most logical format
    #[serde(default = "default_kernel_version")]
    pub system_kernel_version: String,
    /// The entire linux kernel version string just in case we want the extra
    /// information. It may be useful for debugging purposes.
    #[serde(default = "default_kernel_version")]
    pub entire_system_kernel_version: String,
    /// Vector of eth data i.e. whether a link is up and if so what the link speed is
    pub ethernet_stats: Option<Vec<EthernetStats>>,
    // Vector of wifi devices on router with staion and survey data for each
    #[serde(default)]
    pub wifi_devices: Vec<WifiDevice>,
    // List of extenders connected to our router
    #[serde(default)]
    pub extender_list: Option<Vec<ClientExtender>>,
    // Info about the max connections, number of rows in conntrack table and current number of connections made by router
    #[serde(default)]
    pub conntrack: Option<ConntrackInfo>,
}

fn default_kernel_version() -> String {
    "Unknown".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Representation of a sensor discovered in /sys/class/hwmon
/// https://www.kernel.org/doc/Documentation/hwmon/sysfs-interface
/// TODO not completely implemented
pub struct SensorReading {
    /// Human readable device name
    pub name: String,
    /// The sensor reading in Units of centi-celsius not all readings
    /// will end up being read because TODO the interface parsing is not
    /// complete
    pub reading: u64,
    /// The minimum reading this sensor can read in centi-celsius
    pub min: Option<u64>,
    /// The maximum reading this sensor can read in centi-celsius
    pub max: Option<u64>,
    /// A provided temp at which this device starts to risk failure in centi-celsius
    pub crit: Option<u64>,
}

/// Struct that hold information about the ethernet interfaces, i.e. whether a link is
/// up and the speed of the link\
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthernetStats {
    pub is_up: bool,
    pub mode_of_operation: EthOperationMode,
    pub tx_packet_count: u64,
    pub tx_errors: u64,
    pub rx_packet_count: u64,
    pub rx_errors: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConntrackInfo {
    pub max_conns: u32,
    pub current_conns: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Enum that encompases base speed and duplex: full or half. TODO need to add physical medium, twisted pair or fiber.
/// It is possible to get this information since ethtool shows this
pub enum EthOperationMode {
    FullDup40GBase,
    FullDup25GBase,
    FullDup10GBase,
    FullDup5GBase,
    FullDup2500MBBase,
    FullDup1000MBBase,
    HalfDup1000MBBase,
    FullDup100MBBase,
    HalfDup100MBBase,
    FullDup10MBBase,
    HalfDup10MBBase,
    Unknown,
}

/// Struct for storing peer status data for reporting to the operator tools server
/// the goal is to give a full picture of all links in the network to the operator
/// so we include not only the link speed but also the stats history of the link
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NeighborStatus {
    /// the id of the neighbor
    pub id: Identity,
    /// their shaped wg interface speed in mbps
    pub shaper_speed: Option<usize>,
    /// If this user is currently being enforced upon
    #[serde(default)]
    pub enforced: bool,
}

/// Heartbeat sent to the operator server to help monitor
/// liveness and network state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatMessage {
    /// The identity of the sender
    pub id: Identity,
    /// The organizer address set on the device if any
    pub organizer_address: Option<Address>,
    /// The devices current balance, we could in theory query this
    /// using the address in the id anyways, consider dropping
    pub balance: Option<Uint256>,
    /// The full price this node is paying for each byte of traffic
    /// in the usual unit of wei/byte
    pub exit_dest_price: u64,
    /// The identity of the upstream neighbor, being defined as the one
    /// closer to the exit
    pub upstream_id: Identity,
    /// The babel Route to the exit, including details such as metric and
    /// full path rtt
    pub exit_route: Route,
    /// The babel Neighbor over which our traffic flows, this gives us the Reach
    /// (packet loss over 16 seconds) as well as the neighbor RTT
    pub exit_neighbor: Neighbor,
    /// If this user wants to be notified when they have a low balance
    pub notify_balance: bool,
    /// The router version stored in semver format as found in the Cargo.toml
    pub version: String,
}

/// An exit's unix time stamp that can be queried by a downstream router
/// Many routers have no built in clock and need to set their time at boot
/// in order for wireguard tunnels to work correctly
#[derive(Debug, Serialize, Deserialize)]
pub struct ExitSystemTime {
    pub system_time: SystemTime,
}

#[derive(Hash, Eq, PartialEq, Debug)]
pub struct AuthorizedKeys {
    // public ssh key
    pub key: String,
    // if the key is managed by ops-tools or network operator
    pub managed: bool,
    // set flush to remove key from configuratio
    pub flush: bool,
}

#[cfg(test)]
mod test {

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DummyStruct {
        #[serde(
            serialize_with = "data_serialize",
            deserialize_with = "data_deserialize"
        )]
        contact: Option<ContactType>,
    }
    use lettre::Address;

    use crate::{
        legacy::{data_deserialize, data_serialize},
        ContactType,
    };
    #[test]
    fn test_operator_update_serialize() {
        let entry: DummyStruct = DummyStruct {
            contact: Some(ContactType::Email {
                email: Address::new("something", "1.1.1.1").unwrap(),
                sequence_number: Some(0),
            }),
        };
        let data = bincode::serialize(&entry).unwrap();
        let _try_bincode: DummyStruct = bincode::deserialize(&data).unwrap();
    }
}
