use crate::WifiDevice;
use crate::{contact_info::ContactType, wg_key::WgKey, BillingDetails, InstallationDetails};
use arrayvec::ArrayString;
use babel_monitor::Neighbor as NeighborLegacy;
use babel_monitor::Route as RouteLegacy;
use clarity::Address;
use ipnetwork::IpNetwork;
use num256::Uint256;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::fmt::Display;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::net::Ipv4Addr;
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
            Some(nick) => write!(
                f,
                "nickname: {}, mesh_ip: {}, eth_address: {}, wg_pubkey {}",
                nick, self.mesh_ip, self.eth_address, self.wg_public_key
            ),
            None => write!(
                f,
                "mesh_ip: {}, eth_address: {}, wg_pubkey {}",
                self.mesh_ip, self.eth_address, self.wg_public_key
            ),
        }
    }
}

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
            SystemChain::Xdai => write!(f, "Xdai"),
        }
    }
}

impl Default for SystemChain {
    fn default() -> SystemChain {
        SystemChain::Xdai
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
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sequence_number: Option<u32>,
}

/// This is the state an exit can be in
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
#[serde(tag = "state")]
pub enum ExitState {
    New,
    GotInfo {
        general_details: ExitDetails,
        message: String,
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
        match *self {
            ExitState::GotInfo {
                ref general_details,
                ..
            } => Some(general_details),
            ExitState::Registering {
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
            ExitState::Registering { ref message, .. } => message.clone(),
            ExitState::Pending { ref message, .. } => message.clone(),
            ExitState::Registered { ref message, .. } => message.clone(),
            ExitState::Denied { ref message, .. } => message.clone(),
            ExitState::Disabled => "Exit disabled".to_string(),
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

/// This is all the data a light client needs to open a light client tunnel
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
pub struct LightClientLocalIdentity {
    pub wg_port: u16,
    /// If we have an existing tunnel, None if we don't know
    pub have_tunnel: Option<bool>,
    pub global: Identity,
    /// we have to replicate dhcp ourselves due to the android vpn api
    pub tunnel_address: Ipv4Addr,
    /// the local_fee of the node passing light client traffic, much bigger
    /// than the actual babel price field for ergonomics around downcasting
    /// the number after upcasting when we compute it.
    pub price: u128,
}

/// This represents a generic payment that may be to or from us
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

/// Something the operator may want to do to a router under their control
#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub enum OperatorAction {
    /// Resets the Rita dashboard password. This is the password users use to login
    /// to the router dashboard, which is distinct from the WiFi password. This
    /// password is also used for ssh login on the LAN. This reset operation does
    /// not change that password but it will be changed when the dashboard password
    /// is set again by the user.
    ResetRouterPassword,
    /// This resets the WiFi password to the default 'ChangeMe' and restarts the wifi
    /// subsystem (without restarting the router).
    ResetWiFiPassword,
    /// This resets the traffic shaper to 'unlimited' speed for all connections. It can
    /// be useful when the shaper is showing obviously incorrect values for some peer
    /// usually caused by bad network transients. While the shaper will eventually recover
    /// this allows a human to do it right away
    ResetShaper,
    /// Fully reboots the router, this includes a power cycle not just a restart of the
    /// routing processes. For x86 machines this action comes with some risk as devices may
    /// get stuck in the BIOS if not configured properly.
    Reboot,
    /// Sends instructions from op tools about the type of update to perform, either a sysupgrade
    /// or an opkg update
    UpdateV2 { instruction: UpdateType },
    /// Sends instructions from op tools about the type of update to perform, either a sysupgrade
    /// or an opkg update, to be removed after all routers >= beta 19 rc9
    Update { instruction: UpdateTypeLegacy },
    /// Changes the operator address of a given router in order to support Beta 15 and below
    /// this has it's own logic in the operator tools that will later be removed for the logic
    /// you see in Althea_rs
    ChangeOperatorAddress { new_address: Option<Address> },
    /// Sets the min gas value to the provided value, primarily intended for use on xDai where
    /// the validators set a minimum gas price as a group without warning
    SetMinGas { new_min_gas: Uint256 },
    /// Modifies the authorized keys used for access to routers
    UpdateAuthorizedKeys {
        add_list: Vec<String>,
        drop_list: Vec<String>,
    },
}

/// Operator update that we get from the operator server during our checkin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorUpdateMessage {
    /// The default relay price, which is the price that a normal client in the network
    /// will charge other clients to forward bandwidth. Remember that everyone has a
    /// relay price even if they have no one to sell to. Also remember that unless
    /// forbidden with 'force_operator_price' this value can be changed by the user
    /// see the situation described in the max bandwidth setting for what might happen
    ///  if the user sets an insane price.
    /// This field is denominated in wei/byte and is a u32 to reflect the maximum resolution
    /// of the price field we have set in babel.
    pub relay: u32,
    /// The default 'gateway' price, this comes with a few caveats mainly that gateway
    /// auto detection is based around having a wan port and is not always accurate but
    /// generally gateways will always be detected as gateways and relays may sometimes
    /// declare themselves gateways if the user toggled in a WAN port even if that WAN port
    /// is not being used
    /// This field is denominated in wei/byte and is a u32 to reflect the maximum resolution
    /// of the price field we have set in babel.
    pub gateway: u32,
    /// The price specifically charged to phone clients, above and beyond the price to reach
    /// the exit. For example if this value was 5c and the cost for the selling node to reach
    /// the exit was 10c the price presented to the phone client would be 15c. This field is also
    /// denominated  in wei/byte but is not subject to same size restrictions and could in theory
    /// be a u64 or even a u128
    pub phone_relay: u32,
    /// The maximum price any given router will pay in bandwidth, above this price the routers
    /// will only pay their peer the max price, this can cause situations where routers disagree
    /// about how much they have been paid and start enforcing. Remember this must be less than
    /// the relay price + gateway price + exit price of the deepest user in the network in terms
    /// of hops to prevent this from happening in 'intended' scenarios.
    pub max: u32,
    /// This is the pro-rated fee paid to the operator, defined as wei/second
    pub operator_fee: u128,
    /// This is the balance level at which the user starts to see the little 'warning'
    /// message on their dashboard and also when the low balance text message is sent
    pub warning: u128,
    /// The system blockchain that is currently being used, if it is 'none' here it is
    /// interpreted as "don't change anything"
    pub system_chain: Option<SystemChain>,
    /// The withdraw blockchain that is currently being used, if it is 'none' here it is
    /// interpreted as "don't change anything"
    pub withdraw_chain: Option<SystemChain>,
    /// A json payload to be merged into the existing settings, this payload is checked
    /// not to include a variety of things that might break the router but is still not
    /// risk free for example the url fields require http:// or https:// or the router will
    /// crash even though the value will be accepted as a valid string
    pub merge_json: serde_json::Value,
    /// An action the operator wants to take to affect this router, examples may include reset
    /// password or change the wifi ssid
    pub operator_action: Option<OperatorAction>,
    /// String that holds the download link to the latest firmware release
    /// When a user hits 'update router', it updates to this version
    /// to be removed once all routesr are updated to >= beta 19 rc9
    pub local_update_instruction: Option<UpdateTypeLegacy>,
    /// String that holds the download link to the latest firmware release
    /// When a user hits 'update router', it updates to this version
    ///  #[serde(default = "default_shaper_settings")]
    pub local_update_instruction_v2: Option<UpdateType>,
    /// settings for the device bandwidth shaper
    #[serde(default = "default_shaper_settings")]
    pub shaper_settings: ShaperSettings,
    // Updated contact info from ops tools
    #[serde(
        serialize_with = "data_serialize",
        deserialize_with = "data_deserialize"
    )]
    pub contact_info: Option<ContactType>,
    /// Billing details from ops tools, so that we may sync changes
    pub billing_details: Option<BillingDetails>,
}

/// Serializes a ContactType as a string
pub fn data_serialize<S>(value: &Option<ContactType>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let string_value = serde_json::to_string(&value).unwrap_or_default();
    serializer.serialize_str(&string_value)
}

/// Deserializes a string as a ContactType
pub fn data_deserialize<'de, D>(deserializer: D) -> Result<Option<ContactType>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer).unwrap_or_default();
    let value: Option<ContactType> = match serde_json::from_str(&s) {
        Ok(value) => value,
        Err(e) => return Err(e).map_err(D::Error::custom),
    };
    Ok(value)
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

fn default_shaper_settings() -> ShaperSettings {
    ShaperSettings {
        max_speed: 1000,
        min_speed: 50,
        enabled: true,
    }
}

/// The message we send to the operator server to checkin, this allows us to customize
/// the operator checkin response to the device based on it's network and any commands
/// the operator may wish to send
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorCheckinMessage {
    pub id: Identity,
    pub operator_address: Option<Address>,
    /// we include a system chain here because if there is no operator address
    /// we don't know what this router is supposed to be configured like, the best
    /// proxy for that is the system chain value
    pub system_chain: SystemChain,
    /// The status of this devices peers, this is data that we want to communicate
    /// with the operator server but don't really have space in the purely udp
    /// heartbeat packet, neither is it required that this data be sent very often
    /// we don't need instant updates of it. Arguably the phone number and email
    /// values for heartbeats should come in through here.
    pub neighbor_info: Vec<NeighborStatus>,
    /// The user contact details, stored in exit client details but used throughout
    /// for various reasons.
    ///  see the type definition for more details about how this type restricts values
    /// This only exists in Beta 14+
    pub contact_info: Option<ContactType>,
    /// Details about this installation, including ip addresses, phone ip address and other
    /// info to insert into a spreadsheet displayed by operator tools.
    pub install_details: Option<InstallationDetails>,
    /// Details about this user, including city, state, postal code and other
    /// info to insert into a spreadsheet displayed by operator tools. Or submit
    /// to a billing partner to ease onboarding.
    pub billing_details: Option<BillingDetails>,
    /// Info about the current state of this device, including it's model, CPU,
    /// memory, and temperature if sensors are available
    pub hardware_info: Option<HardwareInfo>,
    /// This is a user set bandwidth limit value, it will cap the users download
    /// and upload to the provided value of their choosing. Denoted in mbps
    pub user_bandwidth_limit: Option<usize>,
    /// This is to keep track of the rita client uptime for debugging purposes
    /// In the event something whacko happens, serde will magically derive def-
    /// fault value.
    #[serde(default)]
    pub rita_uptime: Duration,
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
    pub exit_route: RouteLegacy,
    /// The babel Neighbor over which our traffic flows, this gives us the Reach
    /// (packet loss over 16 seconds) as well as the neighbor RTT
    pub exit_neighbor: NeighborLegacy,
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

    use crate::{data_deserialize, data_serialize, ContactType};
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
