use crate::{contact_info::ContactType, wg_key::WgKey, BillingDetails, InstallationDetails};
use crate::{ClientExtender, UsageTrackerFlat, UsageTrackerTransfer, WifiDevice};
use arrayvec::ArrayString;
use babel_monitor::structs::Neighbor;
use babel_monitor::structs::Route;
use clarity::Address;
use deep_space::Address as AltheaAddress;
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

#[derive(Default, Debug, Serialize, Deserialize, Hash, Clone, Eq, PartialEq, Copy)]
pub enum SystemChain {
    Ethereum,
    Rinkeby,
    #[default]
    Xdai,
    Althea,
}

impl Display for SystemChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SystemChain::Ethereum => write!(f, "Ethereum"),
            SystemChain::Rinkeby => write!(f, "Rinkeby"),
            SystemChain::Xdai => write!(f, "Xdai"),
            SystemChain::Althea => write!(f, "Althea"),
        }
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
            "Althea" => Ok(SystemChain::Althea),
            _ => Err(()),
        }
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
    // Given a vector of wifitoken, apply these changes to the router
    SetWifi {
        token: Vec<WifiToken>,
    },
    /// This resets the traffic shaper to 'unlimited' speed for all connections. It can
    /// be useful when the shaper is showing obviously incorrect values for some peer
    /// usually caused by bad network transients. While the shaper will eventually recover
    /// this allows a human to do it right away
    ResetShaper,
    /// Fully reboots the router, this includes a power cycle not just a restart of the
    /// routing processes. For x86 machines this action comes with some risk as devices may
    /// get stuck in the BIOS if not configured properly.
    Reboot,
    /// Restart babeld and rita on the router
    SoftReboot,
    /// Sends instructions from op tools about the type of update to perform, either a sysupgrade
    /// or an opkg update
    UpdateV2 {
        instruction: UpdateType,
    },
    /// Sends instructions from op tools about the type of update to perform, either a sysupgrade
    /// or an opkg update, to be removed after all routers >= beta 19 rc9
    Update {
        instruction: UpdateTypeLegacy,
    },
    /// Changes the operator address of a given router in order to support Beta 15 and below
    /// this has it's own logic in the operator tools that will later be removed for the logic
    /// you see in Althea_rs
    ChangeOperatorAddress {
        new_address: Option<Address>,
    },
    /// Sets the min gas value to the provided value, primarily intended for use on xDai where
    /// the validators set a minimum gas price as a group without warning
    SetMinGas {
        new_min_gas: Uint256,
    },
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
    /// to be removed once all routers are updated to >= beta 19 rc9
    pub local_update_instruction: Option<UpdateTypeLegacy>,
    /// String that holds the download link to the latest firmware release
    /// When a user hits 'update router', it updates to this version
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
    /// Last seen hour that ops tools has for usage data, so we know from the router
    /// side how much history we need to send in with the next checkin cycle
    #[serde(default = "default_ops_last_seen_usage_hour")]
    pub ops_last_seen_usage_hour: u64,
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

fn default_shaper_settings() -> ShaperSettings {
    ShaperSettings {
        max_speed: 1000,
        min_speed: 50,
        enabled: true,
    }
}

fn default_ops_last_seen_usage_hour() -> u64 {
    0
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
    /// Infomation about current exit
    pub exit_con: Option<ExitConnection>,
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
    /// Legacy bandwidth usage from pre beta 20 routers, one of the two will be None
    pub user_bandwidth_usage: Option<UsageTrackerFlat>,
    /// Details of both the Client and Relay bandwidth usage over a given period determined
    /// by the ops_last_seen_usage_hour in OperatorUpdateMessage. When the device's last
    /// saved usage hour is the same as the ops last seen, we send no data here as we are up
    /// to date. Data sent through here gets added to a database entry for each device.
    pub user_bandwidth_usage_v2: Option<UsageTrackerTransfer>,
    /// Current client data usage in mbps computed as the last input to the usage tracker
    /// so an average of around 5-10 seconds
    pub client_mbps: Option<u64>,
    /// Curent relay data usage in mbps, coputed as the last input to the usage tracker
    /// so an average of around 5-10 seconds
    pub relay_mbps: Option<u64>,
    /// This is to keep track of the rita client uptime for debugging purposes
    /// In the event something whacko happens, serde will magically derive def-
    /// fault value.
    #[serde(default)]
    pub rita_uptime: Duration,
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
