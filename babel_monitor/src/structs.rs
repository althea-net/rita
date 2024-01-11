use ipnetwork::{IpNetwork, IpNetworkError};
use std::f32;
use std::fmt::Debug;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::net::{AddrParseError, IpAddr};
use std::num::{ParseFloatError, ParseIntError};
use std::str::{self, ParseBoolError};
use std::string::FromUtf8Error;
use std::time::Duration;

#[derive(Debug)]
pub enum BabelMonitorError {
    VariableNotFound(String, String),
    InvalidPreamble(String),
    LocalFeeNotFound(String),
    CommandFailed(String, String),
    ReadFailed(String),
    NoTerminator(String),
    NoNeighbor(String),
    TcpError(String),
    BabelParseError(String),
    ReadFunctionError(std::io::Error),
    BoolParseError(ParseBoolError),
    ParseAddrError(AddrParseError),
    IntParseError(ParseIntError),
    FloatParseError(ParseFloatError),
    NetworkError(IpNetworkError),
    TokioError(String),
    NoRoute(String),
    MiscStringError(String),
    FromUtf8Error(FromUtf8Error),
}

impl From<std::io::Error> for BabelMonitorError {
    fn from(error: std::io::Error) -> Self {
        BabelMonitorError::ReadFunctionError(error)
    }
}
impl From<ParseBoolError> for BabelMonitorError {
    fn from(error: ParseBoolError) -> Self {
        BabelMonitorError::BoolParseError(error)
    }
}
impl From<AddrParseError> for BabelMonitorError {
    fn from(error: AddrParseError) -> Self {
        BabelMonitorError::ParseAddrError(error)
    }
}
impl From<ParseIntError> for BabelMonitorError {
    fn from(error: ParseIntError) -> Self {
        BabelMonitorError::IntParseError(error)
    }
}
impl From<ParseFloatError> for BabelMonitorError {
    fn from(error: ParseFloatError) -> Self {
        BabelMonitorError::FloatParseError(error)
    }
}
impl From<IpNetworkError> for BabelMonitorError {
    fn from(error: IpNetworkError) -> Self {
        BabelMonitorError::NetworkError(error)
    }
}
impl From<FromUtf8Error> for BabelMonitorError {
    fn from(error: FromUtf8Error) -> Self {
        BabelMonitorError::FromUtf8Error(error)
    }
}

impl Display for BabelMonitorError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            BabelMonitorError::VariableNotFound(a, b) => {
                write!(f, "variable '{a}' not found in '{b}'",)
            }
            BabelMonitorError::InvalidPreamble(a) => write!(f, "Invalid preamble: {a}",),
            BabelMonitorError::LocalFeeNotFound(a) => {
                write!(f, "Could not find local fee in '{a}'",)
            }
            BabelMonitorError::CommandFailed(a, b) => write!(f, "Command '{a}' failed. {b}",),
            BabelMonitorError::ReadFailed(a) => write!(f, "Erroneous Babel output:\n{a}",),
            BabelMonitorError::NoTerminator(a) => {
                write!(f, "No terminator after Babel output:\n{a}",)
            }
            BabelMonitorError::NoNeighbor(a) => {
                write!(f, "No Neighbor was found matching address:\n{a}",)
            }
            BabelMonitorError::TcpError(a) => {
                write!(f, "Tcp connection failure while talking to babel:\n{a}",)
            }
            BabelMonitorError::BabelParseError(a) => write!(f, "Babel parsing failed:\n{a}",),
            BabelMonitorError::ReadFunctionError(e) => write!(f, "{e}"),
            BabelMonitorError::BoolParseError(e) => write!(f, "{e}"),
            BabelMonitorError::ParseAddrError(e) => write!(f, "{e}"),
            BabelMonitorError::IntParseError(e) => write!(f, "{e}"),
            BabelMonitorError::FloatParseError(e) => write!(f, "{e}"),
            BabelMonitorError::NetworkError(e) => write!(f, "{e}"),
            BabelMonitorError::NoRoute(a) => write!(f, "Route not found:\n{a}",),
            BabelMonitorError::TokioError(a) => {
                write!(f, "Tokio had a failure while it was talking to babel:\n{a}",)
            }
            BabelMonitorError::MiscStringError(a) => write!(f, "{a}",),
            BabelMonitorError::FromUtf8Error(a) => write!(f, "{a}",),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    pub up: bool,
    pub ipv6: Option<IpAddr>,
    pub ipv4: Option<IpAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub id: String,
    pub iface: String,
    pub xroute: bool,
    pub installed: bool,
    pub neigh_ip: IpAddr,
    pub prefix: IpNetwork,
    pub metric: u16,
    pub refmetric: u16,
    pub full_path_rtt: f32,
    pub price: u32,
    pub fee: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Neighbor {
    pub id: String,
    pub address: IpAddr,
    pub iface: String,
    pub reach: u16,
    pub txcost: u16,
    pub rxcost: u16,
    pub rtt: f32,
    pub rttcost: u16,
    pub cost: u16,
}

/// This struct lists config options for babeld, these are applied at startup
/// it is not complete and only lists options that will probably be used
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct BabeldConfig {
    /// how often to update the Babeld routing table, by doing a full kernel dump
    /// Babeld listens for routing table changes and applies them immediately. If set to
    /// None Babel will only listen for updates and never perform a full dump
    pub kernel_check_interval: Option<Duration>,
    /// The Price of bandwidth advertised over this router, in terms of wei (1*10^18 of a dollar) per byte
    pub local_fee: u32,
    /// Decides how much weight to give to route quality versus price, a higher value means higher weight on quality
    pub metric_factor: u32,
    /// The default values for various interfaces options
    pub interface_defaults: BabeldInterfaceConfig,
}

/// This struct lists all config options for babeld interfaces, this can be used
/// to set the global default or used to set per interface options
/// this config is not complete, it only includes the options that will proably be used
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct BabeldInterfaceConfig {
    /// If link quality estimation is enabled for this interface
    pub link_quality: bool,
    /// The maximum penalty for a route with a high latency
    /// the rtt value is multiplied by this value and added to the metric
    /// up to rtt_max
    pub max_rtt_penalty: u16,
    /// The minimum rtt at which to start applying the penalty, unit is milliseconds
    pub rtt_min: u16,
    /// The maximum rtt at which to apply the the full value of max_rtt_penalty, unit is milliseconds
    pub rtt_max: u16,
    /// The interval at which to send hello messages, unit is seconds, these are used to compute packet loss
    /// and latency, by default this is 1 second. The last 16 hellos are used to determine
    /// route quality, increasing this value has a smoothing effect on route quality estimations
    pub hello_interval: u16,
    /// The interval at which to send routing table updates, since babel uses triggered
    /// updates when routes becoming infeasible this can be set to a relatively high value
    /// by default it is 4x the hello interval
    pub update_interval: u16,
    /// If set this router will avoid advertising routes it has learned from this interface
    /// back to the interface, this is useful for avoiding routing loops
    pub split_horizon: bool,
}
