use crate::{ClientExtender, WifiDevice};
use serde::Deserialize;
use serde::Serialize;
use std::time::Duration;

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
