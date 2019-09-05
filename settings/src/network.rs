use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr};

use althea_types::WgKey;

use arrayvec::ArrayString;

fn default_discovery_ip() -> Ipv6Addr {
    warn!("Add discovery_ip to network, removed in the next version!");
    Ipv6Addr::new(0xff02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x8)
}

fn default_tunnel_timeout() -> u64 {
    300 // 5 minutes
}

fn default_metric_factor() -> u32 {
    1_900u32
}

fn default_usage_tracker_file() -> String {
    "/etc/rita-usage-tracker.json".to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct NetworkSettings {
    /// How much non-financial metrics matter compared to a route's cost. By default a 2x more
    /// expensive route will only be chosen if it scores more than 2x better in other metrics. The
    /// value is expressed in 1/1000 increments, i.e. 1000 = 1.0, 500 = 0.5 and 1 = 0.001
    #[serde(default = "default_metric_factor")]
    pub metric_factor: u32,
    /// The static IP used on mesh interfaces
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mesh_ip: Option<IpAddr>,
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
    /// The password for dashboard authentication
    pub rita_dashboard_password: Option<String>,
    /// Port over which the bounty hunter will be contacted
    pub bounty_port: u16,
    /// The tick interval in seconds between rita hellos, traffic watcher measurements and payments
    pub rita_tick_interval: u64,
    /// Our private key, encoded with Base64 (what the `wg` command outputs and takes by default)
    /// Note this is the canonical private key for the node
    pub wg_private_key: Option<WgKey>,
    /// Where our private key is saved (written to the path on every start) because wireguard does
    /// not accept private keys via stdin or command line args
    pub wg_private_key_path: String,
    /// The our public key, Base64 encoded
    pub wg_public_key: Option<WgKey>,
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
    /// Nickname of the device on the network
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<ArrayString<[u8; 32]>>,
    /// Full file path for usage tracker storage
    #[serde(default = "default_usage_tracker_file")]
    pub usage_tracker_file: String,
    #[serde(skip_deserializing, default)]
    // Set to true by the dashboard when the user indicates they've made a backup
    pub backup_created: bool,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        NetworkSettings {
            backup_created: false,
            metric_factor: 1900,
            mesh_ip: None,
            bounty_ip: "fd00::3".parse().unwrap(),
            discovery_ip: default_discovery_ip(),
            babel_port: 6872,
            rita_hello_port: 4876,
            rita_dashboard_port: 4877,
            rita_dashboard_password: None,
            rita_contact_port: 4875,
            bounty_port: 8888,
            rita_tick_interval: 5,
            wg_private_key: None,
            wg_private_key_path: String::new(),
            wg_public_key: None,
            wg_start_port: 60000,
            peer_interfaces: HashSet::new(),
            manual_peers: Vec::new(),
            external_nic: None,
            default_route: Vec::new(),
            is_gateway: false,
            tunnel_timeout_seconds: default_tunnel_timeout(),
            device: None,
            nickname: None,
            usage_tracker_file: default_usage_tracker_file(),
        }
    }
}
