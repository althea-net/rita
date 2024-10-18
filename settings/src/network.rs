use althea_kernel_interface::DefaultRoute;
use althea_types::ShaperSettings;
use babel_monitor::structs::{BabeldConfig, BabeldInterfaceConfig};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr};

use althea_types::WgKey;

use arrayvec::ArrayString;

fn default_discovery_ip() -> Ipv6Addr {
    Ipv6Addr::new(0xff02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x8)
}

/// Sets the default configuration values for babeld
fn default_babeld_config() -> BabeldConfig {
    BabeldConfig {
        // how often to update the Babeld routing table, by doing a full kernel dump
        // this is useful to insert routes added to the table by other programs into the babel
        // advertised route list. But this is not a property generally used in Althea. The risk of
        // setting this to none is that in edge cases (such as an overloaded machine) babel may
        // not get notified of a new route in the table added by another program.
        kernel_check_interval: None,
        // how much this router charges other routers for bandwidth, note that this value
        // will be updated from operator tools defaults or the user dashboard
        local_fee: 0,
        // priority of quality versus price, this default value is an 'even' weight between the two
        metric_factor: 1_900u32,
        // the default interface config options
        interface_defaults: BabeldInterfaceConfig {
            // turning this off might break some of our quality monitoring code
            // as we expect all links have packet loss monitoring + rtt monitoring
            link_quality: true,
            // the maximum route penalty for high latency, since babeld estimates latency
            // by sending packets to the next hop and measuring the time it takes to get a response
            // rtt can sometimes not match reality. So be careful with this value as it may cause irrational
            // behavior there
            max_rtt_penalty: 200u16,
            // below this rtt no penalty is applied
            rtt_min: 50u16,
            // above this rtt only the max_rtt_penalty is applied
            rtt_max: 500u16,
            // how often in seconds to send hello messages, these are used to compute packet loss
            hello_interval: 5u16,
            // how often in seconds to send route updates, triggered updates are sent when a route changes
            // so this can be safely set to a high value
            update_interval: 20u16,
            // When true routes are never re-advertised to the interface they were received from, this shoudl always
            // be true for our use case since babel is always listening on a tunnel.
            split_horizon: true,
        },
    }
}

fn default_usage_tracker_file() -> String {
    "/etc/rita-usage-tracker.bincode".to_string()
}

fn default_shaper_settings() -> ShaperSettings {
    ShaperSettings {
        enabled: true,
        max_speed: 10000,
        min_speed: 50,
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct NetworkSettings {
    #[serde(default = "default_babeld_config")]
    pub babeld_settings: BabeldConfig,
    /// How much non-financial metrics matter compared to a route's cost. By default a 2x more
    /// expensive route will only be chosen if it scores more than 2x better in other metrics. The
    /// value is expressed in 1/1000 increments, i.e. 1000 = 1.0, 500 = 0.5 and 1 = 0.001
    pub metric_factor: Option<u32>,
    /// The static IP used on mesh interfaces
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mesh_ip: Option<IpAddr>,
    /// Essentially a list of other ip that can be added to this router on the Babel network
    /// used only by exits so that they can advertise a second ip to the network for the exit list
    #[serde(default)]
    pub alternate_mesh_ips: Vec<IpAddr>,
    /// Broadcast ip address used for peer discovery (in ff02::/8)
    #[serde(default = "default_discovery_ip")]
    pub discovery_ip: Ipv6Addr,
    /// Port on which we connect to a local babel instance (read-write connection required)
    /// this is not in the babeld_settings section because everything else in that section is applied
    /// and communicated to babel, this value is only used by rita and must be pre-configured in babel
    /// as it can't be changed after startup
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
    #[serde(default)]
    pub last_default_route: Option<DefaultRoute>,
    /// This is the NIC which connects to the internet, used by gateways/exits to find its
    /// globally routable ip
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_nic: Option<String>,
    /// The name of the device or router model
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// Nickname of the device on the network
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<ArrayString<32>>,
    /// Full file path for usage tracker storage
    #[serde(default = "default_usage_tracker_file")]
    pub usage_tracker_file: String,
    #[serde(default)]
    /// Set to true by the dashboard when the user indicates they've made a backup
    pub backup_created: bool,
    /// Determines if this device will try and shape interface speeds when latency
    /// spikes are detected. You probably don't want to have this on in networks
    /// where there is significant jitter that's not caused by traffic load
    #[serde(default = "default_shaper_settings")]
    pub shaper_settings: ShaperSettings,
    /// This is a user provided bandwidth limit (upload and download) to be enforced
    /// by cake. Traffic is shaped incoming on wg_exit and outgoing on br_lan resulting
    /// in a symmetrical limit of the users choice. Specified in mbit/s
    #[serde(default)]
    pub user_bandwidth_limit: Option<usize>,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        NetworkSettings {
            shaper_settings: default_shaper_settings(),
            backup_created: false,
            metric_factor: None,
            mesh_ip: None,
            alternate_mesh_ips: vec![],
            discovery_ip: default_discovery_ip(),
            babel_port: 6872,
            rita_contact_port: 4874,
            rita_hello_port: 4876,
            rita_dashboard_port: 4877,
            rita_dashboard_password: None,
            rita_tick_interval: 5,
            wg_private_key: None,
            wg_private_key_path: "/tmp/priv".to_string(),
            wg_public_key: None,
            wg_start_port: 60000,
            peer_interfaces: HashSet::new(),
            manual_peers: Vec::new(),
            external_nic: None,
            last_default_route: None,
            device: None,
            nickname: None,
            usage_tracker_file: default_usage_tracker_file(),
            user_bandwidth_limit: None,
            babeld_settings: default_babeld_config(),
        }
    }
}
