use crate::Identity;
use babel_monitor::structs::Neighbor;
use babel_monitor::structs::Route;
use clarity::Address;
use num256::Uint256;
use serde::Deserialize;
use serde::Serialize;

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
