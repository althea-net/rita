use crate::exits::ExitClientIdentity;
use crate::hardware_info::HardwareInfo;
use crate::neighbors::NeighborStatus;
use crate::{contact_info::ContactType, BillingDetails, InstallationDetails};
use crate::{Identity, SystemChain, UsageTrackerFlat, UsageTrackerTransfer};
use clarity::Address;
use ipnetwork::IpNetwork;
use serde::Deserialize;
use serde::Serialize;
use std::hash::Hash;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

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

/// An exit's unix time stamp that can be queried by a downstream router
/// Many routers have no built in clock and need to set their time at boot
/// in order for wireguard tunnels to work correctly
#[derive(Debug, Serialize, Deserialize)]
pub struct ExitSystemTime {
    pub system_time: SystemTime,
}
