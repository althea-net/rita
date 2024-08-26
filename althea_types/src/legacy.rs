//! This file contains legacy structs that are used in previous router versions to
//! send and receive checkins from ops server before websockets were added in. This
//! code should not be deleted until all routers are updated to versions with websockets.

use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};
use std::time::Duration;

use babel_monitor::structs::BabeldConfig;
use clarity::Address;

use crate::{
    websockets::OperatorAction, BillingDetails, ContactType, ExitConnection, HardwareInfo,
    Identity, InstallationDetails, NeighborStatus, ShaperSettings, SystemChain, UpdateType,
    UpdateTypeLegacy, UsageTrackerFlat, UsageTrackerTransfer,
};

fn default_ops_last_seen_usage_hour() -> u64 {
    0
}

/// The message we send to the operator server to checkin, this allows us to customize
/// the operator checkin response to the device based on it's network and any commands
/// the operator may wish to send. No longer used in rita, kept for ops tools back compatibility
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

/// Operator update that we get from the operator server during our checkin
/// No longer used on the rita side, this is kept in for ops tools back compatibility
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
    pub shaper_settings: Option<ShaperSettings>,
    /// settings for babeld
    pub babeld_settings: Option<BabeldConfig>,
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
        Err(e) => return Err(D::Error::custom(e)),
    };
    Ok(value)
}
