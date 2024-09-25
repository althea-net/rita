use std::time::Duration;

use babel_monitor::structs::BabeldConfig;
use clarity::Address;
use num256::Uint256;

pub mod encryption;

use crate::{
    BillingDetails, ContactType, ExitConnection, HardwareInfo, Identity, InstallationDetails,
    NeighborStatus, ShaperSettings, SystemChain, UpdateType, UpdateTypeLegacy,
    UsageTrackerTransfer, WgKey, WifiToken,
};

/// Variants of this enum are the types of data that ops can receive over a websocket connection
/// and decode from a device, replacing the old http send of all of it at once which was inefficient.
/// data sent here must also be sent with the router ID in order for ops to process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RouterWebsocketMessage {
    OperatorAddress {
        id: Identity,
        address: Option<Address>,
        /// we include a system chain here because if there is no operator address
        /// we don't know what this router is supposed to be configured like, the best
        /// proxy for that is the system chain value
        chain: SystemChain,
    },
    /// Data saved in the timeseries data struct on ops
    TimeseriesData {
        id: Identity,
        /// The status of this devices peers, this is data that we want to communicate
        /// with the operator server but don't really have space in the purely udp
        /// heartbeat packet, neither is it required that this data be sent very often
        /// we don't need instant updates of it. Arguably the phone number and email
        /// values for heartbeats should come in through here.
        neighbor_info: Vec<NeighborStatus>,
        /// Info about the current state of this device, including it's model, CPU,
        /// memory, and temperature if sensors are available
        hardware_info: Option<HardwareInfo>,
        /// This is to keep track of the rita client uptime for debugging purposes
        /// In the event something whacko happens, serde will magically derive default value.
        rita_uptime: Duration,
    },
    /// Information about the customer and the router
    CustomerDetails {
        id: Identity,
        /// The user contact details, stored in exit client details but used throughout
        /// for various reasons.
        /// see the type definition for more details about how this type restricts values
        contact_info: Option<ContactType>,
        /// Details about this installation, including ip addresses, phone ip address and other
        /// info to insert into a spreadsheet displayed by operator tools.
        install_details: Option<InstallationDetails>,
        /// Details about this user, including city, state, postal code and other
        /// info to insert into a spreadsheet displayed by operator tools. Or submit
        /// to a billing partner to ease onboarding.
        billing_details: Option<BillingDetails>,
    },
    /// Information about the router's connection and bandwidth usage
    ConnectionDetails {
        id: Identity,
        /// Infomation about current exit
        exit_con: Option<ExitConnection>,
        /// This is a user set bandwidth limit value, it will cap the users download
        /// and upload to the provided value of their choosing. Denoted in mbps
        user_bandwidth_limit: Option<usize>,
        /// Details of both the Client and Relay bandwidth usage over a given period determined
        /// by the ops_last_seen_usage_hour in OperatorUpdateMessage. When the device's last
        /// saved usage hour is the same as the ops last seen, we are up to date. Data sent
        /// through here gets added to a database entry for each device.
        user_bandwidth_usage: Option<UsageTrackerTransfer>,
        /// Current client data usage in mbps computed as the last input to the usage tracker
        /// so an average of around 5-10 seconds
        client_mbps: Option<u64>,
        /// Curent relay data usage in mbps, coputed as the last input to the usage tracker
        /// so an average of around 5-10 seconds
        relay_mbps: Option<u64>,
    },
}

// just ignore the hardware info field on the timeseries data message for now
impl PartialEq for RouterWebsocketMessage {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                RouterWebsocketMessage::OperatorAddress {
                    id: id1,
                    address: address1,
                    chain: chain1,
                },
                RouterWebsocketMessage::OperatorAddress {
                    id: id2,
                    address: address2,
                    chain: chain2,
                },
            ) => id1 == id2 && address1 == address2 && chain1 == chain2,
            (
                RouterWebsocketMessage::TimeseriesData {
                    id: id1,
                    neighbor_info: neighbor_info1,
                    hardware_info: _hardware_info1,
                    rita_uptime: rita_uptime1,
                },
                RouterWebsocketMessage::TimeseriesData {
                    id: id2,
                    neighbor_info: neighbor_info2,
                    hardware_info: _hardware_info2,
                    rita_uptime: rita_uptime2,
                },
            ) => id1 == id2 && neighbor_info1 == neighbor_info2 && rita_uptime1 == rita_uptime2,
            (
                RouterWebsocketMessage::CustomerDetails {
                    id: id1,
                    contact_info: contact_info1,
                    install_details: install_details1,
                    billing_details: billing_details1,
                },
                RouterWebsocketMessage::CustomerDetails {
                    id: id2,
                    contact_info: contact_info2,
                    install_details: install_details2,
                    billing_details: billing_details2,
                },
            ) => {
                id1 == id2
                    && contact_info1 == contact_info2
                    && install_details1 == install_details2
                    && billing_details1 == billing_details2
            }
            (
                RouterWebsocketMessage::ConnectionDetails {
                    id: id1,
                    exit_con: exit_con1,
                    user_bandwidth_limit: user_bandwidth_limit1,
                    user_bandwidth_usage: user_bandwidth_usage1,
                    client_mbps: client_mbps1,
                    relay_mbps: relay_mbps1,
                },
                RouterWebsocketMessage::ConnectionDetails {
                    id: id2,
                    exit_con: exit_con2,
                    user_bandwidth_limit: user_bandwidth_limit2,
                    user_bandwidth_usage: user_bandwidth_usage2,
                    client_mbps: client_mbps2,
                    relay_mbps: relay_mbps2,
                },
            ) => {
                id1 == id2
                    && exit_con1 == exit_con2
                    && user_bandwidth_limit1 == user_bandwidth_limit2
                    && user_bandwidth_usage1 == user_bandwidth_usage2
                    && client_mbps1 == client_mbps2
                    && relay_mbps1 == relay_mbps2
            }
            _ => false,
        }
    }
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
    /// or an opkg update, to be removed after all routers >= beta 19 rc9
    Update {
        instruction: UpdateTypeLegacy,
    },
    /// Sends instructions from op tools about the type of update to perform, either a sysupgrade
    /// or an opkg update
    UpdateV2 {
        instruction: UpdateType,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PaymentAndNetworkSettings {
    /// The default 'gateway' price, this comes with a few caveats mainly that gateway
    /// auto detection is based around having a wan port and is not always accurate but
    /// generally gateways will always be detected as gateways and relays may sometimes
    /// declare themselves gateways if the user toggled in a WAN port even if that WAN port
    /// is not being used
    /// This field is denominated in wei/byte and is a u32 to reflect the maximum resolution
    /// of the price field we have set in babel.
    pub gateway: u32,
    /// The default relay price, which is the price that a normal client in the network
    /// will charge other clients to forward bandwidth. Remember that everyone has a
    /// relay price even if they have no one to sell to. Also remember that unless
    /// forbidden with 'force_operator_price' this value can be changed by the user
    /// see the situation described in the max bandwidth setting for what might happen
    ///  if the user sets an insane price.
    /// This field is denominated in wei/byte and is a u32 to reflect the maximum resolution
    /// of the price field we have set in babel.
    pub relay: u32,
    /// The maximum price any given router will pay in bandwidth, above this price the routers
    /// will only pay their peer the max price, this can cause situations where routers disagree
    /// about how much they have been paid and start enforcing. Remember this must be less than
    /// the relay price + gateway price + exit price of the deepest user in the network in terms
    /// of hops to prevent this from happening in 'intended' scenarios.
    pub max: u32,
    /// This is the balance level at which the user starts to see the little 'warning'
    /// message on their dashboard and also when the low balance text message is sent
    pub warning: u128,
    /// The system blockchain that is currently being used, if it is 'none' here it is
    /// interpreted as "don't change anything"
    pub system_chain: Option<SystemChain>,
    /// The withdraw blockchain that is currently being used, if it is 'none' here it is
    /// interpreted as "don't change anything"
    pub withdraw_chain: Option<SystemChain>,
}

/// Variants of this enum are the types of data that ops can send a router over a websocket connection,
/// generally when responding to messages from routers or syncing with operator tools.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OperatorWebsocketMessage {
    /// Operator's wg public key to be used for encryption. this must be received by the router
    /// before any further messages can proceed.
    OperatorWgKey(WgKey),
    /// Contains all the payment and network settings to be changed from ops
    PaymentAndNetworkSettings(PaymentAndNetworkSettings),
    /// This is the pro-rated fee paid to the operator, defined as wei/second
    OperatorFee(u128),
    /// A json payload to be merged into the existing settings, this payload is checked
    /// not to include a variety of things that might break the router but is still not
    /// risk free for example the url fields require http:// or https:// or the router will
    /// crash even though the value will be accepted as a valid string
    MergeJson(serde_json::Value),
    /// An action the operator wants to take to affect this router, examples may include reset
    /// password or change the wifi ssid
    OperatorAction(OperatorAction),
    /// String that holds the download link to the latest firmware release
    /// When a user hits 'update router', it updates to this version
    LocalUpdateInstruction(Option<UpdateType>),
    /// settings for the device bandwidth shaper
    ShaperSettings(ShaperSettings),
    /// settings for babeld
    BabeldSettings(BabeldConfig),
    /// Updated contact info from ops tools
    ContactInfo(Option<ContactType>),
    /// Billing details from ops tools, so that we may sync changes
    BillingDetails(Option<BillingDetails>),
    /// Last seen hour that ops tools has for usage data, so we know from the router
    /// side how much history we need to send in with the next checkin cycle
    OpsLastSeenUsageHour(u64),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedRouterWebsocketMessage {
    pub pubkey: WgKey,
    pub nonce: [u8; 24],
    pub encrypted_router_websocket_msg: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedOpsWebsocketMessage {
    pub pubkey: WgKey,
    pub nonce: [u8; 24],
    pub encrypted_ops_websocket_msg: Vec<u8>,
}
