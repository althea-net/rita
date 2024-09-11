use crate::openwrt_updates::{UpdateType, UpdateTypeLegacy};
use crate::operator_tools::action::OperatorAction;
use crate::SystemChain;
use crate::{contact_info::ContactType, BillingDetails};
use babel_monitor::structs::BabeldConfig;
use serde::de::Error;
use serde::Serialize;
use serde::{Deserialize, Deserializer, Serializer};
use std::hash::Hash;

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

fn default_ops_last_seen_usage_hour() -> u64 {
    0
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

    use super::{data_deserialize, data_serialize, ContactType};
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
