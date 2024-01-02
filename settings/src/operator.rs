//! Operator settings are the spiritual successor to the SubnetDAO concept, instead of having DAO's we now have operators, which could be a DAO
//! but far more importantly we don't have to deal with the multiple DAO concept as well as several others and we assume a trusting relationship
//! between the router and the operator. Meaning the operator can do things like reset (but not read) the WiFi password and the Operator trusts
//! that the router will be running stock software and generally not trying to exploit them by underpaying and such. This trustful relationship
//! simplifies things a lot (no need for complex trustless enforcement). If you find that both DAO settings and this exist at the same time
//! that means the transition is still in prgress.

use althea_types::{BillingDetails, InstallationDetails, ContactStorage};
use clarity::Address;
use num256::Uint256;

/// The default operator address, starting with none
fn default_operator_address() -> Option<Address> {
    None
}

/// If this router is following the operator set price or using their own
fn default_use_operator_price() -> bool {
    true
}

/// If we are displaying the operator setup card on the front page or not
/// this is false by default but set to true using the config template in
/// the firmware builder. The reasoning for this is that when we upgrade
/// older routers we don't want this form to suddenly show up, we want to
/// show it only for new routers being setup. Once everyone is upgraded
/// having this starting value be true will have the same affect but that's
/// not until Beta 15 at least
fn default_display_operator_setup() -> bool {
    false
}

/// If the operator has indicated that users should not be able to change
/// their own prices
fn default_force_use_operator_price() -> bool {
    false
}

/// If this user wants low balance text messages or not
fn default_low_balance_notification() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct OperatorSettings {
    /// The operator managing this router
    #[serde(default = "default_operator_address")]
    pub operator_address: Option<Address>,
    /// The amount in wei that will be sent to the organizer in one second
    #[serde(default)]
    pub operator_fee: Uint256,
    /// if this router is tracking the operator suggested price
    #[serde(default = "default_use_operator_price")]
    pub use_operator_price: bool,
    /// If this operator has indicated that users should not change prices
    #[serde(default = "default_force_use_operator_price")]
    pub force_use_operator_price: bool,
    /// Details about this devices installation see the doc comments on the struct
    /// this is set at install time for the router
    pub installation_details: Option<InstallationDetails>,
    /// Details about this devices installation see the doc comments on the struct
    /// this is set at install time for the router
    pub billing_details: Option<BillingDetails>,
    /// If we should display the operator setup on the dashboard
    #[serde(default = "default_display_operator_setup")]
    pub display_operator_setup: bool,
    /// ContactStorage is a TOML serialized representation of ContactType, use the .into()
    /// traits to get ContactType for actual operations. This struct represents a full range
    /// of possibilities for contact info.
    pub contact_info: Option<ContactStorage>,
    //// If this router wants low balance notifications or not
    #[serde(default = "default_low_balance_notification")]
    pub low_balance_notification: bool,
}

impl Default for OperatorSettings {
    fn default() -> OperatorSettings {
        OperatorSettings {
            operator_address: default_operator_address(),
            operator_fee: 0u32.into(),
            use_operator_price: default_force_use_operator_price(),
            force_use_operator_price: default_force_use_operator_price(),
            installation_details: None,
            billing_details: None,
            display_operator_setup: true,
            contact_info: None,
            low_balance_notification: default_low_balance_notification(),
        }
    }
}
