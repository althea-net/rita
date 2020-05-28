//! Operator settings are the spiritual successor to the SubnetDAO concept, instead of having DAO's we now have operators, which could be a DAO
//! but far more importantly we don't have to deal with the multiple DAO concept as well as several others and we assume a trusting relationship
//! between the router and the operator. Meaning the operator can do things like reset (but not read) the WiFi password and the Operator trusts
//! that the router will be running stock software and generally not trying to exploit them by underpaying and such. This trustful relationship
//! simplifies things a lot (no need for complex trustless enforcement). If you find that both DAO settings and this exist at the same time
//! that means the transition is still in prgress.

use althea_types::interop::InstallationDetails;
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
fn default_display_operator_setup() -> bool {
    true
}

/// If the operator has indicated that users should not be able to change
/// their own prices
fn default_force_use_operator_price() -> bool {
    false
}

/// The url for checking in with the operator server.
/// if you are changing this double check the default currency and the default node url
fn default_checkin_url() -> String {
    "https://operator.althea.net:8080/checkin".to_string()
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
    /// The server used to checkin and grab settings
    #[serde(default = "default_checkin_url")]
    pub checkin_url: String,
    /// Details about this devices installation see the doc comments on the struct
    /// this is set at startup time for the router
    pub installation_details: Option<InstallationDetails>,
    /// If we should display the operator setup on the dashboard
    #[serde(default = "default_display_operator_setup")]
    pub display_operator_setup: bool,
}

impl Default for OperatorSettings {
    fn default() -> OperatorSettings {
        OperatorSettings {
            operator_address: default_operator_address(),
            operator_fee: 0u32.into(),
            use_operator_price: default_force_use_operator_price(),
            force_use_operator_price: default_force_use_operator_price(),
            checkin_url: default_checkin_url(),
            installation_details: None,
            display_operator_setup: true,
        }
    }
}
