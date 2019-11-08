use clarity::Address;
use num256::Uint256;

fn default_dao_address() -> Vec<Address> {
    Vec::new()
}

fn default_oracle_enabled() -> bool {
    true
}

fn default_use_oracle_price() -> bool {
    true
}

fn default_oracle_url() -> Option<String> {
    Some("https://updates.althea.net/prices".to_string())
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Default)]
pub struct SubnetDAOSettings {
    /// List of subnet DAO's to which we are a member
    #[serde(default = "default_dao_address")]
    pub dao_addresses: Vec<Address>,
    /// The amount in wei that will be sent to the dao in one second
    #[serde(default)]
    pub dao_fee: Uint256,
    /// If the user desires to disable the oracle from making local settings changes they
    /// may set this to false. This essentially opts them out of the DAO and won't stop
    /// the DAO from kicking them out when they for example fail to pay or exceed the maximum allowed
    /// price. Neither of those are implemented yet so for now it's a get out of jail free card until
    /// the human organizer notices.
    #[serde(default = "default_oracle_enabled")]
    pub oracle_enabled: bool,
    /// It's possible the user wants to ignore the suggested price but still take the suggested settings
    /// at which point they should change this option.
    #[serde(default = "default_use_oracle_price")]
    pub use_oracle_price: bool,
    /// The oracle used to just be for pricing, now we are using it as a proxy for
    /// the DAO's ability to help generate consensus on router settings so it contains
    /// price as well as other updates. A None here would indicate that there's no oracle
    /// configured
    #[serde(default = "default_oracle_url")]
    pub oracle_url: Option<String>,
}
