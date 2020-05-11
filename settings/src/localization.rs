fn default_wyre_enabled() -> bool {
    true
}

fn default_wyre_account_id() -> String {
    "AC_2J6LWQEGW8P".to_string()
}

fn default_display_currency_symbol() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct LocalizationSettings {
    /// A flag indicating whether or not the dashboard should give users the option to purchase
    /// cryptocurrency through Wyre as part of the funding flow.
    #[serde(default = "default_wyre_enabled")]
    pub wyre_enabled: bool,
    /// Wyre account_id used to associate transactions with a specific Wyre account
    #[serde(default = "default_wyre_account_id")]
    pub wyre_account_id: String,
    /// If we should display the $ symbol or just the DAI star symbol next
    /// to the balance, designed to help manage how prominent we want the cryptocurrency
    /// aspect of Althea to be displayed to the user.
    #[serde(default = "default_display_currency_symbol")]
    pub display_currency_symbol: bool,
}

impl Default for LocalizationSettings {
    fn default() -> LocalizationSettings {
        LocalizationSettings {
            wyre_enabled: default_wyre_enabled(),
            wyre_account_id: default_wyre_account_id(),
            display_currency_symbol: default_display_currency_symbol(),
        }
    }
}
