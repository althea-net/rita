fn default_wyre_enabled() -> bool {
    true
}

fn default_wyre_account_id() -> String {
    "AC_2J6LWQEGW8P".to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Default)]
pub struct LocalizationSettings {
    // A flag indicating whether or not the dashboard should give users the option to purchase
    // cryptocurrency through Wyre as part of the funding flow.
    #[serde(default = "default_wyre_enabled")]
    pub wyre_enabled: bool,
    // Wyre account_id used to associate transactions with a specific Wyre account
    #[serde(default = "default_wyre_account_id")]
    pub wyre_account_id: String,
}
