use phonenumber::PhoneNumber;

fn default_wyre_enabled() -> bool {
    false
}

fn default_display_currency_symbol() -> bool {
    true
}

fn default_support_number() -> PhoneNumber {
    "+18664ALTHEA".parse().unwrap()
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct LocalizationSettings {
    /// A flag indicating whether or not the dashboard should give users the option to purchase
    /// cryptocurrency through Wyre as part of the funding flow.
    #[serde(default = "default_wyre_enabled")]
    pub wyre_enabled: bool,
    /// If we should display the $ symbol or just the DAI star symbol next
    /// to the balance, designed to help manage how prominently we want the cryptocurrency
    /// aspect of Althea to be displayed to the user.
    #[serde(default = "default_display_currency_symbol")]
    pub display_currency_symbol: bool,
    /// This is the support number the user should call based on their deployment and other
    /// factors. It's up to the operator tools to overwrite the default global number with
    /// a locally relevant one if possible.
    #[serde(default = "default_support_number")]
    pub support_number: PhoneNumber,
}

impl Default for LocalizationSettings {
    fn default() -> LocalizationSettings {
        LocalizationSettings {
            wyre_enabled: default_wyre_enabled(),
            display_currency_symbol: default_display_currency_symbol(),
            support_number: default_support_number(),
        }
    }
}

#[test]
fn test_default_localization() {
    let _def = LocalizationSettings::default();
}
