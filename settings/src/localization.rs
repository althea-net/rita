use phonenumber::PhoneNumber;

fn default_wyre_enabled() -> bool {
    true
}

fn default_wyre_account_id() -> String {
    "AC_2J6LWQEGW8P".to_string()
}

fn default_display_currency_symbol() -> bool {
    true
}

fn default_support_number() -> PhoneNumber {
    "+18664ALTHEA".parse().unwrap()
}

fn default_wyre_preface_message() -> String {
    "Our payment partner Wyre, is international and expects phone numbers in international format. \
    The United States country code is +1 followed by your area code and number. \
    You may also see the charge come from outside the United States, this is normal."
        .to_string()
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
    /// This is a message that prefaces the Wyre deposit to include some warnings for the
    /// user. Wyre often changes their flow or introduces pitfalls for users. We sadly need
    /// to be able to modify our prep message
    #[serde(default = "default_wyre_preface_message")]
    pub wyre_preface_message: String,
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
            wyre_account_id: default_wyre_account_id(),
            wyre_preface_message: default_wyre_preface_message(),
            display_currency_symbol: default_display_currency_symbol(),
            support_number: default_support_number(),
        }
    }
}

#[test]
fn test_default_localization() {
    let _def = LocalizationSettings::default();
}
