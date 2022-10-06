use crate::localization::LocalizationSettings;
use crate::network::NetworkSettings;
use crate::payment::PaymentSettings;
use crate::{json_merge, set_rita_exit, SettingsError};
use althea_types::{Identity, WgKey};
use core::str::FromStr;
use ipnetwork::IpNetwork;
use phonenumber::PhoneNumber;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

/// This is the network settings specific to rita_exit
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ExitNetworkSettings {
    /// This is the port which the exit registration happens over, and should only be accessible
    /// over the mesh
    pub exit_hello_port: u16,
    /// This is the port which the exit tunnel listens on
    pub wg_tunnel_port: u16,
    pub wg_new_tunnel_port: u16,
    /// Price in wei per byte which is charged to traffic both coming in and out over the internet
    pub exit_price: u64,
    /// This is the exit's own ip/gateway ip in the exit wireguard tunnel
    pub own_internal_ip: Ipv4Addr,
    /// This is the start of the exit tunnel's internal address allocation to clients, incremented
    /// by 1 every time a new client is added
    pub exit_start_ip: Ipv4Addr,
    /// The netmask, in bits to mask out, for the exit tunnel
    pub netmask: u8,
    /// The subnet we use to assign to client routers for ipv6
    pub subnet: Option<IpNetwork>,
    /// The specified client subnet, else use /56
    pub client_subnet_size: Option<u8>,
    /// Time in seconds before user is dropped from the db due to inactivity
    /// 0 means disabled
    pub entry_timeout: u32,
    /// api credentials for Maxmind geoip
    pub geoip_api_user: Option<String>,
    pub geoip_api_key: Option<String>,
    /// The our public key for the wg_exit tunnel
    pub wg_public_key: WgKey,
    /// Our private key for the wg_exit tunnel, not an option because it's better
    /// for exits to crash than to generate their own key
    pub wg_private_key: WgKey,
    /// path for the exit tunnel keyfile must be distinct from the common tunnel path!
    pub wg_private_key_path: String,
    /// Magic phone number operators enter in order to register to exit without auth
    pub magic_phone_number: Option<String>,
    /// Lists of exit ip addrs in this cluster
    pub cluster_ips: Vec<IpAddr>,
}

impl ExitNetworkSettings {
    /// Generates a configuration that can be used in integration tests, does not use the
    /// default trait to prevent some future code from picking up on the 'default' implementation
    /// and actually using it. Since obviously hardcoded keys are not at all secure
    pub fn test_default() -> Self {
        ExitNetworkSettings {
            exit_hello_port: 4875,
            wg_tunnel_port: 59999,
            wg_new_tunnel_port: 59998,
            exit_price: 10,
            own_internal_ip: "172.16.255.254".parse().unwrap(),
            exit_start_ip: "172.16.0.0".parse().unwrap(),
            netmask: 12,
            subnet: Some(IpNetwork::V6("ff01::0/128".parse().unwrap())),
            client_subnet_size: None,
            entry_timeout: 0,
            geoip_api_user: None,
            geoip_api_key: None,
            wg_public_key: WgKey::from_str("Ha2YlTfDimJNboqxOSCh6M29W/H0jKtB4utitjaTO3A=").unwrap(),
            wg_private_key: WgKey::from_str("mFFBLqQYrycxfHo10P9l8I2G7zbw8tia4WkGGgjGCn8=")
                .unwrap(),
            wg_private_key_path: String::new(),
            magic_phone_number: None,
            cluster_ips: Vec::new(),
        }
    }
}

fn default_signup_email_subject() -> String {
    String::from("Althea Exit verification code")
}

fn default_signup_email_body() -> String {
    // templated using the handlebars language
    // the code will be placed in the {{email_code}}, the [] is for integration testing
    String::from("Your althea verification code is [{{email_code}}]")
}

fn default_balance_notification_email_subject() -> String {
    String::from("Althea low balance warning")
}

fn default_balance_notification_email_body() -> String {
    String::from("Your Althea router has a low balance! Your service will be slow until more funds are added. Visit althea.net/add-funds")
}

fn default_remote_log() -> bool {
    false
}
fn default_save_interval() -> u64 {
    300
}

/// These are the settings for email verification
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Default)]
pub struct EmailVerifSettings {
    /// The email address of the from field of the email sent
    pub from_address: String,
    /// Min amount of time for emails going to the same address
    pub email_cooldown: u64,

    // templating stuff
    #[serde(default = "default_signup_email_subject")]
    pub signup_subject: String,

    #[serde(default = "default_signup_email_body")]
    pub signup_body: String,

    #[serde(default = "default_balance_notification_email_subject")]
    pub balance_notification_subject: String,

    #[serde(default = "default_balance_notification_email_body")]
    pub balance_notification_body: String,

    #[serde(default)]
    pub test: bool,
    #[serde(default)]
    pub test_dir: String,
    /// SMTP server url e.g. smtp.fastmail.com
    #[serde(default)]
    pub smtp_url: String,
    /// SMTP domain url e.g. mail.example.com
    #[serde(default)]
    pub smtp_domain: String,
    #[serde(default)]
    pub smtp_username: String,
    #[serde(default)]
    pub smtp_password: String,
    /// time in seconds between notifications
    pub balance_notification_interval: u32,

    /// True if the exit should notify clients when they have a low balance
    pub notify_low_balance: bool,
}

/// These are the settings for text message verification using the twillio api
/// note that while you would expect the authentication and text notification flow
/// to be the same they are in fact totally different and each have separate
/// credentials below
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Default)]
pub struct PhoneVerifSettings {
    /// API key used for the authentication calls
    pub auth_api_key: String,
    /// The Twillio number used to send the notification message
    pub notification_number: String,
    /// The Twillio account id used to authenticate for notifications
    pub twillio_account_id: String,
    /// The auth token used to authenticate for notifications
    pub twillio_auth_token: String,
    /// Operator notification numbers, used to text the operators when we need them
    #[serde(default)]
    pub operator_notification_number: Vec<PhoneNumber>,
}

/// Struct containing the different types of supported verification
/// and their respective settings
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[serde(tag = "type", content = "contents")]
pub enum ExitVerifSettings {
    Email(EmailVerifSettings),
    Phone(PhoneVerifSettings),
}

/// This is the main settings struct for rita_exit
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct RitaExitSettingsStruct {
    /// starts with file:// or postgres://username:password@localhost/diesel_demo
    pub db_uri: String,
    /// the size of the worker thread pool, the connection pool is this plus one
    pub workers: u32,
    /// if we should log remotely or if we should send our logs to the logging server
    #[serde(default = "default_remote_log")]
    pub remote_log: bool,
    /// The description of this exit, what is sent to clients and displayed to the user
    pub description: String,
    pub payment: PaymentSettings,
    #[serde(default)]
    pub localization: LocalizationSettings,
    pub network: NetworkSettings,
    pub exit_network: ExitNetworkSettings,
    /// Countries which the clients to the exit are allowed from, blank for no geoip validation.
    /// (ISO country code)
    #[serde(skip_serializing_if = "HashSet::is_empty", default)]
    pub allowed_countries: HashSet<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verif_settings: Option<ExitVerifSettings>,
    #[serde(skip)]
    pub future: bool,
    /// The save interval defaults to 5 minutes for exit settings represented in seconds
    #[serde(default = "default_save_interval")]
    pub save_interval: u64,
}

impl RitaExitSettingsStruct {
    /// Generates a configuration that can be used in integration tests, does not use the
    /// default trait to prevent some future code from picking up on the 'default' implementation
    pub fn test_default() -> Self {
        RitaExitSettingsStruct {
            db_uri: "".to_string(),
            workers: 1,
            remote_log: false,
            description: "".to_string(),
            payment: PaymentSettings::default(),
            localization: LocalizationSettings::default(),
            network: NetworkSettings::default(),
            exit_network: ExitNetworkSettings::test_default(),
            allowed_countries: HashSet::new(),
            verif_settings: None,
            future: false,
            save_interval: default_save_interval(),
        }
    }

    pub fn get_identity(&self) -> Option<Identity> {
        Some(Identity::new(
            self.network.mesh_ip?,
            self.payment.eth_address?,
            self.network.wg_public_key?,
            self.network.nickname,
        ))
    }

    pub fn get_client_subnet_size(&self) -> Option<u8> {
        self.exit_network.client_subnet_size
    }

    pub fn get_all(&self) -> Result<serde_json::Value, SettingsError> {
        Ok(serde_json::to_value(self.clone())?)
    }

    pub fn merge(&mut self, changed_settings: serde_json::Value) -> Result<(), SettingsError> {
        let mut settings_value = serde_json::to_value(self.clone())?;

        json_merge(&mut settings_value, &changed_settings);

        match serde_json::from_value(settings_value) {
            Ok(new_settings) => {
                *self = new_settings;
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn new(file_name: &str) -> Result<Self, SettingsError> {
        assert!(Path::new(file_name).exists());

        let config_toml = std::fs::read_to_string(file_name)?;
        let ret: Self = toml::from_str(&config_toml)?;
        Ok(ret)
    }

    pub fn new_watched(file_name: &str) -> Result<Self, SettingsError> {
        assert!(Path::new(file_name).exists());

        let config_toml = std::fs::read_to_string(file_name)?;
        let ret: Self = toml::from_str(&config_toml)?;

        set_rita_exit(ret.clone());

        Ok(ret)
    }
}
