use althea_types::WgKey;
use config;
use core::str::FromStr;

use serde_json;

use owning_ref::{RwLockReadGuardRef, RwLockWriteGuardRefMut};

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

use config::Config;

use althea_types::Identity;

use failure::Error;

use crate::dao::SubnetDAOSettings;
use crate::json_merge;
use crate::localization::LocalizationSettings;
use crate::network::NetworkSettings;
use crate::payment::PaymentSettings;
use crate::spawn_watch_thread;
use crate::RitaCommonSettings;

/// This is the network settings specific to rita_exit
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ExitNetworkSettings {
    /// This is the port which the exit registration happens over, and should only be accessable
    /// over the mesh
    pub exit_hello_port: u16,
    /// This is the port which the exit tunnel listens on
    pub wg_tunnel_port: u16,
    /// Price in wei per byte which is charged to traffic both coming in and out over the internet
    pub exit_price: u64,
    /// This is the exit's own ip/gateway ip in the exit wireguard tunnel
    pub own_internal_ip: Ipv4Addr,
    /// This is the start of the exit tunnel's internal address allocation to clients, incremented
    /// by 1 every time a new client is added
    pub exit_start_ip: Ipv4Addr,
    /// The netmask, in bits to mask out, for the exit tunnel
    pub netmask: u8,
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
}

impl ExitNetworkSettings {
    /// Generates a configuration that can be used in integration tests, does not use the
    /// default trait to prevent some future code from picking up on the 'default' implementation
    /// and actually using it. Since obviously hardcoded keys are not at all secure
    pub fn test_default() -> Self {
        ExitNetworkSettings {
            exit_hello_port: 4875,
            wg_tunnel_port: 59999,
            exit_price: 10,
            own_internal_ip: "172.16.255.254".parse().unwrap(),
            exit_start_ip: "172.16.0.0".parse().unwrap(),
            netmask: 12,
            entry_timeout: 0,
            geoip_api_user: None,
            geoip_api_key: None,
            wg_public_key: WgKey::from_str("Ha2YlTfDimJNboqxOSCh6M29W/H0jKtB4utitjaTO3A=").unwrap(),
            wg_private_key: WgKey::from_str("mFFBLqQYrycxfHo10P9l8I2G7zbw8tia4WkGGgjGCn8=")
                .unwrap(),
            wg_private_key_path: String::new(),
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

fn default_balance_notification_text_body() -> String {
    String::from("Your Althea router has a low balance! Your service will be slow until more funds are added. Visit althea.net/add-funds")
}

/// These are the settings for text message verification using the twillio api
/// note that while you would expect the authentication and text notification flow
/// to be the same they are in fact totally different and each have seperate
/// credentials below
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Default)]
pub struct PhoneVerifSettings {
    /// API key used for the authenticaiton calls
    pub auth_api_key: String,
    /// The Twillio number used to send the notification message
    pub notification_number: String,
    /// The Twillio account id used to authenticate for notifications
    pub twillio_account_id: String,
    /// The auth token used to authenticate for notifications
    pub twillio_auth_token: String,
    /// the text for the balance notification
    #[serde(default = "default_balance_notification_text_body")]
    pub balance_notification_body: String,
    /// time in seconds between notifications
    pub balance_notification_interval: u32,
    /// True if the exit should notify clients when they have a low balance
    pub notify_low_balance: bool,
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
    // starts with file:// or postgres://username:password@localhost/diesel_demo
    db_uri: String,
    // the size of the worker thread pool, the connection pool is this plus one
    workers: u32,
    description: String,
    payment: PaymentSettings,
    #[serde(default)]
    localization: LocalizationSettings,
    dao: SubnetDAOSettings,
    network: NetworkSettings,
    exit_network: ExitNetworkSettings,
    /// Countries which the clients to the exit are allowed from, blank for no geoip validation.
    /// (ISO country code)
    #[serde(skip_serializing_if = "HashSet::is_empty", default)]
    allowed_countries: HashSet<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verif_settings: Option<ExitVerifSettings>, // mailer's successor with new verif methods readiness
    #[serde(skip)]
    future: bool,
}

impl RitaExitSettingsStruct {
    /// Generates a configuration that can be used in integration tests, does not use the
    /// default trait to prevent some future code from picking up on the 'default' implementation
    pub fn test_default() -> Self {
        RitaExitSettingsStruct {
            db_uri: "".to_string(),
            workers: 1,
            description: "".to_string(),
            payment: PaymentSettings::default(),
            dao: SubnetDAOSettings::default(),
            localization: LocalizationSettings::default(),
            network: NetworkSettings::default(),
            exit_network: ExitNetworkSettings::test_default(),
            allowed_countries: HashSet::new(),
            verif_settings: None,
            future: false,
        }
    }
}

pub trait RitaExitSettings {
    fn get_exit_network<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaExitSettingsStruct, ExitNetworkSettings>;
    fn get_verif_settings(&self) -> Option<ExitVerifSettings>;
    fn get_verif_settings_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaExitSettingsStruct, Option<ExitVerifSettings>>;
    fn get_db_uri(&self) -> String;
    fn get_workers(&self) -> u32;
    fn get_description(&self) -> String;
    fn get_allowed_countries<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaExitSettingsStruct, HashSet<String>>;
}

impl RitaExitSettings for Arc<RwLock<RitaExitSettingsStruct>> {
    fn get_exit_network<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaExitSettingsStruct, ExitNetworkSettings> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.exit_network)
    }
    fn get_db_uri(&self) -> String {
        self.read().unwrap().db_uri.clone()
    }
    fn get_workers(&self) -> u32 {
        self.read().unwrap().workers
    }
    fn get_description(&self) -> String {
        self.read().unwrap().description.clone()
    }
    fn get_allowed_countries<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaExitSettingsStruct, HashSet<String>> {
        RwLockReadGuardRef::new(self.read().unwrap()).map(|g| &g.allowed_countries)
    }
    fn get_verif_settings(&self) -> Option<ExitVerifSettings> {
        self.read().unwrap().verif_settings.clone()
    }
    fn get_verif_settings_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaExitSettingsStruct, Option<ExitVerifSettings>> {
        RwLockWriteGuardRefMut::new(self.write().unwrap()).map_mut(|g| &mut g.verif_settings)
    }
}

impl RitaExitSettingsStruct {
    pub fn new(file_name: &str) -> Result<Self, Error> {
        let mut s = Config::new();
        s.merge(config::File::with_name(file_name).required(false))?;
        let settings: Self = s.try_into()?;
        Ok(settings)
    }

    pub fn new_watched(file_name: &str) -> Result<Arc<RwLock<Self>>, Error> {
        let mut s = Config::new();
        s.merge(config::File::with_name(file_name).required(false))?;
        let settings: Self = s.clone().try_into()?;

        let settings = Arc::new(RwLock::new(settings));

        trace!("starting with settings: {:?}", settings.read().unwrap());

        spawn_watch_thread(settings.clone(), file_name).unwrap();

        Ok(settings)
    }
}

impl RitaCommonSettings<RitaExitSettingsStruct> for Arc<RwLock<RitaExitSettingsStruct>> {
    fn get_payment<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaExitSettingsStruct, PaymentSettings> {
        RwLockReadGuardRef::new(self.read().expect("Read payment settings!")).map(|g| &g.payment)
    }

    fn get_payment_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaExitSettingsStruct, PaymentSettings> {
        RwLockWriteGuardRefMut::new(self.write().expect("Failed to write payment settings!"))
            .map_mut(|g| &mut g.payment)
    }

    fn get_dao<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaExitSettingsStruct, SubnetDAOSettings> {
        RwLockReadGuardRef::new(self.read().expect("Failed to read DAO settings!")).map(|g| &g.dao)
    }

    fn get_localization_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaExitSettingsStruct, LocalizationSettings> {
        RwLockWriteGuardRefMut::new(
            self.write()
                .expect("Failed to write localization settings!"),
        )
        .map_mut(|g| &mut g.localization)
    }

    fn get_localization<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaExitSettingsStruct, LocalizationSettings> {
        RwLockReadGuardRef::new(self.read().expect("Failed to read localization settings!"))
            .map(|g| &g.localization)
    }

    fn get_dao_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaExitSettingsStruct, SubnetDAOSettings> {
        RwLockWriteGuardRefMut::new(self.write().expect("Failed to write dao settings!"))
            .map_mut(|g| &mut g.dao)
    }

    fn get_network<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockReadGuardRef<'ret, RitaExitSettingsStruct, NetworkSettings> {
        RwLockReadGuardRef::new(self.read().expect("Failed to read network settings!"))
            .map(|g| &g.network)
    }

    fn get_network_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, RitaExitSettingsStruct, NetworkSettings> {
        RwLockWriteGuardRefMut::new(self.write().expect("Failed to write network settings!"))
            .map_mut(|g| &mut g.network)
    }

    fn merge(&self, changed_settings: serde_json::Value) -> Result<(), Error> {
        let mut settings_value = serde_json::to_value(self.read().unwrap().clone())?;

        json_merge(&mut settings_value, &changed_settings);

        match serde_json::from_value(settings_value) {
            Ok(new_settings) => {
                *self.write().unwrap() = new_settings;
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    fn get_all(&self) -> Result<serde_json::Value, Error> {
        Ok(serde_json::to_value(self.read().unwrap().clone())?)
    }

    fn get_identity(&self) -> Option<Identity> {
        Some(Identity::new(
            self.get_network().mesh_ip.clone()?,
            self.get_payment().eth_address.clone()?,
            self.get_network().wg_public_key.clone()?,
            self.get_network().nickname.clone(),
        ))
    }

    fn get_future(&self) -> bool {
        self.read().unwrap().future
    }

    fn set_future(&self, future: bool) {
        self.write().unwrap().future = future
    }
}
