//! These endpoints are used to modify mundane wireless settings

use crate::dashboard::nickname::maybe_set_nickname;
use crate::RitaCommonError;
use ::actix_web::http::StatusCode;
use ::actix_web::web::Path;
use ::actix_web::{web::Json, HttpRequest, HttpResponse};
use althea_kernel_interface::exit_client_tunnel::create_client_nat_rules;
use althea_kernel_interface::fs_sync::fs_sync;
use althea_kernel_interface::manipulate_uci::{
    get_uci_var, openwrt_reset_wireless, set_uci_var, uci_commit,
};
use althea_kernel_interface::openwrt_ubus::ubus_call;
use althea_types::{
    FromStr, WifiChannel, WifiDisabled, WifiPass, WifiSecurity, WifiSsid, WifiToken,
};
use serde::{Deserialize, Deserializer, Serializer};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::{Display, Formatter, Result as FmtResult};

/// legal in the US and around the world, don't allow odd channels
pub const ALLOWED_TWO: [u16; 3] = [1, 6, 11];
/// list of nonoverlapping 20mhz channels generally legal in NA, SA, EU, AU
pub const ALLOWED_FIVE_20: [u16; 22] = [
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 132, 136, 140, 144, 149, 153, 157,
    161, 165,
];
// Note: all channels wider than 20mhz are specified using the first channel they overlap
//       rather than the center value, no idea who though that was a good idea
/// list of nonoverlapping 40mhz channels generally legal in NA, SA, EU, AU
pub const ALLOWED_FIVE_40: [u16; 12] = [36, 44, 52, 60, 100, 108, 116, 124, 132, 140, 149, 157];
/// list of nonoverlapping 80mhz channels generally legal in NA, SA, EU, AU
pub const ALLOWED_FIVE_80: [u16; 6] = [36, 52, 100, 116, 132, 149];
/// list of nonoverlapping 80mhz channels for the GLB1300/EA6350v3
pub const ALLOWED_FIVE_80_IPQ40XX: [u16; 2] = [36, 149];
/// list of nonoverlapping 80mhz channels for the TPLink-a6v3/wr-2100/e5600
pub const ALLOWED_FIVE_80_MT7621: [u16; 1] = [36];
/// NOTE: linksys_mr8300: The first 5 GHz radio (IPQ4019) is limited to ch. 64 and below. The second 5 GHz radio (QCA9888), is limited to ch. 100 and above.
/// But experience suggests it's only channels 36 and 149 that work with 80mhz channel widths.  Maybe there's a different way to declare the channels that will work?
pub const ALLOWED_FIVE_80_LOW: [u16; 1] = [36];
pub const ALLOWED_FIVE_80_HIGH: [u16; 1] = [149];
pub const ALLOWED_FIVE_40_LOW: [u16; 4] = [36, 44, 52, 60];
pub const ALLOWED_FIVE_40_HIGH: [u16; 8] = [100, 108, 116, 124, 132, 140, 149, 157];

pub const ALLOWED_NONE: [u16; 0] = [];

/// list of nonoverlapping 160mhz channels generally legal in NA, SA, EU, AU
pub const ALLOWED_FIVE_160: [u16; 2] = [36, 100];

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WifiInterface {
    #[serde(default)]
    pub section_name: String,
    pub network: String,
    #[serde(default)]
    pub mesh: bool,
    pub mode: String,
    pub ssid: String,
    #[serde(
        deserialize_with = "parse_encryption_modes",
        serialize_with = "print_encryption_modes"
    )]
    pub encryption: EncryptionModes,
    pub key: Option<String>,
    #[serde(default, skip_deserializing)]
    pub device: WifiDevice,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct WifiDevice {
    #[serde(default)]
    pub section_name: String,
    #[serde(rename = "type")]
    pub i_type: String,
    pub channel: String,
    pub path: String,
    pub htmode: String,
    pub disabled: String,
    #[serde(default)]
    pub radio_type: String,
}

/// A string of characters which we don't let users use because of corrupted UCI configs
static FORBIDDEN_CHARS: &str = "'/\"\\";

static MINIMUM_PASS_CHARS: usize = 8;

#[derive(Serialize, Deserialize, Clone, Debug, Copy)]
pub enum EncryptionModes {
    /// WPA3 Personal
    Sae,
    /// WPA2/WPA3 Personal mixed mode
    SaeMixed,
    /// WPA2 Personal
    Psk2TkipCcmp,
    /// WPA/WPA2 Personal mixed mode
    Psk2MixedTkipCcmp,
    /// No encryption
    None,
}

impl EncryptionModes {
    /// returns the wifi mode as it needs to be in the uci config
    fn as_config_value(&self) -> String {
        match self {
            EncryptionModes::None => "none".to_string(),
            EncryptionModes::Sae => "sae".to_string(),
            EncryptionModes::SaeMixed => "sae-mixed".to_string(),
            EncryptionModes::Psk2TkipCcmp => "psk2".to_string(),
            EncryptionModes::Psk2MixedTkipCcmp => "psk-mixed".to_string(),
        }
    }
}

impl Display for EncryptionModes {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            EncryptionModes::None => write!(f, "none",),
            EncryptionModes::Sae => write!(f, "WPA3",),
            EncryptionModes::SaeMixed => write!(f, "WPA2+WPA3",),
            EncryptionModes::Psk2TkipCcmp => write!(f, "WPA2",),
            EncryptionModes::Psk2MixedTkipCcmp => write!(f, "WPA+WPA2",),
        }
    }
}
impl FromStr for EncryptionModes {
    type Err = RitaCommonError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" | "NONE" => Ok(EncryptionModes::None),
            "sae" | "WPA3" => Ok(EncryptionModes::Sae),
            "sae-mixed" | "WPA2+WPA3" => Ok(EncryptionModes::SaeMixed),
            "psk2+tkip+ccmp" | "psk2+tkip+aes" | "psk2+tkip" | "psk2+ccmp" | "psk2+aes"
            | "psk2" | "WPA2" => Ok(EncryptionModes::Psk2TkipCcmp),
            "psk-mixed+tkip+ccmp"
            | "psk-mixed+tkip+aes"
            | "psk-mixed+tkip"
            | "psk-mixed+ccmp"
            | "psk-mixed+aes"
            | "psk-mixed"
            | "WPA+WPA2" => Ok(EncryptionModes::Psk2MixedTkipCcmp),
            _ => {
                let e = RitaCommonError::MiscStringError("Invalid encryption mode!".to_string());
                Err(e)
            }
        }
    }
}
// below are specialized functions to deserialize/serialize encryption modes using from_str
// and display traits
/// actually will generically serialize anything that implements display, useful boilerplate
pub fn print_encryption_modes<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: Display,
    S: Serializer,
{
    serializer.collect_str(value)
}
fn parse_encryption_modes<'de, D>(deserializer: D) -> Result<EncryptionModes, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = String::deserialize(deserializer)?;
    match EncryptionModes::from_str(&s) {
        Ok(val) => Ok(val),
        Err(_) => Err(serde::de::Error::unknown_variant(&s, &["valid value"])),
    }
}

/// A helper error type for displaying UCI config value validation problems human-readably.
#[derive(Debug, Serialize)]
pub enum ValidationError {
    IllegalCharacter { pos: usize, c: char },
    Empty,
    BadChannel(String, String),
    WrongRadio,
    TooShort(usize),
    InvalidChoice,
}

impl Display for ValidationError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            ValidationError::IllegalCharacter { pos, c } => {
                write!(f, "Illegal character {pos} at position {c}")
            }
            ValidationError::Empty => write!(f, "Empty value"),
            ValidationError::BadChannel(a, b) => write!(
                f,
                "Incorrect channel! Your radio has a channel width of {a} please select one of {b}"
            ),
            ValidationError::WrongRadio => write!(
                f,
                "Trying to set a 5ghz channel on a 2.4ghz radio or vice versa!"
            ),
            ValidationError::TooShort(a) => write!(f, "Value too short ({a} required)"),
            ValidationError::InvalidChoice => write!(f, "Invalid Choice"),
        }
    }
}

pub fn set_ssid(wifi_ssid: &WifiSsid) -> Result<(), RitaCommonError> {
    if let Err(e) = validate_config_value(&wifi_ssid.ssid) {
        info!("Setting of invalid SSID was requested: {}", e);
        return Err(e.into());
    }

    // think radio0, radio1
    let iface_name = wifi_ssid.radio.clone();
    let ssid = wifi_ssid.ssid.clone();
    let section_name = format!("default_{iface_name}");
    set_uci_var(&format!("wireless.{section_name}.ssid"), &ssid)?;

    uci_commit("wireless")?;

    // We edited disk contents, force global sync
    fs_sync()?;

    // set the nickname with the first SSID change may fail
    // if the ssid is too long but don't block on that
    let _ = maybe_set_nickname(wifi_ssid.ssid.clone());

    Ok(())
}

/// Resets the wifi password to the stock value for all radios
pub fn reset_wifi_pass() -> Result<(), RitaCommonError> {
    let config = get_wifi_config_internal()?;
    for interface in config {
        let pass = WifiPass {
            radio: interface.device.section_name,
            pass: "ChangeMe".to_string(),
        };
        set_pass(&pass)?;
    }

    uci_commit("wireless")?;
    openwrt_reset_wireless()?;

    // We edited disk contents, force global sync
    fs_sync()?;

    // we have invalidated the old nat rules, update them
    create_client_nat_rules()?;

    Ok(())
}

fn set_pass(wifi_pass: &WifiPass) -> Result<(), RitaCommonError> {
    let wifi_pass_len = wifi_pass.pass.len();
    if wifi_pass_len < MINIMUM_PASS_CHARS {
        return Err(ValidationError::TooShort(MINIMUM_PASS_CHARS).into());
    }

    if let Err(e) = validate_config_value(&wifi_pass.pass) {
        info!("Setting of invalid SSID was requested: {}", e);
        return Err(e.into());
    }

    // think radio0, radio1
    let iface_name = wifi_pass.radio.clone();
    let pass = wifi_pass.pass.clone();
    let section_name = format!("default_{iface_name}");
    set_uci_var(&format!("wireless.{section_name}.key"), &pass)?;

    Ok(())
}

fn set_channel(wifi_channel: &WifiChannel) -> Result<(), RitaCommonError> {
    let current_channel: u16 =
        get_uci_var(&format!("wireless.{}.channel", wifi_channel.radio))?.parse()?;
    let channel_width = get_uci_var(&format!("wireless.{}.htmode", wifi_channel.radio))?;

    if let Err(e) = validate_channel(
        current_channel,
        wifi_channel.channel,
        &channel_width,
        wifi_channel,
    ) {
        info!("Setting of invalid SSID was requested: {}", e);
        return Err(e.into());
    }

    set_uci_var(
        &format!("wireless.{}.channel", wifi_channel.radio),
        &wifi_channel.channel.to_string(),
    )?;

    Ok(())
}

/// Changes the wifi encryption mode from a given dropdown menu
fn set_security(wifi_security: &WifiSecurity) -> Result<(), RitaCommonError> {
    // check that the given string is one of the approved strings for encryption mode
    if let Ok(parsed) = EncryptionModes::from_str(&wifi_security.encryption) {
        // think radio0, radio1
        let iface_name = wifi_security.radio.clone();
        let section_name = format!("default_{iface_name}");
        set_uci_var(
            &format!("wireless.{section_name}.encryption"),
            &parsed.as_config_value(),
        )?;

        Ok(())
    } else {
        Err(RitaCommonError::MiscStringError(
            "Could not set wifi encryption; invalid encryption mode".to_string(),
        ))
    }
}

/// Disables the wifi on the specified radio
fn set_disabled(wifi_disabled: &WifiDisabled) -> Result<(), RitaCommonError> {
    let current_disabled: bool =
        get_uci_var(&format!("wireless.{}.disabled", wifi_disabled.radio))? == "1";

    if current_disabled == wifi_disabled.disabled {
        return Ok(());
    }

    set_uci_var(
        &format!("wireless.{}.disabled", wifi_disabled.radio),
        if wifi_disabled.disabled { "1" } else { "0" },
    )?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct RebootJsonResponse {
    needs_reboot: bool,
}

#[derive(Serialize, Deserialize)]
struct ErrorJsonResponse {
    error: String,
}

/// an endpoint that takes a series of wifi tokens in json format and applies them all at once
/// the reason for this is that changing any setting while on wifi will disconnect the caller
/// so in order to have all the changes 'take' we need to have a single endpoint for all changes
pub async fn set_wifi_multi(wifi_changes: Json<Vec<WifiToken>>) -> HttpResponse {
    let changes = wifi_changes.into_inner();
    let res = set_wifi_multi_internal(changes);
    info!(
        "Set wifi multi returned with {:?} with message {:?}",
        res.status(),
        res.body()
    );
    res
}

pub fn set_wifi_multi_internal(wifi_changes: Vec<WifiToken>) -> HttpResponse {
    trace!("Got multi wifi change!");

    for token in wifi_changes.iter() {
        match token {
            WifiToken::WifiChannel(val) => {
                if let Err(e) = set_channel(val) {
                    return HttpResponse::build(StatusCode::BAD_REQUEST).json(ErrorJsonResponse {
                        error: format!("Failed to set channel: {e}"),
                    });
                }
            }
            WifiToken::WifiPass(val) => {
                if let Err(e) = set_pass(val) {
                    return HttpResponse::build(StatusCode::BAD_REQUEST).json(ErrorJsonResponse {
                        error: format!("Failed to set password: {e}"),
                    });
                }
            }
            WifiToken::WifiSsid(val) => {
                if let Err(e) = set_ssid(val) {
                    return HttpResponse::build(StatusCode::BAD_REQUEST).json(ErrorJsonResponse {
                        error: format!("Failed to set SSID: {e}"),
                    });
                }
            }
            WifiToken::WifiDisabled(val) => {
                if let Err(e) = set_disabled(val) {
                    return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(
                        ErrorJsonResponse {
                            error: format!("{e}"),
                        },
                    );
                };
            }
            WifiToken::WifiSecurity(val) => {
                if let Err(e) = set_security(val) {
                    return HttpResponse::build(StatusCode::BAD_REQUEST).json(ErrorJsonResponse {
                        error: format!("Failed to set encryption: {e}"),
                    });
                }
            }
        };
    }

    if let Err(e) = uci_commit("wireless") {
        return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(ErrorJsonResponse {
            error: format!("{e}"),
        });
    }
    if let Err(e) = openwrt_reset_wireless() {
        return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(ErrorJsonResponse {
            error: format!("{e}"),
        });
    }

    // We edited disk contents, force global sync
    if let Err(e) = fs_sync() {
        return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(ErrorJsonResponse {
            error: format!("{e}"),
        });
    }
    // we have invalidated the old nat rules, update them
    if let Err(e) = create_client_nat_rules() {
        return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(ErrorJsonResponse {
            error: format!("{e}"),
        });
    }

    HttpResponse::Ok().json(())
}

/// Validates that the channel is both correct and legal the underlying driver should prevent
/// channels for the wrong region, but we go tht extra mile just in case
fn validate_channel(
    old_val: u16,
    new_val: u16,
    channel_width: &str,
    wifi_channel: &WifiChannel,
) -> Result<(), ValidationError> {
    let old_is_two = old_val < 20;
    let old_is_five = !old_is_two;
    let new_is_two = new_val < 20;
    let new_is_five = !new_is_two;
    let channel_width_is_20 = channel_width.contains("20");
    let channel_width_is_40 = channel_width.contains("40");
    let channel_width_is_80 = channel_width.contains("80");
    let channel_width_is_160 = channel_width.contains("160");
    let model = settings::get_rita_common().network.device;
    // trying to swap from 5ghz to 2.4ghz or vice versa, usually this
    // is impossible, although some multifunction cards allow it
    if (old_is_two && new_is_five) || (old_is_five && new_is_two) {
        Err(ValidationError::WrongRadio)
    } else if new_is_two && !ALLOWED_TWO.contains(&new_val) {
        Err(ValidationError::BadChannel(
            "20".to_string(),
            format!("{ALLOWED_TWO:?}"),
        ))
    } else if new_is_five && channel_width_is_20 && !ALLOWED_FIVE_20.contains(&new_val) {
        Err(ValidationError::BadChannel(
            "20".to_string(),
            format!("{ALLOWED_FIVE_20:?}"),
        ))
    } else if new_is_five && channel_width_is_40 && !ALLOWED_FIVE_40.contains(&new_val) {
        Err(ValidationError::BadChannel(
            "40".to_string(),
            format!("{ALLOWED_FIVE_40:?}"),
        ))
    } else if new_is_five && channel_width_is_80 && !ALLOWED_FIVE_80.contains(&new_val) {
        Err(ValidationError::BadChannel(
            "80".to_string(),
            format!("{ALLOWED_FIVE_80:?}"),
        ))
    } else if new_is_five && channel_width_is_160 && !ALLOWED_FIVE_160.contains(&new_val) {
        Err(ValidationError::BadChannel(
            "160".to_string(),
            format!("{ALLOWED_FIVE_160:?}"),
        ))
    // model specific restrictions below this point
    } else if let Some(mdl) = model {
        if (mdl.contains("gl-b1300") || mdl.contains("linksys_ea6350v3"))
            && new_is_five
            && channel_width_is_80
            && !ALLOWED_FIVE_80_IPQ40XX.contains(&new_val)
        {
            Err(ValidationError::BadChannel(
                "80".to_string(),
                format!("{ALLOWED_FIVE_80_IPQ40XX:?}"),
            ))
        } else if (mdl.contains("tplink_archer-a6-v3")
            || mdl.contains("cudy_wr2100")
            || mdl.contains("linksys_e5600"))
            && new_is_five
            && channel_width_is_80
            && !ALLOWED_FIVE_80_MT7621.contains(&new_val)
        {
            Err(ValidationError::BadChannel(
                "80".to_string(),
                format!("{ALLOWED_FIVE_80_MT7621:?}"),
            ))
        }
        // NOTE: linksys_mr8300: The first 5 GHz radio (IPQ4019) is limited to ch. 64 and below. The second 5 GHz radio (QCA9888), is limited to ch. 100 and above.
        else if mdl.contains("linksys_mr8300")
            && new_is_five
            && ((wifi_channel.radio == "radio0" && new_val > 64)
                || (wifi_channel.radio == "radio2" && new_val < 100))
        {
            Err(ValidationError::InvalidChoice)
        } else {
            Ok(())
        }
    } else {
        Ok(())
    }
}

/// returns allowed wifi encryption values
pub async fn get_allowed_encryption_modes(radio: Path<String>) -> HttpResponse {
    debug!("/wifi_settings/get_encryption hit with {:?}", radio);
    HttpResponse::Ok().json([
        EncryptionModes::None.to_string(),
        EncryptionModes::Sae.to_string(),
        EncryptionModes::SaeMixed.to_string(),
        EncryptionModes::Psk2TkipCcmp.to_string(),
        EncryptionModes::Psk2MixedTkipCcmp.to_string(),
    ])
    // TODO: restrict list based on device compatibility. This is currently just the full list of used values
}

/// returns what channels are allowed for the provided radio value
pub async fn get_allowed_wifi_channels(radio: Path<String>) -> HttpResponse {
    debug!("/wifi_settings/get_channels hit with {:?}", radio);
    let radio = radio.into_inner();

    let current_channel: u16 = match get_uci_var(&format!("wireless.{radio}.channel")) {
        Ok(uci) => match uci.parse() {
            Ok(a) => a,
            Err(e) => {
                return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(format!("{e}"));
            }
        },
        Err(e) => {
            return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(format!("{e}"));
        }
    };
    let five_channel_width = match get_uci_var(&format!("wireless.{radio}.htmode")) {
        Ok(a) => a,
        Err(e) => {
            return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(format!("{e}"));
        }
    };
    let model = settings::get_rita_common().network.device;

    if current_channel < 20 {
        HttpResponse::Ok().json(ALLOWED_TWO)

    // model specific values start here
    } else if model.is_some() && (model.clone().unwrap().contains("linksys_mr8300")) {
        if five_channel_width.contains("80") && radio == "radio0" {
            HttpResponse::Ok().json(ALLOWED_FIVE_80_LOW)
        } else if five_channel_width.contains("80") && radio == "radio2" {
            HttpResponse::Ok().json(ALLOWED_FIVE_80_HIGH)
        } else if five_channel_width.contains("40") && radio == "radio0" {
            HttpResponse::Ok().json(ALLOWED_FIVE_40_LOW)
        } else if five_channel_width.contains("40") && radio == "radio2" {
            HttpResponse::Ok().json(ALLOWED_FIVE_40_HIGH)
        } else {
            HttpResponse::Ok().json(ALLOWED_NONE)
        }
    } else if model.is_some()
        && (model.clone().unwrap().contains("gl-b1300")
            || model.clone().unwrap().contains("linksys_ea6350v3"))
        && five_channel_width.contains("80")
    {
        HttpResponse::Ok().json(ALLOWED_FIVE_80_IPQ40XX)
    } else if model.is_some()
        && (model.clone().unwrap().contains("tplink_archer-a6-v3")
            || model.clone().unwrap().contains("cudy_wr2100")
            || model.unwrap().contains("linksys_e5600"))
        && five_channel_width.contains("80")
    {
        HttpResponse::Ok().json(ALLOWED_FIVE_80_MT7621)
    // model specific values end here
    } else if five_channel_width.contains("20") {
        HttpResponse::Ok().json(ALLOWED_FIVE_20)
    } else if five_channel_width.contains("40") {
        HttpResponse::Ok().json(ALLOWED_FIVE_40)
    } else if five_channel_width.contains("80") {
        HttpResponse::Ok().json(ALLOWED_FIVE_80)
    } else if five_channel_width.contains("160") {
        HttpResponse::Ok().json(ALLOWED_FIVE_160)
    } else {
        HttpResponse::build(StatusCode::BAD_REQUEST).json("Can't identify Radio!")
    }
}

/// This function checks that a supplied string is non-empty and doesn't contain any of the
/// `FORBIDDEN_CHARS`. If everything's alright the string itself is moved and returned for
/// convenience.
fn validate_config_value(s: &str) -> Result<(), ValidationError> {
    if s.is_empty() {
        return Err(ValidationError::Empty);
    }

    if let Some(pos) = s.find(|c| FORBIDDEN_CHARS.contains(c)) {
        trace!(
            "validate_config_value: Invalid character detected on position {}",
            pos
        );
        Err(ValidationError::IllegalCharacter {
            pos: pos + 1,                   // 1-indexed for human-readable display
            c: s.chars().nth(pos).unwrap(), // pos obtained from find(), must be correct
        })
    } else {
        Ok(())
    }
}

pub async fn get_wifi_config(_req: HttpRequest) -> HttpResponse {
    debug!("Get wificonfig hit!");
    let config = match get_wifi_config_internal() {
        Ok(con) => con,
        Err(e) => {
            return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(format!("{e}"));
        }
    };
    HttpResponse::Ok().json(config)
}

pub fn get_wifi_config_internal() -> Result<Vec<WifiInterface>, RitaCommonError> {
    let mut interfaces = Vec::new();
    let mut devices = HashMap::new();
    let config = ubus_call("uci", "get", "{ \"config\": \"wireless\"}")?;
    let val: Value = serde_json::from_str(&config)?;
    let items = match val["values"].as_object() {
        Some(i) => i,
        None => {
            error!("No \"values\" key in parsed wifi config!");
            return Err(RitaCommonError::ConversionError(
                "No \"values\" key in parsed wifi config!".to_string(),
            ));
        }
    };
    for (k, v) in items {
        if v[".type"] == "wifi-device" {
            let mut device: WifiDevice = serde_json::from_value(v.clone())?;
            device.section_name = strip_string_quotes(k.clone());
            let channel: String = serde_json::from_value(v["channel"].clone())?;
            let channel: u8 = channel.parse()?;
            if channel > 20 {
                device.radio_type = "5ghz".to_string();
            } else {
                device.radio_type = "2ghz".to_string();
            }
            devices.insert(device.section_name.to_string(), device);
        }
    }
    for (k, v) in items {
        if v[".type"] == "wifi-iface" && v["mode"] != "mesh" {
            let mut interface: WifiInterface = serde_json::from_value(v.clone())?;
            interface.mesh = interface.mode.contains("adhoc");
            interface.section_name = strip_string_quotes(k.clone());
            let device_name: String = serde_json::from_value(v["device"].clone())?;
            interface.device = devices[&device_name].clone();
            interfaces.push(interface);
        }
    }
    Ok(interfaces)
}
/// Function removes quotations and quotes from a string and returns it
fn strip_string_quotes(mut name: String) -> String {
    name = str::replace(&name, "'", "");
    name = str::replace(&name, "\"", "");
    name
}

#[cfg(test)]
mod test {
    use crate::dashboard::wifi::strip_string_quotes;

    #[test]
    pub fn unit_test_wifi_escape_name() {
        let name_test = "hello \" ' \" world".to_string();
        assert_eq!(None, strip_string_quotes(name_test.clone()).find('\''));
        assert_eq!(None, strip_string_quotes(name_test).find('\"'));
    }
}
