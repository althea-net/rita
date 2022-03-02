//! These endpoints are used to modify mundane wireless settings

use ::actix_web_async::http::StatusCode;
use ::actix_web_async::web::Path;
use ::actix_web_async::{web::Json, HttpRequest, HttpResponse};
use rita_common::dashboard::nickname::maybe_set_nickname;
use rita_common::{RitaCommonError, KI};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::{Display, Formatter, Result as FmtResult};

use crate::RitaClientError;

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
pub const ALLOWED_FIVE_80_LOW: [u16; 2] = [36, 52];
pub const ALLOWED_FIVE_80_HIGH: [u16; 4] = [100, 116, 132, 149];
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
    pub encryption: String,
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
    pub hwmode: String,
    pub disabled: String,
    #[serde(default)]
    pub radio_type: String,
}

/// A string of characters which we don't let users use because of corrupted UCI configs
static FORBIDDEN_CHARS: &str = "'/\"\\";

static MINIMUM_PASS_CHARS: usize = 8;

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
                write!(f, "Illegal character {} at position {}", pos, c)
            }
            ValidationError::Empty => write!(f, "Empty value"),
            ValidationError::BadChannel(a, b) => write!(
                f,
                "Incorrect channel! Your radio has a channel width of {} please select one of {}",
                a, b
            ),
            ValidationError::WrongRadio => write!(
                f,
                "Trying to set a 5ghz channel on a 2.4ghz radio or vice versa!"
            ),
            ValidationError::TooShort(a) => write!(f, "Value too short ({} required)", a),
            ValidationError::InvalidChoice => write!(f, "Invalid Choice"),
        }
    }
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct WifiSsid {
    pub radio: String,
    pub ssid: String,
}

fn set_ssid(wifi_ssid: &WifiSsid) -> Result<(), RitaClientError> {
    if let Err(e) = validate_config_value(&wifi_ssid.ssid) {
        info!("Setting of invalid SSID was requested: {}", e);
        return Err(e.into());
        // ret.insert("error".to_owned(), format!("{}", e));
        // return Ok(HttpResponse::new(StatusCode::BAD_REQUEST)
        //     .into_builder()
        //     .json(ret));
    }

    // think radio0, radio1
    let iface_name = wifi_ssid.radio.clone();
    let ssid = wifi_ssid.ssid.clone();
    let section_name = format!("default_{}", iface_name);
    KI.set_uci_var(&format!("wireless.{}.ssid", section_name), &ssid)?;

    KI.uci_commit("wireless")?;

    // We edited disk contents, force global sync
    KI.fs_sync()?;

    // set the nickname with the first SSID change may fail
    // if the ssid is too long but don't block on that
    let _ = maybe_set_nickname(wifi_ssid.ssid.clone());

    Ok(())
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct WifiPass {
    pub radio: String,
    pub pass: String,
}

/// Resets the wifi password to the stock value for all radios
pub fn reset_wifi_pass() -> Result<(), RitaClientError> {
    let config = get_wifi_config_internal()?;
    for interface in config {
        let pass = WifiPass {
            radio: interface.device.section_name,
            pass: "ChangeMe".to_string(),
        };
        set_pass(&pass)?;
    }

    KI.uci_commit("wireless")?;
    KI.openwrt_reset_wireless()?;

    // We edited disk contents, force global sync
    KI.fs_sync()?;

    // we have invalidated the old nat rules, update them
    KI.create_client_nat_rules()?;

    Ok(())
}

fn set_pass(wifi_pass: &WifiPass) -> Result<(), RitaClientError> {
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
    let section_name = format!("default_{}", iface_name);
    KI.set_uci_var(&format!("wireless.{}.key", section_name), &pass)?;

    Ok(())
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct WifiChannel {
    pub radio: String,
    pub channel: u16,
}

fn set_channel(wifi_channel: &WifiChannel) -> Result<(), RitaClientError> {
    let current_channel: u16 = KI
        .get_uci_var(&format!("wireless.{}.channel", wifi_channel.radio))?
        .parse()?;
    let channel_width = KI.get_uci_var(&format!("wireless.{}.htmode", wifi_channel.radio))?;

    if let Err(e) = validate_channel(
        current_channel,
        wifi_channel.channel,
        &channel_width,
        wifi_channel,
    ) {
        info!("Setting of invalid SSID was requested: {}", e);
        return Err(e.into());
        // return Ok(HttpResponse::new(StatusCode::BAD_REQUEST)
        //     .into_builder()
        //     .json("Invalid SSID!"));
    }

    KI.set_uci_var(
        &format!("wireless.{}.channel", wifi_channel.radio),
        &wifi_channel.channel.to_string(),
    )?;

    Ok(())
}

#[derive(Clone, Debug)]
pub struct WifiDisabledReturn {
    pub needs_reboot: bool,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct WifiDisabled {
    pub radio: String,
    pub disabled: bool,
}

/// Disables the wifi on the specified radio
fn set_disabled(wifi_disabled: &WifiDisabled) -> Result<WifiDisabledReturn, RitaClientError> {
    let current_disabled: bool =
        KI.get_uci_var(&format!("wireless.{}.disabled", wifi_disabled.radio))? == "1";

    if current_disabled == wifi_disabled.disabled {
        return Ok(WifiDisabledReturn {
            needs_reboot: false,
        });
    }

    KI.set_uci_var(
        &format!("wireless.{}.disabled", wifi_disabled.radio),
        if wifi_disabled.disabled { "1" } else { "0" },
    )?;

    Ok(WifiDisabledReturn { needs_reboot: true })
}

#[derive(Serialize, Deserialize)]
struct RebootJsonResponse {
    needs_reboot: bool,
}

#[derive(Serialize, Deserialize)]
struct ErrorJsonResponse {
    error: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum WifiToken {
    WifiChannel(WifiChannel),
    WifiSsid(WifiSsid),
    WifiPass(WifiPass),
    WifiDisabled(WifiDisabled),
}

/// an endpoint that takes a series of wifi tokens in json format and applies them all at once
/// the reason for this is that changing any setting while on wifi will disconnect the caller
/// so in order to have all the changes 'take' we need to have a single endpoint for all changes
pub async fn set_wifi_multi(wifi_changes: Json<Vec<WifiToken>>) -> HttpResponse {
    trace!("Got multi wifi change!");
    let mut needs_reboot = false;

    for token in wifi_changes.into_inner().iter() {
        match token {
            WifiToken::WifiChannel(val) => {
                if let Err(e) = set_channel(val) {
                    return HttpResponse::build(StatusCode::BAD_REQUEST).json(ErrorJsonResponse {
                        error: format!("Failed to set channel: {}", e),
                    });
                }
            }
            WifiToken::WifiPass(val) => {
                if let Err(e) = set_pass(val) {
                    return HttpResponse::build(StatusCode::BAD_REQUEST).json(ErrorJsonResponse {
                        error: format!("Failed to set password: {}", e),
                    });
                }
            }
            WifiToken::WifiSsid(val) => {
                if let Err(e) = set_ssid(val) {
                    return HttpResponse::build(StatusCode::BAD_REQUEST).json(ErrorJsonResponse {
                        error: format!("Failed to set SSID: {}", e),
                    });
                }
            }
            WifiToken::WifiDisabled(val) => {
                let result = match set_disabled(val) {
                    Ok(a) => a,
                    Err(e) => {
                        return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(
                            ErrorJsonResponse {
                                error: format!("{}", e),
                            },
                        );
                    }
                };
                if result.needs_reboot {
                    needs_reboot = true;
                }
            }
        };
    }

    if let Err(e) = KI.uci_commit("wireless") {
        return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(ErrorJsonResponse {
            error: format!("{}", e),
        });
    }
    if let Err(e) = KI.openwrt_reset_wireless() {
        return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(ErrorJsonResponse {
            error: format!("{}", e),
        });
    }

    // We edited disk contents, force global sync
    if let Err(e) = KI.fs_sync() {
        return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(ErrorJsonResponse {
            error: format!("{}", e),
        });
    }
    // we have invalidated the old nat rules, update them
    if let Err(e) = KI.create_client_nat_rules() {
        return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(ErrorJsonResponse {
            error: format!("{}", e),
        });
    }

    if needs_reboot {
        info!("Changed a radio's active state, rebooting");
        if let Err(e) = KI.run_command("reboot", &[]) {
            return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(
                ErrorJsonResponse {
                    error: format!("{}", e),
                },
            );
        }
        return HttpResponse::Ok().json(RebootJsonResponse { needs_reboot: true });
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
    let model = settings::get_rita_client().network.device;
    // trying to swap from 5ghz to 2.4ghz or vice versa, usually this
    // is impossible, although some multifunction cards allow it
    if (old_is_two && new_is_five) || (old_is_five && new_is_two) {
        Err(ValidationError::WrongRadio)
    } else if new_is_two && !ALLOWED_TWO.contains(&new_val) {
        Err(ValidationError::BadChannel(
            "20".to_string(),
            format!("{:?}", ALLOWED_TWO),
        ))
    } else if new_is_five && channel_width_is_20 && !ALLOWED_FIVE_20.contains(&new_val) {
        Err(ValidationError::BadChannel(
            "20".to_string(),
            format!("{:?}", ALLOWED_FIVE_20),
        ))
    } else if new_is_five && channel_width_is_40 && !ALLOWED_FIVE_40.contains(&new_val) {
        Err(ValidationError::BadChannel(
            "40".to_string(),
            format!("{:?}", ALLOWED_FIVE_40),
        ))
    } else if new_is_five && channel_width_is_80 && !ALLOWED_FIVE_80.contains(&new_val) {
        Err(ValidationError::BadChannel(
            "80".to_string(),
            format!("{:?}", ALLOWED_FIVE_80),
        ))
    } else if new_is_five && channel_width_is_160 && !ALLOWED_FIVE_160.contains(&new_val) {
        Err(ValidationError::BadChannel(
            "160".to_string(),
            format!("{:?}", ALLOWED_FIVE_160),
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
                format!("{:?}", ALLOWED_FIVE_80_IPQ40XX),
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
                format!("{:?}", ALLOWED_FIVE_80_MT7621),
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

// returns what channels are allowed for the provided radio value
pub async fn get_allowed_wifi_channels(radio: Path<String>) -> HttpResponse {
    debug!("/wifi_settings/get_channels hit with {:?}", radio);
    let radio = radio.into_inner();

    let current_channel: u16 = match KI.get_uci_var(&format!("wireless.{}.channel", radio)) {
        Ok(uci) => match uci.parse() {
            Ok(a) => a,
            Err(e) => {
                return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
                    .json(format!("{}", e));
            }
        },
        Err(e) => {
            return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(format!("{}", e));
        }
    };
    let five_channel_width = match KI.get_uci_var(&format!("wireless.{}.htmode", radio)) {
        Ok(a) => a,
        Err(e) => {
            return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(format!("{}", e));
        }
    };
    let model = settings::get_rita_client().network.device;

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
            return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(format!("{}", e));
        }
    };
    HttpResponse::Ok().json(config)
}

fn get_wifi_config_internal() -> Result<Vec<WifiInterface>, RitaClientError> {
    let mut interfaces = Vec::new();
    let mut devices = HashMap::new();
    let config = KI.ubus_call("uci", "get", "{ \"config\": \"wireless\"}")?;
    let val: Value = serde_json::from_str(&config)?;
    let items = match val["values"].as_object() {
        Some(i) => i,
        None => {
            error!("No \"values\" key in parsed wifi config!");
            return Err(RitaCommonError::ConversionError(
                "No \"values\" key in parsed wifi config!".to_string(),
            )
            .into());
        }
    };
    for (k, v) in items {
        if v[".type"] == "wifi-device" {
            let mut device: WifiDevice = serde_json::from_value(v.clone())?;
            device.section_name = k.clone();
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
            interface.section_name = k.clone();
            let device_name: String = serde_json::from_value(v["device"].clone())?;
            interface.device = devices[&device_name].clone();
            interfaces.push(interface);
        }
    }
    Ok(interfaces)
}
