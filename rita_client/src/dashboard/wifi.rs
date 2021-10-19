//! These endpoints are used to modify mundane wireless settings

use rita_common::dashboard::nickname::maybe_set_nickname;
use rita_common::KI;

use ::actix_web::http::StatusCode;
use ::actix_web::Path;
use ::actix_web::{HttpRequest, HttpResponse, Json};
use failure::Error;
use serde_json::Value;
use std::collections::HashMap;

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
/// list of nonoverlapping 80mhz channels for the TPLink-a6v3/wr-2100
pub const ALLOWED_FIVE_80_TPLINK_A6V3: [u16; 1] = [36];
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

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct WifiSsid {
    pub radio: String,
    pub ssid: String,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct WifiPass {
    pub radio: String,
    pub pass: String,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct WifiChannel {
    pub radio: String,
    pub channel: u16,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum WifiToken {
    WifiChannel(WifiChannel),
    WifiSsid(WifiSsid),
    WifiPass(WifiPass),
}

/// A string of characters which we don't let users use because of corrupted UCI configs
static FORBIDDEN_CHARS: &str = "'/\"\\";

static MINIMUM_PASS_CHARS: usize = 8;

/// A helper error type for displaying UCI config value validation problems human-readably.
#[derive(Debug, Fail, Serialize)]
pub enum ValidationError {
    #[fail(display = "Illegal character {} at position {}", c, pos)]
    IllegalCharacter { pos: usize, c: char },
    #[fail(display = "Empty value")]
    Empty,
    #[fail(
        display = "Incorrect channel! Your radio has a channel width of {} please select one of {}",
        _0, _1
    )]
    BadChannel(String, String),
    #[fail(display = "Trying to set a 5ghz channel on a 2.4ghz radio or vice versa!")]
    WrongRadio,
    #[fail(display = "Value too short ({} required)", _0)]
    TooShort(usize),
}

fn set_ssid(wifi_ssid: &WifiSsid) -> Result<HttpResponse, Error> {
    let mut ret: HashMap<String, String> = HashMap::new();

    if let Err(e) = validate_config_value(&wifi_ssid.ssid) {
        info!("Setting of invalid SSID was requested: {}", e);
        ret.insert("error".to_owned(), format!("{}", e));
        return Ok(HttpResponse::new(StatusCode::BAD_REQUEST)
            .into_builder()
            .json(ret));
    }

    // think radio0, radio1
    let iface_name = wifi_ssid.radio.clone();
    let ssid = wifi_ssid.ssid.clone();
    let section_name = format!("default_{}", iface_name);
    KI.set_uci_var(&format!("wireless.{}.ssid", section_name), &ssid)?;

    KI.uci_commit("wireless")?;
    KI.openwrt_reset_wireless()?;

    // We edited disk contents, force global sync
    KI.fs_sync()?;
    // set the nickname with the first SSID change may fail
    // if the ssid is too long but don't block on that
    let _ = maybe_set_nickname(wifi_ssid.ssid.clone());

    // we have invalidated the old nat rules, update them
    KI.create_client_nat_rules()?;

    Ok(HttpResponse::Ok().json(ret))
}

/// Resets the wifi password to the stock value for all radios
pub fn reset_wifi_pass() -> Result<(), Error> {
    let config = get_wifi_config_internal()?;
    for interface in config {
        let pass = WifiPass {
            radio: interface.device.section_name,
            pass: "ChangeMe".to_string(),
        };
        set_pass(&pass)?;
    }
    Ok(())
}

fn set_pass(wifi_pass: &WifiPass) -> Result<HttpResponse, Error> {
    let mut ret = HashMap::new();

    let wifi_pass_len = wifi_pass.pass.len();
    if wifi_pass_len < MINIMUM_PASS_CHARS {
        ret.insert(
            "error".to_owned(),
            format!("{}", ValidationError::TooShort(MINIMUM_PASS_CHARS)),
        );
        return Ok(HttpResponse::new(StatusCode::BAD_REQUEST)
            .into_builder()
            .json(ret));
    }

    if let Err(e) = validate_config_value(&wifi_pass.pass) {
        info!("Setting of invalid SSID was requested: {}", e);
        ret.insert("error".to_owned(), format!("{}", e));
        return Ok(HttpResponse::new(StatusCode::BAD_REQUEST)
            .into_builder()
            .json(ret));
    }

    // think radio0, radio1
    let iface_name = wifi_pass.radio.clone();
    let pass = wifi_pass.pass.clone();
    let section_name = format!("default_{}", iface_name);
    KI.set_uci_var(&format!("wireless.{}.key", section_name), &pass)?;

    KI.uci_commit("wireless")?;
    KI.openwrt_reset_wireless()?;

    // We edited disk contents, force global sync
    KI.fs_sync()?;

    // we have invalidated the old nat rules, update them
    KI.create_client_nat_rules()?;

    Ok(HttpResponse::Ok().json(()))
}

fn set_channel(wifi_channel: &WifiChannel) -> Result<HttpResponse, Error> {
    let current_channel: u16 = KI
        .get_uci_var(&format!("wireless.{}.channel", wifi_channel.radio))?
        .parse()?;
    let channel_width = KI.get_uci_var(&format!("wireless.{}.htmode", wifi_channel.radio))?;

    if let Err(e) = validate_channel(current_channel, wifi_channel.channel, &channel_width) {
        info!("Setting of invalid SSID was requested: {}", e);
        return Ok(HttpResponse::new(StatusCode::BAD_REQUEST)
            .into_builder()
            .json("Invalid SSID!"));
    }

    KI.set_uci_var(
        &format!("wireless.{}.channel", wifi_channel.radio),
        &wifi_channel.channel.to_string(),
    )?;
    KI.uci_commit("wireless")?;
    KI.openwrt_reset_wireless()?;

    // We edited disk contents, force global sync
    KI.fs_sync()?;
    // we have invalidated the old nat rules, update them
    KI.create_client_nat_rules()?;

    Ok(HttpResponse::Ok().json(()))
}

/// an endpoint that takes a series of wifi tokens in json format and applies them all at once
/// the reason for this is that changing any setting while on wifi will disconnect the caller
/// so in order to have all the changes 'take' we need to have a single endpoint for all changes
pub fn set_wifi_multi(wifi_changes: Json<Vec<WifiToken>>) -> Result<HttpResponse, Error> {
    trace!("Got multi wifi change!");
    for token in wifi_changes.into_inner().iter() {
        match token {
            WifiToken::WifiChannel(val) => set_channel(val)?,
            WifiToken::WifiPass(val) => set_pass(val)?,
            WifiToken::WifiSsid(val) => set_ssid(val)?,
        };
    }
    Ok(HttpResponse::Ok().json(()))
}

/// Validates that the channel is both correct and legal the underlying driver should prevent
/// channels for the wrong region, but we go tht extra mile just in case
fn validate_channel(
    old_val: u16,
    new_val: u16,
    channel_width: &str,
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
    } else if model.is_some() {
        let mdl = model.clone().unwrap();
        if (mdl.contains("gl-b1300")
        || mdl.contains("linksys_ea6350v3"))
        && new_is_five
        && channel_width_is_80
        && !ALLOWED_FIVE_80_IPQ40XX.contains(&new_val)
        {
            Err(ValidationError::BadChannel(
                "80".to_string(),
                format!("{:?}", ALLOWED_FIVE_80_IPQ40XX),
            ))
        }
        else if (mdl.contains("tplink_archer-a6-v3")
        || mdl.contains("cudy_wr2100"))
        && new_is_five
        && channel_width_is_80
        && !ALLOWED_FIVE_80_TPLINK_A6V3.contains(&new_val)
        {
            Err(ValidationError::BadChannel(
                "80".to_string(),
                format!("{:?}", ALLOWED_FIVE_80_TPLINK_A6V3),
            ))
        }        
        else {
            Ok(())
        } 
    } else {
        Ok(())
    }
}

// returns what channels are allowed for the provided radio value
pub fn get_allowed_wifi_channels(radio: Path<String>) -> Result<HttpResponse, Error> {
    debug!("/wifi_settings/get_channels hit with {:?}", radio);
    let radio = radio.into_inner();

    let current_channel: u16 = KI
        .get_uci_var(&format!("wireless.{}.channel", radio))?
        .parse()?;
    let five_channel_width = KI.get_uci_var(&format!("wireless.{}.htmode", radio))?;
    let model = settings::get_rita_client().network.device;

    if current_channel < 20 {
        Ok(HttpResponse::Ok().json(ALLOWED_TWO))

    // model specific values start here
    } else if model.is_some()
    && (model.clone().unwrap().contains("gl-b1300")
        || model.clone().unwrap().contains("linksys_ea6350v3"))
        && five_channel_width.contains("80")
    {
        Ok(HttpResponse::Ok().json(ALLOWED_FIVE_80_IPQ40XX))
    } else if model.is_some()
    && (model.clone().unwrap().contains("tplink_archer-a6-v3")
        || model.clone().unwrap().contains("cudy_wr2100"))
        && five_channel_width.contains("80")
    {
        Ok(HttpResponse::Ok().json(ALLOWED_FIVE_80_TPLINK_A6V3))
    // model specific values end here
    } else if five_channel_width.contains("20") {
        Ok(HttpResponse::Ok().json(ALLOWED_FIVE_20))
    } else if five_channel_width.contains("40") {
        Ok(HttpResponse::Ok().json(ALLOWED_FIVE_40))
    } else if five_channel_width.contains("80") {
        Ok(HttpResponse::Ok().json(ALLOWED_FIVE_80))
    } else if five_channel_width.contains("160") {
        Ok(HttpResponse::Ok().json(ALLOWED_FIVE_160))
    } else {
        Ok(HttpResponse::new(StatusCode::BAD_REQUEST)
            .into_builder()
            .json("Can't identify Radio!"))
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

pub fn get_wifi_config(_req: HttpRequest) -> Result<Json<Vec<WifiInterface>>, Error> {
    debug!("Get wificonfig hit!");
    let config = get_wifi_config_internal()?;
    Ok(Json(config))
}

fn get_wifi_config_internal() -> Result<Vec<WifiInterface>, Error> {
    let mut interfaces = Vec::new();
    let mut devices = HashMap::new();
    let config = KI.ubus_call("uci", "get", "{ \"config\": \"wireless\"}")?;
    let val: Value = serde_json::from_str(&config)?;
    let items = match val["values"].as_object() {
        Some(i) => i,
        None => {
            error!("No \"values\" key in parsed wifi config!");
            return Err(format_err!("No \"values\" key parsed wifi config"));
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
