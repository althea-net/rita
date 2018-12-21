//! These endpoints are used to modify mundane wireless settings

use super::*;

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
pub struct WifiSSID {
    pub radio: String,
    pub ssid: String,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct WifiPass {
    pub radio: String,
    pub pass: String,
}

/// A string of characters which we don't let users use because of corrupted UCI configs
static FORBIDDEN_CHARS: &'static str = "'/\"\\";

static MINIMUM_PASS_CHARS: usize = 8;

/// A helper error type for displaying UCI config value validation problems human-readably.
#[derive(Debug, Fail)]
pub enum ValidationError {
    #[fail(display = "Illegal character {} at position {}", c, pos)]
    IllegalCharacter { pos: usize, c: char },
    #[fail(display = "Empty value")]
    Empty,
    #[fail(display = "Value too short ({} required)", _0)]
    TooShort(usize),
}

impl Message for WifiSSID {
    type Result = Result<(), Error>;
}

impl Handler<WifiSSID> for Dashboard {
    type Result = Result<(), Error>;
    fn handle(&mut self, msg: WifiSSID, _ctx: &mut Self::Context) -> Self::Result {
        // think radio0, radio1
        let iface_name = msg.radio;
        let ssid = msg.ssid;
        let section_name = format!("default_{}", iface_name);
        KI.set_uci_var(&format!("wireless.{}.ssid", section_name), &ssid)?;

        KI.uci_commit(&"wireless")?;
        KI.openwrt_reset_wireless()?;

        // We edited disk contents, force global sync
        KI.fs_sync()?;
        Ok(())
    }
}

impl Message for WifiPass {
    type Result = Result<(), Error>;
}

impl Handler<WifiPass> for Dashboard {
    type Result = Result<(), Error>;
    fn handle(&mut self, msg: WifiPass, _ctx: &mut Self::Context) -> Self::Result {
        // think radio0, radio1
        let iface_name = msg.radio;
        let pass = msg.pass;
        let section_name = format!("default_{}", iface_name);
        KI.set_uci_var(&format!("wireless.{}.key", section_name), &pass)?;

        KI.uci_commit(&"wireless")?;
        KI.openwrt_reset_wireless()?;

        // We edited disk contents, force global sync
        KI.fs_sync()?;
        Ok(())
    }
}

pub struct GetWifiConfig;

impl Message for GetWifiConfig {
    type Result = Result<Vec<WifiInterface>, Error>;
}

impl Handler<GetWifiConfig> for Dashboard {
    type Result = Result<Vec<WifiInterface>, Error>;
    fn handle(&mut self, _msg: GetWifiConfig, _ctx: &mut Self::Context) -> Self::Result {
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
}

pub fn set_wifi_ssid(
    wifi_ssid: Json<WifiSSID>,
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    debug!("/wifi_settings/ssid hit with {:?}", wifi_ssid);

    let wifi_ssid = wifi_ssid.into_inner();
    let mut ret: HashMap<String, String> = HashMap::new();

    if let Err(e) = validate_config_value(&wifi_ssid.ssid) {
        info!("Setting of invalid SSID was requested: {}", e);
        ret.insert("error".to_owned(), format!("{}", e));
        return Box::new(future::ok(
            HttpResponse::new(StatusCode::BAD_REQUEST)
                .into_builder()
                .json(ret),
        ));
    }

    Box::new(
        Dashboard::from_registry()
            .send(wifi_ssid)
            .from_err()
            .and_then(move |_reply| future::ok(HttpResponse::Ok().json(ret))),
    )
}

pub fn set_wifi_pass(
    wifi_pass: Json<WifiPass>,
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    debug!("/wifi_settings/pass hit with {:?}", wifi_pass);

    let wifi_pass = wifi_pass.into_inner();
    let mut ret = HashMap::new();

    let wifi_pass_len = wifi_pass.pass.len();
    if wifi_pass_len < MINIMUM_PASS_CHARS {
        ret.insert(
            "error".to_owned(),
            format!("{}", ValidationError::TooShort(MINIMUM_PASS_CHARS)),
        );
        return Box::new(future::ok(
            HttpResponse::new(StatusCode::BAD_REQUEST)
                .into_builder()
                .json(ret),
        ));
    }

    if let Err(e) = validate_config_value(&wifi_pass.pass) {
        info!("Setting of invalid SSID was requested: {}", e);
        ret.insert("error".to_owned(), format!("{}", e));
        return Box::new(future::ok(
            HttpResponse::new(StatusCode::BAD_REQUEST)
                .into_builder()
                .json(ret),
        ));
    }

    Box::new(
        Dashboard::from_registry()
            .send(wifi_pass)
            .from_err()
            .and_then(move |_reply| future::ok(HttpResponse::Ok().json(ret))),
    )
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

pub fn get_wifi_config(
    _req: HttpRequest,
) -> Box<dyn Future<Item = Json<Vec<WifiInterface>>, Error = Error>> {
    debug!("Get wificonfig hit!");
    Dashboard::from_registry()
        .send(GetWifiConfig {})
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}
