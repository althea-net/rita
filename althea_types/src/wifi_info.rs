#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq, Hash)]
pub struct WifiChannel {
    pub radio: String,
    pub channel: u16,
}
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq, Hash)]
pub struct WifiSsid {
    pub radio: String,
    pub ssid: String,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq, Hash)]
pub struct WifiPass {
    pub radio: String,
    pub pass: String,
}
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct WifiSecurity {
    pub radio: String,
    pub encryption: String,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq, Hash)]
pub struct WifiDisabled {
    pub radio: String,
    pub disabled: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum WifiToken {
    WifiChannel(WifiChannel),
    WifiSsid(WifiSsid),
    WifiPass(WifiPass),
    WifiDisabled(WifiDisabled),
    WifiSecurity(WifiSecurity),
}

/// This struct contains information for wifi survey data
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct WifiSurveyData {
    /// Frequency in MHz
    pub frequency_mhz: u16,
    /// Noise in dBm
    pub noise_dbm: i32,
    /// Time in ms
    pub channel_active_time: u64,
    pub channel_busy_time: u64,
    pub channel_receive_time: u64,
    pub channel_transmit_time: u64,
}

/// This struct contains information for wifi station data
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct WifiStationData {
    pub station: String,
    pub inactive_time_ms: u64,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_retries: u16,
    pub tx_failed: u16,
    pub rx_drop_misc: u16,
    pub signal_dbm: String,
    pub signal_avg_dbm: String,
    pub tx_bitrate: f32,
    pub tx_duration_us: u64,
    pub rx_bitrate: f32,
    pub rx_duration_us: u64,
    pub airtime_weight: Option<u16>,
    pub authorized: bool,
    pub authenticated: bool,
    pub associated: bool,
    pub preamble: String,
    pub wmm_wme: bool,
    pub mfp: bool,
    pub tdls_peer: bool,
    pub dtim_period: u16,
    pub beacon_interval: u16,
    pub short_slot_time: bool,
    pub connected_time_sec: u16,
    pub associated_at_boottime_sec: Option<String>,
    pub associated_at_ms: Option<u64>,
    pub current_time_ms: Option<u64>,
}

/// Format client uses to send to optools and frontend
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientExtender {
    pub mac_addr: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct WifiDevice {
    pub name: String,
    pub survey_data: Vec<WifiSurveyData>,
    pub station_data: Vec<WifiStationData>,
    #[serde(default)]
    pub ssid: Option<String>,
    #[serde(default)]
    pub channel: Option<u16>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

impl From<Vec<&str>> for WifiSurveyData {
    fn from(survey: Vec<&str>) -> Self {
        get_struct_sur(survey)
    }
}

impl From<Vec<&str>> for WifiStationData {
    fn from(station: Vec<&str>) -> Self {
        get_struct_stat(station)
    }
}

fn get_struct_sur(survey: Vec<&str>) -> WifiSurveyData {
    let mut iter = survey.iter();
    let mut ret = WifiSurveyData::default();
    while let Some(str) = iter.next() {
        match *str {
            "frequency" => ret.frequency_mhz = iter.next().unwrap().parse::<u16>().unwrap_or(0u16),
            "noise" => ret.noise_dbm = iter.next().unwrap().parse::<i32>().unwrap_or(0i32),
            "activetime" => {
                ret.channel_active_time = iter.next().unwrap().parse::<u64>().unwrap_or(0u64)
            }
            "busytime" => {
                ret.channel_busy_time = iter.next().unwrap().parse::<u64>().unwrap_or(0u64)
            }
            "receivetime" => {
                ret.channel_receive_time = iter.next().unwrap().parse::<u64>().unwrap_or(0u64)
            }
            "transmittime" => {
                ret.channel_transmit_time = iter.next().unwrap().parse::<u64>().unwrap_or(0u64)
            }
            _ => {}
        }
    }
    ret
}

fn get_struct_stat(station: Vec<&str>) -> WifiStationData {
    let mut iter = station.iter();
    // Set station
    let station = iter.next();
    let mut ret = WifiStationData::default();

    if station.is_none() {
        return ret;
    }
    ret.station = station.unwrap().to_string();
    while let Some(str) = iter.next() {
        match *str {
            "inactive" => {
                iter.next();
                ret.inactive_time_ms = iter.next().unwrap().parse::<u64>().unwrap_or(0u64);
            }
            "rx" => {
                let next_str = iter.next().unwrap();
                match *next_str {
                    "bytes:" => ret.rx_bytes = iter.next().unwrap().parse::<u64>().unwrap_or(0u64),
                    "packets:" => {
                        ret.rx_packets = iter.next().unwrap().parse::<u64>().unwrap_or(0u64)
                    }
                    "drop" => {
                        iter.next();
                        ret.rx_drop_misc = iter.next().unwrap().parse::<u16>().unwrap_or(0u16);
                    }
                    "bitrate:" => {
                        ret.rx_bitrate = iter.next().unwrap().parse::<f32>().unwrap_or(0f32);
                    }
                    "duration:" => {
                        ret.rx_duration_us = iter.next().unwrap().parse::<u64>().unwrap_or(0u64)
                    }
                    _ => {}
                }
            }
            "tx" => {
                let next_str = iter.next().unwrap();
                match *next_str {
                    "bytes:" => ret.tx_bytes = iter.next().unwrap().parse::<u64>().unwrap_or(0u64),
                    "packets:" => {
                        ret.tx_packets = iter.next().unwrap().parse::<u64>().unwrap_or(0u64)
                    }
                    "retries:" => {
                        ret.tx_retries = iter.next().unwrap().parse::<u16>().unwrap_or(0u16);
                    }
                    "failed:" => {
                        ret.tx_failed = iter.next().unwrap().parse::<u16>().unwrap_or(0u16)
                    }
                    "bitrate:" => {
                        ret.tx_bitrate = iter.next().unwrap().parse::<f32>().unwrap_or(0f32);
                    }
                    "duration:" => {
                        ret.tx_duration_us = iter.next().unwrap().parse::<u64>().unwrap_or(0u64)
                    }
                    _ => {}
                }
            }
            "signal:" => {
                let mut sig_arr = vec![*iter.next().unwrap()];
                for str_val in iter.by_ref() {
                    let next = *str_val;
                    if next != "dBm" {
                        sig_arr.push(next);
                        if sig_arr.len() > 10 {
                            sig_arr.clear();
                            sig_arr.push("Error with signal parsing logic, please fix");
                            break;
                        }
                    } else {
                        sig_arr.push("dBm");
                        break;
                    }
                }
                let sig_str: String = sig_arr.into_iter().collect();
                ret.signal_dbm = sig_str;
            }
            "avg:" => {
                let mut sig_arr = vec![*iter.next().unwrap()];
                for str_val in iter.by_ref() {
                    let next = *str_val;
                    if next != "dBm" {
                        sig_arr.push(next);
                        if sig_arr.len() > 10 {
                            sig_arr.clear();
                            sig_arr.push("Error with signal parsing logic, please fix");
                            break;
                        }
                    } else {
                        sig_arr.push("dBm");
                        break;
                    }
                }
                let sig_str: String = sig_arr.into_iter().collect();
                ret.signal_avg_dbm = sig_str;
            }
            "airtime" => {
                iter.next();
                ret.airtime_weight = Some(iter.next().unwrap().parse::<u16>().unwrap_or(0u16));
            }
            "authorized:" => {
                let next_str = iter.next().unwrap();
                ret.authorized = *next_str == "yes";
            }
            "authenticated:" => {
                let next_str = iter.next().unwrap();
                ret.authenticated = *next_str == "yes";
            }
            "[boottime]:" => {
                ret.associated_at_boottime_sec = Some(iter.next().unwrap().to_string())
            }
            "at:" => {
                ret.associated_at_ms = Some(iter.next().unwrap().parse::<u64>().unwrap_or(0u64));
            }
            "associated:" => {
                let next_str = iter.next().unwrap();
                ret.associated = *next_str == "yes";
            }
            "preamble:" => ret.preamble = iter.next().unwrap().to_string(),
            "WMM/WME:" => {
                let next_str = iter.next().unwrap();
                ret.wmm_wme = *next_str == "yes";
            }
            "MFP:" => {
                let next_str = iter.next().unwrap();
                ret.mfp = *next_str == "yes";
            }
            "peer:" => {
                let next_str = iter.next().unwrap();
                ret.tdls_peer = *next_str == "yes";
            }
            "period:" => ret.dtim_period = iter.next().unwrap().parse::<u16>().unwrap_or(0u16),
            "beacon" => {
                let next_str = *iter.next().unwrap();
                let next_str = next_str.replace("interval:", "");
                ret.beacon_interval = next_str.parse::<u16>().unwrap_or(0u16);
            }
            "slot" => {
                let next_str = *iter.next().unwrap();
                ret.short_slot_time = next_str.contains("yes");
            }
            "connected" => {
                iter.next();
                ret.connected_time_sec = iter.next().unwrap().parse::<u16>().unwrap_or(0u16);
            }
            "current" => {
                iter.next();
                ret.current_time_ms = Some(iter.next().unwrap().parse::<u64>().unwrap_or(0u64));
            }
            _ => {}
        }
    }
    ret
}

pub fn extract_wifi_survey_data(survey_str: &str, dev_name: &str) -> Vec<WifiSurveyData> {
    let mut ret: Vec<WifiSurveyData> = vec![];

    // Preprocess String
    let freq_list: &str = &survey_str.replace("Survey data from ", "");
    let freq_list: &str = &freq_list.replace("active time", "activetime");
    let freq_list: &str = &freq_list.replace("busy time", "busytime");
    let freq_list: &str = &freq_list.replace("transmit time", "transmittime");
    let freq_list: &str = &freq_list.replace("receive time", "receivetime");
    let freq_list: &str = &freq_list.replace(':', " ");
    let freq_list: Vec<&str> = freq_list.split_ascii_whitespace().collect();

    // Split on device name (wlan0)
    let mut iter = freq_list.split(|dev| *dev == dev_name);
    loop {
        let to_struct = iter.next();
        if let Some(to_struct) = to_struct {
            let to_struct = to_struct.to_vec();
            let survey_struct = WifiSurveyData::from(to_struct);
            //if channel active time is 0, we dont need that data
            if survey_struct.channel_active_time != 0 {
                ret.push(survey_struct)
            }
        } else {
            break;
        }
    }

    ret
}

pub fn extract_wifi_station_data(station_str: &str) -> Vec<WifiStationData> {
    let mut ret: Vec<WifiStationData> = vec![];

    // Preprocess String
    let freq_list: Vec<&str> = station_str.split_ascii_whitespace().collect();

    // Split on "Station"
    let mut iter = freq_list.split(|dev| *dev == "Station");
    loop {
        let to_struct = iter.next();
        if let Some(to_struct) = to_struct {
            let to_struct = to_struct.to_vec();
            let station_struct = WifiStationData::from(to_struct);
            // If not station, its an empty struct
            if !station_struct.station.is_empty() {
                ret.push(station_struct);
            }
        } else {
            break;
        }
    }

    ret
}

#[test]
fn test_extract_surveydata() {
    let str = "Survey data from wlan0
    frequency:            2412 MHz
Survey data from wlan0
    frequency:            2417 MHz
Survey data from wlan0
    frequency:            2422 MHz
Survey data from wlan0
    frequency:            2427 MHz
Survey data from wlan0
    frequency:            2432 MHz
Survey data from wlan0
    frequency:            2437 MHz
Survey data from wlan0
    frequency:            2442 MHz
Survey data from wlan0
    frequency:            2447 MHz
Survey data from wlan0
    frequency:            2452 MHz
Survey data from wlan0
    frequency:            2457 MHz
Survey data from wlan0
    frequency:            2462 MHz [in use]
    noise:                -102 dBm
    channel active time:        4172127 ms
    channel busy time:        828107 ms
    channel receive time:        1448 ms
    channel transmit time:        20225 ms
Survey data from wlan0
    frequency:            24062 MHz [in use]
    noise:                -1002 dBm
    channel active time:        5127 ms
    channel busy time:        5 ms
    channel receive time:        5 ms
    channel transmit time:        5 ms";

    let ret = extract_wifi_survey_data(str, "wlan0");

    println!("{ret:?}");
}

#[test]
fn test_extract_stationdata() {
    let str = "Station 08:66:98:b6:bd:6d (on wlan1)
    inactive time:    22430 ms
    rx bytes:    718014
    rx packets:    2754
    tx bytes:    158437
    tx packets:    503
    tx retries:    1
    tx failed:    0
    rx drop misc:    0
    signal:      -63 [-86, -63, -100, -100] dBm
    signal avg:    -64 [-79, -64, -100, -100] dBm
    tx bitrate:    702.0 MBit/s VHT-MCS 8 80MHz VHT-NSS 2
    tx duration:    11494 us
    rx bitrate:    24.0 MBit/s
    rx duration:    0 us
    airtime weight: 256
    authorized:    yes
    authenticated:    yes
    associated:    yes
    preamble:    long
    WMM/WME:    yes
    MFP:        no
    TDLS peer:    no
    DTIM period:    2
    beacon interval:100
    short slot time:yes
    connected time:    4257 seconds
    associated at [boottime]:    42.228s
    associated at:    1645652326500 ms
    current time:    1645656582641 ms
Station 5c:f7:e6:1c:36:f7 (on wlan1)
    inactive time:    6530 ms
    rx bytes:    74003941
    rx packets:    75242
    tx bytes:    31834401
    tx packets:    46661
    tx retries:    1625
    tx failed:    359
    rx drop misc:    7
    signal:      -83 [-86, -86, -100, -100] dBm
    signal avg:    -85 [-90, -89, -100, -100] dBm
    tx bitrate:    150.0 MBit/s MCS 7 40MHz short GI
    tx duration:    6054270 us
    rx bitrate:    24.0 MBit/s
    rx duration:    0 us
    airtime weight: 256
    authorized:    yes
    authenticated:    yes
    associated:    yes
    preamble:    long
    WMM/WME:    yes
    MFP:        no
    TDLS peer:    no
    DTIM period:    2
    beacon interval:100
    short slot time:yes
    connected time:    4238 seconds
    associated at [boottime]:    60.927s
    associated at:    1645652345197 ms
    current time:    1645656582642 ms
Station 54:88:0e:ab:fb:81 (on wlan1)
    inactive time:    490 ms
    rx bytes:    745497
    rx packets:    6919
    tx bytes:    127474
    tx packets:    520
    tx retries:    0
    tx failed:    0
    rx drop misc:    2
    signal:      -59 [-68, -59, -100, -100] dBm
    signal avg:    -58 [-67, -58, -100, -100] dBm
    tx bitrate:    144.4 MBit/s MCS 15 short GI
    tx duration:    18010 us
    rx bitrate:    144.4 MBit/s MCS 15 short GI
    rx duration:    0 us
    airtime weight: 256
    authorized:    yes
    authenticated:    yes
    associated:    yes
    preamble:    long
    WMM/WME:    yes
    MFP:        no
    TDLS peer:    no
    DTIM period:    2
    beacon interval:100
    short slot time:yes
    connected time:    4140 seconds
    associated at [boottime]:    158.256s
    associated at:    1645652442527 ms
    current time:    1645656582646 ms";

    let ret = extract_wifi_station_data(str);
    println!("{ret:?}");

    let old_str = "Station <mac removed> (on wlan1)
	inactive time:	10 ms
	rx bytes:	141627376
	rx packets:	329289
	tx bytes:	1106901
	tx packets:	6172
	tx retries:	0
	tx failed:	0
	rx drop misc:	322643
	signal:  	-73 dBm
	signal avg:	-73 dBm
	tx bitrate:	6.0 MBit/s 40MHz
	rx bitrate:	54.0 MBit/s
	rx duration:	0 us
	authorized:	yes
	authenticated:	yes
	associated:	yes
	preamble:	short
	WMM/WME:	yes
	MFP:		no
	TDLS peer:	no
	DTIM period:	2
	beacon interval:100
	short preamble:	yes
	short slot time:yes
	connected time:	26651 seconds";

    let ret = extract_wifi_station_data(old_str);
    println!("\n\n{ret:?}");
}

#[test]
fn test_extract_wifi_names() {
    let line1 = "Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE";
    let line2 =
        "    face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22";
    let line3 = "wlan1: 0000    0     0     0        0      0      0      0      0        0";
    let line4 = "wlan0: 0000    0     0     0        0      0      0      0      0        0";

    let vec_lines = vec![line1, line2, line3, line4];
    let mut ret = Vec::new();

    for line in vec_lines {
        if line.contains(':') {
            let name: Vec<&str> = line.split(':').collect();
            let name = name[0];
            ret.push(name.to_string());
        }
    }

    println!("{ret:?}");
}
