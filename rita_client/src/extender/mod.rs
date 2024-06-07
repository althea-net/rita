use crate::dashboard::wifi::WifiInterface;
use althea_kernel_interface::hardware_info::maybe_get_single_line_string;
use althea_types::WgKey;
use settings::logging::LoggingSettings;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtenderUpdate {
    pub device_mac: u64,
    pub wifi_info: Vec<WifiInterface>,
    pub logging_settings: LoggingSettings,
    pub additional_settings: ExtenderAdditionalSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtenderAdditionalSettings {
    pub router_version: String,
    pub wg_key: Option<WgKey>,
    pub operator_addr: Option<clarity::Address>,
    pub rita_dashboard_port: u16,
}

/// This is the list of settings rita extender stores internally
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExtenderCheckin {
    pub device_mac: u64,
    pub wifi_info: Vec<WifiInterface>,
}

pub fn get_device_mac() -> u64 {
    if let Some(addr) = maybe_get_single_line_string("/sys/class/net/eth0/address") {
        if !addr.contains("No such file") {
            let addr = addr.replace(':', "");
            match u64::from_str_radix(&addr, 16) {
                Ok(a) => {
                    return a;
                }
                Err(e) => {
                    error!("Unable to parse {} to a u64 with {:?}", addr, e);
                    return 0u64;
                }
            }
        }
    }
    error!("Unable to get mac address");
    0u64
}
