use actix_web_async::{web::Json, HttpResponse};
use althea_types::{ClientExtender, HardwareInfo};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use super::get_wifi_config_internal;
use crate::extender::{
    get_device_mac, ExtenderAdditionalSettings, ExtenderCheckin, ExtenderUpdate,
};

lazy_static! {
    /// This is a mapping of Mac Addr of extender -> Its checkin struct
    /// This data is stored to send up to ops tools to display information about connected extenders
    static ref EXTENDER_LIST: Arc<RwLock<HashMap<u64, ExtenderCheckin>>> = Arc::new(RwLock::new(HashMap::new()));
}

/// When an extender checks in, we send it our current wifi state so they make changes accordingly
/// We store their info to send up to OPs
pub async fn extender_checkin_handler(extender: Json<ExtenderCheckin>) -> HttpResponse {
    let extender = extender.into_inner();
    // Store this in local database, what info do we need to store here
    add_wifi_extender(extender);

    let rita_client = settings::get_rita_client();

    let ret = ExtenderUpdate {
        device_mac: get_device_mac(),
        wifi_info: match get_wifi_config_internal() {
            Ok(a) => a,
            Err(e) => {
                error!("Unable to send wifi info to entender: {:?}", e);
                Vec::new()
            }
        },
        logging_settings: rita_client.log,
        additional_settings: ExtenderAdditionalSettings {
            router_version: env!("CARGO_PKG_VERSION").to_string(),
            operator_addr: rita_client.operator.operator_address,
            wg_key: rita_client.network.wg_public_key,
            rita_dashboard_port: rita_client.network.rita_dashboard_port,
        },
    };
    HttpResponse::Ok().json(ret)
}

/// Before returning HardwareInfo struct to op tools or an endpoint, we extend it
/// with info about the connected extenders.
pub fn extend_hardware_info(info: HardwareInfo) -> HardwareInfo {
    let extender_list = EXTENDER_LIST.read().unwrap();
    let mut ret = Vec::new();
    for (addr, _) in extender_list.iter() {
        ret.push(ClientExtender { mac_addr: *addr });
    }

    let mut info_copy = info;

    info_copy.extender_list = Some(ret);
    info_copy
}

/// Store a wifi extender locally after it checks in
fn add_wifi_extender(extender: ExtenderCheckin) {
    let mac_id = extender.device_mac;
    EXTENDER_LIST.write().unwrap().insert(mac_id, extender);
}
