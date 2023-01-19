#[macro_use]
extern crate log;

pub mod dashboard;
mod error;

use actix_async::System as AsyncSystem;
use error::RitaExtenderError;
use rita_client::dashboard::wifi::WifiInterface;
use rita_client::extender::get_device_mac;
use rita_client::extender::ExtenderCheckin;
use rita_client::get_wifi_config_internal;
use rita_client::set_ssid;
use rita_client::WifiSsid;

use std::thread;
use std::time::Duration;
use std::time::Instant;

use rita_client::extender::ExtenderUpdate;

const EXTENDER_CHECKIN_TIMEOUT: Duration = Duration::from_secs(5);
const EXTENDER_LOOP_SPEED: Duration = Duration::from_secs(30);
pub const DEFAULT_UPSTREAM_ENDPOINT: &str = "http://192.168.10.1:4877/extender_checkin";

pub fn start_rita_extender_loop() {
    let mut last_restart = Instant::now();
    // outer thread is a watchdog inner thread is the runner
    thread::spawn(move || {
        // this will always be an error, so it's really just a loop statement
        // with some fancy destructuring
        while let Err(e) = {
            thread::spawn(move || loop {
                trace!("Extender tick!");
                let start = Instant::now();

                let runner = AsyncSystem::new();
                runner.block_on(async move {
                    rita_extender_loop().await;
                });
                info!(
                    "Extender tick completed in {}s {}ms",
                    start.elapsed().as_secs(),
                    start.elapsed().subsec_millis()
                );

                thread::sleep(EXTENDER_LOOP_SPEED);
            })
            .join()
        } {
            error!("Rita extender loop thread paniced! Respawning {:?}", e);
            if Instant::now() - last_restart < Duration::from_secs(60) {
                error!("Restarting too quickly, leaving it to auto rescue!");
                let sys = AsyncSystem::current();
                sys.stop_with_code(121);
            }
            last_restart = Instant::now();
        }
    });
}

/// Make a post request to checkin with main router. Get deatils such as wifi
/// info from the router and return that info
pub async fn extender_checkin(
    endpoint: String,
    payload: ExtenderCheckin,
) -> Result<ExtenderUpdate, RitaExtenderError> {
    let client = awc::Client::default();

    info!(
        "About to checkin with {}\n our checkin struct is {:?}",
        endpoint, payload
    );

    let response = client
        .post(&endpoint)
        .timeout(EXTENDER_CHECKIN_TIMEOUT)
        .send_json(&payload)
        .await;

    let mut response = match response {
        Ok(a) => a,
        Err(e) => {
            return Err(RitaExtenderError::MiscStringError(format!(
                "Unable to checkin with router: {:?}",
                e
            )));
        }
    };

    Ok(response.json().await?)
}

/// Populate our current wifi state to send in a checkin message. Contains our mac address
/// along with a list of wifi interfaces and their configuration
pub fn get_checkin_message() -> ExtenderCheckin {
    ExtenderCheckin {
        device_mac: get_device_mac(),
        wifi_info: {
            match get_wifi_config_internal() {
                Ok(a) => a,
                Err(e) => {
                    println!(
                        "Unable to initialize wifi info to send to optools, will try later: {}",
                        e
                    );
                    Vec::new()
                }
            }
        },
    }
}

async fn rita_extender_loop() {
    // Retrieve upstream settings
    let settings = match extender_checkin(
        DEFAULT_UPSTREAM_ENDPOINT.to_string(),
        get_checkin_message(),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => {
            error!("Extender checkin failed with {:?}", e);
            return;
        }
    };

    let current_settings = get_checkin_message();

    apply_wifi_settings(settings.wifi_info, current_settings.wifi_info);
}

/// Find the first 5Ghz channel from router interfaces and apply its ssid to all 5Ghz channels on extender
/// Find the first 2.5Ghz channel from router interfaces and apply its ssid to all 2.5Ghz channels on extender
fn apply_wifi_settings(router_settings: Vec<WifiInterface>, our_settings: Vec<WifiInterface>) {
    // Find 5Ghz
    for iface in &router_settings {
        if iface.device.radio_type == "5ghz" {
            for our_iface in &our_settings {
                if our_iface.device.radio_type == "5ghz" {
                    // Apply all necessary settings
                    if let Err(e) = set_ssid(&WifiSsid {
                        radio: our_iface.device.section_name.clone(),
                        ssid: iface.ssid.clone(),
                    }) {
                        error!(
                            "Unable to set ssid {:?} with error {:?}",
                            iface.ssid.clone(),
                            e
                        );
                    } else {
                        info!(
                            "Successfully set ssid of 5ghz radio {} to {}",
                            our_iface.device.section_name.clone(),
                            iface.ssid.clone()
                        )
                    }
                }
            }
        }
    }

    // Find 2ghz
    for iface in router_settings {
        if iface.device.radio_type == "2ghz" {
            for our_iface in &our_settings {
                if our_iface.device.radio_type == "2ghz" {
                    // Apply all necessary settings
                    if let Err(e) = set_ssid(&WifiSsid {
                        radio: our_iface.device.section_name.clone(),
                        ssid: iface.ssid.clone(),
                    }) {
                        error!(
                            "Unable to set ssid {:?} with error {:?}",
                            iface.ssid.clone(),
                            e
                        );
                    } else {
                        info!(
                            "Successfully set ssid of 2ghz radio {} to {}",
                            our_iface.device.section_name.clone(),
                            iface.ssid.clone()
                        )
                    }
                }
            }
        }
    }
}
