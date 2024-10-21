#[macro_use]
extern crate log;

pub mod dashboard;
mod error;

use actix::System as AsyncSystem;
use althea_kernel_interface::run_command;
use althea_kernel_interface::upgrade::perform_opkg;
use althea_types::OpkgCommand;
use althea_types::WifiSsid;
use error::RitaExtenderError;
use rita_client::extender::get_device_mac;
use rita_client::extender::ExtenderCheckin;
use rita_client::extender::ExtenderUpdate;
use rita_common::dashboard::wifi::get_wifi_config_internal;
use rita_common::dashboard::wifi::set_ssid;
use rita_common::dashboard::wifi::WifiInterface;
use std::thread;
use std::time::Duration;
use std::time::Instant;

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
                "Unable to checkin with router: {e:?}"
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
                        "Unable to initialize wifi info to send to optools, will try later: {e}"
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

    let our_settings = get_checkin_message();

    apply_wifi_settings(settings.wifi_info, our_settings.wifi_info);

    // If there is a discrepency with version number, call an opkg update
    apply_opkg_update_if_needed(
        settings.additional_settings.router_version,
        env!("CARGO_PKG_VERSION").to_string(),
    );
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

fn apply_opkg_update_if_needed(router_version: String, extender_version: String) {
    // Inequal version should imply the router version > extender version . This would be problematic if
    // extender version > router version, but such a case should not come about and implies a problem somewhere else
    if router_version != extender_version {
        let common_args = vec!["-V0".to_string(), "--no-check-certificate".to_string()];
        // common args plus the force maintainer argument which will grab the maintainers version of any
        // config files, absolutely do not use this on rita or rita-exit
        let force_maintainer = {
            let mut tmp = common_args.clone();
            tmp.extend(vec!["--force-maintainer".to_string()]);
            tmp
        };

        // Perfrom an opkg update
        let opkg_update = OpkgCommand::Update {
            feed: match get_opkg_feed(router_version) {
                Ok(a) => a,
                Err(e) => {
                    error!("{:?}", e);
                    return;
                }
            },
            feed_name: "althea_extender".to_string(),
            arguments: common_args,
        };
        let res = perform_opkg(opkg_update);
        match res {
            Ok(o) => match o.status.code() {
                Some(0) => info!("opkg update completed successfully! {:?}", o),
                Some(_) => {
                    let err = format!("opkg update has failed! {o:?}");
                    error!("{}", err);
                    return;
                }
                None => warn!("No return code form opkg update? {:?}", o),
            },
            Err(e) => {
                error!("Unable to perform opkg with error: {:?}", e);
                return;
            }
        }

        // Install the necessary opkg packages
        let opkg_install = OpkgCommand::Install {
            packages: vec!["rita_extender".to_string()],
            arguments: force_maintainer,
        };
        let res = perform_opkg(opkg_install);
        match res {
            Ok(o) => match o.status.code() {
                Some(0) => info!("opkg update completed successfully! {:?}", o),
                Some(_) => {
                    let err = format!("opkg update has failed! {o:?}");
                    error!("{}", err);
                    return;
                }
                None => warn!("No return code form opkg update? {:?}", o),
            },
            Err(e) => {
                error!("Unable to perform opkg with error: {:?}", e);
                return;
            }
        }

        // Restart after opkg is complete
        if let Err(e) = run_command("/etc/init.d/rita_extender", &["restart"]) {
            error!("Unable to restart rita extender after opkg update: {}", e)
        }
    }
}

/// Convert router version to its human readable string to insert into opkg feed
/// We receive router string in form of 0.18.8 and conver to beta18rc8
fn get_opkg_feed(router_ver: String) -> Result<String, RitaExtenderError> {
    let mut version: Vec<&str> = router_ver.split('.').collect();
    version.remove(0);
    let router_beta: u16 = match version[0].parse() {
        Ok(v) => v,
        Err(_) => {
            return Err(RitaExtenderError::MiscStringError(format!(
                "Cannot parse router version beta {:?}",
                version[0]
            )));
        }
    };
    let router_rc: u16 = match version[1].parse() {
        Ok(v) => v,
        Err(_) => {
            return Err(RitaExtenderError::MiscStringError(format!(
                "Cannot parse router version rc {:?}",
                version[1]
            )));
        }
    };

    let mut ret = "beta".to_string();
    ret.push_str(&router_beta.to_string());
    ret.push_str("rc");
    ret.push_str(&router_rc.to_string());

    Ok(format!(
        "https://updates.altheamesh.com/{ret}/packages/mipsel_24kc/althea"
    ))
}

#[test]
fn test_get_opkg_feed() {
    assert_eq!(
        Ok("https://updates.altheamesh.com/beta18rc9/packages/mipsel_24kc/althea".to_string()),
        get_opkg_feed("0.18.9".to_string())
    )
}
