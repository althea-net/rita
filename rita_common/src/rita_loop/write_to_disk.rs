use crate::{debt_keeper::save_debt_to_disk, usage_tracker::save_usage_to_disk};
use settings::{
    client::RitaClientSettings, exit::RitaExitSettingsStruct, get_rita_client, get_rita_exit,
    write_config,
};
use std::{thread, time::Duration};
// Save duration for all writes to disk in order to reduce write operations
// pub const SAVING_TO_DISK_FREQUENCY: Duration = Duration::from_secs(600);
#[derive(Clone)]
pub enum SettingsOnDisk {
    RitaClientSettings(Box<RitaClientSettings>),
    RitaExitSettingsStruct(Box<RitaExitSettingsStruct>),
}

/// 10 minutes
const RITA_EXIT_SAVE_INTERVAL: Duration = Duration::from_secs(600);
/// One hour
const RITA_CLIENT_SAVE_INTERVAL: Duration = Duration::from_secs(3600);
/// 48 hours
const RITA_CLIENT_SMALL_STORAGE_SAVE_INTERVAL: Duration = Duration::from_secs(172800);

/// This loop attempts to perform all write operations for writing to disk
/// This includes writing config/settings, usage tracker, and debt tracker.
/// It takes in a settings enum in order to identify what type the device
/// is. There is also a consideration for the amount of storage the device
/// has on disk since we don't want to save too often if the disk doesn't
/// contain a lot of storage.
pub fn save_to_disk_loop(mut old_settings: SettingsOnDisk) {
    let (loop_speed, router_storage_small) = match old_settings.clone() {
        SettingsOnDisk::RitaClientSettings(old_settings_client) => {
            let router_storage_small = match old_settings_client.network.device.clone() {
                Some(val) => is_router_storage_small(&val),
                None => false,
            };
            (
                match router_storage_small {
                    true => RITA_CLIENT_SMALL_STORAGE_SAVE_INTERVAL,
                    false => RITA_CLIENT_SAVE_INTERVAL,
                },
                router_storage_small,
            )
        }
        SettingsOnDisk::RitaExitSettingsStruct(old_settings_exit) => {
            let router_storage_small = match old_settings_exit.network.device.clone() {
                Some(val) => is_router_storage_small(&val),
                None => false,
            };
            (RITA_EXIT_SAVE_INTERVAL, router_storage_small)
        }
    };

    thread::spawn(move || loop {
        thread::sleep(loop_speed);

        //settings
        match old_settings.clone() {
            SettingsOnDisk::RitaClientSettings(old_settings_client) => {
                let new_settings = get_rita_client();

                if old_settings_client != new_settings.clone().into() {
                    let res = write_config();
                    if let Err(e) = res {
                        error!("Error saving client settings! {:?}", e);
                    }
                }

                old_settings = SettingsOnDisk::RitaClientSettings(Box::new(new_settings));
            }
            SettingsOnDisk::RitaExitSettingsStruct(old_settings_exit) => {
                let new_settings = get_rita_exit();

                if old_settings_exit != new_settings.clone().into() {
                    let res = write_config();
                    if let Err(e) = res {
                        error!("Error saving exit settings! {:?}", e);
                    }
                }

                old_settings = SettingsOnDisk::RitaExitSettingsStruct(Box::new(new_settings));
            }
        }

        // debt keeper, only saved on graceful shutdown
        if !router_storage_small {
            save_debt_to_disk(loop_speed);
        }

        // usage tracker monitors and saves bandwidth usage info and payment metadata
        save_usage_to_disk();
    });
}
/// If the router storage is small/16mb
/// we want to prevent the router from
/// running out of write endurance and
/// the hard drive failing
pub fn is_router_storage_small(router_model: &str) -> bool {
    "linksys_e5600|
    tplink_archer-a6-v3|
    cudy_wr2100|
    mikrotik_hap-ac2|
    mikrotik_routerboard-750gr3|
    mikrotik_routerboard-760igs|
    netgear_ex6100v2"
        .matches(&router_model.to_lowercase())
        .count()
        != 0
}

#[test]
fn test_is_router_storage_small() {
    let router = "linksys_e5600";
    assert!(is_router_storage_small(router));
    let router = "x86_64";
    assert!(!is_router_storage_small(router));
    let router = "test";
    assert!(!is_router_storage_small(router));
}
