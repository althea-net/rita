use crate::{debt_keeper::save_debt_to_disk, usage_tracker::save_usage_to_disk};
use std::{
    thread,
    time::{Duration, Instant},
};

use settings::{
    check_if_exit, client::RitaClientSettings, exit::RitaExitSettingsStruct, get_rita_client,
    get_rita_exit, save_client_settings, save_exit_settings,
};
/// How often we save the nodes debt data, currently 48 minutes
const SAVE_FREQUENCY_EXIT: Duration = Duration::from_secs(172800);
/// How often we save the nodes debt data, currently 5 minutes
const SAVE_FREQUENCY_ROUTER: Duration = Duration::from_secs(300);

pub const FAST_LOOP_TIMEOUT: Duration = Duration::from_secs(4);
// Save duration for all writes to disk in order to reduce write operations
// pub const SAVING_TO_DISK_FREQUENCY: Duration = Duration::from_secs(600);
#[derive(Clone)]
pub enum SettingsOnDisk {
    RitaClientSettings(RitaClientSettings),
    RitaExitSettingsStruct(RitaExitSettingsStruct),
}
/// This loop attempts to perform all write operations for writing to disk
/// This includes writing config/settings, usage tracker, and debt tracker.
/// It takes in a settings enum in order to identify what type the device
/// is. There is also a consideration for the amount of storage the device
/// has on disk since we don't want to save too often if the disk doesn't
/// contain a lot of storage.
pub fn save_to_disk_loop(mut old_settings: SettingsOnDisk, file_path: &str) {
    let file_path = file_path.to_string();
    let router_storage_small;
    let saving_to_disk_frequency: Duration;

    let save_frequency = if check_if_exit() {
        SAVE_FREQUENCY_EXIT
    } else {
        SAVE_FREQUENCY_ROUTER
    };

    match old_settings.clone() {
        SettingsOnDisk::RitaClientSettings(old_settings_client) => {
            match old_settings_client.network.device.clone() {
                Some(val) => router_storage_small = is_router_storage_small(&val),
                None => router_storage_small = false,
            };
            saving_to_disk_frequency = Duration::from_secs(old_settings_client.save_interval);
        }
        SettingsOnDisk::RitaExitSettingsStruct(old_settings_exit) => {
            match old_settings_exit.network.device.clone() {
                Some(val) => router_storage_small = is_router_storage_small(&val),
                None => router_storage_small = false,
            };
            saving_to_disk_frequency = Duration::from_secs(old_settings_exit.save_interval);
        }
    }

    thread::spawn(move || loop {
        let start = Instant::now();

        if start.elapsed() < saving_to_disk_frequency {
            thread::sleep(saving_to_disk_frequency - start.elapsed());
        }

        //settings
        match old_settings.clone() {
            SettingsOnDisk::RitaClientSettings(old_settings_client) => {
                let new_settings = get_rita_client();

                if old_settings_client != new_settings {
                    save_client_settings(old_settings_client, file_path.clone());
                }

                old_settings = SettingsOnDisk::RitaClientSettings(new_settings);
            }
            SettingsOnDisk::RitaExitSettingsStruct(old_settings_exit) => {
                let new_settings = get_rita_exit();

                if old_settings_exit != new_settings {
                    save_exit_settings(new_settings.clone(), file_path.clone());
                }

                old_settings = SettingsOnDisk::RitaExitSettingsStruct(new_settings);
            }
        }

        // debt keeper
        if !router_storage_small {
            save_debt_to_disk(save_frequency);
        }

        let minimum_number_transactions: usize = 75;
        //usage tracker is invoked via trafficwatch/watch() and the block runner
        save_usage_to_disk(minimum_number_transactions);
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
        .into_iter()
        .count()
        != 0
}

#[test]
fn test_is_router_storage_small() {
    let router = "linksys_e5600";
    assert!(is_router_storage_small(router));
}
