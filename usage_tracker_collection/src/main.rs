//! Collects messages from the various traffic watchers to allow the creation of graphs about
//! usage. Within each traffic watcher a simple message containing the amount of bandwidth used
//! in that round and exactly what type of bandwidth it is is sent to this module, from there
//! the handler updates the storage to reflect the new total. When a user would like to inspect
//! or graph usage they query an endpoint which will request the data from this module.

use althea_types::Identity;
use althea_types::WgKey;
use bincode::Error as BincodeError;
use chrono::prelude::DateTime;
use chrono::Datelike;
use chrono::Utc;
use clarity::Address;
use flate2::read::ZlibDecoder;
use num256::Uint256;
use rand::Rng;
use rita_common::RitaCommonError;
use serde::{Deserialize, Serialize};
use serde_json::Error as JsonError;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;
use std::time::UNIX_EPOCH;
use std::usize;

extern crate chrono;
extern crate rand;
extern crate walkdir;

#[macro_use]
extern crate log;

/// In an effort to converge this module between the three possible bw tracking
/// use cases this enum is used to identify which sort of usage we are tracking
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum UsageType {
    Client,
    Relay,
    Exit,
}

/// A struct for tracking each hour of usage, indexed by time in hours since
/// the unix epoch
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub struct UsageHour {
    index: u64,
    up: u64,
    down: u64,
    price: u32,
}

/// A version of payment tx with a string txid so that the formatting is correct
/// for display to users.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct FormattedPaymentTx {
    pub to: Identity,
    pub from: Identity,
    pub amount: Uint256,
    // should always be populated in this case
    pub txid: String,
    // TODO add "payment_type" here which will allow the frontend
    // to easily tell what this payment is for and prevent the need
    // for hacky classification
}

/// A struct for tracking each hours of payments indexed in hours since unix epoch
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PaymentHour {
    index: u64,
    payments: Vec<FormattedPaymentTx>,
}

/// The main actor that holds the usage state for the duration of operations
/// at some point loading and saving will be defined in service started

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct UsageTracker {
    last_save_hour: u64,
    // at least one of these will be left unused
    client_bandwidth: VecDeque<UsageHour>,
    relay_bandwidth: VecDeque<UsageHour>,
    exit_bandwidth: VecDeque<UsageHour>,
    /// A history of payments
    payments: VecDeque<PaymentHour>,
}

impl UsageTracker {
    /// Loads the UsageTracker struct from the disk using the rita_common.network.usage_tracker_file
    /// path from the configuration. If the file is not found or fails to be deserialized a default UsageTracker
    /// struct will be returned so data can be successfully collected from the present moment forward.
    ///
    /// TODO remove in beta 21 migration code migrates json serialized data to bincode
    fn load_from_disk(file_path: String) -> UsageTracker {
        // if the loading process goes wrong for any reason, we just start again
        let blank_usage_tracker = UsageTracker {
            last_save_hour: 0,
            client_bandwidth: VecDeque::new(),
            relay_bandwidth: VecDeque::new(),
            exit_bandwidth: VecDeque::new(),
            payments: VecDeque::new(),
        };

        let file_exists = Path::new(&file_path).exists();
        let file = File::open(&file_path);
        let fileopen = match file {
            Ok(file) => file,
            Err(e) => {
                error!("Failed to open usage tracker file! {:?}", e);
                return blank_usage_tracker;
            }
        };

        let unzipped_bytes = match decompressed(fileopen) {
            Ok(bytes) => bytes,
            Err(_e) => return blank_usage_tracker,
        };

        match (
            file_exists,
            try_bincode(&unzipped_bytes),
            try_json(&unzipped_bytes),
        ) {
            // file exists and bincode deserialization was successful, in the case that somehow json deserialization of the same
            // data was also successful just ignore it and use bincode
            (true, Ok(bincode_tracker), _) => bincode_tracker,
            //file exists, but bincode deserialization failed -> load using serde (old), update settings and save file
            (true, Err(_e), Ok(json_tracker)) => json_tracker,

            // file does not exist; no data to load, this is probably a new router
            // and we'll just generate a new file
            (false, _, _) => blank_usage_tracker,
            // the file exists but both encodings are invalid, we should log the error
            // and return a new file so that the module can continue operating after discard
            // the irrecoverable data.
            (true, Err(e1), Err(e2)) => {
                error!(
                    "Failed to deserialize UsageTracker at location {}  {:?} {:?}",
                    file_path, e1, e2
                );
                blank_usage_tracker
            }
        }
    }
}

/// takes a file handle, reads the file, and decompresses the data using zlibdecoder
/// returning the decompressed data
fn decompressed(mut file: File) -> Result<Vec<u8>, RitaCommonError> {
    let mut byte_contents = Vec::new();
    match file.read_to_end(&mut byte_contents) {
        Ok(_) => {
            let mut decoder = ZlibDecoder::new(&byte_contents[..]);
            let mut bytes = Vec::<u8>::new();
            decoder.read_to_end(&mut bytes)?;

            Ok(bytes)
        }
        Err(e) => {
            error!("Failed to read usage tracker file! {:?}", e);
            Err(RitaCommonError::StdError(e))
        }
    }
}

/// Attempts to deserialize the provided array of bytes as a bincode encoded UsageTracker struct
fn try_bincode(bytes: &[u8]) -> Result<UsageTracker, BincodeError> {
    let deserialized: Result<UsageTracker, _> = bincode::deserialize(bytes);
    deserialized
}

/// Attempts to deserialize the provided array of bytes as a json encoded UsageTracker struct
fn try_json(bytes: &[u8]) -> Result<UsageTracker, JsonError> {
    let deserialized: Result<UsageTracker, _> = serde_json::from_slice(bytes);
    deserialized
}

/// The message used to update the current usage hour from each traffic
/// watcher module
#[derive(Clone, Copy, Debug)]
pub struct UpdateUsage {
    pub kind: UsageType,
    pub up: u64,
    pub down: u64,
    pub price: u32,
}
fn wei_per_byte_to_dollars_per_gb(input: u128) -> u128 {
    let wei_per_eth: u128 = 10_u128.pow(18);
    input / wei_per_eth
}
fn find_majority(payments: Vec<FormattedPaymentTx>) -> Identity {
    let mut last_checked = None;
    for tx in payments {
        if let Some(last) = last_checked {
            if last != tx.to && last != tx.from {
                last_checked = Some(tx.from);
            }
        } else {
            last_checked = Some(tx.from);
        }
    }
    last_checked.unwrap()
}
fn usage_bandwidth(
    mut device_bandwidth: VecDeque<UsageHour>,
) -> VecDeque<(DateTime<Utc>, u64, u128, u32)> {
    let mut month_amount_map: VecDeque<(DateTime<Utc>, u64, u128, u32)> = VecDeque::new();
    while !device_bandwidth.is_empty() {
        match device_bandwidth.pop_front() {
            Some(value) => {
                let d = UNIX_EPOCH + Duration::from_secs(value.index * 60 * 60);
                let datetime = DateTime::<Utc>::from(d);

                let bandwidth_per_byte: u64 = value.up + value.down;
                let bandwidth_convert: u128 = bandwidth_per_byte.into();
                let price_convert: u128 = value.price.into();
                let convert: u128 = bandwidth_convert * price_convert;

                match month_amount_map.front() {
                    Some((front_time, front_bandwidth, front_amount, _price)) => {
                        if front_time.month() != datetime.month() {
                            month_amount_map.push_front((
                                datetime,
                                bandwidth_per_byte,
                                convert,
                                value.price,
                            ));
                        } else {
                            let new_front_amount = front_amount + convert;
                            let new_front_bandwidth = front_bandwidth + bandwidth_per_byte;
                            month_amount_map.pop_front();
                            month_amount_map.push_front((
                                datetime,
                                new_front_bandwidth,
                                new_front_amount,
                                value.price,
                            ))
                        }
                    }
                    None => month_amount_map.push_front((
                        datetime,
                        bandwidth_per_byte,
                        convert,
                        value.price,
                    )),
                }
            }
            None => break,
        }
    }
    month_amount_map
}

fn main() {
    let months = vec![
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let path = format!("enfield_network_data.txt");
    let mut output = std::fs::File::create(path).expect("Unable to open file");

    // Lists all file paths in the directory so we can push the file paths and open each file to parse data
    let mut all_devices = Vec::new();
    for file in fs::read_dir("enfield-usage-trackers/").unwrap() {
        all_devices.push(UsageTracker::load_from_disk(
            file.unwrap().path().display().to_string(),
        ));
    }
    // Iterating over all file paths
    for (device_num, device) in all_devices.iter_mut().enumerate() {
        // device name
        match device.payments.pop_front() {
            Some(value) => {
                let identity = find_majority(value.payments);
                let line = format!("Identity Name {:?},", identity.mesh_ip);
                output.write_all(line.as_bytes());
                let line = format!("Device number {:?},", device_num);
                output.write_all(line.as_bytes());
            }
            None => {
                let line = format!("Device Name{:?}\n", device_num);
                output.write_all(line.as_bytes());
            }
        }
        // gathers all data usage
        let client_list = usage_bandwidth(device.client_bandwidth.clone());
        let relayer_list = usage_bandwidth(device.relay_bandwidth.clone());

        let client_line = "\nClient\n".to_string();
        output.write_all(client_line.as_bytes());

        let mut client_bw = Vec::new();
        for (datetime, bandwidth, amount, price) in client_list {
            client_bw.push(bandwidth);
            let month_num = datetime.month() - 1;
            let converted_price: f64 = price.into();
            let line = format!(
                "{:?} {:?},Bandwidth {:?}GB,Total amount ${:?},Price per GB ${:?}\n",
                months[month_num as usize],
                datetime.year(),
                (bandwidth / (10_u64.pow(9))),
                wei_per_byte_to_dollars_per_gb(amount),
                (converted_price / 10_f64.powf(9.0)),
            );
            output.write_all(line.as_bytes());
        }

        let relayer_line = "\nRelayer\n".to_string();
        output.write_all(relayer_line.as_bytes());

        let mut iter = 0;
        for (datetime, bandwidth, amount, price) in relayer_list {
            let bandwidth = if let Some(cb) = client_bw.get(iter) {
                if bandwidth > *cb {
                    bandwidth - cb
                } else {
                    bandwidth
                }
            } else {
                bandwidth
            };
            iter += 1;
            let month_num = datetime.month() - 1;
            let converted_price: f64 = price.into();
            let line = format!(
                "{:?} {:?},Bandwidth {:?}GB,Total amount ${:?},Price per GB ${:?}\n",
                months[month_num as usize],
                datetime.year(),
                (bandwidth / (10_u64.pow(9))),
                wei_per_byte_to_dollars_per_gb(amount),
                (converted_price / 10_f64.powf(9.0)),
            );
            output.write_all(line.as_bytes());
        }

        let relayer_line = "\n".to_string();
        output.write_all(relayer_line.as_bytes());
    }
}
