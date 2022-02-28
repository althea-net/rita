//! Collects messages from the various traffic watchers to allow the creation of graphs about
//! usage. Within each traffic watcher a simple message containing the amount of bandwidth used
//! in that round and exactly what type of bandwidth it is is sent to this module, from there
//! the handler updates the storage to reflect the new total. When a user would like to inspect
//! or graph usage they query an endpoint which will request the data from this module.

use althea_types::Identity;
use althea_types::PaymentTx;
use bincode::Error as BincodeError;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use num256::Uint256;
use serde::{Deserialize, Serialize};
use serde_json::Error as JsonError;
use settings::set_rita_common;
use std::collections::VecDeque;
use std::fs::File;
use std::io::Error as IOError;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use std::usize;

use crate::RitaCommonError;

/// one year worth of usage storage
const MAX_USAGE_ENTRIES: usize = 8_760;
/// The number of tx's we store in our history to show
/// prices, this data is larger than usage by a large margin
/// so we can store less, it's also less predictable for what values
/// map to how much time in history, 2000 is hopefully enough
const MAX_TX_ENTRIES: usize = 2_000;
/// Save every 4 hours
const SAVE_FREQENCY: u64 = 4;

lazy_static! {
    static ref USAGE_TRACKER: Arc<RwLock<UsageTracker>> =
        Arc::new(RwLock::new(UsageTracker::load_from_disk()));
}

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

fn to_formatted_payment_tx(input: PaymentTx) -> FormattedPaymentTx {
    match input.txid {
        Some(txid) => FormattedPaymentTx {
            to: input.to,
            from: input.from,
            amount: input.amount,
            txid: format!("{:#066x}", txid),
        },
        None => FormattedPaymentTx {
            to: input.to,
            from: input.from,
            amount: input.amount,
            txid: String::new(),
        },
    }
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
    fn save(&mut self) -> Result<(), RitaCommonError> {
        let serialized = bincode::serialize(self)?;
        let mut file = File::create(settings::get_rita_common().network.usage_tracker_file)?;

        let mut compressed_bytes = match compress_serialized(serialized) {
            Ok(bytes) => bytes,
            Err(e) => return Err(RitaCommonError::StdError(e)),
        };

        let mut newsize = MAX_TX_ENTRIES;
        loop {
            match file.write_all(&compressed_bytes) {
                Ok(save) => {
                    return Ok(save);
                }
                Err(e) => {
                    // 500 tx min. Payment data is trimmed if out of space as it is larger than usage data
                    if newsize >= 1000 {
                        newsize /= 2;
                        trim_payments(newsize, &mut self.payments);
                        let serialized = bincode::serialize(self)?;
                        compressed_bytes = match compress_serialized(serialized) {
                            Ok(bytes) => bytes,
                            Err(e) => return Err(RitaCommonError::StdError(e)),
                        };
                    } else {
                        return Err(RitaCommonError::StdError(e));
                    }
                    continue;
                }
            }
        }
    }

    /// Loads the UsageTracker struct from the disk using the rita_common.network.usage_tracker_file
    /// path from the configuration. If the file is not found or fails to be deserialized a default UsageTracker
    /// struct will be returned so data can be successfully collected from the present moment forward.
    ///
    /// TODO remove in beta 20 migration code migrates json serialized data to bincode
    fn load_from_disk() -> UsageTracker {
        // if the loading process goes wrong for any reason, we just start again
        let blank_usage_tracker = UsageTracker {
            last_save_hour: 0,
            client_bandwidth: VecDeque::new(),
            relay_bandwidth: VecDeque::new(),
            exit_bandwidth: VecDeque::new(),
            payments: VecDeque::new(),
        };

        let file_path = settings::get_rita_common().network.usage_tracker_file;

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
            //file exists, but bincode deserialization failed -> load using serde (old), update update settings and save file
            (true, Err(_e), Ok(mut json_tracker)) => {
                let mut settings = settings::get_rita_common();
                // save with bincode regardless of result of serde deserialization in order to end reliance on serde
                let old_path = PathBuf::from(settings.network.usage_tracker_file);

                let mut new_path = old_path.clone();
                new_path.set_extension("bincode");

                settings.network.usage_tracker_file =
                    new_path.clone().into_os_string().into_string().unwrap();
                set_rita_common(settings);

                match json_tracker.save() {
                    Ok(()) => {
                        // delete the old file after successfully migrating, this may cause problems on routers with
                        // low available storage space since we want to take up space for both the new and old file
                        if !(old_path.eq(&new_path)) {
                            // check that we would not be deleting the file just saved to
                            let _r = std::fs::remove_file(old_path);
                        } else {
                            error!(
                                "We are trying to save over {:?} with {:?}, how are they same?",
                                old_path, new_path
                            )
                        }
                        json_tracker
                    }
                    Err(e) => {
                        error!("Failed to save UsageTracker to bincode {:?}", e);
                        json_tracker
                    }
                }
            }
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
        Ok(_bytes_read) => {
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

/// Compresses serialized data
fn compress_serialized(serialized: Vec<u8>) -> Result<Vec<u8>, IOError> {
    let buffer: Vec<u8> = Vec::new();
    let mut encoder = ZlibEncoder::new(buffer, Compression::default());
    encoder.write_all(&serialized)?;
    let compressed_bytes = encoder.finish()?;
    Ok(compressed_bytes)
}

/// Gets the current hour since the unix epoch
fn get_current_hour() -> Result<u64, RitaCommonError> {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(seconds.as_secs() / (60 * 60))
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

pub fn update_usage_data(msg: UpdateUsage) {
    let curr_hour = match get_current_hour() {
        Ok(hour) => hour,
        Err(e) => {
            error!("System time is set earlier than unix epoch {:?}", e);
            return;
        }
    };

    process_usage_update(curr_hour, msg, &mut *(USAGE_TRACKER.write().unwrap()));
}

fn process_usage_update(current_hour: u64, msg: UpdateUsage, data: &mut UsageTracker) {
    // history contains a reference to whatever the correct storage array is
    let history = match msg.kind {
        UsageType::Client => &mut data.client_bandwidth,
        UsageType::Relay => &mut data.relay_bandwidth,
        UsageType::Exit => &mut data.exit_bandwidth,
    };
    // we grab the front entry from the VecDeque, if there is an entry one we check if it's
    // up to date, if it is we add to it, if it's not or there is no entry we create one.
    // note that price is only sampled once per hour.
    match history.front_mut() {
        None => history.push_front(UsageHour {
            index: current_hour,
            up: msg.up,
            down: msg.down,
            price: msg.price,
        }),
        Some(entry) => {
            if entry.index == current_hour {
                entry.up += msg.up;
                entry.down += msg.down;
            } else {
                history.push_front(UsageHour {
                    index: current_hour,
                    up: msg.up,
                    down: msg.down,
                    price: msg.price,
                })
            }
        }
    }
    while history.len() > MAX_USAGE_ENTRIES {
        let _discarded_entry = history.pop_back();
    }
    if (current_hour - SAVE_FREQENCY) > data.last_save_hour {
        data.last_save_hour = current_hour;
        let res = data.save();
        info!("Saving usage data: {:?}", res);
    }
}

fn trim_payments(size: usize, history: &mut VecDeque<PaymentHour>) {
    while history.len() > size {
        let _discarded_entry = history.pop_back();
    }
}

pub fn update_payments(payment: PaymentTx) {
    handle_payments(&mut *(USAGE_TRACKER.write().unwrap()), &payment);
}

/// Internal handler function that deals with adding a payment to the list
/// and saving if required
fn handle_payments(history: &mut UsageTracker, payment: &PaymentTx) {
    let current_hour = match get_current_hour() {
        Ok(hour) => hour,
        Err(e) => {
            error!("System time is set earlier than unix epoch! {:?}", e);
            return;
        }
    };
    let formatted_payment = to_formatted_payment_tx(payment.clone());
    match history.payments.front_mut() {
        None => history.payments.push_front(PaymentHour {
            index: current_hour,
            payments: vec![formatted_payment],
        }),
        Some(entry) => {
            if entry.index == current_hour {
                entry.payments.push(formatted_payment);
            } else {
                history.payments.push_front(PaymentHour {
                    index: current_hour,
                    payments: vec![formatted_payment],
                })
            }
        }
    }
    while history.payments.len() > MAX_TX_ENTRIES {
        let _discarded_entry = history.payments.pop_back();
    }
    if (current_hour - SAVE_FREQENCY) > history.last_save_hour {
        history.last_save_hour = current_hour;
        let res = history.save();
        info!("Saving usage data: {:?}", res);
    }
}

/// Gets usage data for this router, stored on the local disk at periodic intervals
pub fn get_usage_data(kind: UsageType) -> VecDeque<UsageHour> {
    let usage_tracker_var = &*(USAGE_TRACKER.write().unwrap());
    match kind {
        UsageType::Client => usage_tracker_var.client_bandwidth.clone(),
        UsageType::Relay => usage_tracker_var.relay_bandwidth.clone(),
        UsageType::Exit => usage_tracker_var.exit_bandwidth.clone(),
    }
}

/// Gets payment data for this router, stored on the local disk at periodic intervals
pub fn get_payments_data() -> VecDeque<PaymentHour> {
    let usage_tracker_var = &*(USAGE_TRACKER.read().unwrap());
    usage_tracker_var.payments.clone()
}

/// On an interupt (SIGTERM), saving USAGE_TRACKER before exiting
pub fn save_usage_on_shutdown() {
    let current_hour = match get_current_hour() {
        Ok(hour) => hour,
        Err(e) => {
            error!("System time is set earlier than unix epoch! {:?}", e);
            return;
        }
    };

    let history = &mut USAGE_TRACKER.write().unwrap();
    history.last_save_hour = current_hour;
    trim_payments(MAX_TX_ENTRIES, &mut history.payments);
    let res = history.save();
    info!("Shutdown: saving usage data: {:?}", res);
}

#[cfg(test)]
mod tests {

    use super::UsageTracker;
    use crate::usage_tracker::{self, IOError};
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use settings::client::RitaClientSettings;
    use settings::{get_rita_common, set_rita_client, set_rita_common};
    use std::collections::VecDeque;
    use std::fs::File;
    use std::io::Write;
    impl UsageTracker {
        // previous implementation of save which uses serde_json to serialize
        fn save2(&mut self) -> Result<(), IOError> {
            let serialized = serde_json::to_vec(self)?;
            let mut file = File::create(settings::get_rita_common().network.usage_tracker_file)?;
            let buffer: Vec<u8> = Vec::new();
            let mut encoder = ZlibEncoder::new(buffer, Compression::default());
            encoder.write_all(&serialized)?;
            let compressed_bytes = encoder.finish()?;
            file.write_all(&compressed_bytes)
        }
    }

    #[test]
    fn save_usage_tracker_bincode() {
        let rset = RitaClientSettings::new("../settings/test.toml").unwrap();
        set_rita_client(rset);
        let mut newrc = get_rita_common();
        newrc.network.usage_tracker_file = "/tmp/usage_tracker.bincode".to_string();
        set_rita_common(newrc);

        let mut dummy_usage_tracker = UsageTracker {
            last_save_hour: 9,
            client_bandwidth: VecDeque::new(),
            relay_bandwidth: VecDeque::new(),
            exit_bandwidth: VecDeque::new(),
            payments: VecDeque::new(),
        };
        let res = dummy_usage_tracker.save(); // saving to bincode with the new method
        info!("Saving test  data: {:?}", res);

        let res2 = usage_tracker::UsageTracker::load_from_disk();
        info!("Loading test  data: {:?}", res2);

        assert_eq!(dummy_usage_tracker, res2);
    }

    #[test]
    fn convert_legacy_usage_tracker() {
        // make a dummy ustage tracker instance
        // save it as gzipped json ( pull code from the git history that you deleted and put it in this test)
        // makes sure the file exists
        // deserialize the file using the upgrade function
        // make sure it's equal to the original dummy we made
        let rset = RitaClientSettings::new("../settings/test.toml").unwrap();
        set_rita_client(rset);
        let mut newrc = get_rita_common();
        newrc.network.usage_tracker_file = "/tmp/usage_tracker.json".to_string();
        set_rita_common(newrc);
        let mut dummy_usage_tracker = UsageTracker {
            last_save_hour: 8,
            client_bandwidth: VecDeque::new(),
            relay_bandwidth: VecDeque::new(),
            exit_bandwidth: VecDeque::new(),
            payments: VecDeque::new(),
        };
        let res = dummy_usage_tracker.save2();
        info!("Saving test data as json: {:?}", res);
        // using load_from_disk() with usage_tracker_file set to a .json writes bincode
        // serialized data to a .json extended file, but because load_from_disk() deletes
        // the .json file, this test ends with no file left.
        let mut res2 = usage_tracker::UsageTracker::load_from_disk();
        info!("Loading test data from json: {:?}", res2);

        // setting the usage_tracker_file to .bincode, which is what this upgrade expects
        let mut newrc2 = get_rita_common();
        newrc2.network.usage_tracker_file = "/tmp/usage_tracker.bincode".to_string();
        set_rita_common(newrc2);

        // Saving res2 with the new save() and updated usage_tracker_file in order to end with
        // a .bincode file from the loaded json data saved to res2.
        let res3 = res2.save();
        info!("Saving test data as bincode: {:?}", res3);
        let res4 = usage_tracker::UsageTracker::load_from_disk();
        info!("Loading test data from bincode: {:?}", res4);

        assert_eq!(dummy_usage_tracker, res2);
        assert_eq!(res2, res4);
    }
}
