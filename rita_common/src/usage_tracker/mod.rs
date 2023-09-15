//! Collects messages from the various traffic watchers to allow the creation of graphs about
//! usage. Within each traffic watcher a simple message containing the amount of bandwidth used
//! in that round and exactly what type of bandwidth it is is sent to this module, from there
//! the handler updates the storage to reflect the new total. When a user would like to inspect
//! or graph usage they query an endpoint which will request the data from this module.

use crate::rita_loop::write_to_disk::is_router_storage_small;
use crate::RitaCommonError;
use althea_types::convert_flat_to_map_usage_data;
use althea_types::convert_map_to_flat_usage_data;
use althea_types::user_info::Usage;
use althea_types::IndexedUsageHour;
use althea_types::PaymentTx;
use bincode::Error as BincodeError;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::fs::File;
use std::io::Error as IOError;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use std::usize;
use structs::*;

pub mod structs;
pub mod tests;

/// one year worth of usage storage
pub const MAX_USAGE_ENTRIES: usize = 8_760;
/// The number of tx's we store in our history to show
/// prices, this data is larger than usage by a large margin
/// so we can store less, it's also less predictable for what values
/// map to how much time in history, 5000 is hopefully enough
const MAX_TX_ENTRIES: usize = 5_000;
// the number of transactions which must have been sent for us to initiate a
// unprompted save, saving may still occur on graceful shutdown, graceful shutdown
// essentially only occurs when prompted for an upgrade, or a reboot command is sent
// the most common form of restart, yanking the power cord, will not be graceful.
pub const MINIMUM_NUMBER_OF_TRANSACTIONS_LARGE_STORAGE: usize = 5;
pub const MINIMUM_NUMBER_OF_TRANSACTIONS_SMALL_STORAGE: usize = 75;

/// The maximum amount of usage data that may be unsaved before we save out to the disk
pub const MAX_UNSAVED_USAGE: u64 = 10 * 1000u64.pow(3);

lazy_static! {
    static ref USAGE_TRACKER_STORAGE: Arc<RwLock<UsageTrackerStorage>> =
        Arc::new(RwLock::new(UsageTrackerStorage::load_from_disk()));
}

/// Utility function that grabs usage tracker from it's lock and
/// saves it out. Should be called when we want to save anywhere outside this file
pub fn save_usage_to_disk() {
    match USAGE_TRACKER_STORAGE.write().unwrap().save() {
        Ok(_val) => info!("Saved usage tracker successfully"),
        Err(e) => warn!("Unable to save usage tracker {:}", e),
    };
}

/// Helps determine how often we write out to the disk on different devices by setting a device specific mininum
/// number of transactions before saving
pub fn get_minimum_number_of_transactions_to_store() -> usize {
    let settings = settings::get_rita_common();
    if is_router_storage_small(
        &settings
            .network
            .device
            .unwrap_or_else(|| "x86_64".to_string()),
    ) {
        MINIMUM_NUMBER_OF_TRANSACTIONS_SMALL_STORAGE
    } else {
        MINIMUM_NUMBER_OF_TRANSACTIONS_LARGE_STORAGE
    }
}

impl UsageTrackerStorage {
    /// This function checks to see how many bytes were used
    /// and if the amount used is not greater than 10gb than
    /// it will return false. Essentially, it's checking to make
    /// sure that there is enough usage to be worth saving
    pub fn check_unsaved_usage(&self) -> bool {
        let mut total_unsaved_bytes = 0;
        let v = vec![
            &self.client_bandwidth,
            &self.relay_bandwidth,
            &self.exit_bandwidth,
        ];
        for i in v {
            for (index, usage) in i {
                if *index > self.last_save_hour {
                    total_unsaved_bytes += usage.up;
                    total_unsaved_bytes += usage.down;
                }
            }
        }
        total_unsaved_bytes > MAX_UNSAVED_USAGE
    }

    /// Returns true if the numberof unsaved payments is greater than the mininum number of transactions to store
    pub fn check_unsaved_payments(&self) -> bool {
        let mut total_num_unsaved_payments = 0;
        for p in self.payments.iter() {
            if p.index > self.last_save_hour {
                total_num_unsaved_payments += 1;
            }
        }
        total_num_unsaved_payments > get_minimum_number_of_transactions_to_store()
    }

    pub fn save(&mut self) -> Result<(), RitaCommonError> {
        let settings = settings::get_rita_common();

        if self.check_unsaved_payments() || self.check_unsaved_usage() {
            return Err(RitaCommonError::StdError(IOError::new(
                ErrorKind::Other,
                "Too little data for writing",
            )));
        }

        let serialized = bincode::serialize(self)?;
        let mut file = File::create(settings.network.usage_tracker_file)?;

        let mut compressed_bytes = match compress_serialized(serialized) {
            Ok(bytes) => bytes,
            Err(e) => return Err(RitaCommonError::StdError(e)),
        };

        let mut newsize = MAX_TX_ENTRIES;
        // this loop handles if we run out of disk space while trying to save the usage tracker
        // data, if this occurs we trim the data we store until it fits
        loop {
            match file.write_all(&compressed_bytes) {
                Ok(save) => {
                    info!(
                        "Saved to disk for usage tracker {:}",
                        compressed_bytes.len()
                    );
                    return Ok(save);
                }
                Err(e) => {
                    warn!("Failed to save usage tracker data with {:?}", e);
                    // 500 tx min. Payment data is trimmed if out of space as it is larger than usage data
                    if newsize >= 1000 {
                        newsize /= 2;
                        while self.payments.len() > newsize {
                            self.remove_oldest_payment_history_entry()
                        }
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
    /// TODO remove in beta 21 migration code migrates json serialized data to bincode
    fn load_from_disk() -> UsageTrackerStorage {
        // if the loading process goes wrong for any reason, we just start again
        let blank_usage_tracker = UsageTrackerStorage {
            client_bandwidth: HashMap::new(),
            relay_bandwidth: HashMap::new(),
            exit_bandwidth: HashMap::new(),
            payments: HashSet::new(),
            last_save_hour: 0,
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
            try_bincode_new(&unzipped_bytes),
            try_bincode_old(&unzipped_bytes),
        ) {
            // file exists and bincode deserialization was successful, ignore all other possibilities
            (true, Ok(bincode_tracker), _) => bincode_tracker,
            // file exists, up to date encoding failed, beta 20 encoding succeeded
            (true, Err(_), Ok(bincode_tracker)) => UsageTrackerStorage {
                last_save_hour: bincode_tracker.last_save_hour,
                client_bandwidth: convert_flat_to_map_usage_data(bincode_tracker.client_bandwidth),
                relay_bandwidth: convert_flat_to_map_usage_data(bincode_tracker.relay_bandwidth),
                exit_bandwidth: convert_flat_to_map_usage_data(bincode_tracker.exit_bandwidth),
                payments: {
                    let mut out = HashSet::new();
                    for ph in bincode_tracker.payments {
                        for p in ph.payments {
                            match p.txid.parse() {
                                Ok(txid) => {
                                    out.insert(UsageTrackerPayment {
                                        to: p.to,
                                        from: p.from,
                                        amount: p.amount,
                                        txid,
                                        index: ph.index,
                                    });
                                }
                                Err(e) => error!(
                                    "Failed to convert payment with txid {:?} discarding!",
                                    e
                                ),
                            }
                        }
                    }
                    out
                },
            },
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
fn try_bincode_new(bytes: &[u8]) -> Result<UsageTrackerStorage, BincodeError> {
    let deserialized: Result<UsageTrackerStorage, _> = bincode::deserialize(bytes);
    deserialized
}

/// Attempts to deserialize the provided array of bytes as a bincode encoded UsageTracker struct
fn try_bincode_old(bytes: &[u8]) -> Result<UsageTrackerStorageOld, BincodeError> {
    let deserialized: Result<UsageTrackerStorageOld, _> = bincode::deserialize(bytes);
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
pub fn get_current_hour() -> Result<u64, RitaCommonError> {
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

    let mut usage_tracker = USAGE_TRACKER_STORAGE.write().unwrap();

    usage_tracker.process_usage_update(curr_hour, msg);
}

impl UsageTrackerStorage {
    fn process_usage_update(&mut self, current_hour: u64, msg: UpdateUsage) {
        // history contains a reference to whatever the correct storage array is
        let history = match msg.kind {
            UsageType::Client => &mut self.client_bandwidth,
            UsageType::Relay => &mut self.relay_bandwidth,
            UsageType::Exit => &mut self.exit_bandwidth,
        };
        // we grab the front entry from the VecDeque, if there is an entry one we check if it's
        // up to date, if it is we add to it, if it's not or there is no entry we create one.
        // note that price is only sampled once per hour.
        match history.get_mut(&current_hour) {
            None => {
                history.insert(
                    current_hour,
                    Usage {
                        up: msg.up,
                        down: msg.down,
                        price: msg.price,
                    },
                );
            }
            Some(entry) => {
                entry.up += msg.up;
                entry.down += msg.down;
            }
        }
        while history.len() > MAX_USAGE_ENTRIES {
            let smallest_key = history.keys().min_by(|a, b| a.cmp(b)).cloned();
            if let Some(smallest_key) = smallest_key {
                history.remove(&smallest_key);
            }
        }
    }
}

pub fn update_payments(payment: PaymentTx) {
    let history = &mut (USAGE_TRACKER_STORAGE.write().unwrap());

    // This handles the following edge case:
    // Router A is paying router B. Router B reboots and loses all data in
    // payment vaildator datastore. When A sends a make_payment_v2, payments that have
    // already been accounted for get counted twice.
    // This checks the usage history to see if this tx exists
    // thereby preventing the above case.
    if history.get_txids().contains(&payment.txid) {
        error!("Tried to insert duplicate txid into usage tracker!");
        return;
    }

    history.handle_payments(&payment);
}

impl UsageTrackerStorage {
    /// Internal handler function that deals with adding a payment to the list
    /// and saving if required
    fn handle_payments(&mut self, payment: &PaymentTx) {
        let current_hour = match get_current_hour() {
            Ok(hour) => hour,
            Err(e) => {
                error!("System time is set earlier than unix epoch! {:?}", e);
                return;
            }
        };
        let formatted_payment = UsageTrackerPayment::from_payment_tx(*payment, current_hour);
        self.payments.insert(formatted_payment);

        while self.payments.len() > MAX_TX_ENTRIES {
            self.remove_oldest_payment_history_entry()
        }
    }

    /// Removes a single tx from the payment history entry, oldest first
    fn remove_oldest_payment_history_entry(&mut self) {
        let oldest = self
            .payments
            .iter()
            .min_by(|a, b| a.index.cmp(&b.index))
            .cloned();
        if let Some(oldest) = oldest {
            self.payments.remove(&oldest);
        }
    }
}

/// Gets usage data for this router, stored on the local disk at periodic intervals
pub fn get_usage_data_map(kind: UsageType) -> HashMap<u64, Usage> {
    let usage_tracker_var = &*(USAGE_TRACKER_STORAGE.write().unwrap());

    match kind {
        UsageType::Client => usage_tracker_var.client_bandwidth.clone(),
        UsageType::Relay => usage_tracker_var.relay_bandwidth.clone(),
        UsageType::Exit => usage_tracker_var.exit_bandwidth.clone(),
    }
}

/// Gets usage data for this router, stored on the local disk at periodic intervals
pub fn get_usage_data(kind: UsageType) -> VecDeque<IndexedUsageHour> {
    let usage_tracker_var = &*(USAGE_TRACKER_STORAGE.write().unwrap());
    let data = match kind {
        UsageType::Client => usage_tracker_var.client_bandwidth.clone(),
        UsageType::Relay => usage_tracker_var.relay_bandwidth.clone(),
        UsageType::Exit => usage_tracker_var.exit_bandwidth.clone(),
    };
    convert_map_to_flat_usage_data(data)
}

/// Gets the last saved usage hour from the existing usage tracker
pub fn get_last_saved_usage_hour() -> u64 {
    let usage_tracker = &*(USAGE_TRACKER_STORAGE.read().unwrap());
    usage_tracker.last_save_hour
}

/// Gets payment data for this router, stored on the local disk at periodic intervals
pub fn get_payments_data() -> VecDeque<PaymentHour> {
    let usage_tracker_var = &*(USAGE_TRACKER_STORAGE.read().unwrap());
    convert_payment_set_to_payment_hour(usage_tracker_var.payments.clone())
}

/// On an interupt (SIGTERM), saving USAGE_TRACKER before exiting, this is essentially
/// a reboot or restart only, most common form of shutdown is power being pulled
pub fn save_usage_on_shutdown() {
    save_usage_to_disk()
}
