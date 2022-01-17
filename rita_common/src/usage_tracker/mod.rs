//! Collects messages from the various traffic watchers to allow the creation of graphs about
//! usage. Within each traffic watcher a simple message containing the amount of bandwidth used
//! in that round and exactly what type of bandwidth it is is sent to this module, from there
//! the handler updates the storage to reflect the new total. When a user would like to inspect
//! or graph usage they query an endpoint which will request the data from this module.

use actix::Message;
use althea_types::Identity;
use althea_types::PaymentTx;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use num256::Uint256;
use serde::{Deserialize, Serialize};
use serde_json::Error as SerdeError;
use std::collections::VecDeque;
use std::fs::File;
use std::io::Error as IOError;
use std::io::Read;
use std::io::Write;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

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
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentHour {
    index: u64,
    payments: Vec<FormattedPaymentTx>,
}

/// The main actor that holds the usage state for the duration of operations
/// at some point loading and saving will be defined in service started
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    fn save(&mut self) -> Result<(), IOError> {
        let serialized = serde_json::to_vec(self)?;
        let mut file = File::create(settings::get_rita_common().network.usage_tracker_file)?;
        let buffer: Vec<u8> = Vec::new();
        let mut encoder = ZlibEncoder::new(buffer, Compression::default());
        encoder.write_all(&serialized)?;
        let compressed_bytes = encoder.finish()?;
        file.write_all(&compressed_bytes)
    }

    fn load_from_disk() -> UsageTracker {
        let file = File::open(settings::get_rita_common().network.usage_tracker_file);
        // if the loading process goes wrong for any reason, we just start again
        let blank_usage_tracker = UsageTracker {
            last_save_hour: 0,
            client_bandwidth: VecDeque::new(),
            relay_bandwidth: VecDeque::new(),
            exit_bandwidth: VecDeque::new(),
            payments: VecDeque::new(),
        };

        match file {
            Ok(mut file) => {
                let mut byte_contents = Vec::new();
                // try compressed
                match file.read_to_end(&mut byte_contents) {
                    Ok(_bytes_read) => {
                        let decoder = ZlibDecoder::new(&byte_contents[..]);
                        // Extract data from decoder, note this is streaming decoding, so we're
                        // decompressing the data as we take it out of the zlib compressed object
                        trace!("attempting to unzip or read bw history");
                        let deserialized: Result<UsageTracker, SerdeError> =
                            serde_json::from_reader(decoder);

                        match deserialized {
                            Ok(value) => value,
                            Err(e) => {
                                error!(
                                    "Failed to deserialize bytes in compressed bw history {:?}",
                                    e
                                );
                                blank_usage_tracker
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to read usage tracker file! {:?}", e);
                        blank_usage_tracker
                    }
                }
            }
            Err(e) => {
                error!("Failed to open usage tracker file! {:?}", e);
                blank_usage_tracker
            }
        }
    }
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

impl Message for UpdateUsage {
    type Result = Result<(), RitaCommonError>;
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
    let res = history.save();
    info!("Shutdown: saving usage data: {:?}", res);
}
