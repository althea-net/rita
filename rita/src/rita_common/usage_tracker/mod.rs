//! Collects messages from the various traffic watchers to allow the creation of graphs about
//! usage. Within each traffic watcher a simple message containing the amount of bandwidth used
//! in that round and exactly what type of bandwidth it is is sent to this module, from there
//! the handler updates the storage to reflect the new total. When a user would like to inspect
//! or graph usage they query an endpoint which will request the data from this module.

use crate::SETTING;
use actix::Actor;
use actix::Context;
use actix::Handler;
use actix::Message;
use actix::Supervised;
use actix::SystemService;
use althea_types::Identity;
use althea_types::PaymentTx;
use failure::Error;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use num256::Uint256;
use serde::{Deserialize, Serialize};
use serde_json::Error as SerdeError;
use settings::RitaCommonSettings;
use std::collections::VecDeque;
use std::fs::File;
use std::io;
use std::io::Error as IOError;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

/// On year worth of usage storage
const MAX_ENTRIES: usize = 8760;
/// Save every 4 hours
const SAVE_FREQENCY: u64 = 4;

lazy_static! {
/// This is used to allow non-actix workers to add payments to the queue. An alternative to this would be
/// to move all storage for this actor into this locked ref format and this should be done in Beta 16 or
/// later, for now (Beta 15) we want to reduce the amount of changes. So instead these values will be
/// read off any time this actor is triggered by another payment message
    static ref PAYMENT_UPDATE_QUEUE: Arc<RwLock<Vec<PaymentTx>>> = Arc::new(RwLock::new(Vec::new()));
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

/// A legacy struct required to parse the old member names
/// and convert into the new version
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsageTrackerMisspelled {
    last_save_hour: u64,
    // at least one of these will be left unused
    client_bandwith: VecDeque<UsageHour>,
    relay_bandwith: VecDeque<UsageHour>,
    exit_bandwith: VecDeque<UsageHour>,
    /// A history of payments
    payments: VecDeque<PaymentHour>,
}

impl UsageTrackerMisspelled {
    pub fn upgrade(self) -> UsageTracker {
        UsageTracker {
            last_save_hour: self.last_save_hour,
            client_bandwidth: self.client_bandwith,
            relay_bandwidth: self.relay_bandwith,
            exit_bandwidth: self.exit_bandwith,
            payments: self.payments,
        }
    }
}

impl Default for UsageTracker {
    fn default() -> UsageTracker {
        let file = File::open(SETTING.get_network().usage_tracker_file.clone());
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
                        let mut decoder = ZlibDecoder::new(&byte_contents[..]);
                        let mut contents = Vec::new();
                        let mut contents_str = String::new();
                        // Extract data from decoder
                        trace!("attempting to unzip or read bw history");
                        match io::copy(&mut decoder, &mut contents) {
                            Ok(_bytes) => {
                                trace!("found a compressed json stream");
                                let deserialized: Result<UsageTracker, SerdeError> =
                                    serde_json::from_slice(&contents);

                                let legacy_deserialized: Result<
                                    UsageTrackerMisspelled,
                                    SerdeError,
                                > = serde_json::from_slice(&contents);

                                match (deserialized, legacy_deserialized) {
                                    (Ok(value), _) => value,
                                    (Err(_e), Ok(value)) => value.upgrade(),
                                    (Err(e), Err(_e)) => {
                                        error!("Failed to deserialize bytes in compressed bw history {:?}", e);
                                        blank_usage_tracker
                                    }
                                }
                            }
                            Err(e) => {
                                // no active devices are using the flatfile, this should be safe to remove
                                info!("Failed to decompress with, trying flatfile {:?}", e);
                                file.seek(SeekFrom::Start(0))
                                    .expect("Failed to return to start of file!");
                                match file.read_to_string(&mut contents_str) {
                                    Ok(_bytes_read) => {
                                        trace!("failed to inflate, trying raw string");
                                        let deserialized: Result<UsageTracker, SerdeError> =
                                            serde_json::from_str(&contents_str);

                                        let legacy_deserialized: Result<
                                            UsageTrackerMisspelled,
                                            SerdeError,
                                        > = serde_json::from_slice(&contents);

                                        match (deserialized, legacy_deserialized) {
                                            (Ok(value), _) => value,
                                            (Err(_e), Ok(value)) => value.upgrade(),
                                            (Err(e), Err(_e)) => {
                                                error!("Failed to deserialize bytes in compressed bw history {:?}", e);
                                                blank_usage_tracker
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!(
                                            "Failed to read usage tracker file to string! {:?}",
                                            e
                                        );
                                        blank_usage_tracker
                                    }
                                }
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

impl UsageTracker {
    fn save(&mut self) -> Result<(), IOError> {
        let serialized = serde_json::to_vec(self)?;
        let mut file = File::create(SETTING.get_network().usage_tracker_file.clone())?;
        let buffer: Vec<u8> = Vec::new();
        let mut encoder = ZlibEncoder::new(buffer, Compression::fast());
        encoder.write_all(&serialized)?;
        let compressed_bytes = encoder.finish()?;
        file.write_all(&compressed_bytes)
    }
}

impl Actor for UsageTracker {
    type Context = Context<Self>;
}

impl Supervised for UsageTracker {}
impl SystemService for UsageTracker {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("UsageTracker started");
    }
}

/// Gets the current hour since the unix epoch
fn get_current_hour() -> Result<u64, Error> {
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
    type Result = Result<(), Error>;
}

impl Handler<UpdateUsage> for UsageTracker {
    type Result = Result<(), Error>;
    fn handle(&mut self, msg: UpdateUsage, _: &mut Context<Self>) -> Self::Result {
        let current_hour = match get_current_hour() {
            Ok(hour) => hour,
            Err(e) => {
                error!("System time is set earlier than unix epoch! {:?}", e);
                return Ok(());
            }
        };
        process_usage_update(current_hour, msg, self);

        Ok(())
    }
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
    while history.len() > MAX_ENTRIES {
        let _discarded_entry = history.pop_back();
    }
    if (current_hour - SAVE_FREQENCY) > data.last_save_hour {
        data.last_save_hour = current_hour;
        let res = data.save();
        info!("Saving usage data: {:?}", res);
    }
}

pub fn update_payments(payment: PaymentTx) {
    let mut payments = PAYMENT_UPDATE_QUEUE.write().unwrap();
    payments.push(payment);
}

pub struct UpdatePayments {
    pub payment: PaymentTx,
}

impl Message for UpdatePayments {
    type Result = Result<(), Error>;
}

impl Handler<UpdatePayments> for UsageTracker {
    type Result = Result<(), Error>;
    fn handle(&mut self, msg: UpdatePayments, _: &mut Context<Self>) -> Self::Result {
        let mut queue = PAYMENT_UPDATE_QUEUE.write().unwrap();
        for item in *queue {
            let _res = handle_payments(&mut self, item);
        }
        *queue = Vec::new();
        handle_payments(&mut self, msg.payment)
    }
}

fn handle_payments(history: &mut UsageTracker, payment: PaymentTx) -> Result<(), Error> {
    let current_hour = match get_current_hour() {
        Ok(hour) => hour,
        Err(e) => {
            error!("System time is set earlier than unix epoch! {:?}", e);
            return Ok(());
        }
    };
    let formatted_payment = to_formatted_payment_tx(payment);
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
    while history.payments.len() > MAX_ENTRIES {
        let _discarded_entry = history.payments.pop_back();
    }
    if (current_hour - SAVE_FREQENCY) > history.last_save_hour {
        history.last_save_hour = current_hour;
        let res = history.save();
        info!("Saving usage data: {:?}", res);
    }
    Ok(())
}

pub struct GetUsage {
    pub kind: UsageType,
}

impl Message for GetUsage {
    type Result = Result<VecDeque<UsageHour>, Error>;
}

impl Handler<GetUsage> for UsageTracker {
    type Result = Result<VecDeque<UsageHour>, Error>;
    fn handle(&mut self, msg: GetUsage, _: &mut Context<Self>) -> Self::Result {
        match msg.kind {
            UsageType::Client => Ok(self.client_bandwidth.clone()),
            UsageType::Relay => Ok(self.relay_bandwidth.clone()),
            UsageType::Exit => Ok(self.exit_bandwidth.clone()),
        }
    }
}

pub struct GetPayments;

impl Message for GetPayments {
    type Result = Result<VecDeque<PaymentHour>, Error>;
}

impl Handler<GetPayments> for UsageTracker {
    type Result = Result<VecDeque<PaymentHour>, Error>;
    fn handle(&mut self, _msg: GetPayments, _: &mut Context<Self>) -> Self::Result {
        Ok(self.payments.clone())
    }
}
