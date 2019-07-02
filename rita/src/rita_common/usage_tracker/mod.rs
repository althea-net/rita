//! Collects messages from the various traffic watchers to allow the creation of graphs about
//! usage. Within each traffic watcher a simple message containing the amount of bandwidth used
//! in that round and exactly what type of bandwidth it is is sent to this module, from there
//! the handler updates the storage to reflect the new total. When a user would like to inspect
//! or graph usage they query an endpoint which will request the data from this module.
//!
//! Persistant storage is planned but not currently implemented.

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
use num256::Uint256;
use serde::{Deserialize, Serialize};
use serde_json::Error as SerdeError;
use settings::RitaCommonSettings;
use std::collections::VecDeque;
use std::fs::File;
use std::io::Error as IOError;
use std::io::Read;
use std::io::Write;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

/// On year worth of usage storage
const MAX_ENTRIES: usize = 8760;
/// Save every 4 hours
const SAVE_FREQENCY: u64 = 4;

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

/// A struct for tracking each hours of paymetns indexed in hours since unix epoch
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
    client_bandwith: VecDeque<UsageHour>,
    relay_bandwith: VecDeque<UsageHour>,
    exit_bandwith: VecDeque<UsageHour>,
    /// A history of payments
    payments: VecDeque<PaymentHour>,
}

impl Default for UsageTracker {
    fn default() -> UsageTracker {
        let file = File::open(SETTING.get_network().usage_tracker_file.clone());
        // if the loading process goes wrong for any reason, we just start again
        let blank_usage_tracker = UsageTracker {
            last_save_hour: 0,
            client_bandwith: VecDeque::new(),
            relay_bandwith: VecDeque::new(),
            exit_bandwith: VecDeque::new(),
            payments: VecDeque::new(),
        };

        match file {
            Ok(mut file) => {
                let mut contents = String::new();
                match file.read_to_string(&mut contents) {
                    Ok(_bytes_read) => {
                        let deserialized: Result<UsageTracker, SerdeError> =
                            serde_json::from_str(&contents);

                        match deserialized {
                            Ok(value) => value,
                            Err(e) => {
                                error!("Failed to deserialize usage tracker {:?}", e);
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

impl UsageTracker {
    fn save(&mut self) -> Result<(), IOError> {
        let serialized = serde_json::to_string(self)?;
        let mut file = File::create(SETTING.get_network().usage_tracker_file.clone())?;
        file.write_all(serialized.as_bytes())
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

/// The messauge used to update the current usage hour from each traffic
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
        UsageType::Client => &mut data.client_bandwith,
        UsageType::Relay => &mut data.relay_bandwith,
        UsageType::Exit => &mut data.exit_bandwith,
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

pub struct UpdatePayments {
    pub payment: PaymentTx,
}

impl Message for UpdatePayments {
    type Result = Result<(), Error>;
}

impl Handler<UpdatePayments> for UsageTracker {
    type Result = Result<(), Error>;
    fn handle(&mut self, msg: UpdatePayments, _: &mut Context<Self>) -> Self::Result {
        let current_hour = match get_current_hour() {
            Ok(hour) => hour,
            Err(e) => {
                error!("System time is set earlier than unix epoch! {:?}", e);
                return Ok(());
            }
        };
        let formatted_payment = to_formatted_payment_tx(msg.payment);
        match self.payments.front_mut() {
            None => self.payments.push_front(PaymentHour {
                index: current_hour,
                payments: vec![formatted_payment],
            }),
            Some(entry) => {
                if entry.index == current_hour {
                    entry.payments.push(formatted_payment);
                } else {
                    self.payments.push_front(PaymentHour {
                        index: current_hour,
                        payments: vec![formatted_payment],
                    })
                }
            }
        }
        while self.payments.len() > MAX_ENTRIES {
            let _discarded_entry = self.payments.pop_back();
        }
        if (current_hour - SAVE_FREQENCY) > self.last_save_hour {
            self.last_save_hour = current_hour;
            let res = self.save();
            info!("Saving usage data: {:?}", res);
        }
        Ok(())
    }
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
            UsageType::Client => Ok(self.client_bandwith.clone()),
            UsageType::Relay => Ok(self.relay_bandwith.clone()),
            UsageType::Exit => Ok(self.exit_bandwith.clone()),
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
