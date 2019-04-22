//! Collects messages from the various traffic watchers to allow the creation of graphs about
//! usage. Within each traffic watcher a simple message containing the amount of bandwidth used
//! in that round and exactly what type of bandwidth it is is sent to this module, from there
//! the handler updates the storage to reflect the new total. When a user would like to inspect
//! or graph usage they query an endpoint which will request the data from this module.
//!
//! Persistant storage is planned but not currently implemented.

use actix::Actor;
use actix::Context;
use actix::Handler;
use actix::Message;
use actix::Supervised;
use actix::SystemService;
use althea_types::PaymentTx;
use failure::Error;
use std::collections::VecDeque;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

/// On year worth of usage storage
const MAX_ENTRIES: usize = 8760;

/// In an effort to converge this module between the three possible bw tracking
/// use cases this enum is used to identify which sort of usage we are tracking
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub enum UsageType {
    Client,
    Relay,
    Exit,
}

/// A struct for tracking each hour of usage, indexed by time in hours since
/// the unix epoch
#[derive(Clone, Copy, Debug, Serialize)]
pub struct UsageHour {
    index: u64,
    up: u64,
    down: u64,
    price: u32,
}

/// A struct for tracking each hours of paymetns indexed in hours since unix epoch
#[derive(Clone, Debug, Serialize)]
pub struct PaymentHour {
    index: u64,
    payments: Vec<PaymentTx>,
}

/// The main actor that holds the usage state for the duration of operations
/// at some point loading and saving will be defined in service started
#[derive(Default, Clone, Debug, Serialize)]
pub struct UsageTracker {
    // at least one of these will be left unused
    client_bandwith: VecDeque<UsageHour>,
    relay_bandwith: VecDeque<UsageHour>,
    exit_bandwith: VecDeque<UsageHour>,
    /// A history of txid's
    payments: VecDeque<PaymentHour>,
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
        match self.payments.front_mut() {
            None => self.payments.push_front(PaymentHour {
                index: current_hour,
                payments: vec![msg.payment],
            }),
            Some(entry) => {
                if entry.index == current_hour {
                    entry.payments.push(msg.payment);
                } else {
                    self.payments.push_front(PaymentHour {
                        index: current_hour,
                        payments: vec![msg.payment],
                    })
                }
            }
        }
        while self.payments.len() > MAX_ENTRIES {
            let _discarded_entry = self.payments.pop_back();
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
