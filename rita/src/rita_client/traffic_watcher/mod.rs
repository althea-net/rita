//! Traffic watcher monitors system traffic by interfacing with KernelInterface to create and check
//! iptables and ip counters on each per hop tunnel (the WireGuard tunnel between two devices). These counts
//! are then stored and used to compute amounts for bills.
//!
//! This is the client specific billing code used to determine how exits should be compensted. Which is
//! different in that mesh nodes are paid by forwarding traffic, but exits have to return traffic and
//! must get paid for doing so.

use crate::rita_common::debt_keeper::{DebtKeeper, Traffic, TrafficUpdate};
use crate::rita_common::usage_tracker::UpdateUsage;
use crate::rita_common::usage_tracker::UsageTracker;
use crate::rita_common::usage_tracker::UsageType;
use crate::KI;
use crate::SETTING;
use ::actix::prelude::{Actor, Context, Handler, Message, Supervised, SystemService};
use althea_types::Identity;
use babel_monitor::open_babel_stream;
use babel_monitor::Babel;
use babel_monitor::Route;
use failure::Error;
use settings::RitaCommonSettings;
use std::net::IpAddr;

/// Returns the babel route to a given mesh ip with the properly capped price
fn find_exit_route_capped(exit_mesh_ip: IpAddr) -> Result<Route, Error> {
    let stream = open_babel_stream(SETTING.get_network().babel_port)?;
    let mut babel = Babel::new(stream);

    babel.start_connection()?;
    trace!("Getting routes");
    let routes = babel.parse_routes()?;
    trace!("Got routes: {:?}", routes);

    let max_fee = SETTING.get_payment().max_fee;
    let mut exit_route = babel.get_installed_route(&exit_mesh_ip, &routes)?;
    if exit_route.price > max_fee {
        let mut capped_route = exit_route.clone();
        capped_route.price = max_fee;
        exit_route = capped_route;
    }
    Ok(exit_route)
}

pub struct TrafficWatcher {
    last_read_input: u64,
    last_read_output: u64,
}

impl Actor for TrafficWatcher {
    type Context = Context<Self>;
}
impl Supervised for TrafficWatcher {}
impl SystemService for TrafficWatcher {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("Client traffic watcher started");
        self.last_read_input = 0;
        self.last_read_output = 0;
    }
}
impl Default for TrafficWatcher {
    fn default() -> TrafficWatcher {
        TrafficWatcher {
            last_read_input: 0,
            last_read_output: 0,
        }
    }
}

pub struct Watch {
    pub exit_id: Identity,
    pub exit_price: u64,
}

impl Message for Watch {
    type Result = Result<(), Error>;
}

impl Handler<Watch> for TrafficWatcher {
    type Result = Result<(), Error>;

    fn handle(&mut self, msg: Watch, _: &mut Context<Self>) -> Self::Result {
        watch(self, &msg.exit_id, msg.exit_price)
    }
}

/// This traffic watcher watches how much traffic we send to the exit, and how much the exit sends
/// back to us.
pub fn watch(history: &mut TrafficWatcher, exit: &Identity, exit_price: u64) -> Result<(), Error> {
    let exit_route = find_exit_route_capped(exit.mesh_ip)?;

    let counter = match KI.read_wg_counters("wg_exit") {
        Ok(res) => {
            if res.len() > 1 {
                warn!("wg_exit client tunnel has multiple peers!");
            } else if res.is_empty() {
                warn!("No peers on wg_exit why is client traffic watcher running?");
                return Err(format_err!("No peers on wg_exit"));
            }
            // unwrap is safe because we check that len is not equal to zero
            // then we toss the exit's wg key as we don't need it
            res.iter().last().unwrap().1.clone()
        }
        Err(e) => {
            warn!(
                "Error getting router client input output counters {:?} traffic has gone unaccounted!",
                e
            );
            return Err(e);
        }
    };

    // bandwidth usage should always increase if it doesn't the interface has been
    // deleted and recreated and we need to reset our usage, also protects from negatives
    if history.last_read_input > counter.download || history.last_read_output > counter.upload {
        warn!("Exit tunnel reset resetting counters");
        history.last_read_input = 0;
        history.last_read_output = 0;
    }

    let input = counter.download - history.last_read_input;
    let output = counter.upload - history.last_read_output;

    history.last_read_input = counter.download;
    history.last_read_output = counter.upload;

    info!("{:?} bytes downloaded from exit this round", &input);
    info!("{:?} bytes uploaded to exit this round", &output);

    // the price we pay to send traffic through the exit
    info!("exit price {}", exit_price);

    // price to get traffic to the exit as a u64 to make the type rules for math easy
    let exit_route_price: i128 = exit_route.price.into();
    // the total price for the exit returning traffic to us, in the future we should ask
    // the exit for this because TODO assumes symetric route
    let exit_dest_price: i128 = exit_route_price + i128::from(exit_price);

    info!("Exit destination price {}", exit_dest_price);
    trace!("Exit ip: {:?}", exit.mesh_ip);
    trace!("Exit destination:\n{:#?}", exit_route);

    // accounts for what we owe the exit for return data and sent data
    // we have to pay our neighbor for what we send over them
    // remember pay per *forward* so we pay our neighbor for what we
    // send to the exit while we pay the exit to pay it's neighbor to eventually
    // pay our neighbor to send data back to us. Here we only pay the exit the exit
    // fee for traffic we send to it since our neighbors billing should be handled in
    // rita_common but we do pay for return traffic here since it doesn't make sense
    // to handle in the general case
    let mut owes_exit = 0i128;
    let value = i128::from(input) * exit_dest_price;
    trace!(
        "We are billing for {} bytes input times a exit dest price of {} for a total of {}",
        input,
        exit_dest_price,
        value
    );
    owes_exit += value;
    let value = i128::from(exit_price * (output));
    trace!(
        "We are billing for {} bytes output times a exit price of {} for a total of {}",
        output,
        exit_price,
        value
    );
    owes_exit += value;

    if owes_exit > 0 {
        info!("Total client debt of {} this round", owes_exit);

        let exit_update = TrafficUpdate {
            traffic: vec![Traffic {
                from: *exit,
                amount: owes_exit.into(),
            }],
        };

        DebtKeeper::from_registry().do_send(exit_update);

        // update the usage tracker with the details of this round's usage
        UsageTracker::from_registry().do_send(UpdateUsage {
            kind: UsageType::Client,
            up: output,
            down: input,
            price: exit_dest_price as u32,
        });
    } else {
        error!("no Exit bandwidth, no bill!");
    }

    Ok(())
}
