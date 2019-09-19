//! Latency manager is an experimental system to apply traffic shaping to neighbors based on the neighbor rtt

use crate::rita_common::tunnel_manager::Neighbor as RitaNeighbor;
use crate::rita_common::tunnel_manager::{GetNeighbors, TunnelManager};
use crate::SETTING;
use actix::Actor;
use actix::Arbiter;
use actix::Context;
use actix::Handler;
use actix::Message;
use actix::Supervised;
use actix::SystemService;
use babel_monitor::open_babel_stream;
use babel_monitor::parse_neighs;
use babel_monitor::start_connection;
use babel_monitor::Neighbor as BabelNeighbor;
use futures::future::Future;
use settings::RitaCommonSettings;
use std::collections::HashMap;

pub struct LatencyManager {
    latency_history: HashMap<String, [f32; 32]>,
}

impl Actor for LatencyManager {
    type Context = Context<Self>;
}

impl Supervised for LatencyManager {}
impl SystemService for LatencyManager {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("Latency Manager started");
    }
}

impl LatencyManager {
    pub fn new() -> Self {
        LatencyManager {
            latency_history: HashMap::new(),
        }
    }
}

impl Default for LatencyManager {
    fn default() -> LatencyManager {
        LatencyManager::new()
    }
}

#[derive(Message)]
pub struct Tick{
    pub babel_neighbors: Vec<BabelNeighbor>, 
    pub rita_neighbors: Vec<RitaNeighbor>
}

impl Handler<Tick> for LatencyManager {
    type Result = ();

    fn handle(&mut self, msg: Tick, _ctx: &mut Context<Self>) -> Self::Result {
    }
}

/// Attempts to detect bufferbloat by looking at neighbor latency over time
fn detect_bloat(babel_neighbors: Vec<BabelNeighbor>, rita_neighbors: Vec<RitaNeighbor>) {}
