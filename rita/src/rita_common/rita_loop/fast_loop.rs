use crate::rita_common::debt_keeper::{DebtKeeper, SendUpdate};
use crate::rita_common::peer_listener::GetPeers;
use crate::rita_common::peer_listener::PeerListener;
use crate::rita_common::traffic_watcher::{TrafficWatcher, Watch};
use crate::rita_common::tunnel_manager::PeersToContact;
use crate::rita_common::tunnel_manager::{GetNeighbors, TunnelManager};
use crate::KI;
use crate::SETTING;
use actix::{
    Actor, ActorContext, Addr, Arbiter, AsyncContext, Context, Handler, Message, Supervised,
    SystemService,
};
use failure::Error;
use futures::Future;
use settings::RitaCommonSettings;
use std::time::{Duration, Instant};

// the speed in seconds for the common loop
pub const FAST_LOOP_SPEED: u64 = 5;
pub const FAST_LOOP_TIMEOUT: Duration = Duration::from_secs(4);

pub struct RitaFastLoop {
    was_gateway: bool,
}

impl Default for RitaFastLoop {
    fn default() -> RitaFastLoop {
        RitaFastLoop { was_gateway: false }
    }
}

impl Actor for RitaFastLoop {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Context<Self>) {
        trace!("Common rita loop started!");

        ctx.run_interval(Duration::from_secs(FAST_LOOP_SPEED), |_act, ctx| {
            let addr: Addr<Self> = ctx.address();
            addr.do_send(Tick);
        });
    }
}

impl SystemService for RitaFastLoop {}
impl Supervised for RitaFastLoop {
    fn restarting(&mut self, _ctx: &mut Context<RitaFastLoop>) {
        error!("Rita Common loop actor died! recovering!");
    }
}

/// Used to test actor respawning
pub struct Crash;

impl Message for Crash {
    type Result = Result<(), Error>;
}

impl Handler<Crash> for RitaFastLoop {
    type Result = Result<(), Error>;
    fn handle(&mut self, _: Crash, ctx: &mut Context<Self>) -> Self::Result {
        ctx.stop();
        Ok(())
    }
}

pub struct Tick;

impl Message for Tick {
    type Result = Result<(), Error>;
}

impl Handler<Tick> for RitaFastLoop {
    type Result = Result<(), Error>;
    fn handle(&mut self, _: Tick, _ctx: &mut Context<Self>) -> Self::Result {
        trace!("Common tick!");

        self.was_gateway = manage_gateway(self.was_gateway);

        let start = Instant::now();

        // watch neighbors for billing
        Arbiter::spawn(
            TunnelManager::from_registry()
                .send(GetNeighbors)
                .timeout(FAST_LOOP_TIMEOUT)
                .then(move |res| {
                    let res = res.unwrap().unwrap();

                    trace!("Currently open tunnels: {:?}", res);

                    let neigh = Instant::now();
                    info!(
                        "GetNeighbors completed in {}s {}ms",
                        start.elapsed().as_secs(),
                        start.elapsed().subsec_millis()
                    );

                    TrafficWatcher::from_registry()
                        .send(Watch::new(res))
                        .timeout(FAST_LOOP_TIMEOUT)
                        .then(move |_res| {
                            info!(
                                "TrafficWatcher completed in {}s {}ms",
                                neigh.elapsed().as_secs(),
                                neigh.elapsed().subsec_millis()
                            );
                            Ok(())
                        })
                }),
        );

        // Update debts
        DebtKeeper::from_registry().do_send(SendUpdate {});

        let start = Instant::now();
        trace!("Starting PeerListener tick");
        Arbiter::spawn(
            PeerListener::from_registry()
                .send(Tick {})
                .timeout(FAST_LOOP_TIMEOUT)
                .then(move |res| {
                    info!(
                        "PeerListener tick completed in {}s {}ms, with result {:?}",
                        start.elapsed().as_secs(),
                        start.elapsed().subsec_millis(),
                        res
                    );
                    res
                })
                .then(|_| Ok(())),
        );

        let start = Instant::now();
        trace!("Getting Peers from PeerListener to pass to TunnelManager");
        Arbiter::spawn(
            PeerListener::from_registry()
                .send(GetPeers {})
                .timeout(FAST_LOOP_TIMEOUT)
                .and_then(move |peers| {
                    // GetPeers never fails so unwrap is safe
                    let peers = peers.unwrap();
                    info!(
                        "PeerListener get {} peers completed in {}s {}ms",
                        peers.len(),
                        start.elapsed().as_secs(),
                        start.elapsed().subsec_millis(),
                    );
                    TunnelManager::from_registry()
                        .send(PeersToContact::new(peers))
                        .timeout(FAST_LOOP_TIMEOUT)
                })
                .then(|_| Ok(())),
        );

        Ok(())
    }
}

/// Manages gateway functionaltiy and maintains the was_gateway parameter
fn manage_gateway(mut was_gateway: bool) -> bool {
    // Resolves the gateway client corner case
    // Background info here https://forum.altheamesh.com/t/the-gateway-client-corner-case/35
    let gateway = match SETTING.get_network().external_nic {
        Some(ref external_nic) => match KI.is_iface_up(external_nic) {
            Some(val) => val,
            None => false,
        },
        None => false,
    };

    info!("We are a Gateway: {}", gateway);
    SETTING.get_network_mut().is_gateway = gateway;

    if SETTING.get_network().is_gateway {
        match KI.get_resolv_servers() {
            Ok(s) => {
                for ip in s.iter() {
                    trace!("Resolv route {:?}", ip);
                    KI.manual_peers_route(&ip, &mut SETTING.get_network_mut().default_route)
                        .unwrap();
                }
            }
            Err(e) => warn!("Failed to add DNS routes with {:?}", e),
        }
    } else {
        was_gateway = false
    }
    was_gateway
}
