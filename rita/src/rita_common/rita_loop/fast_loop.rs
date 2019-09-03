use crate::rita_common::debt_keeper::{DebtKeeper, SendUpdate};
use crate::rita_common::oracle::{Oracle, Update};
use crate::rita_common::payment_validator::{PaymentValidator, Validate};
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
use babel_monitor::open_babel_stream;
use babel_monitor::parse_routes;
use babel_monitor::start_connection;
use failure::Error;
use futures::Future;
use settings::RitaCommonSettings;
use std::time::{Duration, Instant};

// the speed in seconds for the common loop
pub const FAST_LOOP_SPEED: u64 = 5;
pub const FAST_LOOP_TIMEOUT: Duration = Duration::from_secs(4);

pub struct RitaFastLoop {}

impl Default for RitaFastLoop {
    fn default() -> RitaFastLoop {
        RitaFastLoop {}
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

        manage_gateway();

        let start = Instant::now();

        // Update blockchain info put here because people really
        // hate it when their deposits take a while to show up
        Oracle::from_registry().do_send(Update());

        // Check on payments, only really needs to be run this quickly
        // on large nodes where very high variation in throughput can result
        // in blowing through the entire grace in less than a minute
        PaymentValidator::from_registry().do_send(Validate());

        // watch neighbors for billing
        Arbiter::spawn(
            TunnelManager::from_registry()
                .send(GetNeighbors)
                .timeout(FAST_LOOP_TIMEOUT)
                .then(move |res| {
                    trace!("Currently open tunnels: {:?}", res);
                    let neighbors = res.unwrap().unwrap();
                    let babel_port = SETTING.get_network().babel_port;

                    let neigh = Instant::now();
                    info!(
                        "GetNeighbors completed in {}s {}ms",
                        start.elapsed().as_secs(),
                        start.elapsed().subsec_millis()
                    );

                    open_babel_stream(babel_port)
                        .from_err()
                        .and_then(move |stream| {
                            start_connection(stream).and_then(move |stream| {
                                parse_routes(stream).and_then(move |routes| {
                                    TrafficWatcher::from_registry()
                                        .send(Watch::new(neighbors, routes.1))
                                        .timeout(FAST_LOOP_TIMEOUT)
                                        .then(move |_res| {
                                            info!(
                                                "TrafficWatcher completed in {}s {}ms",
                                                neigh.elapsed().as_secs(),
                                                neigh.elapsed().subsec_millis()
                                            );
                                            Ok(())
                                        })
                                })
                            })
                        })
                        .then(|ret| {
                            if let Err(e) = ret {
                                error!("Failed to watch client traffic with {:?}", e)
                            }
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

/// Manages gateway functionaltiy and maintains the was_gateway parameter, this is different from the gateway
/// identification in rita_client because this must function even if we aren't registered for an exit it's also
/// very prone to being true when the device has a wan port but no actual wan connection.
fn manage_gateway() {
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

    if gateway {
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
    }
}
