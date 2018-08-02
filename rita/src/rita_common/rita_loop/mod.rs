use std::time::{Duration, Instant};

use actix::prelude::*;
use actix::registry::SystemService;
use actix_utils::KillActor;

#[cfg(not(test))]
use trust_dns_resolver::config::ResolverConfig;

use actix_utils::ResolverWrapper;

#[cfg(not(test))]
use KI;

use rita_common::tunnel_manager::{GetNeighbors, TunnelManager};

use rita_common::traffic_watcher::{TrafficWatcher, Watch};

use rita_common::peer_listener::PeerListener;

use rita_common::debt_keeper::{DebtKeeper, SendUpdate};

use rita_common::payment_controller::{PaymentController, PaymentControllerUpdate};

use rita_common::stats_collector::StatsCollector;

use rita_common::peer_listener::GetPeers;

use rita_common::tunnel_manager::PeersToContact;

use failure::Error;

use futures::Future;

use settings::RitaCommonSettings;
use SETTING;

pub struct RitaLoop {
    stats_collector: Addr<StatsCollector>,
    was_gateway: bool,
}

impl RitaLoop {
    pub fn new() -> RitaLoop {
        RitaLoop {
            stats_collector: SyncArbiter::start(1, || StatsCollector::new()),
            was_gateway: false,
        }
    }
}

impl Actor for RitaLoop {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Context<Self>) {
        trace!("Common rita loop started!");

        ctx.run_interval(Duration::from_secs(5), |_act, ctx| {
            let addr: Addr<Self> = ctx.address();
            addr.do_send(Tick);
        });
    }
}

pub struct Tick;

impl Message for Tick {
    type Result = Result<(), Error>;
}

impl Handler<Tick> for RitaLoop {
    type Result = Result<(), Error>;
    fn handle(&mut self, _: Tick, ctx: &mut Context<Self>) -> Self::Result {
        trace!("Common tick!");

        // let mut babel = Babel::new(&format!("[::1]:{}", SETTING.get_network().babel_port).parse().unwrap());

        self.stats_collector.do_send(Tick {});

        // Resolves the gateway client corner case
        // Background info here https://forum.altheamesh.com/t/the-gateway-client-corner-case/35
        if SETTING.get_network().is_gateway {
            if !self.was_gateway {
                let resolver_addr: Addr<ResolverWrapper> = System::current().registry().get();
                resolver_addr.do_send(KillActor);

                self.was_gateway = true
            }
            trace!("Adding default routes for TrustDNS");
            #[cfg(not(test))]
            for i in ResolverConfig::default().name_servers() {
                trace!("TrustDNS default {:?}", i);
                KI.manual_peers_route(
                    &i.socket_addr.ip(),
                    &mut SETTING.get_network_mut().default_route,
                ).unwrap();
            }
        } else {
            self.was_gateway = false
        }

        // TODO refactor this abomination
        let start = Instant::now();
        ctx.spawn(
            TunnelManager::from_registry()
                .send(GetNeighbors)
                .into_actor(self)
                .then(move |res, act, _ctx| {
                    let res = res.unwrap().unwrap();

                    info!("TunnelManager got tunnels: {:?}", res);

                    let neigh = Instant::now();

                    let res = res
                        .iter()
                        .map(|res| (res.0.clone(), res.1.clone()))
                        .collect();

                    TrafficWatcher::from_registry()
                        .send(Watch(res))
                        .into_actor(act)
                        .then(move |_res, _act, _ctx| {
                            info!("loop completed in {:?}", start.elapsed());
                            info!("TrafficWatcher completed in {:?}", neigh.elapsed());
                            DebtKeeper::from_registry().do_send(SendUpdate {});
                            PaymentController::from_registry().do_send(PaymentControllerUpdate {});
                            actix::fut::ok(())
                        })
                }),
        );

        trace!("Starting PeerListener tick");
        Arbiter::spawn(
            PeerListener::from_registry()
                .send(Tick {})
                .then(|res| {
                    trace!("PeerListener said {:?}", res);
                    res
                }).then(|_| Ok(())),
        );

        trace!("Getting Peers from PeerListener to pass to TunnelManager");
        Arbiter::spawn(
            PeerListener::from_registry()
                .send(GetPeers {})
                .and_then(|peers| {
                    trace!("Got peers from PeerListener, passing to TunnelManager");
                    TunnelManager::from_registry().send(PeersToContact(peers.unwrap())) // GetPeers never fails so unwrap is safe
                }).then(|_| Ok(())),
        );

        Ok(())
    }
}
