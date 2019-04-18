//! This is the primary actor loop for rita-client, where periodic tasks are spawed and Actors are
//! tied together with message calls.
//!
//! This loop manages exit signup based on the settings configuration state and deploys an exit vpn
//! tunnel if the signup was successful on the selected exit.

use crate::rita_client::exit_manager::ExitManager;
use crate::SETTING;
use actix::{
    Actor, ActorContext, Addr, Arbiter, AsyncContext, Context, Handler, Message, Supervised,
    SystemService,
};
use althea_types::RTTimestamps;
use babel_monitor::Babel;
use failure::Error;
use futures::future::Future;
use reqwest;
use settings::client::RitaClientSettings;
use settings::RitaCommonSettings;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct RitaLoop;

// the speed in seconds for the client loop
pub const CLIENT_LOOP_SPEED: u64 = 5;

impl Actor for RitaLoop {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Context<Self>) {
        ctx.run_interval(Duration::from_secs(CLIENT_LOOP_SPEED), |_act, ctx| {
            let addr: Addr<Self> = ctx.address();
            addr.do_send(Tick);
        });
    }
}

impl SystemService for RitaLoop {}
impl Supervised for RitaLoop {
    fn restarting(&mut self, _ctx: &mut Context<RitaLoop>) {
        error!("Rita Client loop actor died! recovering!");
    }
}

/// Used to test actor respawning
pub struct Crash;

impl Message for Crash {
    type Result = Result<(), Error>;
}

impl Handler<Crash> for RitaLoop {
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

impl Handler<Tick> for RitaLoop {
    type Result = Result<(), Error>;
    fn handle(&mut self, _: Tick, _ctx: &mut Context<Self>) -> Self::Result {
        let start = Instant::now();
        trace!("Client Tick!");

        if SETTING.get_network().is_gateway {
            for (_exit_name, exit_client) in SETTING.get_exits().iter() {
                correct_exit_flapping(exit_client.id.mesh_ip);
            }
        }

        Arbiter::spawn(ExitManager::from_registry().send(Tick {}).then(|res| {
            trace!("exit manager said {:?}", res);
            Ok(())
        }));

        info!(
            "Rita Client loop completed in {}s {}ms",
            start.elapsed().as_secs(),
            start.elapsed().subsec_millis()
        );
        Ok(())
    }
}

/// The reason why we need this is complex, within the network most nodes offering
/// routes to a destination are offering a route to the same destination, so switching
/// routes is seamless and involves at most a lost packet or two. For the case of our exit
/// clustering multihomed our exits, with two nodes advertising the same route. Babel may switch
/// between them, because exit nodes nat external traffic this kills any existing tcp sessions and
/// is very disruptive to the user. Since only gateways can pick routes that may be different exits
/// this function artificially increases the difficulty of switching to prevent babel from doing it
/// as often as it might otherwise. It's hacky and a little risky but the alternative is manually
/// asking about exit regions or pulling even more complexity into Rita to replicate packet loss
/// and latency sensitive exit selection.
fn correct_exit_flapping(current_exit: IpAddr) -> Result<(), Error> {
    let stream = TcpStream::connect::<SocketAddr>(
        format!("[::1]:{}", SETTING.get_network().babel_port).parse()?,
    )?;
    let mut babel = Babel::new(stream);

    babel.start_connection()?;
    trace!("Getting routes");
    let routes = babel.parse_routes()?;
    let routes_to_exit = babel.get_routes(&current_exit, &routes);
    let installed_route = babel.get_installed_route(&current_exit, &routes);
    trace!("Got routes: {:?}", routes);
    let neighs = babel.parse_neighs()?;

    Ok(())
}

pub fn _compute_verification_rtt() -> Result<RTTimestamps, Error> {
    let exit = match SETTING.get_exit_client().get_current_exit() {
        Some(current_exit) => current_exit.clone(),
        None => {
            return Err(format_err!(
                "No current exit even though an exit route is present"
            ));
        }
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()?;

    let timestamps: RTTimestamps = client
        .get(&format!(
            "http://[{}]:{}/rtt",
            exit.id.mesh_ip, exit.registration_port
        ))
        .send()?
        .json()?;

    let exit_rx = timestamps.exit_rx;
    let exit_tx = timestamps.exit_tx;
    let client_tx = Instant::now();
    let client_rx = Instant::now();

    let inner_rtt = client_rx.duration_since(client_tx) - exit_tx.duration_since(exit_rx)?;
    let inner_rtt_millis =
        inner_rtt.as_secs() as f32 * 1000.0 + inner_rtt.subsec_nanos() as f32 / 1_000_000.0;
    //                        secs -> millis                            nanos -> millis

    info!("Computed RTTs: inner {}ms", inner_rtt_millis);
    Ok(timestamps)
}
