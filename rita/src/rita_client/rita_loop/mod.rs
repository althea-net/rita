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
use failure::Error;
use futures::future::Future;
use reqwest;
use settings::client::RitaClientSettings;
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

        Arbiter::spawn(
            ExitManager::from_registry()
                .send(Tick {})
                .timeout(Duration::from_secs(4))
                .then(|res| {
                    trace!("exit manager said {:?}", res);
                    Ok(())
                }),
        );

        info!(
            "Rita Client loop completed in {}s {}ms",
            start.elapsed().as_secs(),
            start.elapsed().subsec_millis()
        );
        Ok(())
    }
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
