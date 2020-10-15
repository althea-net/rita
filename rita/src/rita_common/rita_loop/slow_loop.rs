use crate::rita_common::simulated_txfee_manager::tick_simulated_tx;
use crate::rita_common::token_bridge::tick_token_bridge;
use crate::rita_common::utils::wait_timeout::wait_timeout;
use crate::rita_common::utils::wait_timeout::WaitResult;
use crate::SETTING;
use actix::System;
use actix_async::{Arbiter, System as AsyncSystem};
use babel_monitor::open_babel_stream;
use babel_monitor::set_local_fee;
use babel_monitor::set_metric_factor;
use babel_monitor::start_connection;
use futures01::future::Future;
use settings::RitaCommonSettings;
use std::thread;
use std::time::Duration;
use std::time::Instant;

/// the speed in seconds for the common loop
pub const SLOW_LOOP_SPEED: Duration = Duration::from_secs(60);
pub const SLOW_LOOP_TIMEOUT: Duration = Duration::from_secs(15);

pub fn start_rita_slow_loop() {
    let system = System::current();
    let mut last_restart = Instant::now();
    thread::spawn(move || {
        // this will always be an error, so it's really just a loop statement
        // with some fancy destructuring
        while let Err(e) = {
            thread::spawn(move || loop {
                let start = Instant::now();
                info!("Common Slow tick!");

                let res = AsyncSystem::run(move || {
                    Arbiter::spawn(async move {
                        tick_token_bridge().await;
                        tick_simulated_tx().await;
                        info!("Common Slow tick async completed!");
                        AsyncSystem::current().stop();
                    });
                });
                if res.is_err() {
                    error!("Error in actix system {:?}", res);
                }

                // we really only need to run this on startup, but doing so periodically
                // could catch the edge case where babel is restarted under us
                set_babel_price();
                info!("Common Slow tick completed!");

                // sleep until it has been SLOW_LOOP_SPEED seconds from start, whenever that may be
                // if it has been more than SLOW_LOOP_SPEED seconds from start, go right ahead
                if start.elapsed() < SLOW_LOOP_SPEED {
                    thread::sleep(SLOW_LOOP_SPEED - start.elapsed());
                }
            })
            .join()
        } {
            error!("Rita common slow loop thread panicked! Respawning {:?}", e);
            if Instant::now() - last_restart < Duration::from_secs(120) {
                error!("Restarting too quickly, leaving it to auto rescue!");
                system.stop_with_code(121)
            }
            last_restart = Instant::now();
        }
    });
}

fn set_babel_price() {
    let start = Instant::now();
    let babel_port = SETTING.get_network().babel_port;
    let local_fee = SETTING.get_payment().local_fee;
    let metric_factor = SETTING.get_network().metric_factor;
    let res = wait_timeout(
        open_babel_stream(babel_port)
            .from_err()
            .and_then(move |stream| {
                start_connection(stream).and_then(move |stream| {
                    set_local_fee(stream, local_fee)
                        .and_then(move |stream| Ok(set_metric_factor(stream, metric_factor)))
                })
            }),
        SLOW_LOOP_TIMEOUT,
    );
    match res {
        WaitResult::Err(e) => warn!(
            "Failed to set babel price with {:?} {}ms since start",
            e,
            start.elapsed().as_millis()
        ),
        WaitResult::Ok(_) => info!(
            "Set babel price successfully {}ms since start",
            start.elapsed().as_millis()
        ),
        WaitResult::TimedOut(_) => error!(
            "Set babel price timed out! {}ms since start",
            start.elapsed().as_millis()
        ),
    }
}
