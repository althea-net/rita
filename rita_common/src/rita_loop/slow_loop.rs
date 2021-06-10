use crate::simulated_txfee_manager::tick_simulated_tx;
use crate::token_bridge::tick_token_bridge;
use crate::utils::wait_timeout::wait_timeout;
use crate::utils::wait_timeout::WaitResult;
use actix::System;
use actix_async::System as AsyncSystem;
// use babel_monitor::open_babel_stream;
// use babel_monitor::set_local_fee;
// use babel_monitor::set_metric_factor;
// use babel_monitor::start_connection;
use babel_monitor_legacy::open_babel_stream_legacy;
use babel_monitor_legacy::set_local_fee_legacy;
use babel_monitor_legacy::set_metric_factor_legacy;
use babel_monitor_legacy::start_connection_legacy;
use futures01::future::Future;

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

                let runner = AsyncSystem::new();
                runner.block_on(async move {
                    tick_token_bridge().await;
                    tick_simulated_tx().await;
                    info!("Common Slow tick async completed!");
                    AsyncSystem::current().stop();
                });

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
    let babel_port = settings::get_rita_common().get_network().babel_port;
    let local_fee = settings::get_rita_common().get_payment().local_fee;
    let metric_factor = settings::get_rita_common().get_network().metric_factor;
    let res = wait_timeout(
        open_babel_stream_legacy(babel_port)
            .from_err()
            .and_then(move |stream| {
                start_connection_legacy(stream).and_then(move |stream| {
                    set_local_fee_legacy(stream, local_fee)
                        .and_then(move |stream| Ok(set_metric_factor_legacy(stream, metric_factor)))
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
