//! Independent loop for operator updates, this prevents errors in the rita fast loop from causing the
//! router to become unresponsive to updates or reboot instructions

use crate::operator_update::operator_update;
use crate::rita_loop::CLIENT_LOOP_SPEED;
use actix_async::System as AsyncSystem;
use std::thread;
use std::time::{Duration, Instant};

/// This function spawns a thread soley responsible for performing the operator update
/// the sends large format data to operator tools (versus the heartbeat which is about 1200 bytes)
/// this update also gets instructions from operator tools, such as updates, reboots, or any OperatorAction
pub fn start_operator_update_loop() {
    let mut last_restart = Instant::now();
    // outer thread is a watchdog inner thread is the runner
    thread::spawn(move || {
        // this will always be an error, so it's really just a loop statement
        // with some fancy destructuring
        while let Err(e) = {
            thread::spawn(move || loop {
                let start = Instant::now();
                trace!("Update loop tick!");

                let runner = AsyncSystem::new();
                runner.block_on(async move {
                    // Check in with Operator
                    operator_update().await;
                });

                info!(
                    "Operator Update loop completed in {}s {}ms",
                    start.elapsed().as_secs(),
                    start.elapsed().subsec_millis()
                );

                // sleep until it has been CLIENT_LOOP_SPEED seconds from start, whenever that may be
                // if it has been more than CLIENT_LOOP_SPEED seconds from start, go right ahead
                let update_loop_speed = Duration::from_secs(CLIENT_LOOP_SPEED);
                if start.elapsed() < update_loop_speed {
                    thread::sleep(update_loop_speed - start.elapsed());
                }
            })
            .join()
        } {
            error!(
                "Rita Operator Update loop thread paniced! Respawning {:?}",
                e
            );
            if Instant::now() - last_restart < Duration::from_secs(60) {
                error!("Restarting too quickly, leaving it to auto rescue!");
                let sys = AsyncSystem::current();
                sys.stop_with_code(121);
            }
            last_restart = Instant::now();
        }
    });
}
