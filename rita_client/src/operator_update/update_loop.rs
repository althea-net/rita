//! Independent loop for operator updates, this prevents errors in the rita fast loop from causing the
//! router to become unresponsive to updates or reboot instructions

use crate::operator_update::{operator_update, UPDATE_FREQUENCY};
use actix_async::System as AsyncSystem;
use std::thread;
use std::time::{Duration, Instant};

/// This function spawns a thread soley responsible for performing the operator update
/// the sends large format data to operator tools (versus the heartbeat which is about 1200 bytes)
/// this update also gets instructions from operator tools, such as updates, reboots, or any OperatorAction
#[allow(unused_assignments)]
pub fn start_operator_update_loop() {
    let mut ops_last_seen_usage_hour: u64 = 0;
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
                    let last = operator_update(ops_last_seen_usage_hour).await;
                    ops_last_seen_usage_hour = last;
                });

                info!(
                    "Operator Update loop completed in {}s {}ms",
                    start.elapsed().as_secs(),
                    start.elapsed().subsec_millis()
                );

                thread::sleep(UPDATE_FREQUENCY);
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
