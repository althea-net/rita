//! Independent loop for operator updates

use crate::operator_update::{operator_update, UPDATE_FREQUENCY};
use actix_async::System as AsyncSystem;
use std::thread;
use std::time::{Duration, Instant};

/// This function spawns a thread soley responsible for performing the operator update
pub fn start_operator_update_loop() {
    let mut last_restart = Instant::now();
    let rita_started = Instant::now();
    // outer thread is a watchdog inner thread is the runner
    thread::spawn(move || {
        // this will always be an error, so it's really just a loop statement
        // with some fancy destructuring
        while let Err(e) = {
            thread::spawn(move || loop {
                let start = Instant::now();
                trace!("exit Update loop tick!");

                let runner = AsyncSystem::new();
                runner.block_on(async move {
                    // Check in with Operator
                    operator_update(rita_started).await;
                });

                info!(
                    "exit Operator Update loop completed in {}s {}ms",
                    start.elapsed().as_secs(),
                    start.elapsed().subsec_millis()
                );

                thread::sleep(UPDATE_FREQUENCY);
            })
            .join()
        } {
            error!(
                "Rita exit Operator Update loop thread paniced! Respawning {:?}",
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
