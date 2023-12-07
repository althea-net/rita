//! Independent loop for operator updates, this prevents errors in the rita fast loop from causing the
//! router to become unresponsive to updates or reboot instructions

use crate::operator_update::{operator_update, TARGET_UPDATE_FREQUENCY, UPDATE_FREQUENCY_CAP};
use actix_async::System as AsyncSystem;
use althea_kernel_interface::KI;
use rand::Rng;
use std::cmp::{max, min};
use std::thread;
use std::time::{Duration, Instant};

/// This function spawns a thread soley responsible for performing the operator update
/// the sends large format data to operator tools (versus the heartbeat which is about 1200 bytes)
/// this update also gets instructions from operator tools, such as updates, reboots, or any OperatorAction
#[allow(unused_assignments)]
pub fn start_operator_update_loop() {
    let mut last_restart = Instant::now();
    let mut wait_unti_next_update = TARGET_UPDATE_FREQUENCY;
    // outer thread is a watchdog inner thread is the runner
    thread::spawn(move || {
        // this will always be an error, so it's really just a loop statement
        // with some fancy destructuring
        while let Err(e) = {
            thread::spawn(move || {
                let mut rng = rand::thread_rng();
                let mut ops_last_seen_usage_hour: Option<u64> = None;

                loop {
                    let start = Instant::now();
                    trace!("Update loop tick!");

                    let runner = AsyncSystem::new();
                    runner.block_on(async {
                        // timeout should never exceed this amount, beyond here we want to back off, but not
                        // wait that long for a response
                        let timeout = min(Duration::from_secs(120), wait_unti_next_update);
                        // Check in with Operatortools
                        match operator_update(ops_last_seen_usage_hour, timeout).await {
                            Ok(last) => {
                                // update the last seen usage hour so we send the next segment of data
                                // in the next loop, or none at all
                                ops_last_seen_usage_hour = Some(last);
                                // successful checkin, reduce wait if needed
                                wait_unti_next_update =
                                    max(wait_unti_next_update / 2, TARGET_UPDATE_FREQUENCY);
                            }
                            Err(()) => {
                                // failed checkin, backoff with a random multiplier the goal of random backoff
                                // is to prevent collisions
                                wait_unti_next_update = min(
                                    wait_unti_next_update * rng.gen_range(1..4),
                                    UPDATE_FREQUENCY_CAP,
                                );
                            }
                        }
                    });

                    info!(
                        "Operator Update loop completed in {}s {}ms with next checkin target of {}s",
                        start.elapsed().as_secs(),
                        start.elapsed().subsec_millis(),
                        wait_unti_next_update.as_secs()
                    );

                    thread::sleep(wait_unti_next_update);
                }
            })
            .join()
        } {
            error!(
                "Rita Operator Update loop thread paniced! Respawning {:?}",
                e
            );
            if Instant::now() - last_restart < Duration::from_secs(60) {
                error!("Restarting too quickly, rebooting instead!");
                let _res = KI.run_command("reboot", &[]);
            }
            last_restart = Instant::now();
        }
    });
}
