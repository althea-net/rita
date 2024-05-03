use super::time_sync::maybe_set_local_to_exit_time;
use super::utils::linux_setup_exit_tunnel;
use actix_async::System;
use althea_kernel_interface::KI;
use babel_monitor::get_babel_routes_and_neighbors;
use rita_common::FAST_LOOP_TIMEOUT;
use std::{
    thread,
    time::{Duration, Instant},
};
use rita_common::utils::compute_next_loop_time;

/// How often the exit manager loop runs, this is a target speed, if the loop takes longer than this
/// to actually execute it will end up running less often
const EXIT_LOOP_SPEED: Duration = Duration::from_secs(30);

/// The exit manager loop performs 3 main functions, checking in with the exit servers
/// as provided by the Exit database. Using this info to select which of the available exits
/// this router would like to use. Setting up the exit tunnel to this selected exit and maintaining it
/// if the internal ip changes or the best exit changes. Finally a time sync function to keep the router
/// type as correct as possible.
pub fn start_exit_manager_loop() {

    // guard against impossible configuration
    if settings::get_rita_client().exit_client.bootstrapping_exits.is_empty() {
        panic!("No bootstrapping exits! Impossible to bootstrap to a successful connection!, provide at least one!")
    }

    // start by setting up the exit tunnel, panic on failure, if we are not registered to
    // an exit this will be a no-op. It's important to do this outside of the loop to minimize
    // startup time in the common case where a router is already registered to an exit
    linux_setup_exit_tunnel().expect("Failed to setup exit tunnel");

    // get the babel port from the settings, this won't change at runtime so no reason to get it multiple times
    let babel_port = settings::get_rita_client().network.babel_port;

    let mut last_restart = Instant::now();
    // outer thread is a watchdog inner thread is the runner
    thread::spawn(move || {
        // this will always be an error, so it's really just a loop statement
        // with some fancy destructuring
        while let Err(e) = {
            thread::spawn(move || {
                loop {
                    let start = Instant::now();
                    let runner = System::new();

                    // get babel routes once per instance of this loop to check for the best exit, and if our selected is the best
                    let babel_routes_and_neighbors =
                        get_babel_routes_and_neighbors(babel_port, FAST_LOOP_TIMEOUT);
                        
                    // async part of the loop, making requests to the exit server or servers
                    runner.block_on(async {

                        // ok at this stage we need to get the exit list, compare to routes list and select the best exit
                        // or setup an exit in the first place if registration has completed since we first ran

                        // problems, how do we handle which exit to request the list from and how to update the list
                        // in the future to ensure we eventually have a successful query. Do we just want to round robin?

                        // Potential downsides would be that the round robin might not include some exits, we assume they are all functoining
                        // properly and that might not always be the case

                        // we need to pick an ip for this, to do that we need to have the exit selected
                        // check the exit's time and update locally if it's very different
                        maybe_set_local_to_exit_time().await;
                    });

                    info!("Exit Manager loop elapsed in = {:?}", start.elapsed());
                    thread::sleep(compute_next_loop_time(start, EXIT_LOOP_SPEED));
                }
            })
            .join()
        } {
            error!(
                "Rita client Exit Manager loop thread paniced! Respawning {:?}",
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


