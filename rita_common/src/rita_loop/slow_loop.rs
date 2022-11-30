use crate::simulated_txfee_manager::tick_simulated_tx;
use crate::token_bridge::tick_token_bridge;
use crate::tunnel_manager::tm_monitor_check;
use actix_async::System as AsyncSystem;
use babel_monitor::open_babel_stream;
use babel_monitor::parse_interfaces;
use babel_monitor::set_local_fee;
use babel_monitor::set_metric_factor;
use std::thread;
use std::time::Duration;
use std::time::Instant;

/// the speed in seconds for the common loop
pub const SLOW_LOOP_SPEED: Duration = Duration::from_secs(60);
pub const SLOW_LOOP_TIMEOUT: Duration = Duration::from_secs(15);

pub fn start_rita_slow_loop() {
    let mut last_restart = Instant::now();
    thread::spawn(move || {
        // this will always be an error, so it's really just a loop statement
        // with some fancy destructuring
        while let Err(e) = {
            thread::spawn(move || loop {
                info!("Common Slow tick!");

                let runner = AsyncSystem::new();
                runner.block_on(async move {
                    info!("Ticking token bridge");
                    tick_token_bridge().await;
                    info!("Ticking simulated tx!");
                    tick_simulated_tx().await;
                    info!("Common Slow tick async completed!");
                    AsyncSystem::current().stop();
                });

                // we really only need to run this on startup, but doing so periodically
                // could catch the edge case where babel is restarted under us
                set_babel_price();

                // This checks that all tunnels are attached to babel. This may not be the case when babel restarts
                let babel_port = settings::get_rita_common().network.babel_port;
                if let Ok(mut stream) = open_babel_stream(babel_port, SLOW_LOOP_TIMEOUT) {
                    let babel_interfaces = parse_interfaces(&mut stream);
                    tm_monitor_check(&babel_interfaces);
                }

                thread::sleep(SLOW_LOOP_SPEED);
                info!("Common Slow tick completed!");
            })
            .join()
        } {
            error!("Rita common slow loop thread panicked! Respawning {:?}", e);
            if Instant::now() - last_restart < Duration::from_secs(120) {
                error!("Restarting too quickly, leaving it to auto rescue!");
                let sys = AsyncSystem::current();
                sys.stop_with_code(121);
            }
            last_restart = Instant::now();
        }
    });
}

fn set_babel_price() {
    let start = Instant::now();
    let common = settings::get_rita_common();
    let babel_port = common.network.babel_port;
    let local_fee = common.payment.local_fee;
    let metric_factor = common.network.metric_factor;
    let stream = open_babel_stream(babel_port, SLOW_LOOP_TIMEOUT);
    match stream {
        Ok(mut stream) => {
            let result = set_local_fee(&mut stream, local_fee);
            if let Err(e) = result {
                warn!(
                    "Failed to set local fee with {} in {} ms",
                    e,
                    start.elapsed().as_millis()
                )
            }
            let result = set_metric_factor(&mut stream, metric_factor);
            if let Err(e) = result {
                warn!(
                    "Failed to set metric factor with {} in {} ms",
                    e,
                    start.elapsed().as_millis()
                )
            }
        }
        Err(e) => warn!(
            "Failed to open babel stream to set price with {:?} in {}ms",
            e,
            start.elapsed().as_millis()
        ),
    }
}
