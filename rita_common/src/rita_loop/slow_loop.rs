use crate::simulated_txfee_manager::tick_simulated_tx;
use crate::tm_trigger_gc;
use crate::token_bridge::tick_token_bridge;
use crate::tunnel_manager::tm_monitor_check;
use crate::KI;
use crate::TUNNEL_HANDSHAKE_TIMEOUT;
use crate::TUNNEL_TIMEOUT;
use actix_async::System as AsyncSystem;
use althea_kernel_interface::hardware_info::get_hardware_info;
use babel_monitor::open_babel_stream;
use babel_monitor::parse_interfaces;
use babel_monitor::set_local_fee;
use babel_monitor::set_metric_factor;
use babel_monitor::structs::BabelMonitorError;
use settings::get_rita_client;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;
use std::time::Instant;

/// the speed in seconds for the common loop
pub const SLOW_LOOP_SPEED: Duration = Duration::from_secs(60);
pub const SLOW_LOOP_TIMEOUT: Duration = Duration::from_secs(15);
/// How many times we must fail to contact babel (consecutive) before we send a babel restart
pub const BABEL_RESTART_COUNT: usize = 10;

pub fn start_rita_slow_loop() {
    let mut last_restart = Instant::now();
    // the number of times we have failed to contact babel consecutively,
    // if this goes above BABEL_RESTART_COUNT we trigger a restart
    let mut num_babel_failures = 0;
    thread::spawn(move || {
        // this will always be an error, so it's really just a loop statement
        // with some fancy destructuring
        while let Err(e) = {
            thread::spawn(move || loop {
                let model = get_rita_client().network.device;
                let hw_info = get_hardware_info(model.clone());
                match (model, hw_info) {
                    (None, _) => error!("Model name not found?"),
                    (Some(mdl), Ok(info)) => {
                        if mdl.contains("mikrotik_hap-ac2") && info.load_avg_fifteen_minute > 4.0 {
                            info!("15 minute load average > 4, rebooting!");
                            let _res = KI.run_command("reboot", &[]);
                        }
                    },
                    (Some(_), Err(_)) => error!("Could not get hardware info!"),
                }

                info!("Common Slow tick!");
                let start = Instant::now();

                let runner = AsyncSystem::new();
                runner.block_on(async move {
                    info!("Ticking token bridge");
                    tick_token_bridge().await;
                    info!("Ticking simulated tx!");
                    tick_simulated_tx().await;
                    info!("Common Slow tick async completed!");
                    AsyncSystem::current().stop();
                });

                // This checks that all tunnels are attached to babel. This may not be the case when babel restarts
                let babel_port = settings::get_rita_common().network.babel_port;
                match open_babel_stream(babel_port, SLOW_LOOP_TIMEOUT) {
                    Ok(mut stream) => {
                        // we really only need to run this on startup, but doing so periodically
                        // could catch the edge case where babel is restarted under us
                        if let Err(e) = set_babel_price(&mut stream) {
                            warn!("Failed to set babel price with {:?}", e);
                            num_babel_failures += 1;
                        }

                        match parse_interfaces(&mut stream) {
                            Ok(babel_interfaces) => {
                                tm_monitor_check(&babel_interfaces);

                                trace!("Sending tunnel GC");
                                tm_trigger_gc(
                                    TUNNEL_TIMEOUT,
                                    TUNNEL_HANDSHAKE_TIMEOUT,
                                    babel_interfaces,
                                );

                                // reset failure count
                                num_babel_failures = 0;
                            }
                            Err(e) => {
                                num_babel_failures += 1;
                                error!(
                                    "Failed to parse babel interfaces in common slow loop with {:?}",
                                    e
                                );
                            }
                        }
                    },
                    Err(e) => {
                                num_babel_failures += 1;
                            error!(
                                "Failed to connect to babel in common slow loop with {:?}",
                                e
                            );

                    },
                }
                // auto recovery when babel crashes or otherwise behaves poorly
                num_babel_failures += 1;
                if num_babel_failures > BABEL_RESTART_COUNT {
                    error!("We have not successfully talked to babel in {} loop iterations, restarting babel", num_babel_failures);
                    // we restart babel here and then rely on the tm_monitor_check function to re-attach the tunnels in the next loop
                    // iteration
                    KI.restart_babel();
                }

                thread::sleep(SLOW_LOOP_SPEED);
                info!("Common Slow tick completed in {}s {}ms", 
                                start.elapsed().as_secs(),
                                start.elapsed().subsec_millis()
                );
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

fn set_babel_price(stream: &mut TcpStream) -> Result<(), BabelMonitorError> {
    let start = Instant::now();
    let common = settings::get_rita_common();
    let local_fee = common.payment.local_fee;
    let metric_factor = common.network.metric_factor;
    let result = set_local_fee(stream, local_fee);
    if let Err(e) = result {
        warn!(
            "Failed to set local fee with {} in {} ms",
            e,
            start.elapsed().as_millis()
        );
        return Err(e);
    }
    let result = set_metric_factor(stream, metric_factor);
    if let Err(e) = result {
        warn!(
            "Failed to set metric factor with {} in {} ms",
            e,
            start.elapsed().as_millis()
        );
        return Err(e);
    }
    Ok(())
}
