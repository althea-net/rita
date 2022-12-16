//! This is the primary actor loop for rita-client, where periodic tasks are spawned and Actors are
//! tied together with message calls.
//!
//! This loop manages exit signup based on the settings configuration state and deploys an exit vpn
//! tunnel if the signup was successful on the selected exit.

use crate::exit_manager::exit_manager_tick;
use crate::exit_manager::get_selected_exit;
use crate::heartbeat::send_heartbeat_loop;
use crate::heartbeat::HEARTBEAT_SERVER_KEY;
use crate::light_client_manager::lcm_watch;
use crate::light_client_manager::light_client_hello_response;
use crate::light_client_manager::Watch;
use crate::operator_fee_manager::tick_operator_payments;
use crate::traffic_watcher::get_exit_dest_price;
use actix_async::System as AsyncSystem;
use actix_web_async::web;
use actix_web_async::{App, HttpServer};
use althea_kernel_interface::KI;
use althea_types::ExitState;
use antenna_forwarding_client::start_antenna_forwarding_proxy;
use rita_common::rita_loop::set_gateway;
use rita_common::tunnel_manager::tm_get_neighbors;
use rita_common::tunnel_manager::tm_get_tunnels;
use settings::client::RitaClientSettings;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Seek;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// The maximum size in bytes an babel log is allowed to be, 5MB
const MAX_LOG_SIZE: u64 = 5 * 1000 * 1000;

lazy_static! {
    /// see the comment on check_for_gateway_client_billing_corner_case()
    /// to identify why this variable is needed. In short it identifies
    /// a specific billing corner case.
    static ref IS_GATEWAY_CLIENT: AtomicBool = AtomicBool::new(false);
}

pub fn is_gateway_client() -> bool {
    IS_GATEWAY_CLIENT.load(Ordering::Relaxed)
}

pub fn set_gateway_client(input: bool) {
    IS_GATEWAY_CLIENT.store(input, Ordering::Relaxed)
}

/// This function determines if metrics are permitted for this device, if the user has
/// disabled logging we should not send any logging data. If they are a member of a network
/// with an operator address this overrides the logging setting to ensure metrics are sent.
/// Since an operator address indicates an operator that is being paid for supporting this user
/// and needs info to assist them. The logging setting may be inspected to disable metrics
/// not required for a normal operator
pub fn metrics_permitted() -> bool {
    settings::get_rita_client().log.enabled
        || settings::get_rita_client()
            .operator
            .operator_address
            .is_some()
}

// the speed in seconds for the client loop
pub const CLIENT_LOOP_SPEED: Duration = Duration::from_secs(5);
pub const CLIENT_LOOP_TIMEOUT: Duration = Duration::from_secs(4);

/// Rita loop thread spawning function, there are currently two rita loops, one that
/// runs as a thread with async/await support and one that runs as a actor using old futures
/// slowly things will be migrated into this new sync loop as we move to async/await
pub fn start_rita_loop() {
    let mut last_restart = Instant::now();

    // outer thread is a watchdog inner thread is the runner
    thread::spawn(move || {
        // this will always be an error, so it's really just a loop statement
        // with some fancy destructuring

        while let Err(e) = {
            thread::spawn(move || loop {
                let start = Instant::now();
                trace!("Client tick!");

                let runner = AsyncSystem::new();
                runner.block_on(async move {
                    manage_gateway();
                    info!(
                        "Rita Client loop manage gateway in {}s {}ms",
                        start.elapsed().as_secs(),
                        start.elapsed().subsec_millis()
                    );

                    manage_babeld_logs();
                    info!(
                        "Rita Client loop manage babeld in {}s {}ms",
                        start.elapsed().as_secs(),
                        start.elapsed().subsec_millis()
                    );

                    let exit_dest_price = get_exit_dest_price();
                    let tunnels = tm_get_tunnels().unwrap();
                    info!(
                        "Rita Client loop get tunnels in {}s {}ms",
                        start.elapsed().as_secs(),
                        start.elapsed().subsec_millis()
                    );

                    lcm_watch(Watch {
                        tunnels,
                        exit_dest_price,
                    });

                    check_for_gateway_client_billing_corner_case();
                    info!(
                        "Rita Client loop corner case in {}s {}ms",
                        start.elapsed().as_secs(),
                        start.elapsed().subsec_millis()
                    );
                    // update the client exit manager, which handles exit registrations
                    // and manages the exit state machine in general. This includes
                    // updates to the local ip and description from the exit side
                    exit_manager_tick().await;
                    info!(
                        "Rita Client loop exit manager completed in {}s {}ms",
                        start.elapsed().as_secs(),
                        start.elapsed().subsec_millis()
                    );
                    // sends an operator payment if enough time has elapsed
                    tick_operator_payments().await;
                    info!(
                        "Rita Client loop operator payments completed in {}s {}ms",
                        start.elapsed().as_secs(),
                        start.elapsed().subsec_millis()
                    );
                });

                info!(
                    "Rita Client loop completed in {}s {}ms",
                    start.elapsed().as_secs(),
                    start.elapsed().subsec_millis()
                );

                thread::sleep(CLIENT_LOOP_SPEED);
            })
            .join()
        } {
            error!("Rita client loop thread paniced! Respawning {:?}", e);
            if Instant::now() - last_restart < Duration::from_secs(60) {
                error!("Restarting too quickly, leaving it to auto rescue!");
                let sys = AsyncSystem::current();
                sys.stop_with_code(121);
            }
            last_restart = Instant::now();
        }
    });
}

pub fn start_rita_client_loops() {
    if metrics_permitted() {
        send_heartbeat_loop();
    }
    crate::rita_loop::start_rita_loop();
    crate::operator_update::update_loop::start_operator_update_loop();
}

/// There is a complicated corner case where the gateway is a client and a relay to
/// the same exit, this will produce incorrect billing data as we need to reconcile the
/// relay bills (under the exit relay id) and the client bills (under the exit id) versus
/// the exit who just has the single billing id for the client and is combining debts
/// This function grabs neighbors and determines if we have a neighbor with the same mesh ip
/// and eth address as our selected exit, if we do we trigger the special case handling
fn check_for_gateway_client_billing_corner_case() {
    let res = tm_get_neighbors();
    // strange notation lets us scope our access to SETTING and prevent
    // holding a readlock
    let exit_server = {
        settings::get_rita_client()
            .exit_client
            .get_current_exit()
            .cloned()
    };
    let rita_client = settings::get_rita_client();
    let current_exit = match rita_client.exit_client.current_exit {
        Some(a) => a,
        None => "".to_string(),
    };
    let neighbors = res;
    if let Some(exit) = exit_server {
        if let ExitState::Registered { .. } = exit.info {
            for neigh in neighbors {
                info!("Neighbor is {:?}", neigh);
                // we have a neighbor who is also our selected exit!
                // wg_key excluded due to multihomed exits having a different one
                let current_ip = get_selected_exit(current_exit.clone())
                    .expect("If registered, there should be an exit ip here");
                if neigh.identity.global.mesh_ip == current_ip
                    && neigh.identity.global.eth_address == exit.eth_address
                {
                    info!("We are a gateway client");
                    set_gateway_client(true);
                    return;
                }
            }
            info!("We are NOT a gateway client");
            set_gateway_client(false);
        }
    }
}

pub fn start_rita_client_endpoints(workers: usize) {
    // listen on the light client gateway ip if it's not none
    thread::spawn(move || {
        let runner = AsyncSystem::new();
        runner.block_on(async move {
            if let Some(gateway_ip) = settings::get_rita_client().network.light_client_router_ip {
                trace!("Listening for light client hellos on {}", gateway_ip);
                let unstarted_server = HttpServer::new(|| {
                    App::new().route(
                        "/light_client_hello",
                        web::post().to(light_client_hello_response),
                    )
                })
                .workers(workers)
                .bind(format!(
                    "{}:{}",
                    gateway_ip,
                    settings::get_rita_client().network.light_client_hello_port
                ));
                if let Ok(val) = unstarted_server {
                    info!("Starting client endpoint: light client");
                    let _res = val.shutdown_timeout(0).run().await;
                } else {
                    trace!("Failed to bind to light client ip, probably toggled off!")
                }
            }
        });
    });
}

pub fn start_antenna_forwarder(settings: RitaClientSettings) {
    if metrics_permitted() {
        let url: &str;
        if cfg!(feature = "dev_env") {
            url = "0.0.0.0:33300";
        } else if cfg!(feature = "operator_debug") {
            url = "192.168.10.2:33334";
        } else {
            url = "operator.althea.net:33334";
        }

        let our_id = settings.get_identity().unwrap();
        let network = settings.network;
        let mut interfaces = network.peer_interfaces.clone();
        interfaces.insert("br-pbs".to_string());
        start_antenna_forwarding_proxy(
            url.to_string(),
            our_id,
            *HEARTBEAT_SERVER_KEY,
            network.wg_public_key.unwrap(),
            network.wg_private_key.unwrap(),
            interfaces,
        );
    }
}

/// Manages gateway functionality and maintains the gateway parameter, this is different from the gateway
/// identification in rita_client because this must function even if we aren't registered for an exit it's also
/// very prone to being true when the device has a wan port but no actual wan connection.
fn manage_gateway() {
    // Resolves the gateway client corner case
    // Background info here https://forum.altheamesh.com/t/the-gateway-client-corner-case/35
    // the is_up detection is mostly useless because these ports reside on switches which mark
    // all ports as up all the time.
    let gateway = match settings::get_rita_common().network.external_nic {
        Some(ref external_nic) => KI.is_iface_up(external_nic).unwrap_or(false),
        None => false,
    };

    info!("We are a Gateway: {}", gateway);
    set_gateway(gateway);

    if gateway {
        let mut common = settings::get_rita_common();
        match KI.get_resolv_servers() {
            Ok(s) => {
                for ip in s.iter() {
                    trace!("Resolv route {:?}", ip);
                    KI.manual_peers_route(ip, &mut common.network.last_default_route)
                        .unwrap();
                }
                settings::set_rita_common(common);
            }
            Err(e) => warn!("Failed to add DNS routes with {:?}", e),
        }
    }
}

/// This function truncates babeld.log and sends them over to graylog to prevent memory getting full
fn manage_babeld_logs() {
    info!("Running babel log truncation loop");

    let log_file = "/tmp/log/babeld.log";
    let path = Path::new(log_file);
    let mut file = match File::open(path) {
        Ok(a) => a,
        Err(e) => {
            error!("Unable to truncate babel logs: {:?}", e);
            return;
        }
    };

    // Read file and log data
    let mut buf = String::new();
    match file.read_to_string(&mut buf) {
        Ok(_) => {
            for line in buf.lines() {
                info!("{} {}", log_file, line);
            }
        }
        Err(e) => {
            error!("Unable to truncate babel logs: {:?}", e);
            return;
        }
    }

    // truncating babeld logs
    if let Ok(metadata) = file.metadata() {
        // length of the file
        if metadata.len() > MAX_LOG_SIZE {
            info!(
                "File {} has exceeded {} bytes, truncating",
                log_file, MAX_LOG_SIZE
            );
            // our current file handle does not have write permissions, so we open a new
            // one in 'truncate' mode which means it clears out the entire file on open
            let mut options = OpenOptions::new();
            let path = Path::new(log_file);
            match options.write(true).truncate(true).open(path) {
                Ok(_) => {
                    // now that the file has been truncated we need to take our read only file
                    // handle and rewind it's internal pointer to the start otherwise we'll be
                    // trying to read at an offset longer than the file
                    match file.rewind() {
                        Ok(_) => info!("Log truncate {} successful!", log_file),
                        Err(e) => {
                            error!("Failed to truncate {} with {:?}", log_file, e)
                        }
                    }
                }
                Err(e) => error!("Failed to truncate {} logs with {:?}", log_file, e),
            }
        }
    } else {
        warn!("Failed to get metadata for log file {}", log_file)
    }
}
