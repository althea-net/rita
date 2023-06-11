use super::exit_switcher::{get_babel_routes, set_best_exit};
use super::ExitManager;
use crate::exit_manager::time_sync::maybe_set_local_to_exit_time;
use crate::exit_manager::{
    correct_default_route, exit_general_details_request, exit_status_request, get_client_pub_ipv6,
    get_cluster_ip_list, get_full_selected_exit, get_routes_hashmap, initialize_selected_exit_list,
    linux_setup_exit_tunnel, remove_nat, restore_nat, run_ping_test, set_exit_list,
};
use crate::traffic_watcher::{query_exit_debts, QueryExitDebts};
use actix_async::System as AsyncSystem;
use althea_types::ExitList;
use althea_types::ExitState;
use althea_types::Identity;
use futures::future::join_all;
use futures::join;
use rita_common::blockchain_oracle::low_balance;
use rita_common::KI;

use std::thread;
use std::time::{Duration, Instant};

const EXIT_LOOP_SPEED: Duration = Duration::from_secs(5);
const PING_TEST_SPEED: Duration = Duration::from_secs(100);
const REBOOT_TIMEOUT: Duration = Duration::from_secs(600);

/// This asnyc loop runs functions related to Exit management.
pub fn start_exit_manager_loop() {
    let mut last_restart = Instant::now();
    // outer thread is a watchdog inner thread is the runner
    thread::spawn(move || {
        // this will always be an error, so it's really just a loop statement
        // with some fancy destructuring
        while let Err(e) = {
            thread::spawn(move || {
                // Our Exit state variable
                let em_state = &mut ExitManager::default();
                let runner = AsyncSystem::new();

                runner.block_on(async move {
                    loop {
                        let start = Instant::now();

                        // update the client exit manager, which handles exit registrations
                        // and manages the exit state machine in general. This includes
                        // updates to the local ip and description from the exit side
                        info!("Exit_Switcher: exit manager tick");
                        let client_can_use_free_tier = { settings::get_rita_client().payment.client_can_use_free_tier };
                        //  Get mut rita client to setup exits
                        let rita_client = settings::get_rita_client();
                        let current_exit = match rita_client.clone().exit_client.current_exit {
                            Some(a) => a,
                            None => "".to_string(),
                        };
                        let last_exit = em_state.last_exit;
                        let mut exits = rita_client.exit_client.exits;
                        // Initialize all exits ip addrs in local lazy static if they havent been set already
                        for (k, s) in exits.clone() {
                            initialize_selected_exit_list(k, s);
                        }
                        let exit_ser_ref = exits.get_mut(&current_exit);
                        // code that connects to the current exit server
                        info!("About to setup exit tunnel!");
                        if let Some(exit) = exit_ser_ref {
                            info!("We have selected an exit!, {:?}", exit.clone());
                            if let Some(general_details) = exit.clone().info.general_details() {
                                info!("We have details for the selected exit!");
                                // Logic to determnine what the best exit is and if we should switch
                                let babel_port = settings::get_rita_client().network.babel_port;
                                let routes = match get_babel_routes(babel_port) {
                                    Ok(a) => a,
                                    Err(_) => {
                                        warn!("No babel routes present to setup an exit");
                                        Vec::new()
                                    }
                                };

                                // Run this ping test every PING_TEST_SPEED seconds
                                if Instant::now() - em_state.last_connection_time > PING_TEST_SPEED {
                                    if run_ping_test() {
                                        em_state.last_connection_time = Instant::now();
                                    } else {
                                         // If this router has been in a bad state for >10 mins, reboot
                                         if (Instant::now() - em_state.last_connection_time) > REBOOT_TIMEOUT {
                                            let _res = KI.run_command("reboot", &[]);
                                        }
                                    }
                                }

                                // Get cluster exit list. This is saved locally and updated every tick depending on what exit we connect to.
                                // When it is empty, it means an exit we connected to went down, and we use the list from memory to connect to a new instance
                                let exit_list = match get_cluster_ip_list(current_exit.clone()).await {
                                    Ok(a) => a,
                                    Err(e) => {
                                        error!("Exit_Switcher: Unable to get exit list: {:?}", e);

                                        ExitList {
                                            exit_list: Vec::new(),
                                            wg_exit_listen_port: 0,
                                        }
                                    }
                                };
                                info!(
                                    "Received a cluster exit list from the exit: {:?}",
                                    exit_list
                                );
                                let exit_wg_port = exit_list.wg_exit_listen_port;
                                let is_valid = set_exit_list(exit_list, em_state);
                                // When the list is empty or the port is 0, the exit services us
                                // an invalid struct or we made a bad request
                                if !is_valid || exit_wg_port == 0 {
                                    error!("Received an invalid exit list!")
                                }
                                // Set all babel routes in a hashmap that we use to instantly get the route object of the exit we are trying to
                                // connect to
                                let ip_route_hashmap = get_routes_hashmap(routes);
                                // Calling set best exit function, this looks though a list of exit in a cluster, does some math, and determines what exit we should connect to
                                let exit_list = em_state.exit_list.clone();
                                info!("Exit_Switcher: Calling set best exit");
                                let selected_exit =
                                    match set_best_exit(current_exit.clone(), &exit_list, ip_route_hashmap) {
                                        Ok(a) => Some(a),
                                        Err(e) => {
                                            warn!("Found no exit yet : {}", e);
                                            thread::sleep(EXIT_LOOP_SPEED);
                                            continue;
                                        }
                                    };
                                info!("Exit_Switcher: After selecting best exit this tick, we have selected_exit_details: {:?}", get_full_selected_exit(current_exit.clone()));
                                em_state.last_exit = selected_exit;
                                // check the exit's time and update locally if it's very different
                                maybe_set_local_to_exit_time(exit.clone(), current_exit.clone()).await;
                                // Determine states to setup tunnels
                                let signed_up_for_exit = exit.info.our_details().is_some();
                                let exit_has_changed = !(last_exit.is_some()
                                    && selected_exit.is_some()
                                    && last_exit.unwrap() == selected_exit.unwrap());

                                let default_route = match KI.get_default_route() {
                                    Ok(route) => route,
                                    Err(e) => {
                                        error!("Failed to get default route, skipping exit switcher loop {:?}", e);
                                        continue;
                                    },
                                };
                                let correct_default_route = correct_default_route(default_route);
                                let current_exit_id = selected_exit;
                                info!("Reaches this part of the code: signed_up: {:?}, exit_has_changed: {:?}, correct_default_route {:?}", signed_up_for_exit, exit_has_changed, correct_default_route);
                                match (signed_up_for_exit, exit_has_changed, correct_default_route) {
                                    (true, true, _) => {
                                        trace!("Exit change, setting up exit tunnel");
                                        linux_setup_exit_tunnel(
                                            current_exit,
                                            &general_details.clone(),
                                            exit.info.our_details().unwrap(),
                                            &exit_list,
                                        )
                                        .expect("failure setting up exit tunnel");
                                        em_state.nat_setup = true;
                                    }
                                    (true, false, false) => {
                                        trace!("DHCP overwrite setup exit tunnel again");
                                        linux_setup_exit_tunnel(
                                            current_exit,
                                            &general_details.clone(),
                                            exit.info.our_details().unwrap(),
                                            &exit_list,
                                        )
                                        .expect("failure setting up exit tunnel");
                                        em_state.nat_setup = true;
                                    }
                                    _ => {}
                                }
                                // Adds and removes the nat rules in low balance situations
                                // this prevents the free tier from being confusing (partially working)
                                // when deployments are not interested in having a sufficiently fast one
                                let low_balance = low_balance();
                                let nat_setup = em_state.nat_setup;
                                trace!(
                                    "client can use free tier {} low balance {}",
                                    client_can_use_free_tier,
                                    low_balance
                                );
                                match (low_balance, client_can_use_free_tier, nat_setup) {
                                    // remove when we have a low balance, do not have a free tier
                                    // and have a nat setup.
                                    (true, false, true) => {
                                        trace!("removing exit tunnel!");
                                        remove_nat();
                                        em_state.nat_setup = false;
                                    }
                                    // restore when our balance is not low and our nat is not setup
                                    // regardless of the free tier value
                                    (false, _, false) => {
                                        trace!("restoring exit tunnel!");
                                        restore_nat();
                                        em_state.nat_setup = true;
                                    }
                                    // restore if the nat is not setup and the free tier is enabled
                                    // this only happens when settings change under the hood
                                    (true, true, false) => {
                                        trace!("restoring exit tunnel!");
                                        restore_nat();
                                        em_state.nat_setup = true;
                                    }
                                    _ => {}
                                }
                                // run billing at all times when an exit is setup
                                if signed_up_for_exit {
                                    let exit_price = general_details.clone().exit_price;
                                    let exit_internal_addr = general_details.clone().server_internal_ip;
                                    let exit_port = exit.registration_port;
                                    let exit_id = Identity::new(
                                        current_exit_id.expect("There should be a selected mesh ip here"),
                                        exit.eth_address,
                                        exit.wg_public_key,
                                        None,
                                    );
                                    let babel_port = settings::get_rita_client().network.babel_port;
                                    info!("We are signed up for the selected exit!");
                                    let routes = match get_babel_routes(babel_port) {
                                        Ok(a) => a,
                                        Err(_) => {
                                            error!("No babel routes present to query exit debts");
                                            thread::sleep(EXIT_LOOP_SPEED);
                                            continue;
                                        }
                                    };
                                    query_exit_debts(QueryExitDebts {
                                        exit_id,
                                        exit_price,
                                        routes,
                                        exit_internal_addr,
                                        exit_port,
                                    })
                                    .await;
                                }
                            }
                        }
                        // code that manages requesting details to exits, run in parallel becuse they respond slowly
                        let mut general_requests = Vec::new();
                        let mut status_requests = Vec::new();
                        let servers = { settings::get_rita_client().exit_client.exits };
                        for (k, s) in servers {
                            match s.info {
                                ExitState::New { .. } => {
                                    trace!("Exit {} is in state NEW, calling general details", k);
                                    general_requests.push(exit_general_details_request(k.clone()))
                                },
                                // now that Operator tools can register clients, we perform status update on GotInfo to check if
                                // Ops has registered us. This will move our GotInfo -> Registered state for an exit
                                ExitState::GotInfo { .. } => {
                                    trace!("Exit {} is in state GotInfo, calling status request", k);
                                    status_requests.push(exit_status_request(k.clone()))
                                },
                                // For routers that register normally, (not through ops), GotInfo -> Pending. In this state, we 
                                // continue to query until we reach Registered
                                ExitState::Pending { .. } => {
                                    trace!("Exit {} is in state Pending, calling status request", k);
                                    status_requests.push(exit_status_request(k.clone()));
                                },
                                ExitState::Registered { .. } => {
                                    trace!("Exit {} is in state Registered, calling status request", k);
                                    status_requests.push(exit_status_request(k.clone()));
                                },
                                _ => {
                                    trace!("Exit {} is in state {:?} calling status request", k, s.info);
                                }
                            }
                        }
                        join!(join_all(general_requests), join_all(status_requests));

                        // This block runs after an exit manager tick (an exit is selected),
                        // and looks at the ipv6 subnet assigned to our router in the ExitState struct
                        // which should be present after requesting general status from a registered exit.
                        // This subnet is then added the lan network interface on the router to be used by slaac
                        // And the subnet ip /128 is assigned to wg_exit as 'our own' ip
                        trace!("Setting up ipv6 for slaac");
                        if let Some(ipv6_sub) = get_client_pub_ipv6() {
                            trace!("setting up slaac with {:?}", ipv6_sub);
                            KI.setup_ipv6_slaac(ipv6_sub)
                        }

                        // sleep until it has been FAST_LOOP_SPEED seconds from start, whenever that may be
                        // if it has been more than FAST_LOOP_SPEED seconds from start, go right ahead
                        info!("Exit Manager loop elapsed in = {:?}", start.elapsed());
                        if start.elapsed() < EXIT_LOOP_SPEED {
                            info!(
                                "Exit Manager sleeping for {:?}",
                                EXIT_LOOP_SPEED - start.elapsed()
                            );
                            thread::sleep(EXIT_LOOP_SPEED - start.elapsed());
                        }
                        info!("Exit Manager sleeping Done!");
                    }
                });
            })
            .join()
        } {
            error!(
                "Rita client Exit Manager loop thread paniced! Respawning {:?}",
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
