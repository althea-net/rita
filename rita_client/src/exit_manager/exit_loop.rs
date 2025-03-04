use super::utils::get_babel_routes;
use super::{ExitManager, LastExitStates};
use crate::exit_manager::exit_selector::select_best_exit;
use crate::exit_manager::requests::exit_status_request;
use crate::exit_manager::requests::get_exit_list;
use crate::exit_manager::time_sync::maybe_set_local_to_exit_time;
use crate::exit_manager::utils::{
    correct_default_route, get_client_pub_ipv6, has_exit_changed, linux_setup_exit_tunnel,
    remove_nat, restore_nat,
};
use crate::traffic_watcher::{query_exit_debts, QueryExitDebts};
use actix::System as AsyncSystem;
use althea_kernel_interface::ip_addr::setup_ipv6_slaac as setup_ipv6_slaac_ki;
use althea_kernel_interface::ip_route::get_default_route;
use althea_types::ExitDetails;
use althea_types::{ExitIdentity, ExitState};
use rita_common::blockchain_oracle::low_balance;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

pub const EXIT_LOOP_SPEED: Duration = Duration::from_secs(5);
/// How often we make a exit status request for registered exits. Prevents us from bogging up exit processing
/// power
const STATUS_REQUEST_QUERY: Duration = Duration::from_secs(600);

/// This asnyc loop runs functions related to Exit management.
pub fn start_exit_manager_loop(exit_state_ref: Arc<RwLock<ExitManager>>) {
    thread::spawn(move || {
        let babel_port = settings::get_rita_client().network.babel_port;
        let runner = AsyncSystem::new();

        runner.block_on(async move {
            loop {
                let start = Instant::now();

                exit_manager_loop(exit_state_ref.clone(), babel_port).await;

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
            }
        });
    });
}

/// This function manages the lifecycle of exits, including updating our registration states, querying exit debts, and setting up exit tunnels.
async fn exit_manager_loop(em_state: Arc<RwLock<ExitManager>>, babel_port: u16) {
    info!("Exit_Switcher: exit manager tick");
    let client_can_use_free_tier = { settings::get_rita_client().payment.client_can_use_free_tier };

    handle_exit_switching(em_state.clone(), babel_port).await;

    let registration_state = em_state.read().unwrap().get_exit_registration_state();
    let currently_selected = em_state.read().unwrap().get_current_exit();

    // if there is no current exit, we can't setup- wait for the next tick/until we have a verified exit list.
    // handle_exit_switching will populate the verified_exit_list to get a selected exit if it can reach one.
    if let (Some(general_details), Some(selected_exit)) = (
        registration_state.general_details(),
        currently_selected.clone(),
    ) {
        {
            let mut em_state = em_state.write().unwrap();
            setup_exit_tunnel(
                selected_exit.clone(),
                general_details,
                registration_state.clone(),
                em_state.last_exit_state.clone(),
            );

            // Set last state vairables
            em_state.last_exit_state = Some(LastExitStates {
                last_exit: selected_exit.clone(),
                last_exit_details: registration_state.clone(),
            });

            em_state.nat_setup = setup_nat(em_state.nat_setup, client_can_use_free_tier);
        }

        // check the exit's time and update locally if it's very different
        maybe_set_local_to_exit_time(selected_exit.clone()).await;
        // run billing at all times when an exit is setup
        run_exit_billing(general_details, &selected_exit, registration_state.clone()).await;
    }

    handle_exit_status_request(currently_selected, registration_state.clone(), em_state).await;

    setup_ipv6_slaac(registration_state);
}

/// This function handles deciding if we need to switch exits, the new selected exit is returned. If no exit is selected, the current exit is returned.
async fn handle_exit_switching(em_state: Arc<RwLock<ExitManager>>, babel_port: u16) {
    // Get cluster exit list. This is saved locally and updated every tick depending on what exit we connect to.
    // When it is empty, it means an exit we connected to went down, and we use the list from memory to connect to a new instance
    let exit_list = match get_exit_list().await {
        Ok(a) => a.get_server_list(),
        Err(_) => {
            // try from saved verified exit list
            let rita_client = settings::get_rita_client();
            let exit_client = rita_client.exit_client;
            match exit_client.verified_exit_list.clone() {
                Some(list) => list,
                None => {
                    warn!("No verified exits");
                    return;
                }
            }
        }
    };

    // Calling set best exit function, this looks though a list of exit in a cluster, does some math, and determines what exit we should connect to
    trace!("Using exit list: {:?}", exit_list);
    let mut em_state = em_state.write().unwrap();
    select_best_exit(&mut em_state.exit_switcher_state, exit_list, babel_port)
}

fn setup_exit_tunnel(
    selected_exit: ExitIdentity,
    general_details: &ExitDetails,
    registration_state: ExitState,
    last_exit_states: Option<LastExitStates>,
) -> bool {
    // Determine states to setup tunnels
    let exit_has_changed = has_exit_changed(
        last_exit_states,
        selected_exit.clone(),
        registration_state.clone(),
    );
    let signed_up_for_exit = registration_state.our_details();

    let default_route = match get_default_route() {
        Ok(a) => a,
        Err(e) => {
            error!("Failed to get default route: {:?}", e);
            return false;
        }
    };
    let correct_default_route = correct_default_route(default_route);

    info!(
        "Exit change status: signed_up: {:?}, exit_has_changed: {:?}, correct_default_route {:?}",
        signed_up_for_exit, exit_has_changed, correct_default_route
    );
    match (signed_up_for_exit, exit_has_changed, correct_default_route) {
        (Some(details), true, _) => {
            trace!("Exit change, setting up exit tunnel");
            linux_setup_exit_tunnel(selected_exit, &general_details.clone(), details)
                .expect("failure setting up exit tunnel");
            true
        }
        (Some(details), false, false) => {
            trace!("DHCP overwrite setup exit tunnel again");
            linux_setup_exit_tunnel(selected_exit, &general_details.clone(), details)
                .expect("failure setting up exit tunnel");
            true
        }
        (None, _, _) => {
            trace!("Not signed up for exit, not setting up exit tunnel");
            false
        }
        // no op case, nothing to do here
        (Some(_), false, true) => true,
    }
}

async fn run_exit_billing(
    general_details: &ExitDetails,
    exit: &ExitIdentity,
    reg_state: ExitState,
) {
    if reg_state.our_details().is_none() {
        return;
    }

    let exit_price = general_details.clone().exit_price;
    let exit_internal_addr = general_details.clone().server_internal_ip;
    let exit_port = exit.registration_port;
    let exit_id = exit.into();
    let babel_port = settings::get_rita_client().network.babel_port;
    info!("We are signed up for the selected exit!");
    let routes = match get_babel_routes(babel_port) {
        Ok(a) => a,
        Err(_) => {
            error!("No babel routes present to query exit debts");
            thread::sleep(EXIT_LOOP_SPEED);
            return;
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

fn setup_nat(nat_setup: bool, client_can_use_free_tier: bool) -> bool {
    // Adds and removes the nat rules in low balance situations
    // this prevents the free tier from being confusing (partially working)
    // when deployments are not interested in having a sufficiently fast one
    let low_balance = low_balance();
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
            false
        }
        // restore when our balance is not low and our nat is not setup
        // regardless of the free tier value
        (false, _, false) => {
            trace!("restoring exit tunnel!");
            restore_nat();
            true
        }
        // restore if the nat is not setup and the free tier is enabled
        // this only happens when settings change under the hood
        (true, true, false) => {
            trace!("restoring exit tunnel!");
            restore_nat();
            true
        }
        _ => nat_setup,
    }
}

async fn handle_exit_status_request(
    current_exit: Option<ExitIdentity>,
    registration_state: ExitState,
    em_state: Arc<RwLock<ExitManager>>,
) {
    // code that manages requesting details, we make this query to a single exit in a cluster.
    // as they will all have the same registration state, but different individual ip or other info
    let mut exit_status_requested = false;
    let curr_exit = match current_exit {
        Some(a) => a,
        None => {
            trace!("No exit selected, can't request status");
            return;
        }
    };
    match registration_state {
        // Once one exit is registered, this moves all exits from New -> Registered
        // Giving us an internal ipv4 and ipv6 address for each exit in our config
        ExitState::New { .. } => {
            trace!(
                "Exit {} is in state NEW, calling general details",
                curr_exit.mesh_ip
            );
            let _ = exit_status_request(curr_exit, em_state.clone()).await;
        }
        // For routers that register normally, (not through ops), New -> Pending. In this state, we
        // continue to query until we reach Registered
        ExitState::Pending { .. } => {
            trace!(
                "Exit {} is in state Pending, calling status request",
                curr_exit.mesh_ip
            );
            let _ = exit_status_request(curr_exit, em_state.clone()).await;
        }
        ExitState::Registered { .. } => {
            trace!(
                "Exit {} is in state Registered, calling status request",
                curr_exit.mesh_ip
            );
            // Make a status request every STATUS_REQUEST_QUERY seconds
            let last_query = { em_state.clone().read().unwrap().last_status_request };
            if let Some(last_query) = last_query {
                if Instant::now() - last_query > STATUS_REQUEST_QUERY {
                    exit_status_requested = true;
                    let _ = exit_status_request(curr_exit, em_state.clone()).await;
                }
            } else {
                exit_status_requested = true;
                let _ = exit_status_request(curr_exit, em_state.clone()).await;
            }
        }
        ExitState::Denied { .. } => {
            trace!(
                "Exit {} is in state Denied, calling status request",
                curr_exit.mesh_ip
            );
            let _ = exit_status_request(curr_exit, em_state.clone()).await;
        }
    }
    if exit_status_requested {
        em_state.write().unwrap().last_status_request = Some(Instant::now());
    }
}

fn setup_ipv6_slaac(exit_state: ExitState) {
    // This block runs after an exit manager tick (an exit is selected),
    // and looks at the ipv6 subnet assigned to our router in the ExitState struct
    // which should be present after requesting general status from a registered exit.
    // This subnet is then added the lan network interface on the router to be used by slaac
    // And the subnet ip /128 is assigned to wg_exit as 'our own' ip
    trace!("Setting up ipv6 for slaac");
    if let Some(ipv6_sub) = get_client_pub_ipv6(exit_state) {
        trace!("setting up slaac with {:?}", ipv6_sub);
        setup_ipv6_slaac_ki(ipv6_sub)
    }
}
