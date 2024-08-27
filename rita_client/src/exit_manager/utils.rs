use crate::exit_manager::DEFAULT_WG_LISTEN_PORT;
use crate::heartbeat::get_exit_registration_state;
use crate::heartbeat::get_selected_exit_server;
use crate::RitaClientError;
use actix_web_async::Result;
use althea_kernel_interface::{
    exit_client_tunnel::ClientExitTunnelConfig, DefaultRoute, KernelInterfaceError,
};
use althea_types::exit_identity_to_id;
use althea_types::ExitClientDetails;
use althea_types::ExitDetails;
use althea_types::ExitListV2;
use althea_types::ExitState;
use babel_monitor::structs::Route;
use ipnetwork::IpNetwork;
use rita_common::KI;
use settings::client::ExitServer;
use settings::set_rita_client;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use super::LastExitStates;

pub fn linux_setup_exit_tunnel(
    general_details: &ExitDetails,
    our_details: &ExitClientDetails,
) -> Result<(), RitaClientError> {
    let mut rita_client = settings::get_rita_client();
    let mut network = rita_client.network;
    let local_mesh_ip = network.mesh_ip;

    // TODO this should be refactored to return a value
    KI.update_settings_route(&mut network.last_default_route)?;
    info!("Updated settings route");

    if let Err(KernelInterfaceError::RuntimeError(v)) = KI.create_blank_wg_interface("wg_exit") {
        return Err(RitaClientError::MiscStringError(v));
    }

    let selected_exit = get_selected_exit_server().expect("There should be a selected exit here");
    let args = ClientExitTunnelConfig {
        endpoint: SocketAddr::new(
            selected_exit.exit_id.mesh_ip,
            selected_exit.wg_exit_listen_port,
        ),
        pubkey: selected_exit.exit_id.wg_public_key,
        private_key_path: network.wg_private_key_path.clone(),
        listen_port: DEFAULT_WG_LISTEN_PORT,
        local_ip: our_details.client_internal_ip,
        netmask: general_details.netmask,
        rita_hello_port: network.rita_hello_port,
        user_specified_speed: network.user_bandwidth_limit,
    };

    info!("Args while setting up wg_exit on client are: {:?}", args);

    rita_client.network = network;
    settings::set_rita_client(rita_client);

    KI.set_client_exit_tunnel_config(args, local_mesh_ip)?;
    KI.set_route_to_tunnel(&general_details.server_internal_ip)?;
    KI.set_ipv6_route_to_tunnel()?;

    KI.create_client_nat_rules()?;

    Ok(())
}

pub fn restore_nat() {
    if let Err(e) = KI.restore_client_nat() {
        error!("Failed to restore client nat! {:?}", e);
    }
}

pub fn remove_nat() {
    if let Err(e) = KI.block_client_nat() {
        error!("Failed to block client nat! {:?}", e);
    }
}

/// When we retrieve an exit list from an exit, add the compatible exits to the exit server list.
/// This allows these exits to move to GotInfo state, allowing us to switch or connect quickly
pub fn add_exits_to_exit_server_list(list: ExitListV2) {
    let mut rita_client = settings::get_rita_client();
    let mut exits = rita_client.exit_client.bootstrapping_exits;

    for e in list.exit_list {
        exits.entry(e.mesh_ip).or_insert(ExitServer {
            exit_id: exit_identity_to_id(e.clone()),
            registration_port: e.registration_port,
            wg_exit_listen_port: e.wg_exit_listen_port,
        });
    }

    // Update settings with new exits
    rita_client.exit_client.bootstrapping_exits = exits;
    set_rita_client(rita_client);
}

pub fn correct_default_route(input: Option<DefaultRoute>) -> bool {
    match input {
        Some(v) => v.is_althea_default_route(),
        None => false,
    }
}

/// This function takes a list of babel routes and uses this to insert ip -> route
/// instances in the hashmap. This is an optimization that allows us to reduce route lookups from O(n * m ) to O(m + n)
/// when trying to find exit ips in our cluster
pub fn get_routes_hashmap(routes: Vec<Route>) -> HashMap<IpAddr, Route> {
    let mut ret = HashMap::new();
    for r in routes {
        ret.insert(r.prefix.ip(), r);
    }

    ret
}

pub fn get_client_pub_ipv6() -> Option<IpNetwork> {
    let exit_info = get_exit_registration_state();
    if let ExitState::Registered { our_details, .. } = exit_info {
        return our_details.internet_ipv6_subnet;
    }
    None
}

/// Verfies if exit has changed to reestablish wg tunnels
/// 1.) When exit instance ip has changed
/// 2.) Exit reg details have chaged
pub fn has_exit_changed(
    last_states: LastExitStates,
    selected_exit: IpAddr,
    current_reg_state: ExitState,
) -> bool {
    let last_exit = last_states.last_exit;

    let instance_has_changed = !(last_exit.is_some() && last_exit.unwrap() == selected_exit);

    let last_exit_details = last_states.last_exit_details;
    let exit_reg_has_changed =
        !(last_exit_details.is_some() && last_exit_details.unwrap() == current_reg_state);

    instance_has_changed | exit_reg_has_changed
}
