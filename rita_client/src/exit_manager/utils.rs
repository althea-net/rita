use super::LastExitStates;
use crate::exit_manager::DEFAULT_WG_LISTEN_PORT;
use crate::heartbeat::get_exit_registration_state;
use crate::rita_loop::CLIENT_LOOP_TIMEOUT;
use crate::RitaClientError;
use actix_web_async::Result;
use althea_kernel_interface::{
    exit_client_tunnel::ClientExitTunnelConfig, DefaultRoute, KernelInterfaceError,
};
use althea_types::ExitClientDetails;
use althea_types::ExitDetails;
use althea_types::ExitIdentity;
use althea_types::ExitListV2;
use althea_types::ExitState;
use babel_monitor::open_babel_stream;
use babel_monitor::parse_routes;
use babel_monitor::structs::Route;
use ipnetwork::IpNetwork;
use rita_common::KI;
use settings::set_rita_client;
use std::net::SocketAddr;

pub fn linux_setup_exit_tunnel(
    selected_exit: ExitIdentity,
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

    let args = ClientExitTunnelConfig {
        endpoint: SocketAddr::new(selected_exit.mesh_ip, selected_exit.wg_exit_listen_port),
        pubkey: selected_exit.wg_key,
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

/// This merges the exit list we get from the exit with our local bootstrapping list
/// TODO this is a temporary solution, instead we need to move to the new universal endpoint
/// design where each exit hosts a multihomed ip endpoint returning a signed list of bootstrapping
/// exits rather than each exit hosting a list of exits
pub fn merge_exit_lists(mut list: ExitListV2) -> ExitListV2 {
    let mut rita_client = settings::get_rita_client();
    let mut exits = rita_client.exit_client.bootstrapping_exits;

    info!("We have bootstrap exits: {:?}", exits);

    for e in list.exit_list.iter() {
        exits.entry(e.mesh_ip).or_insert(e.clone());
    }

    // Update settings with new exits
    rita_client.exit_client.bootstrapping_exits = exits.clone();
    set_rita_client(rita_client);

    for e in exits.iter() {
        list.exit_list.push(e.1.clone());
    }

    list
}

pub fn correct_default_route(input: Option<DefaultRoute>) -> bool {
    match input {
        Some(v) => v.is_althea_default_route(),
        None => false,
    }
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
    last_states: Option<LastExitStates>,
    selected_exit: ExitIdentity,
    current_reg_state: ExitState,
) -> bool {
    let last_states = match last_states {
        Some(a) => a,
        None => return true,
    };

    let last_exit = last_states.last_exit;
    let instance_has_changed = !(last_exit == selected_exit);

    let last_exit_details = last_states.last_exit_details;
    let exit_reg_has_changed = !(last_exit_details == current_reg_state);

    instance_has_changed | exit_reg_has_changed
}

/// Simple helper function that opens a babel stream to get all routes related to us. We can use these routes to
/// check which ips are exits and thereby register or setup exits
pub fn get_babel_routes(babel_port: u16) -> Result<Vec<Route>, RitaClientError> {
    let mut stream = match open_babel_stream(babel_port, CLIENT_LOOP_TIMEOUT) {
        Ok(a) => a,
        Err(_) => {
            return Err(RitaClientError::MiscStringError(
                "open babel stream error in exit manager tick".to_string(),
            ))
        }
    };
    let routes = match parse_routes(&mut stream) {
        Ok(a) => a,
        Err(_) => {
            return Err(RitaClientError::MiscStringError(
                "Parse routes error in exit manager tick".to_string(),
            ))
        }
    };

    Ok(routes)
}
