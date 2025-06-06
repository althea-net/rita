use super::LastExitStates;
use crate::rita_loop::CLIENT_LOOP_TIMEOUT;
use crate::RitaClientError;
use actix_web::Result;
use althea_kernel_interface::exit_client_tunnel::{
    block_client_nat, create_client_nat_rules, restore_client_nat, set_client_exit_tunnel_config,
    set_ipv6_route_to_tunnel, set_route_to_tunnel,
};
use althea_kernel_interface::ip_route::update_settings_route;
use althea_kernel_interface::setup_wg_if::create_blank_wg_interface;
use althea_kernel_interface::{
    exit_client_tunnel::ClientExitTunnelConfig, DefaultRoute, KernelInterfaceError,
};
use althea_types::ExitClientDetails;
use althea_types::ExitDetails;
use althea_types::ExitIdentity;
use althea_types::ExitState;
use babel_monitor::open_babel_stream;
use babel_monitor::parse_routes;
use babel_monitor::structs::Route;
use ipnetwork::IpNetwork;
use rita_common::CLIENT_WG_PORT;
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
    update_settings_route(&mut network.last_default_route)?;
    info!("Updated settings route");

    if let Err(KernelInterfaceError::RuntimeError(v)) = create_blank_wg_interface("wg_exit") {
        return Err(RitaClientError::MiscStringError(v));
    }

    info!(
        "Got wg exit listen port as: {}",
        selected_exit.wg_exit_listen_port
    );
    let args = ClientExitTunnelConfig {
        endpoint: SocketAddr::new(selected_exit.mesh_ip, selected_exit.wg_exit_listen_port),
        pubkey: selected_exit.wg_key,
        private_key_path: network.wg_private_key_path.clone(),
        listen_port: CLIENT_WG_PORT,
        local_ip: our_details.client_internal_ip,
        netmask: general_details.netmask,
        rita_hello_port: network.rita_hello_port,
        user_specified_speed: network.user_bandwidth_limit,
    };

    info!("Args while setting up wg_exit on client are: {:?}", args);

    rita_client.network = network;
    settings::set_rita_client(rita_client);

    set_client_exit_tunnel_config(args, local_mesh_ip)?;
    set_route_to_tunnel(&general_details.server_internal_ip)?;
    set_ipv6_route_to_tunnel()?;

    create_client_nat_rules()?;

    Ok(())
}

pub fn restore_nat() {
    if let Err(e) = restore_client_nat() {
        error!("Failed to restore client nat! {:?}", e);
    }
}

pub fn remove_nat() {
    if let Err(e) = block_client_nat() {
        error!("Failed to block client nat! {:?}", e);
    }
}

pub fn correct_default_route(input: Option<DefaultRoute>) -> bool {
    match input {
        Some(v) => v.is_althea_default_route(),
        None => false,
    }
}

pub fn get_client_pub_ipv6(exit_info: ExitState) -> Option<IpNetwork> {
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
