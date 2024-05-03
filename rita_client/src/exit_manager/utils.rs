use crate::{rita_loop::CLIENT_LOOP_TIMEOUT, RitaClientError};
use althea_kernel_interface::{exit_client_tunnel::ClientExitTunnelConfig, KI};
use althea_types::{ExitClientIdentity, ExitListV2};
use babel_monitor::{open_babel_stream, parse_routes, structs::Route};
use rand::Rng;
use settings::client::{ExitServer, EXIT_CLIENT_LISTEN_PORT};
use std::net::SocketAddr;

/// Performs initial setup of the exit tunnel on the router, this function is called once on startup
/// and sets up the last exit tunnel used by the router by default
pub fn linux_setup_exit_tunnel() -> Result<(), RitaClientError> {
    let mut rita_client = settings::get_rita_client();
    let mut network = rita_client.network;
    let local_mesh_ip = network.mesh_ip;
    let (general_details, our_details) = match rita_client.exit_client.registration_state {
        _ => return Ok(()),
        althea_types::ExitState::Registered {
            general_details,
            our_details,
            message,
        } => (general_details, our_details),
    };

    KI.update_settings_route(&mut network.last_default_route)?;
    KI.create_blank_wg_interface("wg_exit")?;

    let args = ClientExitTunnelConfig {
        endpoint: SocketAddr::new(
            general_details.server_mesh_ip.into(),
            general_details.wg_exit_port,
        ),
        pubkey: general_details.server_wg_pubkey,
        private_key_path: network.wg_private_key_path.clone(),
        listen_port: EXIT_CLIENT_LISTEN_PORT,
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

/// Gets an exit from the bootstrapping list at random, this is used to round robin select an exit to query
pub fn pick_bootstrapping_exit_at_random() -> ExitServer {
    let rita_client = settings::get_rita_client();
    let len = rita_client.exit_client.bootstrapping_exits.len();
    let rand = rand::thread_rng().gen_range(0..len);
    rita_client
        .exit_client
        .bootstrapping_exits
        .iter()
        .nth(rand)
        .unwrap()
        .clone()
}

/// Hits the exit_list endpoint for a given exit, returning the exit list as configured
/// for that particular exit. For Postgres DB exits this will return the list in the config
/// for Solidity DB exits this will return the exits in the registration contract
async fn get_exit_list(server: ExitServer) -> Result<ExitListV2, RitaClientError> {
    let exit_pubkey = server.exit_id.wg_public_key;
    let ident = ExitClientIdentity {
        global: match settings::get_rita_client().get_identity() {
            Some(id) => id,
            None => {
                return Err(RitaClientError::NoMeshIpError)
            }
        },
        wg_port: server.registration_port,
        reg_details,
    };

    // TODO exit server should accept a json object that doesn't include the reg details
    // it's not needed for this request at all

    let exit_server = current_exit.exit_id.mesh_ip;

    let endpoint = format!(
        "http://[{}]:{}/exit_list_v2",
        exit_server, current_exit.registration_port
    );
    let ident = encrypt_exit_client_id(&exit_pubkey.into(), ident);

    let client = awc::Client::default();
    let response = client
        .post(&endpoint)
        .timeout(CLIENT_LOOP_TIMEOUT)
        .send_json(&ident)
        .await;
    let mut response = match response {
        Ok(a) => {
            reset_blacklist_warnings(exit_server);
            a
        }
        Err(awc::error::SendRequestError::Timeout) => {
            // Did not get a response, is it a rogue exit or some netork error?
            blacklist_strike_ip(exit_server, WarningType::SoftWarning);
            return Err(RitaClientError::SendRequestError(
                awc::error::SendRequestError::Timeout.to_string(),
            ));
        }
        Err(e) => return Err(RitaClientError::SendRequestError(e.to_string())),
    };

    let value = response.json().await?;

    match decrypt_exit_list(value, exit_pubkey.into()) {
        Err(e) => {
            blacklist_strike_ip(exit_server, WarningType::HardWarning);
            Err(e)
        }
        Ok(a) => {
            reset_blacklist_warnings(exit_server);
            Ok(a)
        }
    }
}