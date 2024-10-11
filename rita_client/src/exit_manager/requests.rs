use super::get_current_exit;
use super::DEFAULT_WG_LISTEN_PORT;
use crate::rita_loop::CLIENT_LOOP_TIMEOUT;
use crate::RitaClientError;
use actix_web_async::Result;
use althea_types::decrypt_exit_list;
use althea_types::decrypt_exit_state;
use althea_types::encrypt_exit_client_id;
use althea_types::ExitListV2;
use althea_types::WgKey;
use althea_types::{ExitClientIdentity, ExitRegistrationDetails, ExitState};
use settings::set_rita_client;
use std::net::{IpAddr, SocketAddr};

async fn send_exit_setup_request(
    exit_pubkey: WgKey,
    to: SocketAddr,
    ident: ExitClientIdentity,
) -> Result<ExitState, RitaClientError> {
    let endpoint = format!("http://[{}]:{}/secure_setup", to.ip(), to.port());
    let settings = settings::get_rita_client();
    let our_pubkey = settings.network.wg_public_key.unwrap();
    let our_privkey = settings.network.wg_private_key.unwrap();

    let ident = encrypt_exit_client_id(our_pubkey, &our_privkey.into(), &exit_pubkey.into(), ident);

    let client = awc::Client::default();

    let response = client
        .post(&endpoint)
        .timeout(CLIENT_LOOP_TIMEOUT)
        .send_json(&ident)
        .await;
    let mut response = match response {
        Ok(a) => a,
        Err(awc::error::SendRequestError::Timeout) => {
            return Err(RitaClientError::SendRequestError(
                awc::error::SendRequestError::Timeout.to_string(),
            ));
        }
        Err(e) => return Err(RitaClientError::SendRequestError(e.to_string())),
    };

    let value = response.json().await?;

    match decrypt_exit_state(&our_privkey.into(), value, &exit_pubkey.into()) {
        Err(e) => Err(e.into()),
        Ok(a) => Ok(a),
    }
}

async fn send_exit_status_request(
    exit_pubkey: WgKey,
    to: &SocketAddr,
    ident: ExitClientIdentity,
) -> Result<ExitState, RitaClientError> {
    let settings = settings::get_rita_client();
    let our_pubkey = settings.network.wg_public_key.unwrap();
    let our_privkey = settings.network.wg_private_key.unwrap();

    let endpoint = format!("http://[{}]:{}/secure_status", to.ip(), to.port());
    let ident = encrypt_exit_client_id(our_pubkey, &our_privkey.into(), &exit_pubkey.into(), ident);

    let client = awc::Client::default();
    let response = client
        .post(&endpoint)
        .timeout(CLIENT_LOOP_TIMEOUT)
        .send_json(&ident)
        .await;

    let mut response = match response {
        Ok(a) => a,
        Err(awc::error::SendRequestError::Timeout) => {
            // Did not get a response, is it a rogue exit or some netork error?
            return Err(RitaClientError::SendRequestError(
                awc::error::SendRequestError::Timeout.to_string(),
            ));
        }
        Err(e) => return Err(RitaClientError::SendRequestError(e.to_string())),
    };
    let value = response.json().await?;

    match decrypt_exit_state(&our_privkey.into(), value, &exit_pubkey.into()) {
        Err(e) => Err(e.into()),
        Ok(a) => Ok(a),
    }
}

/// Registration is simply one of the exits requesting an update to a global smart contract
/// with our information.
pub async fn exit_setup_request(code: Option<String>) -> Result<(), RitaClientError> {
    let client_settings = settings::get_rita_client();
    let exit = get_current_exit();

    match client_settings.exit_client.registration_state {
        ExitState::New { .. } | ExitState::Pending { .. } => {
            let exit_pubkey = exit.wg_key;

            let mut reg_details: ExitRegistrationDetails =
                match client_settings.payment.contact_info {
                    Some(val) => val.into(),
                    None => {
                        return Err(RitaClientError::MiscStringError(
                            "No registration info set!".to_string(),
                        ))
                    }
                };

            // Send a verification code if we have one
            reg_details.phone_code = code;

            let ident = ExitClientIdentity {
                global: match settings::get_rita_client().get_identity() {
                    Some(id) => id,
                    None => {
                        return Err(RitaClientError::MiscStringError(
                            "Identity has no mesh IP ready yet".to_string(),
                        ));
                    }
                },
                wg_port: DEFAULT_WG_LISTEN_PORT,
                reg_details,
            };

            let endpoint = SocketAddr::new(exit.mesh_ip, exit.registration_port);

            info!(
                "sending exit setup request {:?} to {:?}, using {:?}",
                ident, exit, endpoint
            );

            let exit_response = send_exit_setup_request(exit_pubkey, endpoint, ident).await?;

            info!("Setting an exit setup response");
            // we already have a loaded rita client settings above, but it could have been several seconds
            // since we loaded above, better to load a new copy just in case
            let mut client_settings = settings::get_rita_client();
            client_settings.exit_client.registration_state = exit_response;
            set_rita_client(client_settings);

            return Ok(());
        }
        ExitState::Denied { message } => {
            warn!(
                "Exit {} is in ExitState DENIED with {}, not able to be setup",
                exit.mesh_ip, message
            );
        }
        ExitState::Registered { .. } => {
            warn!("Exit {} already reports us as registered", exit.mesh_ip)
        }
    }

    Err(RitaClientError::MiscStringError(
        "Could not find a valid exit to register to!".to_string(),
    ))
}

pub async fn exit_status_request(exit: IpAddr) -> Result<(), RitaClientError> {
    let current_exit = match settings::get_rita_client()
        .exit_client
        .bootstrapping_exits
        .get(&exit)
    {
        Some(current_exit) => current_exit.clone(),
        None => {
            return Err(RitaClientError::NoExitError(exit.to_string()));
        }
    };
    let reg_details = match settings::get_rita_client().payment.contact_info {
        Some(val) => val.into(),
        None => {
            return Err(RitaClientError::MiscStringError(
                "No valid details".to_string(),
            ))
        }
    };

    let exit_pubkey = current_exit.wg_key;
    let ident = ExitClientIdentity {
        global: match settings::get_rita_client().get_identity() {
            Some(id) => id,
            None => {
                return Err(RitaClientError::MiscStringError(
                    "Identity has no mesh IP ready yet".to_string(),
                ));
            }
        },
        wg_port: DEFAULT_WG_LISTEN_PORT,
        reg_details,
    };

    let endpoint = SocketAddr::new(current_exit.mesh_ip, current_exit.registration_port);

    trace!(
        "sending exit status request to {} using {:?}",
        exit,
        endpoint
    );

    let exit_response = send_exit_status_request(exit_pubkey, &endpoint, ident).await?;
    let mut rita_client = settings::get_rita_client();
    rita_client.exit_client.registration_state = exit_response.clone();
    settings::set_rita_client(rita_client);

    trace!("Got exit status response {:?}", exit_response);
    Ok(())
}

/// Hits the exit_list endpoint for a given exit.
/// todo this is where we ask the exit for a new list (and do we have to decrypt it?)
pub async fn get_exit_list(exit: IpAddr) -> Result<ExitListV2, RitaClientError> {
    let current_exit = match settings::get_rita_client()
        .exit_client
        .bootstrapping_exits
        .get(&exit)
    {
        Some(current_exit) => current_exit.clone(),
        None => {
            return Err(RitaClientError::NoExitError(exit.to_string()));
        }
    };

    let exit_pubkey = current_exit.wg_key;
    let reg_details = match settings::get_rita_client().payment.contact_info {
        Some(val) => val.into(),
        None => {
            return Err(RitaClientError::MiscStringError(
                "No valid details".to_string(),
            ))
        }
    };
    let ident = ExitClientIdentity {
        global: match settings::get_rita_client().get_identity() {
            Some(id) => id,
            None => {
                return Err(RitaClientError::MiscStringError(
                    "Identity has no mesh IP ready yet".to_string(),
                ));
            }
        },
        wg_port: DEFAULT_WG_LISTEN_PORT,
        reg_details,
    };

    let exit_server = current_exit.wg_key;

    let endpoint = format!(
        "http://[{}]:{}/exit_list_v2",
        exit_server, current_exit.registration_port
    );
    let settings = settings::get_rita_client();
    let our_pubkey = settings.network.wg_public_key.unwrap();
    let our_privkey = settings.network.wg_private_key.unwrap();

    let ident = encrypt_exit_client_id(our_pubkey, &our_privkey.into(), &exit_pubkey.into(), ident);

    let client = awc::Client::default();
    let response = client
        .post(&endpoint)
        .timeout(CLIENT_LOOP_TIMEOUT)
        .send_json(&ident)
        .await;
    let mut response = match response {
        Ok(a) => a,
        Err(awc::error::SendRequestError::Timeout) => {
            // Did not get a response, is it a rogue exit or some netork error?
            return Err(RitaClientError::SendRequestError(
                awc::error::SendRequestError::Timeout.to_string(),
            ));
        }
        Err(e) => return Err(RitaClientError::SendRequestError(e.to_string())),
    };

    let value = response.json().await?;

    match decrypt_exit_list(&our_privkey.into(), value, &exit_pubkey.into()) {
        Err(e) => Err(e.into()),
        Ok(a) => Ok(a),
    }
}
