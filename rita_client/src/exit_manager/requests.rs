use super::ExitManager;
use crate::rita_loop::CLIENT_LOOP_TIMEOUT;
use crate::RitaClientError;
use actix_web::Result;
use althea_types::decrypt_exit_state;
use althea_types::encrypt_exit_client_id;
use althea_types::ExitIdentity;
use althea_types::SignedExitServerList;
use althea_types::WgKey;
use althea_types::{ExitClientIdentity, ExitRegistrationDetails, ExitState};
use rita_common::CLIENT_WG_PORT;
use settings::exit::EXIT_LIST_IP;
use settings::exit::EXIT_LIST_PORT;
use settings::get_registration_details;
use settings::get_rita_client;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

const EXIT_LIST_TIMEOUT: Duration = Duration::from_secs(20);
const EXIT_SETUP_TIMEOUT: Duration = Duration::from_secs(10);

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
        .timeout(EXIT_SETUP_TIMEOUT)
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
pub async fn exit_setup_request(
    em_ref: Arc<Arc<RwLock<ExitManager>>>,
    code: Option<String>,
) -> Result<(), RitaClientError> {
    let client_settings = settings::get_rita_client();

    info!("In exit setup request about to grab em_ref lock");
    // This is put into it's own scope to drop the lock as soon as possible
    // so that we don't hold it while waiting for the exit to respond
    let (exit, registration_state) = {
        let em_ref = em_ref.read().unwrap();
        (
            em_ref.get_current_exit(),
            em_ref.get_exit_registration_state(),
        )
    };
    info!("got the info from the lock");

    let exit = match exit {
        Some(exit) => exit,
        None => {
            return Err(RitaClientError::MiscStringError(
                "No exit selected".to_string(),
            ))
        }
    };

    match registration_state.clone() {
        ExitState::New | ExitState::Pending { .. } => {
            let exit_pubkey = exit.wg_key;

            let mut reg_details: ExitRegistrationDetails = match get_registration_details() {
                Some(val) => val,
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
                wg_port: CLIENT_WG_PORT,
                reg_details,
            };

            let endpoint = SocketAddr::new(exit.mesh_ip, exit.registration_port);

            info!(
                "sending exit setup request {:?} to {:?}, using {:?}",
                ident, exit, endpoint
            );

            let exit_response = send_exit_setup_request(exit_pubkey, endpoint, ident).await?;

            info!("Got exit setup response {:?}", exit_response);
            em_ref
                .write()
                .unwrap()
                .set_exit_registration_state(exit, exit_response.clone());

            Ok(())
        }
        ExitState::Denied { message } => {
            warn!(
                "Exit {} is in ExitState DENIED with {}, not able to be setup",
                exit.mesh_ip, message
            );
            error!(
                "Could not find a valid exit to register to! {:#?} {:#?}",
                client_settings.exit_client.verified_exit_list, registration_state
            );
            Err(RitaClientError::MiscStringError(
                "Could not find a valid exit to register to!".to_string(),
            ))
        }
        ExitState::Registered { .. } => {
            warn!("Exit {} already reports us as registered", exit.mesh_ip);
            Ok(())
        }
    }
}

pub async fn exit_status_request(
    exit: ExitIdentity,
    em_state: Arc<RwLock<ExitManager>>,
) -> Result<(), RitaClientError> {
    let exit_list = match settings::get_rita_client().exit_client.verified_exit_list {
        Some(list) => list,
        None => {
            return Err(RitaClientError::MiscStringError(
                "No verified exits".to_string(),
            ))
        }
    };

    let current_exit = match exit_list.find_exit(&exit) {
        Some(current_exit) => current_exit.clone(),
        None => {
            return Err(RitaClientError::NoExitError(exit.mesh_ip.to_string()));
        }
    };
    let reg_details = match get_registration_details() {
        Some(val) => val,
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
        wg_port: CLIENT_WG_PORT,
        reg_details,
    };

    let endpoint = SocketAddr::new(current_exit.mesh_ip, current_exit.registration_port);

    trace!(
        "sending exit status request to {} using {:?}",
        current_exit.mesh_ip,
        endpoint
    );

    let exit_response = send_exit_status_request(exit_pubkey, &endpoint, ident).await?;
    trace!("Got exit status response {:?}", exit_response);
    em_state
        .write()
        .unwrap()
        .set_exit_registration_state(exit, exit_response);
    Ok(())
}

/// Hits the exit_list endpoint
pub async fn get_exit_list() -> Result<SignedExitServerList, RitaClientError> {
    let endpoint = format!("http://[{}]:{}/exit_list", EXIT_LIST_IP, EXIT_LIST_PORT);
    let client = awc::Client::default();
    let response = client
        .post(&endpoint)
        .timeout(EXIT_LIST_TIMEOUT)
        .send()
        .await;
    let response = match response {
        Ok(mut response) => response.json().await,
        Err(awc::error::SendRequestError::Timeout) => {
            // Did not get a response, is it a rogue exit or some netork error?
            return Err(RitaClientError::SendRequestError(
                awc::error::SendRequestError::Timeout.to_string(),
            ));
        }
        Err(e) => {
            trace!("Failed to get exit list from exit {:?}", e);
            return Err(RitaClientError::SendRequestError(e.to_string()));
        }
    };

    let list: SignedExitServerList = match response {
        Ok(a) => a,
        Err(e) => {
            return Err(RitaClientError::MiscStringError(format!(
                "Failed to get exit list from exit payload {:?}",
                e
            )));
        }
    };

    let config = get_rita_client();
    let mut allowed_signers = config.exit_client.allowed_exit_list_signers;
    if cfg!(feature = "operator_debug") {
        // In test mode, we allow any signer
        allowed_signers.push(
            "0x34d97aaf58b1a81d3ed3068a870d8093c6341cf5d1ef7e6efa03fe7f7fc2c3a8"
                .parse()
                .unwrap(),
        );
    }

    trace!(
        "About to verify exit list signer and contract we are expecting {} and signer {:?}",
        config.exit_client.exit_db_smart_contract,
        allowed_signers
    );
    trace!(
        "We have the contract {} with signer {}",
        list.get_server_list().contract,
        list.get_signer()
    );

    // signature must both be valid, from a trusted signer and for the contract we asked for
    if list.verify()
        && allowed_signers.contains(&list.get_signer())
        && list.get_server_list().contract == config.exit_client.exit_db_smart_contract
    {
        // save list of verified exits
        let mut rita_client = settings::get_rita_client();
        rita_client.exit_client.verified_exit_list = Some(list.get_server_list());
        settings::set_rita_client(rita_client);
        return Ok(list);
    }
    Err(RitaClientError::MiscStringError(
        "Failed to verify exit list signature!".to_owned(),
    ))
}
