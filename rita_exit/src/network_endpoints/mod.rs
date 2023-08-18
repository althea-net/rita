//! Network endpoints for rita-exit that are not dashboard or local infromational endpoints
//! these are called by rita instances to operate the mesh

use crate::database::{client_status, get_exit_info, signup_client};
use crate::get_clients_exit_cluster_list;
#[cfg(feature = "development")]
use crate::rita_exit::database::db_client::DbClient;
#[cfg(feature = "development")]
use crate::rita_exit::database::db_client::TruncateTables;

use crate::RitaExitError;
#[cfg(feature = "development")]
use actix::SystemService;
#[cfg(feature = "development")]
use actix_web::AsyncResponder;
use actix_web_async::{http::StatusCode, web::Json, HttpRequest, HttpResponse, Result};
use althea_types::{
    EncryptedExitClientIdentity, EncryptedExitState, ExitClientIdentity, ExitState, ExitSystemTime,
};
use althea_types::{EncryptedExitList, Identity};
use althea_types::{ExitList, WgKey};
use num256::Int256;
use rita_common::blockchain_oracle::potential_payment_issues_detected;
use rita_common::debt_keeper::get_debts_list;
use rita_common::payment_validator::calculate_unverified_payments;
use settings::get_rita_exit;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::Nonce;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::SecretKey;
use std::net::SocketAddr;
use std::time::SystemTime;

/// helper function for returning from secure_setup_request()
fn secure_setup_return(
    ret: ExitState,
    our_secretkey: &SecretKey,
    their_pubkey: PublicKey,
) -> Json<EncryptedExitState> {
    let plaintext = serde_json::to_string(&ret)
        .expect("Failed to serialize ExitState!")
        .into_bytes();
    let nonce = box_::gen_nonce();
    let ciphertext = box_::seal(&plaintext, &nonce, &their_pubkey, our_secretkey);
    Json(EncryptedExitState {
        nonce: nonce.0,
        encrypted_exit_state: ciphertext,
    })
}

enum DecryptResult {
    Success(Box<ExitClientIdentity>),
    Failure(Result<Json<EncryptedExitState>, RitaExitError>),
}

fn decrypt_exit_client_id(
    val: EncryptedExitClientIdentity,
    our_secretkey: &SecretKey,
) -> DecryptResult {
    let their_wg_pubkey = val.pubkey;
    let their_nacl_pubkey = val.pubkey.into();
    let their_nonce = Nonce(val.nonce);
    let ciphertext = val.encrypted_exit_client_id;

    let decrypted_bytes =
        match box_::open(&ciphertext, &their_nonce, &their_nacl_pubkey, our_secretkey) {
            Ok(value) => value,
            Err(e) => {
                error!(
                    "Error decrypting exit setup request for {} with {:?}",
                    their_wg_pubkey, e
                );
                let state = ExitState::Denied {
                    message: "could not decrypt your message!".to_string(),
                };
                return DecryptResult::Failure(Ok(secure_setup_return(
                    state,
                    our_secretkey,
                    their_nacl_pubkey,
                )));
            }
        };

    let decrypted_string = match String::from_utf8(decrypted_bytes) {
        Ok(value) => value,
        Err(e) => {
            error!(
                "Error decrypting exit setup request for {} with {:?}",
                their_wg_pubkey, e
            );
            let state = ExitState::Denied {
                message: "could not decrypt your message!".to_string(),
            };
            return DecryptResult::Failure(Ok(secure_setup_return(
                state,
                our_secretkey,
                their_nacl_pubkey,
            )));
        }
    };

    let decrypted_id = match serde_json::from_str(&decrypted_string) {
        Ok(value) => value,
        Err(e) => {
            error!(
                "Error deserializing exit setup request for {} with {:?}",
                their_wg_pubkey, e
            );
            let state = ExitState::Denied {
                message: "could not deserialize your message!".to_string(),
            };
            return DecryptResult::Failure(Ok(secure_setup_return(
                state,
                our_secretkey,
                their_nacl_pubkey,
            )));
        }
    };

    DecryptResult::Success(Box::new(decrypted_id))
}

pub async fn secure_setup_request(
    request: (Json<EncryptedExitClientIdentity>, HttpRequest),
) -> HttpResponse {
    let exit_settings = get_rita_exit();
    let our_secretkey: WgKey = exit_settings.exit_network.wg_private_key;
    let our_secretkey = our_secretkey.into();

    let their_wg_pubkey = request.0.pubkey;
    let their_nacl_pubkey = request.0.pubkey.into();
    let socket = request.1;
    let decrypted_id = match decrypt_exit_client_id(request.0.into_inner(), &our_secretkey) {
        DecryptResult::Success(val) => val,
        DecryptResult::Failure(val) => match val {
            Ok(val) => return HttpResponse::Ok().json(val),
            Err(_) => return HttpResponse::InternalServerError().finish(),
        },
    };

    info!("Received Encrypted setup request from, {}", their_wg_pubkey);

    let remote_mesh_socket: SocketAddr = match socket.peer_addr() {
        Some(val) => val,
        None => {
            error!(
                "Error in exit setup for {} malformed packet header!",
                their_wg_pubkey,
            );
            return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(format!(
                "Error in exit setup for {their_wg_pubkey} malformed packet header!"
            ));
        }
    };

    let client_mesh_ip = decrypted_id.global.mesh_ip;
    let client = decrypted_id;

    let remote_mesh_ip = remote_mesh_socket.ip();
    if remote_mesh_ip == client_mesh_ip {
        let result = signup_client(*client).await;
        match result {
            Ok(exit_state) => HttpResponse::Ok().json(secure_setup_return(
                exit_state,
                &our_secretkey,
                their_nacl_pubkey,
            )),
            Err(e) => {
                error!("Signup client failed with {:?}", e);
                HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
                    .json(format!("Signup client failed with {e:?}"))
            }
        }
    } else {
        let state = ExitState::Denied {
            message: "The request ip does not match the signup ip".to_string(),
        };
        HttpResponse::Ok().json(secure_setup_return(
            state,
            &our_secretkey,
            their_nacl_pubkey,
        ))
    }
}

pub async fn secure_status_request(request: Json<EncryptedExitClientIdentity>) -> HttpResponse {
    let exit_settings = get_rita_exit();
    let our_secretkey: WgKey = exit_settings.exit_network.wg_private_key;
    let our_secretkey = our_secretkey.into();

    let their_wg_pubkey = request.pubkey;
    let their_nacl_pubkey = request.pubkey.into();
    let decrypted_id = match decrypt_exit_client_id(request.into_inner(), &our_secretkey) {
        DecryptResult::Success(val) => val,
        DecryptResult::Failure(val) => match val {
            Ok(val) => return HttpResponse::Ok().json(val),
            Err(_) => return HttpResponse::InternalServerError().finish(),
        },
    };
    trace!("got status request from {}", their_wg_pubkey);

    let state = match client_status(*decrypted_id) {
        Ok(state) => state,
        Err(e) => match *e {
            RitaExitError::NoClientError => {
                return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
                    .json(format!("{their_wg_pubkey} is not yet registered"));
            }
            e => {
                error!(
                    "Internal error in client status for {} with {:?}",
                    their_wg_pubkey, e
                );
                return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).json(format!(
                    "Internal error in client status for {their_wg_pubkey} with {e:?}"
                ));
            }
        },
    };
    HttpResponse::Ok().json(secure_setup_return(
        state,
        &our_secretkey,
        their_nacl_pubkey,
    ))
}

pub async fn get_exit_info_http(_req: HttpRequest) -> HttpResponse {
    HttpResponse::Ok().json(ExitState::GotInfo {
        general_details: get_exit_info(),
        message: "Got info successfully".to_string(),
    })
}

pub async fn get_exit_timestamp_http(_req: HttpRequest) -> HttpResponse {
    HttpResponse::Ok().json(ExitSystemTime {
        system_time: SystemTime::now(),
    })
}

/// This function takes a list of exit ips in a cluster from its config, signs the list and
/// sends it to the client
pub async fn get_exit_list(request: Json<EncryptedExitClientIdentity>) -> HttpResponse {
    let exit_settings = get_rita_exit();
    let our_secretkey: WgKey = exit_settings.exit_network.wg_private_key;
    let our_secretkey = our_secretkey.into();

    let their_nacl_pubkey = request.pubkey.into();

    let ret: ExitList = ExitList {
        exit_list: get_clients_exit_cluster_list(request.pubkey),
        wg_exit_listen_port: settings::get_rita_exit().exit_network.wg_v2_tunnel_port,
    };

    let plaintext = serde_json::to_string(&ret)
        .expect("Failed to serialize Vec of ips!")
        .into_bytes();
    let nonce = box_::gen_nonce();
    let ciphertext = box_::seal(&plaintext, &nonce, &their_nacl_pubkey, &our_secretkey);
    HttpResponse::Ok().json(Json(EncryptedExitList {
        nonce: nonce.0,
        exit_list: ciphertext,
    }))
}

/// Used by clients to get their debt from the exits. While it is in theory possible for the
/// client to totally compute their own bill it's not possible for the exit and the client
/// to agree on the billed amount in the presence of packet loss. Normally Althea is pay per forward
/// which means packet loss simply resolves to overpayment, but the exit is being paid for uploaded traffic
/// (the clients download traffic) which breaks this assumption
/// TODO secure this endpoint with libsodium
pub async fn get_client_debt(client: Json<Identity>) -> HttpResponse {
    let client = client.into_inner();
    let neg_one: i32 = -1;
    let neg_one = Int256::from(neg_one);
    let zero: Int256 = 0u8.into();

    // if we detect payment issues and development mode is not enabled, return zero
    // to prevent overpayment
    if potential_payment_issues_detected() {
        warn!("Potential payment issue detected");
        return HttpResponse::Ok().json(zero);
    }

    // these are payments to us, remember debt is positive when we owe and negative when we are owed
    // this value is being presented to the client router who's debt is positive (they owe the exit) so we
    // want to make it negative
    let unverified_payments_uint = calculate_unverified_payments(client);
    let unverified_payments = unverified_payments_uint.to_int256().unwrap();

    let debts = get_debts_list();
    for debt in debts {
        if debt.identity == client {
            let client_debt = debt.payment_details.debt;
            let incoming_payments = debt.payment_details.incoming_payments;

            let we_owe_them = client_debt > zero;
            let they_owe_more_than_in_queue = if we_owe_them {
                false
            } else {
                (neg_one * client_debt).to_uint256().unwrap() > unverified_payments_uint
            };

            // they have more credit than they owe, wait for this to unwind
            // we apply credit right before enforcing or on payment.
            if !we_owe_them && incoming_payments > (neg_one * client_debt).to_uint256().unwrap() {
                return HttpResponse::Ok().json(zero);
            }

            match (we_owe_them, they_owe_more_than_in_queue) {
                // in this case we owe them, return zero
                (true, _) => return HttpResponse::Ok().json(zero),
                // they owe us more than is in the queue
                (false, true) => {
                    // client debt is negative, they owe us, so we make it positive and subtract
                    // the unverified payments, which we're sure are less than or equal to the debt
                    let ret = (client_debt * neg_one) - unverified_payments;
                    return HttpResponse::Ok().json(ret);
                }
                // they owe us less than what is in the queue, return zero
                (false, false) => return HttpResponse::Ok().json(zero),
            }
        }
    }
    HttpResponse::NotFound().json("No client by that ID")
}
