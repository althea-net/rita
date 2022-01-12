//! Network endpoints for rita-exit that are not dashboard or local infromational endpoints
//! these are called by rita instances to operate the mesh

use crate::database::database_tools::get_database_connection;
use crate::database::{client_status, get_exit_info, signup_client};
#[cfg(feature = "development")]
use crate::rita_exit::database::db_client::DbClient;
#[cfg(feature = "development")]
use crate::rita_exit::database::db_client::TruncateTables;

#[cfg(feature = "development")]
use actix::SystemService;
#[cfg(feature = "development")]
use actix_web::AsyncResponder;
use actix_web::{HttpRequest, HttpResponse, Json, Result};
use althea_types::Identity;
use althea_types::WgKey;
use althea_types::{
    EncryptedExitClientIdentity, EncryptedExitState, ExitClientIdentity, ExitState,
};
use futures01::future;
use futures01::Future;
use num256::Int256;
use rita_common::debt_keeper::get_debts_list;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::Nonce;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::SecretKey;
use std::net::SocketAddr;

use crate::{EXIT_WG_PRIVATE_KEY, RitaExitError};

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
    Success(ExitClientIdentity),
    Failure(Box<dyn Future<Item = Json<EncryptedExitState>, Error = RitaExitError>>),
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
                return DecryptResult::Failure(Box::new(future::ok(secure_setup_return(
                    state,
                    our_secretkey,
                    their_nacl_pubkey,
                ))));
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
            return DecryptResult::Failure(Box::new(future::ok(secure_setup_return(
                state,
                our_secretkey,
                their_nacl_pubkey,
            ))));
        }
    };

    let decrypted_id: ExitClientIdentity = match serde_json::from_str(&decrypted_string) {
        Ok(value) => value,
        Err(e) => {
            error!(
                "Error deserializing exit setup request for {} with {:?}",
                their_wg_pubkey, e
            );
            let state = ExitState::Denied {
                message: "could not deserialize your message!".to_string(),
            };
            return DecryptResult::Failure(Box::new(future::ok(secure_setup_return(
                state,
                our_secretkey,
                their_nacl_pubkey,
            ))));
        }
    };

    DecryptResult::Success(decrypted_id)
}

pub fn secure_setup_request(
    request: (Json<EncryptedExitClientIdentity>, HttpRequest),
) -> Box<dyn Future<Item = Json<EncryptedExitState>, Error = RitaExitError>> {
    let our_secretkey: WgKey = *EXIT_WG_PRIVATE_KEY;
    let our_secretkey = our_secretkey.into();

    let their_wg_pubkey = request.0.pubkey;
    let their_nacl_pubkey = request.0.pubkey.into();
    let socket = request.1;
    let decrypted_id = match decrypt_exit_client_id(request.0.into_inner(), &our_secretkey) {
        DecryptResult::Success(val) => val,
        DecryptResult::Failure(val) => {
            return val;
        }
    };

    info!("Received Encrypted setup request from, {}", their_wg_pubkey);

    let remote_mesh_socket: SocketAddr = match socket.connection_info().remote() {
        Some(val) => match val.parse() {
            Ok(val) => val,
            Err(e) => {
                error!(
                    "Error in exit setup for {} malformed packet header {:?}!",
                    their_wg_pubkey, e
                );
                return Box::new(future::err(RitaExitError::MiscStringError("Invalid packet!".to_string()))); 
            }
        },
        None => {
            error!(
                "Error in exit setup for {} invalid remote_mesh_sender!",
                their_wg_pubkey
            );
            return Box::new(future::err(RitaExitError::MiscStringError("Invalid packet!".to_string()))); 
        }
    };

    let client_mesh_ip = decrypted_id.global.mesh_ip;
    let client = decrypted_id;

    let remote_mesh_ip = remote_mesh_socket.ip();
    if remote_mesh_ip == client_mesh_ip {
        Box::new(signup_client(client).then(move |result| match result {
            Ok(exit_state) => Ok(secure_setup_return(
                exit_state,
                &our_secretkey,
                their_nacl_pubkey,
            )),
            Err(e) => {
                error!("Signup client failed with {:?}", e);
                Err(RitaExitError::MiscStringError("There was an internal server error!".to_string()))
            }
        }))
    } else {
        let state = ExitState::Denied {
            message: "The request ip does not match the signup ip".to_string(),
        };
        Box::new(future::ok(secure_setup_return(
            state,
            &our_secretkey,
            their_nacl_pubkey,
        )))
    }
}

pub fn secure_status_request(
    request: Json<EncryptedExitClientIdentity>,
) -> Box<dyn Future<Item = Json<EncryptedExitState>, Error = RitaExitError>> {
    let our_secretkey: WgKey = *EXIT_WG_PRIVATE_KEY;
    let our_secretkey = our_secretkey.into();

    let their_wg_pubkey = request.pubkey;
    let their_nacl_pubkey = request.pubkey.into();
    let decrypted_id = match decrypt_exit_client_id(request.into_inner(), &our_secretkey) {
        DecryptResult::Success(val) => val,
        DecryptResult::Failure(val) => {
            return val;
        }
    };
    trace!("got status request from {}", their_wg_pubkey);

    Box::new(get_database_connection().and_then(move |conn| {
        let state = match client_status(decrypted_id, &conn) {
            Ok(state) => state,
            Err(e) => {
                error!(
                    "Internal error in client status for {} with {:?}",
                    their_wg_pubkey, e
                );
                return Err(RitaExitError::MiscStringError("There was an internal error!".to_string())); 
            }
        };
        Ok(secure_setup_return(
            state,
            &our_secretkey,
            their_nacl_pubkey,
        ))
    }))
}

pub fn get_exit_info_http(_req: HttpRequest) -> Result<Json<ExitState>, RitaExitError> {
    Ok(Json(ExitState::GotInfo {
        general_details: get_exit_info(),
        message: "Got info successfully".to_string(),
    }))
}

/// Used by clients to get their debt from the exits. While it is in theory possible for the
/// client to totally compute their own bill it's not possible for the exit and the client
/// to agree on the billed amount in the presence of packet loss. Normally Althea is pay per forward
/// which means packet loss simply resolves to overpayment, but the exit is being paid for uploaded traffic
/// (the clients download traffic) which breaks this assumption
/// TODO secure this endpoint with libsodium
pub fn get_client_debt(client: Json<Identity>) -> HttpResponse {
    let client = client.into_inner();
    let debts = get_debts_list();
    for debt in debts {
        if debt.identity == client {
            return HttpResponse::Ok().json(debt.payment_details.debt * Int256::from(-1));
        }
    }
    HttpResponse::NotFound().json("No client by that ID")
}

#[cfg(not(feature = "development"))]
pub fn nuke_db(_req: HttpRequest) -> Result<HttpResponse, RitaExitError> {
    // This is returned on production builds.
    Ok(HttpResponse::NotFound().finish())
}

#[cfg(feature = "development")]
pub fn nuke_db(_req: HttpRequest) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    trace!("nuke_db: Truncating all data from the database");
    DbClient::from_registry()
        .send(TruncateTables {})
        .from_err()
        .and_then(move |_| Ok(HttpResponse::NoContent().finish()))
        .responder()
}
