//! Network endpoints for rita-exit that are not dashboard or local infromational endpoints
//! these are called by rita instances to operate the mesh

use crate::database::{client_status, signup_client};
use crate::RitaExitError;
use actix_web_async::{http::StatusCode, web::Json, HttpRequest, HttpResponse, Result};
use althea_types::exit_identity_to_id;
use althea_types::regions::Regions;
use althea_types::ExitListV2;
use althea_types::{
    EncryptedExitClientIdentity, EncryptedExitState, ExitClientIdentity, ExitState, ExitSystemTime,
};
use althea_types::{EncryptedExitList, Identity};
use althea_types::{ExitList, WgKey};
use num256::Int256;
use rita_client_registration::client_db::get_exits_list;
use rita_common::blockchain_oracle::potential_payment_issues_detected;
use rita_common::debt_keeper::get_debts_list;
use rita_common::rita_loop::get_web3_server;
use settings::get_rita_exit;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::Nonce;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::SecretKey;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;
use std::time::SystemTime;
use web30::client::Web3;

// Timeout to contact Althea contract and query info about a user
pub const CLIENT_STATUS_TIMEOUT: Duration = Duration::from_secs(20);

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
                warn!(
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

    let our_old_secretkey: WgKey = exit_settings.exit_network.wg_private_key.unwrap();
    let our_new_secretkey = exit_settings.network.wg_private_key.unwrap();

    let our_old_secretkey: SecretKey = our_old_secretkey.into();
    let our_new_secretkey = our_new_secretkey.into();
    // The secret key that is used by the client, this value
    let valid_secret_key;

    let their_wg_pubkey = request.0.pubkey;
    let their_nacl_pubkey = request.0.pubkey.into();
    let socket = request.1;
    let exit_client_id = request.0.into_inner();

    let decrypted_id = match (
        decrypt_exit_client_id(exit_client_id.clone(), &our_new_secretkey),
        decrypt_exit_client_id(exit_client_id, &our_old_secretkey),
    ) {
        (DecryptResult::Success(val_new), DecryptResult::Success(_)) => {
            valid_secret_key = our_new_secretkey;
            val_new
        }
        (DecryptResult::Success(val), _) => {
            valid_secret_key = our_new_secretkey;
            val
        }
        (_, DecryptResult::Success(val)) => {
            valid_secret_key = our_old_secretkey;
            val
        }
        (DecryptResult::Failure(val), _) => match val {
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
                &valid_secret_key,
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
            &valid_secret_key,
            their_nacl_pubkey,
        ))
    }
}

pub async fn secure_status_request(request: Json<EncryptedExitClientIdentity>) -> HttpResponse {
    let exit_settings = get_rita_exit();
    let our_old_secretkey: WgKey = exit_settings.exit_network.wg_private_key.unwrap();
    let our_new_secretkey = exit_settings.network.wg_private_key.unwrap();

    let our_old_secretkey = our_old_secretkey.into();
    let our_new_secretkey = our_new_secretkey.into();

    let our_address = exit_settings
        .payment
        .eth_private_key
        .expect("Why dont we have a private key?")
        .to_address();
    let contract_addr = exit_settings.exit_network.registered_users_contract_addr;
    let contact = Web3::new(&get_web3_server(), CLIENT_STATUS_TIMEOUT);

    let their_wg_pubkey = request.pubkey;
    let their_nacl_pubkey = request.pubkey.into();
    let exit_client_id = request.into_inner();
    // The secret key that is used by the client, this value
    let valid_secret_key;

    let decrypted_id = match (
        decrypt_exit_client_id(exit_client_id.clone(), &our_new_secretkey),
        decrypt_exit_client_id(exit_client_id, &our_old_secretkey),
    ) {
        (DecryptResult::Success(val_new), DecryptResult::Success(_)) => {
            valid_secret_key = our_new_secretkey;
            val_new
        }
        (DecryptResult::Success(val), _) => {
            valid_secret_key = our_new_secretkey;
            val
        }
        (_, DecryptResult::Success(val)) => {
            valid_secret_key = our_old_secretkey;
            val
        }
        (DecryptResult::Failure(val), _) => match val {
            Ok(val) => return HttpResponse::Ok().json(val),
            Err(_) => return HttpResponse::InternalServerError().finish(),
        },
    };

    trace!("got status request from {}", their_wg_pubkey);

    // We use our eth address as the requesting address
    let state = match client_status(*decrypted_id, our_address, contract_addr, &contact).await {
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
        &valid_secret_key,
        their_nacl_pubkey,
    ))
}

pub async fn get_exit_timestamp_http(_req: HttpRequest) -> HttpResponse {
    HttpResponse::Ok().json(ExitSystemTime {
        system_time: SystemTime::now(),
    })
}

/// This function takes a list of exit ips in the cluster from the exit registration smart
/// contract, and returns a list of exit ips that are in the same region and currency as the client
/// if this exit fits the region and currenty requirements it will always return a list containing itself
/// even if this exit is not in the smart contract. If a client is speaking with this exit then the exit
/// data is in the config and this is considered to be a key exchange in and of itself.
pub async fn get_exit_list(request: Json<EncryptedExitClientIdentity>) -> HttpResponse {
    let exit_settings = get_rita_exit();
    let our_secretkey: WgKey = exit_settings.exit_network.wg_private_key.unwrap();
    let our_secretkey = our_secretkey.into();

    let their_nacl_pubkey = request.pubkey.into();

    let contact = Web3::new(&get_web3_server(), CLIENT_STATUS_TIMEOUT);
    let rita_exit = get_rita_exit();
    let our_id = rita_exit.get_identity().unwrap();
    let our_addr = rita_exit
        .payment
        .eth_private_key
        .expect("Why do we not have a private key?")
        .to_address();
    let contract_addr = rita_exit.exit_network.registered_users_contract_addr;

    let ret: ExitList = ExitList {
        exit_list: match get_exits_list(&contact, our_addr, contract_addr).await {
            Ok(a) => {
                let exit_regions = rita_exit.network.allowed_countries;

                // only one payment type can be accepted for now, but this structure allows for
                // multiple payment types in the future
                let mut accepted_payments = HashSet::new();
                accepted_payments.insert(exit_settings.payment.system_chain);

                if exit_regions.is_empty() || accepted_payments.is_empty() {
                    error!("Exit list not configured correctly. Please set up exit regions and accepted payment types in config");
                    return HttpResponse::InternalServerError().finish();
                }
                let mut ret = vec![];
                for exit in a {
                    // Remove Exits that dont have proper regions defined
                    let mut exit_allowed_regions = exit.allowed_regions.clone();
                    if exit_allowed_regions.remove(&Regions::UnkownRegion) {
                        warn!("Found an uknown region in exit! {:?}", exit);
                    }

                    if exit_allowed_regions.is_empty() || exit.payment_types.is_empty() {
                        error!(
                            "Invalid configured exit, no allowed regions or payments setup! {:?}",
                            exit
                        );
                        continue;
                    }
                    if !exit_allowed_regions.is_disjoint(&exit_regions)
                        && !exit.payment_types.is_disjoint(&accepted_payments)
                    {
                        ret.push(exit_identity_to_id(exit))
                    }
                }
                ret.push(our_id); // add ourselves to the list
                ret
            }
            Err(e) => {
                error!(
                    "Unable to retreive the exit list with {}, returning empty list",
                    e
                );
                vec![]
            }
        },
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

/// Exit list v2, for newer router that do the fitering (region and payment type) themselves, this endpoint
/// returns the entire list
pub async fn get_exit_list_v2(request: Json<EncryptedExitClientIdentity>) -> HttpResponse {
    let exit_settings = get_rita_exit();
    let our_secretkey: WgKey = match exit_settings.network.wg_private_key {
        Some(a) => a,
        None => {
            error!("This exit doesnt have a network wg key?");
            return HttpResponse::InternalServerError().finish();
        }
    };
    let our_secretkey = our_secretkey.into();

    let their_nacl_pubkey = request.pubkey.into();

    let contact = Web3::new(&get_web3_server(), CLIENT_STATUS_TIMEOUT);
    let rita_exit = get_rita_exit();
    let our_addr = rita_exit
        .payment
        .eth_private_key
        .expect("Why do we not have a private key?")
        .to_address();
    let contract_addr = rita_exit.exit_network.registered_users_contract_addr;

    let mut ret: ExitListV2 = ExitListV2 {
        exit_list: match get_exits_list(&contact, our_addr, contract_addr).await {
            Ok(a) => a,
            Err(e) => {
                error!(
                    "Unable to retreive the exit list with {}, returning empty list",
                    e
                );
                vec![]
            }
        },
    };
    ret.exit_list.push(exit_settings.get_exit_identity()); // add ourselves to the list

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

    let debts = get_debts_list();
    for debt in debts {
        if debt.identity == client {
            let client_debt = debt.payment_details.debt;
            let incoming_payments = debt.payment_details.incoming_payments;

            let we_owe_them = client_debt > zero;

            // they have more credit than they owe, wait for this to unwind
            // we apply credit right before enforcing or on payment.
            if !we_owe_them && incoming_payments > (neg_one * client_debt).to_uint256().unwrap() {
                return HttpResponse::Ok().json(zero);
            }

            match we_owe_them {
                // in this case we owe them, return zero
                true => return HttpResponse::Ok().json(zero),
                // they owe us more than is in the queue
                false => {
                    // client debt is negative, they owe us, so we make it positive and subtract
                    // the unverified payments, which we're sure are less than or equal to the debt
                    let ret = client_debt * neg_one;
                    return HttpResponse::Ok().json(ret);
                }
            }
        }
    }
    HttpResponse::NotFound().json("No client by that ID")
}
