//! Network endpoints for rita-exit that are not dashboard or local infromational endpoints
//! these are called by rita instances to operate the mesh

use crate::database::signup_client;
use crate::{ClientListAnIpAssignmentMap, RitaExitError};
use actix_web::web;
use actix_web::{http::StatusCode, web::Json, HttpRequest, HttpResponse, Result};
use althea_types::Identity;
use althea_types::SignedExitServerList;
use althea_types::WgKey;
use althea_types::{decrypt_exit_client_id, encrypt_setup_return};
use althea_types::{
    EncryptedExitClientIdentity, EncryptedExitState, ExitClientIdentity, ExitState, ExitSystemTime,
};
use clarity::Address;
use crypto_box::SecretKey;
use num256::Int256;
use rita_common::blockchain_oracle::potential_payment_issues_detected;
use rita_common::debt_keeper::get_debts_list;
use settings::get_rita_exit;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::time::SystemTime;

// Timeout to contact Althea contract and query info about a user
pub const CLIENT_STATUS_TIMEOUT: Duration = Duration::from_secs(20);

enum DecryptResult {
    Success(Box<ExitClientIdentity>),
    Failure(Result<EncryptedExitState, RitaExitError>),
}

fn decrypt_exit_client_id_helper(
    val: EncryptedExitClientIdentity,
    our_secretkey: &SecretKey,
) -> DecryptResult {
    match decrypt_exit_client_id(val.clone(), our_secretkey) {
        Ok(decrypted_id) => DecryptResult::Success(Box::new(decrypted_id)),
        Err(e) => {
            let their_nacl_pubkey = val.pubkey.into();
            let their_wg_pubkey = val.pubkey;
            warn!(
                "Error decrypting exit setup request for {} with {:?}",
                their_wg_pubkey, e
            );
            let state = ExitState::Denied {
                message: "could not decrypt your message!".to_string(),
            };
            DecryptResult::Failure(Ok(encrypt_setup_return(
                state,
                our_secretkey,
                &their_nacl_pubkey,
            )))
        }
    }
}

pub async fn secure_setup_request(
    request: (Json<EncryptedExitClientIdentity>, HttpRequest),
    client_and_ip_info: web::Data<Arc<RwLock<ClientListAnIpAssignmentMap>>>,
) -> HttpResponse {
    let exit_settings = get_rita_exit();
    let client_and_ip_info = client_and_ip_info.into_inner();

    let our_secretkey: WgKey = exit_settings.network.wg_private_key.unwrap();

    let their_wg_pubkey = request.0.pubkey;
    let their_nacl_pubkey = request.0.pubkey.into();
    let socket = request.1;
    let exit_client_id = request.0.into_inner();

    let decrypted_id =
        match decrypt_exit_client_id_helper(exit_client_id.clone(), &our_secretkey.into()) {
            DecryptResult::Success(val_new) => val_new,
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
        let result = signup_client(*client, client_and_ip_info).await;
        match result {
            Ok(exit_state) => HttpResponse::Ok().json(encrypt_setup_return(
                exit_state,
                &our_secretkey.into(),
                &their_nacl_pubkey,
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
        HttpResponse::Ok().json(encrypt_setup_return(
            state,
            &our_secretkey.into(),
            &their_nacl_pubkey,
        ))
    }
}

pub async fn secure_status_request(
    request: Json<EncryptedExitClientIdentity>,
    client_and_ip_info: web::Data<Arc<RwLock<ClientListAnIpAssignmentMap>>>,
) -> HttpResponse {
    let exit_settings = get_rita_exit();
    let our_secretkey: WgKey = exit_settings.network.wg_private_key.unwrap();

    let their_wg_pubkey = request.pubkey;
    let their_nacl_pubkey = request.pubkey.into();
    let exit_client_id = request.into_inner();

    let decrypted_id =
        match decrypt_exit_client_id_helper(exit_client_id.clone(), &our_secretkey.into()) {
            DecryptResult::Success(val_new) => val_new,
            DecryptResult::Failure(val) => match val {
                Ok(val) => return HttpResponse::Ok().json(val),
                Err(_) => return HttpResponse::InternalServerError().finish(),
            },
        };

    trace!("got status request from {}", their_wg_pubkey);

    // We use our eth address as the requesting address
    let state = match client_and_ip_info
        .write()
        .unwrap()
        .get_client_status(*decrypted_id)
    {
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
    HttpResponse::Ok().json(encrypt_setup_return(
        state,
        &our_secretkey.into(),
        &their_nacl_pubkey,
    ))
}

pub async fn get_exit_timestamp_http(_req: HttpRequest) -> HttpResponse {
    HttpResponse::Ok().json(ExitSystemTime {
        system_time: SystemTime::now(),
    })
}

/// This function takes a list of exit ips in the cluster from the exit registration smart
/// contract, and returns a list of exit ips that are in the same region and currency as the client
/// This exit may not be included in the list returned by the smart contract! All exits run their
/// get_exit_list endpoint on the same IP within the babel mesh, so any exit that is online will get
/// requests regardless of whether they are on the list. Clients verify the signature on the list and
/// switch only to valid exits, and exits not on the list must be added to the root of trust server's
/// list in order to be considered valid.
pub async fn get_exit_list(
    cache: web::Data<Arc<RwLock<HashMap<Address, SignedExitServerList>>>>,
) -> HttpResponse {
    let rita_exit = get_rita_exit();
    let contract_addr = rita_exit.exit_network.registered_users_contract_addr;

    // we are receiving a SignedExitServerList from the root server.
    let signed_list: SignedExitServerList = match get_exit_list_from_root(contract_addr).await {
        Some(a) => {
            // add to the cache
            cache.write().unwrap().insert(contract_addr, a.clone());
            a
        }
        None => {
            error!("Failed to get exit list from root server, trying cached list");
            match cache.read().unwrap().get(&contract_addr).cloned() {
                Some(a) => a,
                None => {
                    return HttpResponse::InternalServerError()
                        .json("Failed to get exit list and no cached value present!")
                }
            }
        }
    };

    HttpResponse::Ok().json(signed_list)
}

async fn get_exit_list_from_root(contract_addr: Address) -> Option<SignedExitServerList> {
    let rita_exit = get_rita_exit();
    let request_url = rita_exit.exit_root_url;
    let timeout = Duration::new(15, 0);
    let client = awc::Client::new();
    let request_url = format!("{}/{}", request_url, contract_addr);
    trace!("Requesting exit list from {}", request_url);
    let mut response = client
        .get(request_url)
        .timeout(timeout)
        .send()
        .await
        .expect("Could not receive data from exit root server");
    if response.status().is_success() {
        trace!("Received an exit list");
        match response.json::<SignedExitServerList>().await {
            Ok(a) => {
                // verify the signature of the exit list
                // note the exit cares if it's passing along a valid signature
                // but does not police allowed signers, that's entierly up to the client
                if a.verify() {
                    trace!("Verified exit list signature");
                    return Some(a);
                }
                error!("Failed to verify exit list signature");
                None
            }
            Err(e) => {
                error!("Failed to parse exit list from root server {:?}", e);
                None
            }
        }
    } else {
        error!(
            "Failed to get exit list from root server with {:?}",
            response
        );
        None
    }
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
