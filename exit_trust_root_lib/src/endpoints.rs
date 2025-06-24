use std::time::Duration;

use crate::client_db::check_user_admin;
use crate::register_client_batch_loop::RegistrationRequest;
use crate::retrieve_exit_server_list;
use crate::sms_auth::check_sms_auth_result;
use crate::sms_auth::start_sms_auth_flow;
use crate::sms_auth::TextApiError;
use crate::ConfigAndCache;
use actix_web::post;
use actix_web::{get, web, HttpResponse, Responder};
use althea_types::Identity;
use clarity::Address;
use log::error;
use log::info;
use phonenumber::PhoneNumber;
use serde::Deserialize;
use serde::Serialize;
use web30::client::Web3;

// TODO we will want a backend list here for accepted contracts
/// This endpoint retrieves and signs the data from any specified exit contract,
/// allowing this server to serve as a root of trust for several different exit contracts.
#[get("/{exit_contract}")]
pub async fn return_signed_exit_contract_data(
    exit_contract: web::Path<Address>,
    cache: web::Data<ConfigAndCache>,
) -> impl Responder {
    let contract: Address = exit_contract.into_inner();
    let cached_list = cache.get(&contract);
    info!("Retrieving exit server list for contract {:?}", contract);
    info!("Cached list: {:?}", cached_list);

    match cached_list {
        Some(list) => {
            // return a signed exit server list based on the given key
            HttpResponse::Ok().json(list)
        }
        None => match retrieve_exit_server_list(contract, cache.get_ref().clone()).await {
            Ok(list) => HttpResponse::Ok().json(list),
            Err(e) => {
                info!("Failed to get exit list from contract {:?}", e);
                HttpResponse::InternalServerError().json("Failed to get exit list from contract")
            }
        },
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
/// Registration request stuct posted by the client to start the registration process
pub struct RegisterRequest {
    pub phone_number: PhoneNumber,
}

/// This function starts client registration
/// It will send a text to the client with a code that they must submit
/// to the submit_code endpoint to complete registration
#[post("/register")]
pub async fn start_client_registration(
    client: web::Json<RegisterRequest>,
    cache: web::Data<ConfigAndCache>,
) -> impl Responder {
    let config = cache.get_config();
    info!("Starting phone registration for {}", client.phone_number);

    if cache.has_hit_text_limit(&client.phone_number) {
        error!("Registration text limit hit for {}", client.phone_number);
        return HttpResponse::TooManyRequests().finish();
    }

    // the magic number in this case doesn't really do anything, they can
    // just call the verification endpoint directly and 'complete' the verification
    if let Some(number) = config.magic_number.clone() {
        if number == client.phone_number {
            info!("Magic number detected",);
            return HttpResponse::Ok().finish();
        }
    }

    // below this point we send a text, so we should increment the counter
    // first, just in case there's some error in the text sending process
    // where we might send a text but not increment the counter
    cache.insert_text_sent(client.phone_number.clone());
    let res = start_sms_auth_flow(
        client.phone_number.clone(),
        config.telnyx_api_key.clone(),
        config.verify_profile_id.clone(),
    )
    .await;
    match res {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => match e {
            TextApiError::InternalServerError { error } => {
                error!("Internal server error {:?}", error);
                HttpResponse::InternalServerError().finish()
            }
            TextApiError::SendRequestError { error } => {
                error!("Failed to send text {:?}", error);
                HttpResponse::InternalServerError().finish()
            }
        },
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
/// Registration request stuct posted by the client to start the registration process
pub struct SubmitCodeRequest {
    /// The phone number, must have first been used to start the registration process
    /// with the register endpoint
    pub phone_number: PhoneNumber,
    /// The identity of the client router to be registered
    pub identity: Identity,
    /// The code sent to the phone number
    pub code: String,
    /// The contract address to register with
    pub contract: Address,
}

/// This endpoint is used by clients to submit their registration code
/// once successfully verified they will be added to the registration queue
/// and will be registered with the registration contract of their choice
#[post("/submit_code")]
pub async fn submit_registration_code(
    request: web::Json<SubmitCodeRequest>,
    cache: web::Data<ConfigAndCache>,
) -> impl Responder {
    let config = cache.get_config();
    info!(
        "Submitting code for {} with identity {:?}",
        request.phone_number, request.identity
    );

    let contract_addr = request.contract;
    let web3 = Web3::new(&cache.get_config().rpc, Duration::from_secs(2));
    let our_private_key = cache.get_config().private_key;
    // ensure that it is possible to register with the contract, having this here
    // is less efficient, but really helps with debugging by not giving a confusing
    // 'ok' response to the client when we can't actually register them
    match check_user_admin(
        &web3,
        contract_addr,
        our_private_key.to_address(),
        our_private_key,
    )
    .await
    {
        Ok(b) => {
            if !b {
                error!(
                    "We are not a user admin for contract {:?}, responding with 403",
                    contract_addr
                );
                return HttpResponse::Forbidden().finish();
            }
        }
        Err(e) => {
            error!("Failed to check if we are a user admin {:?}", e);
            return HttpResponse::InternalServerError().finish();
        }
    }

    // the magic number in this case doesn't really do anything, they can
    // just call the verification endpoint directly and 'complete' the verification
    if let Some(number) = config.magic_number.clone() {
        if number == request.phone_number {
            info!(
                "Magic number detected, submitting user {} for registration",
                request.identity.wg_public_key
            );
            cache.insert_client_to_reg_queue(RegistrationRequest {
                identity: request.identity,
                contract: request.contract,
            });
            return HttpResponse::Ok().finish();
        }
    }

    let res = check_sms_auth_result(
        request.phone_number.clone(),
        request.code.clone(),
        config.telnyx_api_key.clone(),
        config.verify_profile_id.clone(),
    )
    .await;

    match res {
        Ok(true) => {
            info!(
                "Code verified for {} submitting {} for registration",
                request.phone_number, request.identity.wg_public_key
            );
            cache.insert_client_to_reg_queue(RegistrationRequest {
                identity: request.identity,
                contract: request.contract,
            });
            HttpResponse::Ok().finish()
        }
        Ok(false) => {
            info!("Code not verified for {}", request.phone_number);
            HttpResponse::BadRequest().finish()
        }
        Err(e) => match e {
            TextApiError::InternalServerError { error } => {
                error!("Internal server error {:?}", error);
                HttpResponse::InternalServerError().finish()
            }
            TextApiError::SendRequestError { error } => {
                error!("Failed to send text {:?}", error);
                HttpResponse::InternalServerError().finish()
            }
        },
    }
}
