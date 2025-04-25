use actix::System;
/// TODO: This file is here so legacy exits can still register clients (ops tools needs these functions
/// in order to do so.) This file should be removed once all exits are independent
use althea_types::{error::AltheaTypesError, ExitClientIdentity, Identity, WgKey};
use awc::error::JsonPayloadError;
use awc::error::SendRequestError;
use clarity::Address;
use clarity::PrivateKey;
use lazy_static::lazy_static;
use log::error;
use log::info;
use log::trace;
use phonenumber::PhoneNumber;
use serde::{Deserialize, Serialize};
use std::thread;
use std::time::Instant;
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt::Display,
    sync::{Arc, RwLock},
    time::Duration,
};
use web30::client::Web3;
use web30::jsonrpc::error::Web3Error;
use web30::types::SendTxOption;

use crate::client_db::add_users_to_registered_list;
use crate::client_db::get_all_registered_clients;
use crate::register_client_batch_loop::MAX_BATCH_SIZE;
use crate::sms_auth::start_sms_auth_flow;
use crate::sms_auth::TextApiError;

lazy_static! {
    /// A map that stores number of texts sent to a client during registration
    static ref TEXTS_SENT: Arc<RwLock<HashMap<WgKey, u8>>> = Arc::new(RwLock::new(HashMap::new()));
    static ref REGISTER_QUEUE: Arc<RwLock<HashSet<Identity>>> = Arc::new(RwLock::new(HashSet::new()));
}

pub const REGISTRATION_LOOP_SPEED: Duration = Duration::from_secs(10);
pub const WEB3_TIMEOUT: Duration = Duration::from_secs(15);
pub const TX_TIMEOUT: Duration = Duration::from_secs(60);

/// Return struct from check_text and Send Text. Verified indicates status from api http req,
/// bad phone number is an error parsing clients phone number
/// Internal server error is an error while querying api endpoint
#[derive(Debug)]
pub enum LegacyTextApiError {
    BadPhoneNumber,
    InternalServerError { error: String },
    SendRequestError { error: SendRequestError },
}

impl Display for LegacyTextApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LegacyTextApiError::BadPhoneNumber => write!(f, "InvalidPhoneNumber"),
            LegacyTextApiError::InternalServerError { error } => {
                write!(f, "Internal error {}", error)
            }
            LegacyTextApiError::SendRequestError { error } => write!(f, "{}", error),
        }
    }
}

impl Error for LegacyTextApiError {}

impl From<JsonPayloadError> for LegacyTextApiError {
    fn from(value: JsonPayloadError) -> Self {
        LegacyTextApiError::InternalServerError {
            error: value.to_string(),
        }
    }
}

impl From<TextApiError> for LegacyTextApiError {
    fn from(value: TextApiError) -> Self {
        match value {
            TextApiError::InternalServerError { error } => {
                LegacyTextApiError::InternalServerError { error }
            }
            TextApiError::SendRequestError { error } => {
                LegacyTextApiError::SendRequestError { error }
            }
        }
    }
}

impl From<SendRequestError> for LegacyTextApiError {
    fn from(value: SendRequestError) -> Self {
        LegacyTextApiError::SendRequestError { error: value }
    }
}

/// Return struct from Registration server to exit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LegacyExitSignupReturn {
    RegistrationOk,
    PendingRegistration,
    BadPhoneNumber,
    InternalServerError { e: String },
}
// Lazy static setters and getters
fn increment_texts_sent(key: WgKey) {
    let lock = &mut *TEXTS_SENT.write().unwrap();
    let txt_sent = lock.get_mut(&key);
    if let Some(val) = txt_sent {
        *val += 1;
    } else {
        lock.insert(key, 1);
    }
}

fn reset_texts_sent(key: WgKey) {
    TEXTS_SENT.write().unwrap().remove(&key);
}

fn get_texts_sent(key: WgKey) -> u8 {
    *TEXTS_SENT.read().unwrap().get(&key).unwrap_or(&0u8)
}

pub fn add_client_to_reg_queue(id: Identity) {
    REGISTER_QUEUE.write().unwrap().insert(id);
}

pub fn remove_client_from_reg_queue(id: Identity) {
    REGISTER_QUEUE.write().unwrap().remove(&id);
}

pub fn get_reg_queue() -> Vec<Identity> {
    REGISTER_QUEUE.read().unwrap().clone().into_iter().collect()
}

#[derive(Serialize)]
pub struct LegacySmsCheck {
    api_key: String,
    verification_code: String,
    phone_number: String,
    country_code: String,
}

#[derive(Serialize)]
pub struct LegacySmsRequest {
    api_key: String,
    via: String,
    phone_number: String,
    country_code: String,
}

/// Handles the minutia of phone registration states
pub async fn legacy_handle_sms_registration(
    client: ExitClientIdentity,
    api_key: String,
    verify_profile_id: String,
    magic_number: Option<PhoneNumber>,
) -> LegacyExitSignupReturn {
    info!(
        "Handling phone registration for {}",
        client.global.wg_public_key
    );

    // Get magic phone number
    let magic_phone_number = magic_number;

    let text_num = get_texts_sent(client.global.wg_public_key);
    let sent_more_than_allowed_texts = text_num > 10;

    match client.reg_details.phone {
        Some(number) => match number.parse() {
            Ok(number) => {
                let number: PhoneNumber = number;
                match (
                    client.reg_details.phone_code.clone(),
                    sent_more_than_allowed_texts,
                ) {
                    // all texts exhausted, but they can still submit the correct code
                    (Some(code), true) => {
                        let is_magic = magic_phone_number.is_some()
                            && magic_phone_number.unwrap() == number.clone();
                        let result = is_magic || {
                            match check_sms_auth_result(
                                number.clone(),
                                code,
                                api_key,
                                verify_profile_id,
                            )
                            .await
                            {
                                Ok(a) => a,
                                Err(e) => return return_api_error(e),
                            }
                        };
                        if result {
                            info!(
                                "Phone registration complete for {}",
                                client.global.wg_public_key
                            );

                            add_client_to_reg_queue(client.global);
                            reset_texts_sent(client.global.wg_public_key);
                            LegacyExitSignupReturn::RegistrationOk
                        } else {
                            LegacyExitSignupReturn::PendingRegistration
                        }
                    }
                    // user has exhausted attempts but is still not submitting code
                    (None, true) => LegacyExitSignupReturn::PendingRegistration,
                    // user has attempts remaining and is requesting the code be resent
                    (None, false) => {
                        if let Err(e) =
                            start_sms_auth_flow(number, api_key, verify_profile_id).await
                        {
                            return return_api_error(e.into());
                        }
                        increment_texts_sent(client.global.wg_public_key);
                        LegacyExitSignupReturn::PendingRegistration
                    }
                    // user has attempts remaining and is submitting a code
                    (Some(code), false) => {
                        let is_magic = magic_phone_number.is_some()
                            && magic_phone_number.unwrap() == number.clone();

                        let result = is_magic || {
                            match check_sms_auth_result(
                                number.clone(),
                                code,
                                api_key,
                                verify_profile_id,
                            )
                            .await
                            {
                                Ok(a) => a,
                                Err(e) => return return_api_error(e),
                            }
                        };
                        trace!("Check text returned {}", result);
                        if result {
                            info!(
                                "Phone registration complete for {}",
                                client.global.wg_public_key
                            );
                            add_client_to_reg_queue(client.global);
                            reset_texts_sent(client.global.wg_public_key);
                            LegacyExitSignupReturn::RegistrationOk
                        } else {
                            LegacyExitSignupReturn::PendingRegistration
                        }
                    }
                }
            }
            Err(_) => LegacyExitSignupReturn::BadPhoneNumber,
        },
        None => LegacyExitSignupReturn::BadPhoneNumber,
    }
}

fn return_api_error(e: LegacyTextApiError) -> LegacyExitSignupReturn {
    match e {
        LegacyTextApiError::BadPhoneNumber => LegacyExitSignupReturn::BadPhoneNumber,
        LegacyTextApiError::InternalServerError { error } => {
            LegacyExitSignupReturn::InternalServerError { e: error }
        }
        LegacyTextApiError::SendRequestError { error } => {
            LegacyExitSignupReturn::InternalServerError {
                e: error.to_string(),
            }
        }
    }
}

#[derive(Serialize)]
pub struct TelnyxSmsAuthCheck {
    verify_profile_id: String,
    code: String,
}

#[derive(Debug, Deserialize)]
pub struct TelnyxSmsAuthResponseBody {
    pub data: TelnyxSmsAuthResponse,
}

/// Response code is either accepted or rejected
#[derive(Debug, Deserialize)]
pub struct TelnyxSmsAuthResponse {
    pub phone_number: String,
    pub response_code: String,
}

/// Posts to the validation endpoint with the code, will return success if the code
/// is the same as the one sent to the user
pub async fn check_sms_auth_result(
    number: PhoneNumber,
    code: String,
    bearer_key: String,
    verify_profile_id: String,
) -> Result<bool, LegacyTextApiError> {
    info!("About to check text message status for {}", number);

    let check_url = format!(
        "https://api.telnyx.com/v2/verifications/by_phone_number/{}/actions/verify",
        number
    );

    let client = awc::Client::default();
    match client
        .post(check_url)
        .bearer_auth(bearer_key)
        .send_json(&TelnyxSmsAuthCheck {
            verify_profile_id,
            code,
        })
        .await
    {
        Ok(mut a) => {
            let response = a.json::<TelnyxSmsAuthResponseBody>().await?;
            if response.data.response_code == "accepted" {
                Ok(true)
            } else {
                Ok(false)
            }
        }
        Err(e) => {
            error!("Failed to verify code with {:?}", e);
            Err(e.into())
        }
    }
}

#[derive(Serialize)]
pub struct TelnyxAuthMessage {
    /// user target number
    pub phone_number: String,
    pub verify_profile_id: String,
}

/// Required because althea types doesn't import web30 and web30 doesn't import althea types making a from or
/// into conversion impossible
pub fn convert_althea_types_to_web3_error<T>(
    input: Result<T, AltheaTypesError>,
) -> Result<T, Web3Error> {
    match input {
        Ok(a) => Ok(a),
        Err(e) => Err(Web3Error::BadResponse(format!("{e}"))),
    }
}

/// This function starts  a separate thread that monitors the registraiton batch lazy static variable and every REGISTRATION_LOOP_SPEED seconds
/// sends a batch register tx to the smart contract
pub fn legacy_register_client_batch_loop(
    web3_url: String,
    contract_addr: Address,
    our_private_key: PrivateKey,
) {
    let mut last_restart = Instant::now();
    thread::spawn(move || {
        // this will always be an error, so it's really just a loop statement
        // with some fancy destructuring
        while let Err(e) = {
            let web3_url = web3_url.clone();
            thread::spawn(move || {
                let web3_url = web3_url.clone();
                // Our Exit state variabl
                let runner = System::new();

                runner.block_on(async move {
                    loop {
                        let start = Instant::now();
                        // there is no one in the queue
                        let list = get_reg_queue();
                        if list.is_empty() {
                            thread::sleep(WEB3_TIMEOUT);
                            continue
                        }

                        let web3 = Web3::new(&web3_url, WEB3_TIMEOUT);
                        // get a copy of all existing clients, we do this in order to handle a potential future edgecase where more than one registration server
                        // is operating at a time and the same user attempts to register to more than one before the transaction can be sent. Without this check
                        // once a already registered user is in the queue all future transactions would fail and the server would no longer operate correctly
                        let all_clients = match get_all_registered_clients(&web3, our_private_key.to_address(), contract_addr).await {
                            Ok(all_clients) => all_clients,
                            Err(e) => {
                                error!("Failed to get list of already registered clients {:?}, retrying", e);
                                continue;
                            },
                        };

                        let mut clients_to_register = Vec::new();
                        for client in list {
                            if !all_clients.contains(&client) {
                                clients_to_register.push(client);
                                if clients_to_register.len() > MAX_BATCH_SIZE {
                                    break;
                                }
                            }
                        }
                        // there is no one once we filter already registered users
                        if clients_to_register.is_empty() {
                            thread::sleep(WEB3_TIMEOUT);
                            continue
                        }

                        info!("Prepped user batch sending register tx");
                        match add_users_to_registered_list(
                            &web3,
                            clients_to_register.clone(),
                            contract_addr,
                            our_private_key,
                            Some(TX_TIMEOUT),
                            vec![SendTxOption::GasPriorityFee(1000000000u128.into()), SendTxOption::GasMaxFee(4000000000u128.into())],
                        )
                        .await
                        {
                            Ok(_) => {
                                info!(
                                    "Successfully registered {} clients!",
                                    clients_to_register.len()
                                );
                                // remove all the successfully registered clients from the queue
                                for client in clients_to_register {
                                    remove_client_from_reg_queue(client);
                                }
                            }
                            Err(e) => {
                                error!("Failed to register clients with {:?}, will try again!", e)
                            }
                        }

                        info!("Registration loop elapsed in = {:?}", start.elapsed());
                        if start.elapsed() < REGISTRATION_LOOP_SPEED {
                            info!(
                                "Registration Loop sleeping for {:?}",
                                REGISTRATION_LOOP_SPEED - start.elapsed()
                            );
                            thread::sleep(REGISTRATION_LOOP_SPEED - start.elapsed());
                        }
                        info!("Registration loop sleeping Done!");
                    }
                });
            })
            .join()
        } {
            error!("Registration loop thread panicked! Respawning {:?}", e);
            if Instant::now() - last_restart < Duration::from_secs(60) {
                error!("Restarting too quickly, leaving it to auto rescue!");
                let sys = System::current();
                sys.stop_with_code(121);
            }
            last_restart = Instant::now();
        }
    });
}
