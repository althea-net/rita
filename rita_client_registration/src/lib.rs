#![deny(unused_crate_dependencies)]
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
    time::Duration,
};

use althea_types::{ExitClientIdentity, Identity, WgKey};
use phonenumber::PhoneNumber;
use serde::{Deserialize, Serialize};

#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

pub mod client_db;
pub mod register_client_batch_loop;

lazy_static! {
    /// A map that stores number of texts sent to a client during registration
    static ref TEXTS_SENT: Arc<RwLock<HashMap<WgKey, u8>>> = Arc::new(RwLock::new(HashMap::new()));
    static ref TX_BATCH: Arc<RwLock<HashSet<Identity>>> = Arc::new(RwLock::new(HashSet::new()));
}

const REGISTRATION_LOOP_SPEED: Duration = Duration::from_secs(10);
const WEB3_TIMEOUT: Duration = Duration::from_secs(15);
pub const TX_TIMEOUT: Duration = Duration::from_secs(60);

/// Return struct from check_text and Send Text. Verified indicates status from api http req,
/// bad phone number is an error parsing clients phone number
/// Internal server error is an error while querying api endpoint
enum TextApiError {
    BadPhoneNumber,
    InternalServerError { error: String },
}

/// Return struct from Registration server to exit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExitSignupReturn {
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

pub fn add_client_to_reg_batch(id: Identity) {
    TX_BATCH.write().unwrap().insert(id);
}

fn remove_client_from_reg_batch(id: Identity) {
    TX_BATCH.write().unwrap().remove(&id);
}

fn get_reg_batch() -> Vec<Identity> {
    TX_BATCH.read().unwrap().clone().into_iter().collect()
}

#[derive(Serialize)]
pub struct SmsCheck {
    api_key: String,
    verification_code: String,
    phone_number: String,
    country_code: String,
}

#[derive(Serialize)]
pub struct SmsRequest {
    api_key: String,
    via: String,
    phone_number: String,
    country_code: String,
}

/// Handles the minutia of phone registration states
pub async fn handle_sms_registration(
    client: ExitClientIdentity,
    api_key: String,
    magic_number: Option<String>,
) -> ExitSignupReturn {
    info!(
        "Handling phone registration for {}",
        client.global.wg_public_key
    );

    // Get magic phone number
    let magic_phone_number = magic_number;

    let text_num = get_texts_sent(client.global.wg_public_key);
    let sent_more_than_allowed_texts = text_num > 10;

    match (
        client.reg_details.phone.clone(),
        client.reg_details.phone_code.clone(),
        sent_more_than_allowed_texts,
    ) {
        // all texts exhausted, but they can still submit the correct code
        (Some(number), Some(code), true) => {
            let is_magic =
                magic_phone_number.is_some() && magic_phone_number.unwrap() == number.clone();
            let result = is_magic || {
                match check_text(number.clone(), code, api_key).await {
                    Ok(a) => a,
                    Err(e) => return return_api_error(e),
                }
            };
            if result {
                info!(
                    "Phone registration complete for {}",
                    client.global.wg_public_key
                );

                add_client_to_reg_batch(client.global);
                reset_texts_sent(client.global.wg_public_key);
                ExitSignupReturn::RegistrationOk
            } else {
                ExitSignupReturn::PendingRegistration
            }
        }
        // user has exhausted attempts but is still not submitting code
        (Some(_number), None, true) => ExitSignupReturn::PendingRegistration,
        // user has attempts remaining and is requesting the code be resent
        (Some(number), None, false) => {
            if let Err(e) = send_text(number, api_key).await {
                return return_api_error(e);
            }
            increment_texts_sent(client.global.wg_public_key);
            ExitSignupReturn::PendingRegistration
        }
        // user has attempts remaining and is submitting a code
        (Some(number), Some(code), false) => {
            let is_magic =
                magic_phone_number.is_some() && magic_phone_number.unwrap() == number.clone();

            let result = is_magic || {
                match check_text(number.clone(), code, api_key).await {
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
                add_client_to_reg_batch(client.global);
                reset_texts_sent(client.global.wg_public_key);
                ExitSignupReturn::RegistrationOk
            } else {
                ExitSignupReturn::PendingRegistration
            }
        }
        // user did not submit a phonenumber
        (None, _, _) => ExitSignupReturn::BadPhoneNumber,
    }
}

fn return_api_error(e: TextApiError) -> ExitSignupReturn {
    match e {
        TextApiError::BadPhoneNumber => ExitSignupReturn::BadPhoneNumber,
        TextApiError::InternalServerError { error } => {
            ExitSignupReturn::InternalServerError { e: error }
        }
    }
}

/// Posts to the validation endpoint with the code, will return success if the code
/// is the same as the one sent to the user
async fn check_text(number: String, code: String, api_key: String) -> Result<bool, TextApiError> {
    trace!("About to check text message status for {}", number);
    let number: PhoneNumber = match number.parse() {
        Ok(number) => number,
        Err(e) => {
            error!("Phone parse error: {}", e);
            return Err(TextApiError::BadPhoneNumber);
        }
    };
    let url = "https://api.authy.com/protected/json/phones/verification/check";

    let client = awc::Client::default();
    let response = match client
        .get(url)
        .send_form(&SmsCheck {
            api_key,
            verification_code: code,
            phone_number: number.national().to_string(),
            country_code: number.code().value().to_string(),
        })
        .await
    {
        Ok(a) => a,
        Err(e) => {
            return Err(TextApiError::InternalServerError {
                error: e.to_string(),
            })
        }
    };

    trace!("Got {} back from check text", response.status());
    Ok(response.status().is_success())
}

/// Sends the authy verification text by hitting the api endpoint
async fn send_text(number: String, api_key: String) -> Result<(), TextApiError> {
    info!("Sending message for {}", number);
    let url = "https://api.authy.com/protected/json/phones/verification/start";
    let number: PhoneNumber = match number.parse() {
        Ok(number) => number,
        Err(e) => {
            error!("Parse phone number error {}", e);
            return Err(TextApiError::BadPhoneNumber);
        }
    };

    let client = awc::Client::default();
    match client
        .post(url)
        .send_form(&SmsRequest {
            api_key,
            via: "sms".to_string(),
            phone_number: number.national().to_string(),
            country_code: number.code().value().to_string(),
        })
        .await
    {
        Ok(_a) => Ok(()),
        Err(e) => {
            error!("Send text error! {}", e);
            Err(TextApiError::InternalServerError {
                error: e.to_string(),
            })
        }
    }
}
