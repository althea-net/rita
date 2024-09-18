use althea_types::{ExitClientIdentity, Identity, WgKey};
use awc::error::{JsonPayloadError, SendRequestError};
use phonenumber::PhoneNumber;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt::Display,
    sync::{Arc, RwLock},
    time::Duration,
};

#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

pub mod client_db;
pub mod register_client_batch_loop;

lazy_static! {
    /// A map that stores number of texts sent to a client during registration
    static ref TEXTS_SENT: Arc<RwLock<HashMap<WgKey, u8>>> = Arc::new(RwLock::new(HashMap::new()));
    static ref REGISTER_QUEUE: Arc<RwLock<HashSet<Identity>>> = Arc::new(RwLock::new(HashSet::new()));
}

const REGISTRATION_LOOP_SPEED: Duration = Duration::from_secs(10);
const WEB3_TIMEOUT: Duration = Duration::from_secs(15);
pub const TX_TIMEOUT: Duration = Duration::from_secs(60);

/// Return struct from check_text and Send Text. Verified indicates status from api http req,
/// bad phone number is an error parsing clients phone number
/// Internal server error is an error while querying api endpoint
#[derive(Debug)]
pub enum TextApiError {
    BadPhoneNumber,
    InternalServerError { error: String },
    SendRequestError { error: SendRequestError },
}

impl Display for TextApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TextApiError::BadPhoneNumber => write!(f, "InvalidPhoneNumber"),
            TextApiError::InternalServerError { error } => write!(f, "Internal error {}", error),
            TextApiError::SendRequestError { error } => write!(f, "{}", error),
        }
    }
}

impl Error for TextApiError {}

impl From<JsonPayloadError> for TextApiError {
    fn from(value: JsonPayloadError) -> Self {
        TextApiError::InternalServerError {
            error: value.to_string(),
        }
    }
}

impl From<SendRequestError> for TextApiError {
    fn from(value: SendRequestError) -> Self {
        TextApiError::SendRequestError { error: value }
    }
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

pub fn add_client_to_reg_queue(id: Identity) {
    REGISTER_QUEUE.write().unwrap().insert(id);
}

fn remove_client_from_reg_queue(id: Identity) {
    REGISTER_QUEUE.write().unwrap().remove(&id);
}

fn get_reg_queue() -> Vec<Identity> {
    REGISTER_QUEUE.read().unwrap().clone().into_iter().collect()
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
    verify_profile_id: String,
    magic_number: Option<PhoneNumber>,
) -> ExitSignupReturn {
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
                            ExitSignupReturn::RegistrationOk
                        } else {
                            ExitSignupReturn::PendingRegistration
                        }
                    }
                    // user has exhausted attempts but is still not submitting code
                    (None, true) => ExitSignupReturn::PendingRegistration,
                    // user has attempts remaining and is requesting the code be resent
                    (None, false) => {
                        if let Err(e) =
                            start_sms_auth_flow(number, api_key, verify_profile_id).await
                        {
                            return return_api_error(e);
                        }
                        increment_texts_sent(client.global.wg_public_key);
                        ExitSignupReturn::PendingRegistration
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
                            ExitSignupReturn::RegistrationOk
                        } else {
                            ExitSignupReturn::PendingRegistration
                        }
                    }
                }
            }
            Err(_) => ExitSignupReturn::BadPhoneNumber,
        },
        None => ExitSignupReturn::BadPhoneNumber,
    }
}

fn return_api_error(e: TextApiError) -> ExitSignupReturn {
    match e {
        TextApiError::BadPhoneNumber => ExitSignupReturn::BadPhoneNumber,
        TextApiError::InternalServerError { error } => {
            ExitSignupReturn::InternalServerError { e: error }
        }
        TextApiError::SendRequestError { error } => ExitSignupReturn::InternalServerError {
            e: error.to_string(),
        },
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
) -> Result<bool, TextApiError> {
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

/// Url for sending auth code
const URL_START: &str = "https://api.telnyx.com/v2/verifications/sms";
pub async fn start_sms_auth_flow(
    phone_number: PhoneNumber,
    bearer_key: String,
    verify_profile_id: String,
) -> Result<(), TextApiError> {
    let client = awc::Client::default();
    match client
        .post(URL_START)
        .bearer_auth(bearer_key)
        .timeout(Duration::from_secs(1))
        .send_json(&TelnyxAuthMessage {
            phone_number: phone_number.to_string(),
            verify_profile_id,
        })
        .await
    {
        Ok(_) => Ok(()),
        Err(e) => {
            error!("auth text error {:?}", e);
            Err(e.into())
        }
    }
}
