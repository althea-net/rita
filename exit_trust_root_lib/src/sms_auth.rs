use althea_types::error::AltheaTypesError;
use awc::error::JsonPayloadError;
use awc::error::SendRequestError;
use log::error;
use log::info;
use phonenumber::PhoneNumber;
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt::Display, time::Duration};
use web30::jsonrpc::error::Web3Error;

pub const REGISTRATION_LOOP_SPEED: Duration = Duration::from_secs(10);
pub const WEB3_TIMEOUT: Duration = Duration::from_secs(15);
pub const TX_TIMEOUT: Duration = Duration::from_secs(60);

/// Return struct from check_text and Send Text. Verified indicates status from api http req,
/// bad phone number is an error parsing clients phone number
/// Internal server error is an error while querying api endpoint
#[derive(Debug)]
pub enum TextApiError {
    InternalServerError { error: String },
    SendRequestError { error: SendRequestError },
}

impl Display for TextApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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
