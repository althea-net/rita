use crate::rita_exit::database::database_tools::text_sent;
use crate::rita_exit::database::database_tools::verify_client;
use crate::rita_exit::database::get_exit_info;
use crate::rita_exit::database::struct_tools::text_done;
use althea_types::{ExitClientDetails, ExitClientIdentity, ExitState};
use diesel;
use diesel::prelude::*;
use failure::Error;
use phonenumber::PhoneNumber;
use reqwest;
use settings::exit::PhoneVerifSettings;
use std::time::Duration;

#[derive(Serialize)]
pub struct SmsCheck {
    api_key: String,
    verification_code: String,
    phone_number: String,
    country_code: String,
}

fn check_text(number: String, code: String, api_key: String) -> Result<bool, Error> {
    trace!("About to check text message status for {}", number);
    let number: PhoneNumber = number.parse()?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()?;
    let res = client
        .get("https://api.authy.com/protected/json/phones/verification/check")
        .form(&SmsCheck {
            api_key: api_key,
            verification_code: code,
            phone_number: number.national().to_string(),
            country_code: number.code().value().to_string(),
        })
        .send()?;
    Ok(res.status().is_success())
}

#[derive(Serialize)]
pub struct SmsRequest {
    api_key: String,
    via: String,
    phone_number: String,
    country_code: String,
}

fn send_text(number: String, api_key: String) -> Result<(), Error> {
    trace!("Sending message for {}", number);
    let number: PhoneNumber = number.parse()?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()?;
    let res = client
        .post("https://api.authy.com/protected/json/phones/verification/start")
        .form(&SmsRequest {
            api_key: api_key,
            via: "sms".to_string(),
            phone_number: number.national().to_string(),
            country_code: number.code().value().to_string(),
        })
        .send()?;
    if res.status().is_success() {
        Ok(())
    } else {
        bail!("SMS API failure! Maybe bad number?")
    }
}

/// Handles the minutia of phone registration states
pub fn handle_sms_registration(
    client: &ExitClientIdentity,
    their_record: &exit_db::models::Client,
    api_key: String,
    conn: &PgConnection,
) -> Result<ExitState, Error> {
    trace!("Handling phone registration for {:?}", client);
    match (
        client.reg_details.phone.clone(),
        client.reg_details.phone_code.clone(),
        text_done(their_record),
    ) {
        (Some(number), Some(code), true) => {
            if check_text(number, code, api_key)? {
                verify_client(&client, true, conn)?;
                Ok(ExitState::Registered {
                    our_details: ExitClientDetails {
                        client_internal_ip: their_record.internal_ip.parse()?,
                    },
                    general_details: get_exit_info(),
                    message: "Registration OK".to_string(),
                })
            } else {
                Ok(ExitState::Pending {
                    general_details: get_exit_info(),
                    message: "awaiting phone verification".to_string(),
                    email_code: None,
                    phone_code: None,
                })
            }
        }
        (Some(_number), None, true) => Ok(ExitState::Pending {
            general_details: get_exit_info(),
            message: "awaiting phone verification".to_string(),
            email_code: None,
            phone_code: None,
        }),
        (Some(number), None, false) => {
            send_text(number, api_key)?;
            text_sent(&client, &conn)?;
            Ok(ExitState::Pending {
                general_details: get_exit_info(),
                message: "awaiting phone verification".to_string(),
                email_code: None,
                phone_code: None,
            })
        }
        (Some(_), Some(_), false) => Ok(ExitState::GotInfo {
            auto_register: false,
            general_details: get_exit_info(),
            message: "Please submit a phone number first".to_string(),
        }),
        (None, _, _) => Ok(ExitState::Denied {
            message: "This exit requires a phone number to register!".to_string(),
        }),
    }
}

#[derive(Serialize)]
pub struct SmsNotification {
    #[serde(rename = "To")]
    to: String,
    #[serde(rename = "From")]
    from: String,
    #[serde(rename = "Body")]
    body: String,
}

pub fn send_low_balance_sms(number: &str, phone: PhoneVerifSettings) -> Result<(), Error> {
    info!("Sending low balance message for {}", number);

    let url = format!(
        "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json",
        phone.twillio_account_id
    );
    let number: PhoneNumber = number.parse()?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()?;
    let res = client
        .post(&url)
        .basic_auth(phone.twillio_account_id, Some(phone.twillio_auth_token))
        .form(&SmsNotification {
            to: number.to_string(),
            from: phone.notification_number,
            body: phone.balance_notification_body,
        })
        .send()?;
    if res.status().is_success() {
        Ok(())
    } else {
        bail!("SMS API failure! Maybe bad number?")
    }
}
