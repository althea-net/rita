use crate::database::database_tools::text_sent;
use crate::database::database_tools::verify_client;
use crate::database::get_database_connection;
use crate::database::get_exit_info;
use crate::database::struct_tools::texts_sent;
use crate::RitaExitError;

use althea_types::{ExitClientDetails, ExitClientIdentity, ExitState};
use phonenumber::PhoneNumber;
use settings::exit::ExitVerifSettings;
use std::time::Duration;

#[derive(Serialize)]
pub struct SmsCheck {
    api_key: String,
    verification_code: String,
    phone_number: String,
    country_code: String,
}

/// Posts to the validation endpoint with the code, will return success if the code
/// is the same as the one sent to the user
async fn check_text(number: String, code: String, api_key: String) -> Result<bool, RitaExitError> {
    trace!("About to check text message status for {}", number);
    let number: PhoneNumber = match number.parse() {
        Ok(number) => number,
        Err(e) => return Err(e.into()),
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
            return Err(RitaExitError::MiscStringError(format!(
                "Send request error: {:?}",
                e
            )))
        }
    };

    trace!("Got {} back from check text", response.status());
    Ok(response.status().is_success())
}

#[derive(Serialize)]
pub struct SmsRequest {
    api_key: String,
    via: String,
    phone_number: String,
    country_code: String,
}

/// Sends the authy verification text by hitting the api endpoint
async fn send_text(number: String, api_key: String) -> Result<(), RitaExitError> {
    info!("Sending message for {}", number);
    let url = "https://api.authy.com/protected/json/phones/verification/start";
    let number: PhoneNumber = match number.parse() {
        Ok(number) => number,
        Err(e) => return Err(e.into()),
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
            return Err(RitaExitError::MiscStringError(format!(
                "Send text error: {:?}",
                e
            )))
        }
    }
}

/// Handles the minutia of phone registration states
pub async fn handle_sms_registration(
    client: ExitClientIdentity,
    their_record: exit_db::models::Client,
    api_key: String,
) -> Result<ExitState, RitaExitError> {
    info!(
        "Handling phone registration for {}",
        client.global.wg_public_key
    );
    let text_num = texts_sent(&their_record);
    let sent_more_than_allowed_texts = text_num > 10;
    match (
        client.reg_details.phone.clone(),
        client.reg_details.phone_code.clone(),
        sent_more_than_allowed_texts,
    ) {
        // all texts exhausted, but they can still submit the correct code
        (Some(number), Some(code), true) => {
            let result = check_text(number, code, api_key).await?;
            let conn = get_database_connection()?;
            if result {
                verify_client(&client, true, &conn)?;
                info!(
                    "Phone registration complete for {}",
                    client.global.wg_public_key
                );
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
        // user has exhausted attempts but is still not submitting code
        (Some(_number), None, true) => Ok(ExitState::Pending {
            general_details: get_exit_info(),
            message: "awaiting phone verification".to_string(),
            email_code: None,
            phone_code: None,
        }),
        // user has attempts remaining and is requesting the code be resent
        (Some(number), None, false) => {
            let _res = send_text(number, api_key).await?;
            let conn = get_database_connection()?;
            text_sent(&client, &conn, text_num)?;
            Ok(ExitState::Pending {
                general_details: get_exit_info(),
                message: "awaiting phone verification".to_string(),
                email_code: None,
                phone_code: None,
            })
        }
        // user has attempts remaining and is submitting a code
        (Some(number), Some(code), false) => {
            let result = check_text(number, code, api_key).await?;
            let conn = get_database_connection()?;

            trace!("Check text returned {}", result);
            if result {
                verify_client(&client, true, &conn)?;
                info!(
                    "Phone registration complete for {}",
                    client.global.wg_public_key
                );
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
        // user did not submit a phonenumber
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

/// This function is used to send texts to the admin notification list, in the case of no configured
/// admin phones you will get an empty array
pub fn send_admin_notification_sms(message: &str) {
    let verif_settings = settings::get_rita_exit().verif_settings;
    let exit_title = settings::get_rita_exit().description;
    if let Some(ExitVerifSettings::Phone(phone)) = verif_settings {
        info!("Sending Admin notification message for");

        let url = format!(
            "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json",
            phone.twillio_account_id
        );

        for number in phone.operator_notification_number {
            let client = reqwest::blocking::Client::new();
            match client
                .post(&url)
                .basic_auth(
                    phone.twillio_account_id.clone(),
                    Some(phone.twillio_auth_token.clone()),
                )
                .form(&SmsNotification {
                    to: number.to_string(),
                    from: phone.notification_number.clone(),
                    body: exit_title.clone() + ": " + message,
                })
                .timeout(Duration::from_secs(1))
                .send()
            {
                Ok(val) => {
                    info!("Admin notification text sent successfully with {:?}", val);
                }
                Err(e) => {
                    error!(
                        "Admin notification text to {} failed with {:?}",
                        number.to_string(),
                        e
                    );
                }
            }
        }
    } else {
        warn!("We don't send admin messages over email!");
    }
}
