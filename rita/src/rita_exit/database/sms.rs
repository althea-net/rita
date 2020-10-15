use crate::rita_exit::database::database_tools::text_sent;
use crate::rita_exit::database::database_tools::verify_client;
use crate::rita_exit::database::get_database_connection;
use crate::rita_exit::database::get_exit_info;
use crate::rita_exit::database::struct_tools::texts_sent;
use crate::SETTING;
use actix_web::client as actix_client;
use actix_web::client::ClientResponse;
use althea_types::{ExitClientDetails, ExitClientIdentity, ExitState};
use failure::Error;
use futures01::future;
use futures01::future::Either;
use futures01::future::Future;
use phonenumber::PhoneNumber;
use settings::exit::{ExitVerifSettings, PhoneVerifSettings, RitaExitSettings};
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
fn check_text(
    number: String,
    code: String,
    api_key: String,
) -> impl Future<Item = bool, Error = Error> {
    trace!("About to check text message status for {}", number);
    let number: PhoneNumber = match number.parse() {
        Ok(number) => number,
        Err(e) => return Either::A(future::err(e.into())),
    };
    let url = "https://api.authy.com/protected/json/phones/verification/check";
    Either::B(
        actix_client::get(&url)
            .form(&SmsCheck {
                api_key,
                verification_code: code,
                phone_number: number.national().to_string(),
                country_code: number.code().value().to_string(),
            })
            .unwrap()
            .send()
            .from_err()
            .and_then(|value| {
                trace!("Got {} back from check text", value.status());
                Ok(value.status().is_success())
            }),
    )
}

#[derive(Serialize)]
pub struct SmsRequest {
    api_key: String,
    via: String,
    phone_number: String,
    country_code: String,
}

/// Sends the authy verification text by hitting the api endpoint
fn send_text(number: String, api_key: String) -> impl Future<Item = ClientResponse, Error = Error> {
    info!("Sending message for {}", number);
    let url = "https://api.authy.com/protected/json/phones/verification/start";
    let number: PhoneNumber = match number.parse() {
        Ok(number) => number,
        Err(e) => return Either::A(future::err(e.into())),
    };
    Either::B(
        actix_client::post(&url)
            .form(&SmsRequest {
                api_key,
                via: "sms".to_string(),
                phone_number: number.national().to_string(),
                country_code: number.code().value().to_string(),
            })
            .unwrap()
            .send()
            .from_err(),
    )
}

/// Handles the minutia of phone registration states
pub fn handle_sms_registration(
    client: ExitClientIdentity,
    their_record: exit_db::models::Client,
    api_key: String,
) -> impl Future<Item = ExitState, Error = Error> {
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
            Box::new(check_text(number, code, api_key).and_then(move |result| {
                get_database_connection().and_then(move |conn| {
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
                })
            })) as Box<dyn Future<Item = ExitState, Error = Error>>
        }
        // user has exhausted attempts but is still not submitting code
        (Some(_number), None, true) => Box::new(future::ok(ExitState::Pending {
            general_details: get_exit_info(),
            message: "awaiting phone verification".to_string(),
            email_code: None,
            phone_code: None,
        })),
        // user has attempts remaining and is requesting the code be resent
        (Some(number), None, false) => {
            Box::new(send_text(number, api_key).and_then(move |_result| {
                get_database_connection().and_then(move |conn| {
                    text_sent(&client, &conn, text_num)?;
                    Ok(ExitState::Pending {
                        general_details: get_exit_info(),
                        message: "awaiting phone verification".to_string(),
                        email_code: None,
                        phone_code: None,
                    })
                })
            })) as Box<dyn Future<Item = ExitState, Error = Error>>
        }
        // user has attempts remaining and is submitting a code
        (Some(number), Some(code), false) => {
            Box::new(check_text(number, code, api_key).and_then(move |result| {
                get_database_connection().and_then(move |conn| {
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
                })
            })) as Box<dyn Future<Item = ExitState, Error = Error>>
        }
        // user did not submit a phonenumber
        (None, _, _) => Box::new(future::ok(ExitState::Denied {
            message: "This exit requires a phone number to register!".to_string(),
        })) as Box<dyn Future<Item = ExitState, Error = Error>>,
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

/// This function sends a low balance message to a users device. This is no longer the primary
/// Way to send these messages as they are now sent through the operator tools. That being said
/// this functionality here has not been removed because a future FOSS version of rita_exit may
/// use it. If you feel like this is a dumb reason to keep a few hundred lines of code around
/// I don't disagree and you can remove it.
pub fn send_low_balance_sms(number: &str, phone: PhoneVerifSettings) -> Result<(), Error> {
    info!("Sending low balance message for {}", number);

    let url = format!(
        "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json",
        phone.twillio_account_id
    );
    let number: PhoneNumber = number.parse()?;
    let client = reqwest::blocking::Client::new();
    match client
        .post(&url)
        .basic_auth(phone.twillio_account_id, Some(phone.twillio_auth_token))
        .form(&SmsNotification {
            to: number.to_string(),
            from: phone.notification_number,
            body: phone.balance_notification_body,
        })
        .timeout(Duration::from_secs(1))
        .send()
    {
        Ok(val) => {
            info!("Low balance text sent successfully with {:?}", val);
            Ok(())
        }
        Err(e) => {
            error!(
                "Low blanace text to {} failed with {:?}",
                number.to_string(),
                e
            );
            Err(e.into())
        }
    }
}

/// This function is used to send texts to the admin notification list, in the case of no configured
/// admin phones you will get an empty array
pub fn send_admin_notification_sms(message: &str) {
    let verif_settings = SETTING.get_verif_settings();
    let exit_title = SETTING.get_description();
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
