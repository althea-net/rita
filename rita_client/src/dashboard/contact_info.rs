//! This file manages the contact info struct in the client exit details. Which is the one true location of contact details storage, although
//! we end up processing and moving contact data in a few other places (exit registration, text notifications) the contact_details member of
//! the exit settings struct is the one true source. All the others are updated as needed and you should try to phase them out if practical.

use rita_common::utils::option_convert;

use actix_web::HttpRequest;
use actix_web::HttpResponse;
use althea_types::ContactType;
use lettre::EmailAddress;
use phonenumber::PhoneNumber;
use settings::FileWrite;

fn clean_quotes(val: &str) -> String {
    val.trim().trim_matches('"').trim_matches('\\').to_string()
}

pub fn set_phone_number(req: String) -> HttpResponse {
    let clean_string = clean_quotes(&req);
    trace!("Got number {:?}", clean_string);
    let number: PhoneNumber = match clean_string.parse() {
        Ok(p) => p,
        Err(e) => {
            info!("Failed to parse phonenumber with {:?}", e);
            return HttpResponse::BadRequest().finish();
        }
    };

    let mut exit_client = settings::get_rita_client().exit_client;
    // merge the new value into the existing struct, for the various possibilities
    let res = match option_convert(exit_client.contact_info.clone()) {
        Some(ContactType::Phone { .. }) => Some(ContactType::Phone { number }),
        Some(ContactType::Email { email }) => Some(ContactType::Both { number, email }),
        Some(ContactType::Both {
            number: _number,
            email,
        }) => Some(ContactType::Both { number, email }),
        Some(ContactType::Bad { .. }) => Some(ContactType::Phone { number }),
        None => Some(ContactType::Phone { number }),
    };
    let mut rita_client = settings::get_rita_client();
    exit_client.contact_info = option_convert(res);
    rita_client.exit_client = exit_client;

    settings::set_rita_client(rita_client);
    // try and save the config and fail if we can't
    let rita_client = settings::get_rita_client();
    if let Err(_e) = rita_client.write(&settings::get_flag_config()) {
        return HttpResponse::InternalServerError().finish();
    } else {
        settings::set_rita_client(rita_client);
    }

    HttpResponse::Ok().finish()
}

pub fn get_phone_number(_req: HttpRequest) -> HttpResponse {
    let rita_client = settings::get_rita_client();
    let exit_client = rita_client.exit_client;
    match &option_convert(exit_client.contact_info) {
        Some(ContactType::Phone { number }) => HttpResponse::Ok().json(number.to_string()),
        Some(ContactType::Both {
            email: _email,
            number,
        }) => HttpResponse::Ok().json(number.to_string()),
        _ => HttpResponse::Ok().finish(),
    }
}

pub fn set_email(req: String) -> HttpResponse {
    let clean_string = clean_quotes(&req);
    trace!("Got email {:?}", clean_string);
    let email: EmailAddress = match clean_string.parse() {
        Ok(p) => p,
        Err(e) => {
            info!("Failed to parse email with {:?}", e);
            return HttpResponse::BadRequest().finish();
        }
    };

    let mut exit_client = settings::get_rita_client().exit_client;
    // merge the new value into the existing struct, for the various possibilities
    let res = match option_convert(exit_client.contact_info.clone()) {
        Some(ContactType::Phone { number }) => Some(ContactType::Both { number, email }),
        Some(ContactType::Email { .. }) => Some(ContactType::Email { email }),
        Some(ContactType::Both {
            number,
            email: _email,
        }) => Some(ContactType::Both { number, email }),
        Some(ContactType::Bad { .. }) => Some(ContactType::Email { email }),
        None => Some(ContactType::Email { email }),
    };
    exit_client.contact_info = option_convert(res);

    // try and save the config and fail if we can't
    let rita_client = settings::get_rita_client();
    if let Err(_e) = rita_client.write(&settings::get_flag_config()) {
        return HttpResponse::InternalServerError().finish();
    } else {
        settings::set_rita_client(rita_client);
    }
    let mut rita_client = settings::get_rita_client();
    rita_client.exit_client = exit_client;
    settings::set_rita_client(rita_client);

    HttpResponse::Ok().finish()
}

pub fn get_email(_req: HttpRequest) -> HttpResponse {
    let rita_client = settings::get_rita_client();
    let exit_client = rita_client.exit_client;
    match &option_convert(exit_client.contact_info) {
        Some(ContactType::Email { email }) => HttpResponse::Ok().json(email.to_string()),
        Some(ContactType::Both {
            number: _number,
            email,
        }) => HttpResponse::Ok().json(email.to_string()),
        _ => HttpResponse::Ok().finish(),
    }
}
