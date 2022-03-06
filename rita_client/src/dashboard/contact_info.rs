//! This file manages the contact info struct in the client exit details. Which is the one true location of contact details storage, although
//! we end up processing and moving contact data in a few other places (exit registration, text notifications) the contact_details member of
//! the exit settings struct is the one true source. All the others are updated as needed and you should try to phase them out if practical.

use actix_web_async::HttpRequest;
use actix_web_async::HttpResponse;
use althea_types::ContactDetails;
use althea_types::ContactType;
use lettre::EmailAddress;
use phonenumber::PhoneNumber;

use crate::operator_update::get_contact_info;
use crate::operator_update::set_contact_info;

fn clean_quotes(val: &str) -> String {
    val.trim().trim_matches('"').trim_matches('\\').to_string()
}

pub async fn set_phone_number(req: String) -> HttpResponse {
    let clean_string = clean_quotes(&req);
    trace!("Got number {:?}", clean_string);
    let number: PhoneNumber = match clean_string.parse() {
        Ok(p) => p,
        Err(e) => {
            info!("Failed to parse phonenumber with {:?}", e);
            return HttpResponse::BadRequest().finish();
        }
    };

    // merge the new value into the existing struct, for the various possibilities
    let res = match ContactType::convert(get_contact_info()) {
        Some(ContactType::Phone { .. }) => Some(ContactType::Phone { number }),
        Some(ContactType::Email { email }) => Some(ContactType::Both { number, email }),
        Some(ContactType::Both {
            number: _number,
            email,
        }) => Some(ContactType::Both { number, email }),
        Some(ContactType::Bad { .. }) => Some(ContactType::Phone { number }),
        None => Some(ContactType::Phone { number }),
    };
    set_contact_info(ContactDetails::from(res));

    // save immediately
    if let Err(_e) = settings::write_config() {
        return HttpResponse::InternalServerError().finish();
    }

    HttpResponse::Ok().finish()
}

pub async fn get_phone_number(_req: HttpRequest) -> HttpResponse {
    match ContactType::convert(get_contact_info()) {
        Some(ContactType::Phone { number }) => HttpResponse::Ok().json(number.to_string()),
        Some(ContactType::Both {
            email: _email,
            number,
        }) => HttpResponse::Ok().json(number.to_string()),
        _ => HttpResponse::Ok().finish(),
    }
}

pub async fn set_email(req: String) -> HttpResponse {
    let clean_string = clean_quotes(&req);
    trace!("Got email {:?}", clean_string);
    let email: EmailAddress = match clean_string.parse() {
        Ok(p) => p,
        Err(e) => {
            info!("Failed to parse email with {:?}", e);
            return HttpResponse::BadRequest().finish();
        }
    };

    // merge the new value into the existing struct, for the various possibilities
    let res = match ContactType::convert(get_contact_info()) {
        Some(ContactType::Phone { number }) => Some(ContactType::Both { number, email }),
        Some(ContactType::Email { .. }) => Some(ContactType::Email { email }),
        Some(ContactType::Both {
            number,
            email: _email,
        }) => Some(ContactType::Both { number, email }),
        Some(ContactType::Bad { .. }) => Some(ContactType::Email { email }),
        None => Some(ContactType::Email { email }),
    };

    set_contact_info(ContactDetails::from(res));

    if let Err(_e) = settings::write_config() {
        return HttpResponse::InternalServerError().finish();
    }

    HttpResponse::Ok().finish()
}

pub async fn get_email(_req: HttpRequest) -> HttpResponse {
    match ContactType::convert(get_contact_info()) {
        Some(ContactType::Email { email }) => HttpResponse::Ok().json(email.to_string()),
        Some(ContactType::Both {
            number: _number,
            email,
        }) => HttpResponse::Ok().json(email.to_string()),
        _ => HttpResponse::Ok().finish(),
    }
}
