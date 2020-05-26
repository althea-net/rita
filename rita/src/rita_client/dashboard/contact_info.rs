//! This file manages the contact info struct in the client exit details. Which is the one true location of contact details storage, although
//! we end up processing and moving contact data in a few other places (exit registration, text notifications) the contact_details member of
//! the exit settings struct is the one true source. All the others are updated as needed and you should try to phase them out if practical.

use crate::SETTING;
use actix_web::HttpRequest;
use actix_web::HttpResponse;
use actix_web::Json;
use althea_types::interop::ContactType;
use lettre::EmailAddress;
use phonenumber::PhoneNumber;
use settings::client::RitaClientSettings;

pub fn set_phone_number(req: Json<String>) -> HttpResponse {
    let number: PhoneNumber = match req.into_inner().parse() {
        Ok(p) => p,
        Err(_e) => return HttpResponse::BadRequest().finish(),
    };
    let mut exit_client = SETTING.get_exit_client_mut();
    // merge the new value into the existing struct, for the various possibilities
    exit_client.contact_info = match exit_client.contact_info.clone() {
        Some(ContactType::Phone { .. }) => Some(ContactType::Phone { number }),
        Some(ContactType::Email { email }) => Some(ContactType::Both { number, email }),
        Some(ContactType::Both {
            number: _number,
            email,
        }) => Some(ContactType::Both { number, email }),
        Some(ContactType::Bad { .. }) => Some(ContactType::Phone { number }),
        None => Some(ContactType::Phone { number }),
    };
    HttpResponse::Ok().finish()
}

pub fn get_phone_number(_req: HttpRequest) -> HttpResponse {
    let exit_client = SETTING.get_exit_client();
    match &exit_client.contact_info {
        Some(ContactType::Phone { number }) => HttpResponse::Ok().json(number),
        Some(ContactType::Both {
            email: _email,
            number,
        }) => HttpResponse::Ok().json(number),
        _ => HttpResponse::Ok().finish(),
    }
}

pub fn set_email(req: Json<String>) -> HttpResponse {
    let email: EmailAddress = match req.into_inner().parse() {
        Ok(p) => p,
        Err(_e) => return HttpResponse::BadRequest().finish(),
    };
    let mut exit_client = SETTING.get_exit_client_mut();
    // merge the new value into the existing struct, for the various possibilities
    exit_client.contact_info = match exit_client.contact_info.clone() {
        Some(ContactType::Phone { number }) => Some(ContactType::Both { number, email }),
        Some(ContactType::Email { .. }) => Some(ContactType::Email { email }),
        Some(ContactType::Both {
            number,
            email: _email,
        }) => Some(ContactType::Both { number, email }),
        Some(ContactType::Bad { .. }) => Some(ContactType::Email { email }),
        None => Some(ContactType::Email { email }),
    };
    HttpResponse::Ok().finish()
}

pub fn get_email(_req: HttpRequest) -> HttpResponse {
    let exit_client = SETTING.get_exit_client();
    match &exit_client.contact_info {
        Some(ContactType::Email { email }) => HttpResponse::Ok().json(email),
        Some(ContactType::Both {
            number: _number,
            email,
        }) => HttpResponse::Ok().json(email),
        _ => HttpResponse::Ok().finish(),
    }
}
