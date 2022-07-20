//! This file manages the contact info struct in the client exit details. Which is the one true location of contact details storage, although
//! we end up processing and moving contact data in a few other places (exit registration, text notifications) the contact_details member of
//! the exit settings struct is the one true source. All the others are updated as needed and you should try to phase them out if practical.

use rita_common::utils::option_convert;

use actix_web_async::HttpRequest;
use actix_web_async::HttpResponse;
use althea_types::ContactType;
use lettre::Address as EmailAddress;
use phonenumber::PhoneNumber;

fn clean_quotes(val: &str) -> String {
    val.trim().trim_matches('"').trim_matches('\\').to_string()
}

fn add_to_sequence(sequence: Option<u32>) -> u32 {
    match sequence {
        Some(seq) => seq + 1,
        None => 1,
    }
}

pub async fn set_phone_number(req: String) -> HttpResponse {
    let clean_string = clean_quotes(&req);
    trace!("Got number {:?}", clean_string);
    let phone_number: PhoneNumber = match clean_string.parse() {
        Ok(p) => p,
        Err(e) => {
            info!("Failed to parse phonenumber with {:?}", e);
            return HttpResponse::BadRequest().finish();
        }
    };

    let mut rita_client = settings::get_rita_client();

    // merge the new value into the existing struct, for the various possibilities
    let res = match option_convert(rita_client.exit_client.contact_info.clone()) {
        Some(ContactType::Phone {
            number: _,
            sequence_number,
        }) => Some(ContactType::Phone {
            number: phone_number,
            sequence_number: Some(add_to_sequence(sequence_number)),
        }),
        Some(ContactType::Email {
            email,
            sequence_number,
        }) => Some(ContactType::Both {
            number: phone_number,
            email,
            sequence_number: Some(add_to_sequence(sequence_number)),
        }),
        Some(ContactType::Both {
            number: _number,
            email,
            sequence_number,
        }) => Some(ContactType::Both {
            number: phone_number,
            email,
            sequence_number: Some(add_to_sequence(sequence_number)),
        }),
        Some(ContactType::Bad {
            invalid_number: _,
            invalid_email: _,
            sequence_number,
        }) => Some(ContactType::Phone {
            number: phone_number,
            sequence_number: Some(add_to_sequence(sequence_number)),
        }),
        None => Some(ContactType::Phone {
            number: phone_number,
            sequence_number: Some(0),
        }),
    };
    rita_client.exit_client.contact_info = option_convert(res);

    settings::set_rita_client(rita_client);

    // save immediately
    if let Err(_e) = settings::write_config() {
        return HttpResponse::InternalServerError().finish();
    }

    HttpResponse::Ok().finish()
}

pub async fn get_phone_number(_req: HttpRequest) -> HttpResponse {
    let rita_client = settings::get_rita_client();
    let exit_client = rita_client.exit_client;
    match &option_convert(exit_client.contact_info) {
        Some(ContactType::Phone {
            number,
            sequence_number: _,
        }) => HttpResponse::Ok().json(number.to_string()),
        Some(ContactType::Both {
            email: _email,
            number,
            sequence_number: _,
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

    let mut rita_client = settings::get_rita_client();

    // merge the new value into the existing struct, for the various possibilities
    let res = match option_convert(rita_client.exit_client.contact_info.clone()) {
        Some(ContactType::Phone {
            number,
            sequence_number,
        }) => Some(ContactType::Both {
            number,
            email,
            sequence_number: Some(add_to_sequence(sequence_number)),
        }),
        Some(ContactType::Email {
            email,
            sequence_number,
        }) => Some(ContactType::Email {
            email,
            sequence_number: Some(add_to_sequence(sequence_number)),
        }),
        Some(ContactType::Both {
            number,
            email: _email,
            sequence_number,
        }) => Some(ContactType::Both {
            number,
            email,
            sequence_number: Some(add_to_sequence(sequence_number)),
        }),
        Some(ContactType::Bad {
            invalid_number: _,
            invalid_email: _,
            sequence_number,
        }) => Some(ContactType::Email {
            email,
            sequence_number: Some(add_to_sequence(sequence_number)),
        }),
        None => Some(ContactType::Email {
            email,
            sequence_number: Some(0),
        }),
    };

    rita_client.exit_client.contact_info = option_convert(res);
    settings::set_rita_client(rita_client);

    if let Err(_e) = settings::write_config() {
        return HttpResponse::InternalServerError().finish();
    }

    HttpResponse::Ok().finish()
}

pub async fn get_email(_req: HttpRequest) -> HttpResponse {
    let rita_client = settings::get_rita_client();
    let exit_client = rita_client.exit_client;
    match &option_convert(exit_client.contact_info) {
        Some(ContactType::Email {
            email,
            sequence_number: _,
        }) => HttpResponse::Ok().json(email.to_string()),
        Some(ContactType::Both {
            number: _number,
            email,
            sequence_number: _,
        }) => HttpResponse::Ok().json(email.to_string()),
        _ => HttpResponse::Ok().finish(),
    }
}
