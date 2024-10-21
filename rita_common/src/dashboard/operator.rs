//! This module contains the operator address related endpoints the operator address is used to organize
//! what network a given device is a part of and for client devices the address to which operator fees are
//! paid, exits only use operator addresses for organization and not for fee collection.
use actix_web::web::Path;
use actix_web::{HttpRequest, HttpResponse};
use clarity::Address;

enum Mode {
    Client,
    Exit,
}

fn get_mode() -> Option<Mode> {
    if settings::check_if_client() {
        Some(Mode::Client)
    } else if settings::check_if_exit() {
        Some(Mode::Exit)
    } else {
        None
    }
}

fn get_operator_address(mode: Mode) -> Option<Address> {
    match mode {
        Mode::Client => settings::get_rita_client().operator.operator_address,
        Mode::Exit => settings::get_rita_exit().operator.operator_address,
    }
}

fn set_operator_address_and_save(mode: Mode, address: Option<Address>) {
    match mode {
        Mode::Client => {
            let mut rita_client = settings::get_rita_client();
            rita_client.operator.operator_address = address;
            settings::set_rita_client(rita_client);
        }
        Mode::Exit => {
            let mut rita_exit = settings::get_rita_exit();
            rita_exit.operator.operator_address = address;
            settings::set_rita_exit(rita_exit);
        }
    }

    // Save configuration immediately and log any error, but don't return it
    if let Err(e) = settings::write_config() {
        error!("Failed to write config: {:?}", e);
    }
}

pub async fn get_operator(_req: HttpRequest) -> HttpResponse {
    trace!("get operator address: Hit");

    match get_mode() {
        Some(mode) => HttpResponse::Ok().json(get_operator_address(mode)),
        None => HttpResponse::InternalServerError().finish(),
    }
}

pub async fn change_operator(path: Path<Address>) -> HttpResponse {
    trace!("add operator address: Hit");
    let provided_address = Some(path.into_inner());

    match get_mode() {
        Some(mode) => {
            set_operator_address_and_save(mode, provided_address);
            HttpResponse::Ok().finish()
        }
        None => HttpResponse::InternalServerError().finish(),
    }
}

pub async fn remove_operator(_path: Path<Address>) -> HttpResponse {
    match get_mode() {
        Some(mode) => {
            set_operator_address_and_save(mode, None);
            HttpResponse::Ok().finish()
        }
        None => HttpResponse::InternalServerError().finish(),
    }
}
