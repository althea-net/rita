// this file for frontend endpoitns called from the root of trust server frontend only

use crate::{
    client_db::{
        get_all_registered_clients, get_exit_admin_list, get_exits_list, get_state_admin_list,
        get_user_admin_list,
    },
    config::ConfigAndCache,
    WEB3_TIMEOUT,
};
use actix_web::{get, web, HttpResponse, Responder};
use clarity::Address;
use log::error;
use std::str::FromStr;
use web30::client::Web3;

const EXIT_CONTRACT: &str = "0x36eA7d5BC88f363FaD90D4AC8c64789E86e45027";

/// Used by frontend, gets just the exit list. does not need to be signed
#[get("/exit_list")]
pub async fn get_exit_list(cache: web::Data<ConfigAndCache>) -> impl Responder {
    let config = cache.get_config();
    let exit_list = get_exits_list(
        &Web3::new(&config.rpc, WEB3_TIMEOUT),
        config.private_key.to_address(),
        Address::from_str(EXIT_CONTRACT).unwrap(),
    )
    .await;
    match exit_list {
        Ok(exits) => HttpResponse::Ok().json(exits),
        Err(e) => {
            error!("Failed to get exit list from contract: {:?}", e);
            HttpResponse::InternalServerError().json("Failed to get exit list from contract")
        }
    }
}

#[get("/clients_list")]
pub async fn get_client_list(cache: web::Data<ConfigAndCache>) -> impl Responder {
    let config = cache.get_config();
    let client_list = get_all_registered_clients(
        &Web3::new(&config.rpc, WEB3_TIMEOUT),
        config.private_key.to_address(),
        Address::from_str(EXIT_CONTRACT).unwrap(),
    )
    .await;
    match client_list {
        Ok(exits) => HttpResponse::Ok().json(exits),
        Err(e) => {
            error!("Failed to get client list from contract: {:?}", e);
            HttpResponse::InternalServerError().json("Failed to get client list from contract")
        }
    }
}

#[get("/exit_admin_list")]
pub async fn get_exit_admins(cache: web::Data<ConfigAndCache>) -> impl Responder {
    let config = cache.get_config();
    let client_list = get_exit_admin_list(
        &Web3::new(&config.rpc, WEB3_TIMEOUT),
        config.private_key.to_address(),
        Address::from_str(EXIT_CONTRACT).unwrap(),
    )
    .await;
    match client_list {
        Ok(exits) => HttpResponse::Ok().json(exits),
        Err(e) => {
            error!("Failed to get client list from contract: {:?}", e);
            HttpResponse::InternalServerError().json("Failed to get client list from contract")
        }
    }
}

#[get("/user_admin_list")]
pub async fn get_user_admins(cache: web::Data<ConfigAndCache>) -> impl Responder {
    let config = cache.get_config();
    let client_list = get_user_admin_list(
        &Web3::new(&config.rpc, WEB3_TIMEOUT),
        config.private_key.to_address(),
        Address::from_str(EXIT_CONTRACT).unwrap(),
    )
    .await;
    match client_list {
        Ok(exits) => HttpResponse::Ok().json(exits),
        Err(e) => {
            error!("Failed to get client list from contract: {:?}", e);
            HttpResponse::InternalServerError().json("Failed to get client list from contract")
        }
    }
}

#[get("/state_admin_list")]
pub async fn get_state_admins(cache: web::Data<ConfigAndCache>) -> impl Responder {
    let config = cache.get_config();
    let client_list = get_state_admin_list(
        &Web3::new(&config.rpc, WEB3_TIMEOUT),
        config.private_key.to_address(),
        Address::from_str(EXIT_CONTRACT).unwrap(),
    )
    .await;
    match client_list {
        Ok(exits) => HttpResponse::Ok().json(exits),
        Err(e) => {
            error!("Failed to get client list from contract: {:?}", e);
            HttpResponse::InternalServerError().json("Failed to get client list from contract")
        }
    }
}
