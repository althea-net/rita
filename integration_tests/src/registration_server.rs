use std::{
    sync::{Arc, RwLock},
    thread,
};

use actix_rt::System;
use actix_web::{
    web::{self, Json},
    App, HttpResponse, HttpServer,
};
use althea_types::ExitClientIdentity;
use clarity::Address;
use rita_client_registration::{
    client_conflict, handle_sms_registration, register_client_batch_loop,
};
use web30::client::Web3;

use crate::registration_server::register_client_batch_loop::register_client_batch_loop;
use crate::{
    payments_eth::{get_miner_address, get_miner_key, WEB3_TIMEOUT},
    utils::{get_eth_node, get_test_runner_magic_phone},
};
use log::{error, info};

pub const REGISTRATION_PORT_SERVER: u16 = 40400;

#[derive(Clone, Copy, Debug, Default)]
struct RegistrationServerState {
    pub db_contract_addr: Option<Address>,
}

lazy_static! {
    static ref REGISTRATION_SERVER_STATE: Arc<RwLock<RegistrationServerState>> =
        Arc::new(RwLock::new(RegistrationServerState::default()));
}

fn get_althea_db_addr() -> Option<Address> {
    REGISTRATION_SERVER_STATE.read().unwrap().db_contract_addr
}

fn set_althea_db_addr(addr: Address) {
    REGISTRATION_SERVER_STATE.write().unwrap().db_contract_addr = Some(addr)
}

pub fn start_registration_server(db_addr: Address) {
    // Start the register loop
    register_client_batch_loop(get_eth_node(), db_addr, get_miner_key());

    set_althea_db_addr(db_addr);
    // Start endpoint listener
    thread::spawn(move || {
        let runner = System::new();
        runner.block_on(async move {
            // Exit stuff, huge threadpool to offset Pgsql blocking
            let _res = HttpServer::new(|| {
                App::new()
                    .route("/register_router", web::post().to(register_router))
                    .route("/test", web::get().to(test_endpoint))
            })
            .bind(format!("7.7.7.1:{}", REGISTRATION_PORT_SERVER))
            .unwrap()
            .shutdown_timeout(0)
            .run()
            .await;
        });
    });
}

async fn register_router(client: Json<ExitClientIdentity>) -> HttpResponse {
    let client = client.into_inner();
    info!("Attempting to register client: {}", client.global.mesh_ip);
    let contact = Web3::new(&get_eth_node(), WEB3_TIMEOUT);
    let db_addr = get_althea_db_addr();

    // Check for an existing client
    let client = client;
    if client_conflict(
        &client,
        &contact,
        db_addr.expect("This should be set"),
        get_miner_address(),
    )
    .await
    {
        error!("Found a client conflict! {}", client.global.mesh_ip);
        return HttpResponse::Unauthorized().finish();
    }

    HttpResponse::Ok().json(
        handle_sms_registration(
            client,
            "dummy key".to_string(),
            Some(get_test_runner_magic_phone()),
        )
        .await,
    )
}

async fn test_endpoint() -> HttpResponse {
    HttpResponse::Ok().finish()
}
