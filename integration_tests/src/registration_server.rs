use std::thread;

use actix_rt::System;
use actix_web::{
    web::{self, Json},
    App, HttpResponse, HttpServer,
};
use althea_types::ExitClientIdentity;
use rita_client_registration::{
    client_conflict, handle_sms_registration, register_client_batch_loop,
};
use web30::client::Web3;

use crate::{
    payments_eth::{ETH_MINER_KEY, WEB3_TIMEOUT},
    utils::{get_altheadb_contract_addr, get_eth_node, get_test_runner_magic_phone},
};
use log::{error, info};

pub const REGISTRATION_PORT_SERVER: u16 = 40400;

pub fn start_registration_server() {
    // Start the register loop
    register_client_batch_loop(
        get_eth_node(),
        get_altheadb_contract_addr(),
        ETH_MINER_KEY.parse().unwrap(),
    );

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

    // Check for an existing client
    let client = client;
    if client_conflict(
        &client,
        &contact,
        get_altheadb_contract_addr(),
        ETH_MINER_KEY
            .parse::<clarity::PrivateKey>()
            .unwrap()
            .to_address(),
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
