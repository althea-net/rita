use std::thread;

use actix_rt::System;
use actix_web::{
    web::{self, Json},
    App, HttpResponse, HttpServer,
};
use althea_types::ExitClientIdentity;
use clarity::{Address, PrivateKey};
use rita_client_registration::{
    client_db::check_and_add_user_admin, handle_sms_registration, register_client_batch_loop,
};
use web30::client::Web3;

use crate::{
    payments_eth::WEB3_TIMEOUT,
    utils::{get_eth_node, get_test_runner_magic_phone, TX_TIMEOUT},
};
use crate::{
    registration_server::register_client_batch_loop::register_client_batch_loop,
    utils::REGISTRATION_SERVER_KEY,
};

pub const REGISTRATION_PORT_SERVER: u16 = 40400;

pub async fn start_registration_server(db_addr: Address) {
    let miner_private_key: PrivateKey = REGISTRATION_SERVER_KEY.parse().unwrap();
    let miner_pub_key = miner_private_key.to_address();
    let contact = Web3::new(&get_eth_node(), WEB3_TIMEOUT);

    check_and_add_user_admin(
        &contact,
        db_addr,
        miner_pub_key,
        miner_private_key,
        Some(TX_TIMEOUT),
        vec![],
    )
    .await
    .unwrap();

    // Start the register loop
    register_client_batch_loop(get_eth_node(), db_addr, miner_private_key);

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

    HttpResponse::Ok().json(
        handle_sms_registration(
            client,
            "dummy key".to_string(),
            "dummy-id".to_string(),
            Some(get_test_runner_magic_phone()),
        )
        .await,
    )
}

async fn test_endpoint() -> HttpResponse {
    HttpResponse::Ok().finish()
}
