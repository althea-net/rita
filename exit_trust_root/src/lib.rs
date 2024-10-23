use actix_web::{web, App, HttpServer};
use althea_types::{ExitServerList, SignedExitServerList};
use clarity::Address;
use client_db::get_exits_list;
use config::Config;
use config::ConfigAndCache;
use crossbeam::queue::SegQueue;
use endpoints::return_signed_exit_contract_data;
use endpoints::start_client_registration;
use endpoints::submit_registration_code;
use log::info;
use openssl::ssl::{SslAcceptor, SslMethod};
use register_client_batch_loop::register_client_batch_loop;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::join;
use web30::client::Web3;
use web30::jsonrpc::error::Web3Error;

pub mod client_db;
pub mod config;
pub mod endpoints;
pub mod register_client_batch_loop;
pub mod sms_auth;

const RPC_SERVER: &str = "https://dai.althea.net";
const WEB3_TIMEOUT: Duration = Duration::from_secs(10);

// Faster update time in development mode
const SIGNATURE_UPDATE_SLEEP: Duration = if DEVELOPMENT || cfg!(test) {
    Duration::from_secs(10)
} else {
    Duration::from_secs(300)
};

pub const DEVELOPMENT: bool = cfg!(feature = "development");
/// The backend RPC port for the info server fucntions implemented in this repo
pub const SERVER_PORT: u16 = 4050;

async fn retrieve_exit_server_list(
    exit_contract: Address,
    cache: ConfigAndCache,
) -> Result<SignedExitServerList, Web3Error> {
    let config = cache.get_config();
    let exits = match DEVELOPMENT || cfg!(test) {
        true => {
            let node_ip = IpAddr::V4(Ipv4Addr::new(7, 7, 7, 1));
            let web3_url = format!("http://{}:8545", node_ip);
            info!("Our address is {:?}", config.private_key.to_address());
            get_exits_list(
                &Web3::new(&web3_url, WEB3_TIMEOUT),
                config.private_key.to_address(),
                exit_contract,
            )
            .await
        }
        false => {
            get_exits_list(
                &Web3::new(RPC_SERVER, WEB3_TIMEOUT),
                config.private_key.to_address(),
                exit_contract,
            )
            .await
        }
    };

    match exits {
        Ok(exits) => {
            let exit_list = ExitServerList {
                contract: exit_contract,
                exit_list: exits,
                created: std::time::SystemTime::now(),
            };
            info!(
                "Signing exit list with PUBKEY: {:?}",
                config.private_key.to_address()
            );
            let cache_value = exit_list.sign(config.private_key);

            // add this new exit list to the cache
            cache.insert(exit_contract, cache_value.clone());
            Ok(cache_value)
        }
        Err(e) => {
            info!("Failed to get exit list from contract {:?}", e);
            Err(e)
        }
    }
}

pub async fn start_exit_trust_root_server(config: Config) {
    let domain = config.url.clone();
    let https = config.https;
    let exit_contract_data_cache: ConfigAndCache = ConfigAndCache {
        config: Arc::new(config.clone()),
        cache: Arc::new(RwLock::new(HashMap::new())),
        registration_queue: Arc::new(SegQueue::new()),
        texts_sent: Arc::new(RwLock::new(HashMap::new())),
    };
    let sig_loop = signature_update_loop(exit_contract_data_cache.clone());
    let reg_loop = register_client_batch_loop(
        config.rpc,
        config.private_key,
        exit_contract_data_cache.registration_queue.clone(),
    );
    let web_data = web::Data::new(exit_contract_data_cache.clone());

    let server = HttpServer::new(move || {
        App::new()
            .service(return_signed_exit_contract_data)
            .service(start_client_registration)
            .service(submit_registration_code)
            .app_data(web_data.clone())
    });
    info!("Starting exit trust root server on {:?}", domain);

    let server = if https {
        // build TLS config from files
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        // set the certificate chain file location
        builder
            .set_certificate_chain_file(format!("/etc/letsencrypt/live/{}/fullchain.pem", domain))
            .unwrap();
        builder
            .set_private_key_file(
                format!("/etc/letsencrypt/live/{}/privkey.pem", domain),
                openssl::ssl::SslFiletype::PEM,
            )
            .unwrap();

        info!("Binding to SSL");
        server
            .bind_openssl(format!("{}:{}", domain, SERVER_PORT), builder)
            .unwrap()
    } else {
        info!("Binding to {}:{}", domain, SERVER_PORT);
        server.bind(format!("{}:{}", domain, SERVER_PORT)).unwrap()
    };

    // run all three of these loops in the async executor that called this function
    // this function will not return and block indefinitely
    let _ = join!(server.run(), sig_loop, reg_loop);
}

/// In order to improve scalability this loop grabs and signs an updated list of exits from each exit contract
/// that has previously been requested from this server every 5 minutes. This allows the server to return instantly
/// on the next request from the client without having to perform rpc query 1-1 with requests.
pub async fn signature_update_loop(cache: ConfigAndCache) {
    loop {
        let cache_iter = cache.get_all();
        for exit_contract in cache_iter.keys() {
            // get the latest exit list from the contract
            match retrieve_exit_server_list(*exit_contract, cache.clone()).await {
                // grab the cache here so we don't lock it while awaiting for every single contract
                Ok(cache_value) => {
                    // update the cache
                    cache.insert(*exit_contract, cache_value);
                }
                Err(e) => {
                    info!("Failed to get exit list from contract {:?}", e);
                }
            }
        }
        tokio::time::sleep(SIGNATURE_UPDATE_SLEEP).await;
    }
}
