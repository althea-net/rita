use actix_web::rt::System;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use althea_types::{ExitServerList, SignedExitServerList};
use clarity::Address;
use client_db::get_exits_list;
use config::CONFIG;
use log::info;
use openssl::ssl::{SslAcceptor, SslMethod};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;
use web30::client::Web3;
use web30::jsonrpc::error::Web3Error;

pub mod client_db;
pub mod config;
pub mod register_client_batch_loop;
pub mod rita_client_registration;

const RPC_SERVER: &str = "https://dai.althea.net";
const WEB3_TIMEOUT: Duration = Duration::from_secs(10);

// five minutes
const SIGNATURE_UPDATE_SLEEP: Duration = Duration::from_secs(300);

pub const DEVELOPMENT: bool = cfg!(feature = "development");
const SSL: bool = !DEVELOPMENT;
pub const EXIT_ROOT_DOMAIN: &str = if cfg!(test) || cfg!(feature = "development") {
    "http://10.0.0.1:4050"
} else {
    "https://exitroot.althea.net"
};
/// The backend RPC port for the info server fucntions implemented in this repo
pub const SERVER_PORT: u16 = 4050;

/// This endpoint retrieves and signs the data from any specified exit contract,
/// allowing this server to serve as a root of trust for several different exit contracts.
#[get("/{exit_contract}")]
pub async fn return_exit_contract_data(
    exit_contract: web::Path<Address>,
    cache: web::Data<Arc<RwLock<HashMap<Address, SignedExitServerList>>>>,
) -> impl Responder {
    let contract: Address = exit_contract.into_inner();
    let cached_list = {
        let cache_read = cache.read().unwrap();
        cache_read.get(&contract).cloned()
    };

    match cached_list {
        Some(list) => {
            // return a signed exit server list based on the given key
            HttpResponse::Ok().json(list)
        }
        None => match retrieve_exit_server_list(contract, cache.get_ref().clone()).await {
            Ok(list) => HttpResponse::Ok().json(list),
            Err(e) => {
                info!("Failed to get exit list from contract {:?}", e);
                HttpResponse::InternalServerError().json("Failed to get exit list from contract")
            }
        },
    }
}

async fn retrieve_exit_server_list(
    exit_contract: Address,
    cache: Arc<RwLock<HashMap<Address, SignedExitServerList>>>,
) -> Result<SignedExitServerList, Web3Error> {
    let exits = match DEVELOPMENT || cfg!(test) {
        true => {
            let node_ip = IpAddr::V4(Ipv4Addr::new(7, 7, 7, 1));
            let web3_url = format!("http://{}:8545", node_ip);
            info!(
                "Our address is {:?}",
                CONFIG.clarity_private_key.to_address()
            );
            get_exits_list(
                &Web3::new(&web3_url, WEB3_TIMEOUT),
                CONFIG.clarity_private_key.to_address(),
                exit_contract,
            )
            .await
        }
        false => {
            get_exits_list(
                &Web3::new(RPC_SERVER, WEB3_TIMEOUT),
                CONFIG.clarity_private_key.to_address(),
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
                CONFIG.clarity_private_key.to_address()
            );
            let cache_value = exit_list.sign(CONFIG.clarity_private_key);

            // add this new exit list to the cache
            cache
                .write()
                .unwrap()
                .insert(exit_contract, cache_value.clone());
            Ok(cache_value)
        }
        Err(e) => {
            info!("Failed to get exit list from contract {:?}", e);
            Err(e)
        }
    }
}

pub fn start_exit_trust_root_server() {
    let exit_contract_data_cache: Arc<RwLock<HashMap<Address, SignedExitServerList>>> =
        Arc::new(RwLock::new(HashMap::new()));
    signature_update_loop(exit_contract_data_cache.clone());
    let web_data = web::Data::new(exit_contract_data_cache.clone());
    thread::spawn(move || {
        let runner = System::new();
        runner.block_on(async move {
            let server = HttpServer::new(move || {
                App::new()
                    .service(return_exit_contract_data)
                    .app_data(web_data.clone())
            });
            info!("Starting exit trust root server on {:?}", EXIT_ROOT_DOMAIN);

            let server = if SSL {
                // build TLS config from files
                let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
                // set the certificate chain file location
                builder
                    .set_certificate_chain_file(format!(
                        "/etc/letsencrypt/live/{}/fullchain.pem",
                        EXIT_ROOT_DOMAIN
                    ))
                    .unwrap();
                builder
                    .set_private_key_file(
                        format!("/etc/letsencrypt/live/{}/privkey.pem", EXIT_ROOT_DOMAIN),
                        openssl::ssl::SslFiletype::PEM,
                    )
                    .unwrap();

                info!("Binding to SSL");
                server
                    .bind_openssl(format!("{}:{}", EXIT_ROOT_DOMAIN, SERVER_PORT), builder)
                    .unwrap()
            } else {
                info!("Binding to {}:{}", EXIT_ROOT_DOMAIN, SERVER_PORT);
                server
                    .bind(format!("{}:{}", EXIT_ROOT_DOMAIN, SERVER_PORT))
                    .unwrap()
            };

            let _ = server.run().await;
        });
    });
}

/// In order to improve scalability this loop grabs and signs an updated list of exits from each exit contract
/// that has previously been requested from this server every 5 minutes. This allows the server to return instantly
/// on the next request from the client without having to perform rpc query 1-1 with requests.
pub fn signature_update_loop(cache: Arc<RwLock<HashMap<Address, SignedExitServerList>>>) {
    thread::spawn(move || loop {
        let runner = System::new();
        runner.block_on(async {
            let cache_iter = cache.read().unwrap().clone();
            for (exit_contract, _value) in cache_iter.iter() {
                // get the latest exit list from the contract
                match retrieve_exit_server_list(*exit_contract, cache.clone()).await {
                    // grab the cache here so we don't lock it while awaiting for every single contract
                    Ok(cache_value) => {
                        // update the cache
                        cache.write().unwrap().insert(*exit_contract, cache_value);
                    }
                    Err(e) => {
                        info!("Failed to get exit list from contract {:?}", e);
                    }
                }
            }
        });
        if DEVELOPMENT || cfg!(test) {
            thread::sleep(Duration::from_secs(10));
        } else {
            thread::sleep(SIGNATURE_UPDATE_SLEEP);
        }
    });
}
