use actix_web::rt::System;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use althea_types::{EncryptedExitServerList, ExitServerList, SignedExitServerList};
use clarity::Address;
use config::{load_config, CONFIG};
use crypto_box::aead::{Aead, AeadCore, OsRng};
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use env_logger::Env;
use log::info;
use rita_client_registration::client_db::get_exits_list;
use rustls::ServerConfig;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;
use tls::{load_certs, load_rustls_private_key};
use web30::client::Web3;
use web30::jsonrpc::error::Web3Error;

pub mod config;
pub mod tls;

const RPC_SERVER: &str = "https://althea.gravitychain.io";

pub const DEVELOPMENT: bool = cfg!(feature = "development");
const SSL: bool = !DEVELOPMENT;
pub const DOMAIN: &str = if cfg!(test) || DEVELOPMENT {
    "localhost"
} else {
    "exitroot.althea.net"
};
/// The backend RPC port for the info server fucntions implemented in this repo
const SERVER_PORT: u16 = 9000;

/// This endpoint retrieves and signs the data from any specified exit contract,
/// allowing this server to serve as a root of trust for several different exit contracts.
#[get("/{exit_contract}")]
async fn return_exit_contract_data(
    exit_contract: web::Path<Address>,
    pubkey: web::Data<[u8; 32]>,
    cache: web::Data<Arc<RwLock<HashMap<Address, ExitContractSignatureCacheValue>>>>,
) -> impl Responder {
    let contract = exit_contract.into_inner();
    match cache.read().unwrap().get(&contract) {
        Some(cache) => {
            // return an encrypted exit server list based on the given key
            HttpResponse::Ok().json(cache.to_encrypted_exit_server_list((*pubkey.get_ref()).into()))
        }
        None => {
            match retrieve_exit_server_list(contract, cache.get_ref().clone()).await {
                Ok(cache_value) => {
                    // encrypt and return
                    return HttpResponse::Ok().json(
                        cache_value.to_encrypted_exit_server_list((*pubkey.get_ref()).into()),
                    );
                }
                Err(e) => {
                    info!("Failed to get exit list from contract {:?}", e);
                    HttpResponse::InternalServerError()
                        .json("Failed to get exit list from contract")
                }
            }
        }
    }
}

async fn retrieve_exit_server_list(
    exit_contract: Address,
    cache: Arc<RwLock<HashMap<Address, ExitContractSignatureCacheValue>>>,
) -> Result<ExitContractSignatureCacheValue, Web3Error> {
    const WEB3_TIMEOUT: Duration = Duration::from_secs(10);
    let exits = get_exits_list(
        &Web3::new("https://dai.althea.net", WEB3_TIMEOUT),
        CONFIG.clarity_private_key.to_address(),
        exit_contract,
    )
    .await;
    match exits {
        Ok(exits) => {
            info!("Got exit list from contract");
            let exit_list = ExitServerList {
                contract: exit_contract,
                exit_list: exits,
                created: std::time::SystemTime::now(),
            };
            let nonce = SalsaBox::generate_nonce(&mut OsRng);
            let cache_value = ExitContractSignatureCacheValue {
                exit_list: exit_list.sign(CONFIG.clarity_private_key),
                nonce: nonce.into(),
            };
            // add this new exit to the cache
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

/// Cache struct for the exit contract signature data
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct ExitContractSignatureCacheValue {
    exit_list: SignedExitServerList,
    nonce: [u8; 24],
}

impl ExitContractSignatureCacheValue {
    fn to_encrypted_exit_server_list(&self, their_pubkey: PublicKey) -> EncryptedExitServerList {
        // we already have a signed list- now to encrypt it given the nonce & our... keys...
        let plaintext = serde_json::to_string(&self.exit_list.data)
            .expect("Failed to serialize ExitServerList")
            .into_bytes();
        // using the clarity private key as the Crypto_box SecretKey
        let our_secretkey = SecretKey::from(CONFIG.clarity_private_key.to_bytes());
        let b = SalsaBox::new(&their_pubkey, &our_secretkey);
        let ciphertext = b.encrypt((&self.nonce).into(), plaintext.as_ref()).unwrap();
        EncryptedExitServerList {
            pubkey: CONFIG.wg_private_key,
            nonce: self.nonce,
            encrypted_exit_server_list: ciphertext,
        }
    }
}

// five minutes
const SIGNATURE_UPDATE_SLEEP: Duration = Duration::from_secs(300);

/// In order to improve scalability this loop grabs and signs an updated list of exits from each exit contract
/// that has previously been requested from this server every 5 minutes. This allows the server to return instantly
/// on the next request from the client without having to perform rpc query 1-1 with requests.
fn signature_update_loop(cache: Arc<RwLock<HashMap<Address, ExitContractSignatureCacheValue>>>) {
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
        thread::sleep(SIGNATURE_UPDATE_SLEEP);
    });
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    openssl_probe::init_ssl_cert_env_vars();
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    // ensure that the config file is valid, we discard the result and use
    // lazy static variable after this
    load_config();

    let exit_contract_data_cache: Arc<RwLock<HashMap<Address, ExitContractSignatureCacheValue>>> =
        Arc::new(RwLock::new(HashMap::new()));
    signature_update_loop(exit_contract_data_cache.clone());
    let web_data = web::Data::new(exit_contract_data_cache.clone());

    let server = HttpServer::new(move || {
        App::new()
            .service(return_exit_contract_data)
            .app_data(web_data.clone())
    });
    let server = if SSL {
        let cert_chain = load_certs(&format!("/etc/letsencrypt/live/{}/fullchain.pem", DOMAIN));
        let keys =
            load_rustls_private_key(&format!("/etc/letsencrypt/live/{}/privkey.pem", DOMAIN));
        let config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, keys)
            .unwrap();

        info!("Binding to SSL");
        server.bind_rustls(format!("{}:{}", DOMAIN, SERVER_PORT), config.clone())?
    } else {
        server.bind(format!("{}:{}", DOMAIN, SERVER_PORT))?
    };

    server.run().await
}
