use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use althea_types::{ExitServerList, SignedExitServerList};
use clarity::{Address, PrivateKey};
use env_logger::Env;
use log::info;
use rustls::ServerConfig;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;
use tls::{load_certs, load_clarity_private_key, load_rustls_private_key};

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
    // also- why are we being passed a cache here? this should come from our side
    cache: web::Data<Arc<RwLock<HashMap<Address, ExitContractSignatureCacheValue>>>>,
) -> impl Responder {
    match cache.read().unwrap().get(&exit_contract.into_inner()) {
        Some(cache) => {
            // is the idea here to return the data we would be populating in signature_update_loop?
            // all that would save is time grabbing the private key from file- since the match in this
            // fn in based on the same cache
            HttpResponse::Ok().json(cache.to_encrypted_exit_server_list(load_clarity_private_key()))
        }
        None => {
            todo!()
            // no data in cache for this exit contract, we need to retrieve it from rpc server, sign it,
            // add it to the cache and return it
        }
    }
}

/// Cache struct for the exit contract signature data
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct ExitContractSignatureCacheValue {
    exit_list: ExitServerList,
    signature: Vec<u8>,
    nonce: [u8; 24],
}

impl ExitContractSignatureCacheValue {
    fn to_encrypted_exit_server_list(&self, our_privkey: PrivateKey) -> SignedExitServerList {
        self.exit_list.sign(our_privkey)
    }
}

const CACHE_TIMEOUT: Duration = Duration::from_secs(600);

/// In order to improve scalability this loop grabs and signs an updated list of exits from each exit contract
/// that has previously been requested from this server every 5 minutes. This allows the server to return instantly
/// on the next request from the client without having to perform rpc query 1-1 with requests.
fn signature_update_loop(cache: Arc<RwLock<HashMap<Address, ExitContractSignatureCacheValue>>>) {
    // where does privkey come from? exit root server must have its own key preset
    let our_privkey = load_clarity_private_key();
    thread::spawn(move || loop {
        let cache = cache.write().unwrap();
        for (_exit_contract, cache) in cache.iter() {
            cache.to_encrypted_exit_server_list(our_privkey);
            // do nothing with these results- does this get saved to a second cache?
            // todo: possibly remove this loop
        }
    });
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    openssl_probe::init_ssl_cert_env_vars();
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

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
