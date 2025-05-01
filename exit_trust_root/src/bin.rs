use std::net::{IpAddr, Ipv4Addr};

use clap::Parser;
use env_logger::Env;
use exit_trust_root::{config::Config, start_exit_trust_root_server};

#[actix_web::main]
async fn main() {
    // On Linux static builds we need to probe ssl certs path to be able to
    // do TLS stuff.
    openssl_probe::probe();
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    if cfg!(feature = "local_test") {
        println!("Warning!");
        println!("This build is meant only for development purposes.");
        println!("Running this on production is unsupported and not safe!");
        let registration_server_key: &str =
            "0x34d97aaf58b1a81d3ed3068a870d8093c6341cf5d1ef7e6efa03fe7f7fc2c3a8";
        //todo this should be our ip
        let node_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 235));
        let rpc = format!("http://{}:8545", node_ip);
        let exit_contract_data_cache = Config {
            timeout: 60,
            rpc,
            private_key: registration_server_key.parse().unwrap(),
            telnyx_api_key: String::new(),
            verify_profile_id: String::new(),
            magic_number: Some("+17040000000".parse().unwrap()),
            https: false,
            url: "127.0.0.1".to_string(),
        };
        start_exit_trust_root_server(exit_contract_data_cache).await;
    } else {
        let args = Config::parse();
        start_exit_trust_root_server(args).await;
    }
}
