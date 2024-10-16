use env_logger::Env;
use exit_trust_root::{config::load_config, start_exit_trust_root_server};

#[actix_web::main]
async fn main() {
    openssl_probe::init_ssl_cert_env_vars();
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    // ensure that the config file is valid, we discard the result and use
    // lazy static variable after this
    load_config();

    start_exit_trust_root_server();
}
