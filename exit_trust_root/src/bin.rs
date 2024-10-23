use clap::Parser;
use env_logger::Env;
use exit_trust_root::{config::Config, start_exit_trust_root_server};

#[actix_web::main]
async fn main() {
    // On Linux static builds we need to probe ssl certs path to be able to
    // do TLS stuff.
    openssl_probe::init_ssl_cert_env_vars();
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let args = Config::parse();

    start_exit_trust_root_server(args).await;
}
