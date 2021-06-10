use althea_types::WgKey;
pub(crate) use antenna_forwarding_client::start_antenna_forwarding_proxy;
use compressed_log::builder::LoggerBuilder;
use compressed_log::compression::Compression;
#[cfg(feature = "jemalloc")]
use jemallocator::Jemalloc;
#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;
#[cfg(test)]
extern crate arrayvec;

use docopt::Docopt;
use log::{LevelFilter, Record};
use settings::client::RitaClientSettings;

use settings::FileWrite;
use std::env;

use failure::Error;

use rita_common::dashboard::own_info::READABLE_VERSION;
use rita_common::rita_loop::check_rita_common_actors;
use rita_common::rita_loop::start_core_rita_endpoints;
use rita_common::utils::env_vars_contains;

#[derive(Debug, Deserialize, Default)]
pub struct Args {
    flag_config: String,
    flag_platform: String,
    flag_future: bool,
}

lazy_static! {
    pub static ref HEARTBEAT_SERVER_KEY: WgKey = "hizclQFo/ArWY+/9+AJ0LBY2dTiQK4smy5icM7GA5ng="
        .parse()
        .unwrap();
}

lazy_static! {
    static ref USAGE: String = format!(
        "Usage: rita --config=<settings> --platform=<platform> [--future]
Options:
    -c, --config=<settings>     Name of config file
    --future                    Enable B side of A/B releases
About:
    Version {} - {}
    git hash {}",
        READABLE_VERSION,
        env!("CARGO_PKG_VERSION"),
        env!("GIT_HASH")
    );
}

use althea_kernel_interface::KernelInterface;
use althea_kernel_interface::LinuxCommandRunner;

lazy_static! {
    pub static ref KI: Box<dyn KernelInterface> = Box::new(LinuxCommandRunner {});
}

lazy_static! {
    pub static ref ARGS: Args = Docopt::new((*USAGE).as_str())
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());
}

lazy_static! {
    pub static ref SETTING: RitaClientSettings = {
        let settings_file = &ARGS.flag_config;
        let platform = &ARGS.flag_platform;

        let mut s = RitaClientSettings::new_watched(settings_file).unwrap();

        s.set_future(ARGS.flag_future);

        let s = clu::init(platform, s);

        s.write(settings_file).unwrap();
        s
    };
}

fn main() {
    // On Linux static builds we need to probe ssl certs path to be able to
    // do TLS stuff.
    openssl_probe::init_ssl_cert_env_vars();

    let should_remote_log = SETTING.log.enabled || SETTING.operator.operator_address.is_some();
    // if remote logging is disabled, or the NO_REMOTE_LOG env var is set we should use the
    // local logger and log to std-out. Note we don't care what is actually set in NO_REMOTE_LOG
    // just that it is set
    if !should_remote_log || env_vars_contains("NO_REMOTE_LOG") {
        env_logger::init();
    } else {
        let res = enable_remote_logging();
        println!("logging status {:?}", res);
    }

    let _args: Args = Docopt::new((*USAGE).as_str())
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    info!(
        "crate ver {}, git hash {}",
        env!("CARGO_PKG_VERSION"),
        env!("GIT_HASH")
    );

    check_rita_common_actors();
    start_core_rita_endpoints(4);
    start_antenna_forwarder();
}
/// starts the antenna forwarder, this is a logically independent set of code
/// that does not care about anything else Rita is doing, it only deals with the
/// actual physical interfaces and attempting to find antennas to forward on them.
fn start_antenna_forwarder() {
    #[cfg(not(feature = "operator_debug"))]
    let url = "operator.althea.net:33334";
    #[cfg(feature = "operator_debug")]
    let url = "192.168.10.2:33334";

    let network = SETTING.get_network();
    let our_id = SETTING.get_identity().unwrap();
    let mut interfaces = network.peer_interfaces.clone();
    interfaces.insert("br-pbs".to_string());
    start_antenna_forwarding_proxy(
        url.to_string(),
        our_id,
        *HEARTBEAT_SERVER_KEY,
        network.wg_public_key.unwrap(),
        network.wg_private_key.unwrap(),
        interfaces,
    );
}
/// enables remote logging if the user has configured it
pub fn enable_remote_logging() -> Result<(), Error> {
    trace!("About to enable remote logging");
    let log = &SETTING.log;
    let key = SETTING
        .get_network()
        .wg_public_key
        .expect("Tried to init remote logging without WgKey!");
    let logging_url = &log.dest_url;
    let level: LevelFilter = match log.level.parse() {
        Ok(level) => level,
        Err(_) => LevelFilter::Error,
    };

    let logger = LoggerBuilder::default()
        .set_level(
            level
                .to_level()
                .ok_or_else(|| format_err!("Unable to convert level filter to a level"))?,
        )
        .set_compression_level(Compression::Fast)
        .set_sink_url(logging_url)
        .set_threshold(1000)
        .set_format(Box::new(move |record: &Record| {
            format!(
                "{} {} rita: {}\n",
                key,
                env!("CARGO_PKG_VERSION"),
                record.args()
            )
        }))
        .build();
    if let Err(e) = logger {
        bail!(format_err!("{}", e))
    }
    let logger = logger.unwrap();

    if let Err(e) = log::set_boxed_logger(Box::new(logger)) {
        bail!(format_err!("{}", e))
    }
    log::set_max_level(level);

    println!(
        "Remote compressed logging enabled with target {}",
        logging_url
    );
    Ok(())
}
