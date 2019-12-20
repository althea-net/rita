pub mod dashboard;
pub mod exit_manager;
pub mod light_client_manager;
pub mod rita_loop;
pub mod traffic_watcher;

use crate::SETTING;
use compressed_log::builder::LoggerBuilder;
use compressed_log::compression::Compression;
use failure::Error;
use log::LevelFilter;
use log::Record;
use settings::client::RitaClientSettings;
use settings::RitaCommonSettings;

/// enables remote logging if the user has configured it
pub fn enable_remote_logging() -> Result<(), Error> {
    trace!("About to enable remote logging");
    let log = SETTING.get_log();
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
        .build()?;

    log::set_boxed_logger(Box::new(logger))?;
    log::set_max_level(level);

    println!(
        "Remote compressed logging enabled with target {}",
        logging_url
    );
    Ok(())
}
