use compressed_log::builder::LoggerBuilder;
use compressed_log::compression::Compression;
use log::LevelFilter;
use log::Record;

use crate::RitaClientError;

/// enables remote logging if the user has configured it
pub fn enable_remote_logging() -> Result<(), RitaClientError> {
    trace!("About to enable remote logging");
    let rita_client = settings::get_rita_client();
    let log = rita_client.log;
    let key = rita_client
        .network
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
                .ok_or_else(|| RitaClientError::ConversionError("Unable to convert level filter to a level".to_string()))?,
        )
        .set_compression_level(Compression::Suggested)
        .set_sink_url(logging_url)
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
        return Err(RitaClientError::LoggerError(e))
    }
    let logger = logger.unwrap();

    if let Err(e) = log::set_boxed_logger(Box::new(logger)) {
        return Err(RitaClientError::SetLoggerError(e))
    }
    log::set_max_level(level);

    println!(
        "Remote compressed logging enabled with target {}",
        logging_url
    );
    Ok(())
}
