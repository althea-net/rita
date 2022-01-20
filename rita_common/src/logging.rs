use compressed_log::builder::LoggerBuilder;
use compressed_log::compression::Compression;
use log::LevelFilter;
use log::Record;

use crate::RitaCommonError;

/// enables remote logging if the user has configured it
pub fn enable_remote_logging(
    log_label: String,
    log_url: String,
    log_level: String,
    wg_public_key: String,
) -> Result<(), RitaCommonError> {
    trace!("About to enable remote logging");
    let level: LevelFilter = match log_level.parse() {
        Ok(level) => level,
        Err(_) => LevelFilter::Error,
    };

    let logger = LoggerBuilder::default()
        .set_level(level.to_level().ok_or_else(|| {
            RitaCommonError::ConversionError(
                "Unable to convert level filter to a level".to_string(),
            )
        })?)
        .set_compression_level(Compression::Slow)
        .set_sink_url(log_url.as_str())
        .set_format(Box::new(move |record: &Record| {
            format!(
                "{} {} {}: {}\n",
                wg_public_key,
                env!("CARGO_PKG_VERSION"),
                log_label,
                record.args()
            )
        }))
        .build();
    if let Err(e) = logger {
        return Err(RitaCommonError::LoggerError(e));
    }
    let logger = logger.unwrap();

    if let Err(e) = log::set_boxed_logger(Box::new(logger)) {
        return Err(RitaCommonError::SetLoggerError(e));
    }
    log::set_max_level(level);

    println!("Remote compressed logging enabled with target {}", log_url);
    Ok(())
}
