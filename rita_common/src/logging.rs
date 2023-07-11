use std::cmp::min;

use althea_kernel_interface::hardware_info::get_memory_info;
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

    let logger = prepare_logger()
        .set_level(level.to_level().ok_or_else(|| {
            RitaCommonError::ConversionError(
                "Unable to convert level filter to a level".to_string(),
            )
        })?)
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

    println!("Remote compressed logging enabled with target {log_url}");
    Ok(())
}

/// Prepares a logger based on hardware properties, for example if we have less memory
/// we want to use faster compression and a smaller buffer, on the other hand if we're running
/// on a beefy server we should be efficient and use a larger buffer
fn prepare_logger() -> LoggerBuilder {
    if let Ok((_total_mem, free_mem)) = get_memory_info() {
        // values are in kb, converting to bytes
        let free_mem = free_mem * 1000;
        // 32MB maximum buffer size
        const MAX_BUFFER: usize = 32000000;
        // max buffer size 32mb or 5% free mem
        let buffer_size = min(free_mem as usize / 20, MAX_BUFFER);
        if buffer_size == MAX_BUFFER {
            // if we're at the max size we can afford memory inefficient compression
            // and we can also afford to buffer some logs in /tmp (which also uses memory
            // since tmpfs is a memory filesystem)
            LoggerBuilder::default()
                .set_compression_level(Compression::Slow)
                .set_buffer_size(buffer_size)
                .enable_tmp_log_storage()
        } else {
            LoggerBuilder::default().set_buffer_size(buffer_size)
        }
    } else {
        // use conservative default settings
        LoggerBuilder::default()
    }
}
