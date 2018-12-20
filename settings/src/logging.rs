fn default_logging() -> bool {
    true
}

fn default_logging_level() -> String {
    "INFO".to_string()
}

fn default_logging_dest_url() -> String {
    "https://stats.altheamesh.com:9999/compressed_sink".to_string()
}

/// Remote logging settings. Used to control remote logs being
/// forwarded to the dest_url address, https is used to encrypt
/// the logs as they travel over the internet so don't use non-https
/// links
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct LoggingSettings {
    #[serde(default = "default_logging")]
    pub enabled: bool,
    #[serde(default = "default_logging_level")]
    pub level: String,
    #[serde(default = "default_logging_dest_url")]
    pub dest_url: String,
}

impl Default for LoggingSettings {
    fn default() -> Self {
        LoggingSettings {
            enabled: true,
            level: "INFO".to_string(),
            dest_url: "https://stats.altheamesh.com:9999/sink/".to_string(),
        }
    }
}
