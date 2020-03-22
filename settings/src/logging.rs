fn default_logging() -> bool {
    true
}

fn default_logging_level() -> String {
    "INFO".to_string()
}

fn default_logging_dest_url() -> String {
    "https://stats.altheamesh.com:9999/compressed_sink".to_string()
}

fn default_heartbeat_url() -> String {
    "stats.altheamesh.com:33333".to_string()
}

fn default_forwarding_checkin_url() -> String {
    "stats.altheamesh.com:33334".to_string()
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
    /// Address and port of UDP heartbeat monitoring server
    #[serde(default = "default_heartbeat_url")]
    pub heartbeat_url: String,
    /// Address and port of the tcp checkin socket for the antenna forwarding server
    #[serde(default = "default_forwarding_checkin_url")]
    pub forwarding_checkin_url: String,
}

impl Default for LoggingSettings {
    fn default() -> Self {
        LoggingSettings {
            enabled: default_logging(),
            level: default_logging_level(),
            dest_url: default_logging_dest_url(),
            heartbeat_url: default_heartbeat_url(),
            forwarding_checkin_url: default_forwarding_checkin_url(),
        }
    }
}
