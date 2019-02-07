fn default_logging() -> bool {
    true
}

// TODO change to warn in alpha 11
fn default_logging_level() -> String {
    "INFO".to_string()
}

fn default_logging_send_port() -> u16 {
    5044
}

fn default_logging_dest_port() -> u16 {
    514
}

/// Remote logging settings. Used to control remote logs being
/// forwarded to an aggregator on the exit. The reason there is
/// no general destination setting is that syslog udp is not
/// secured or encrypted, sending it over the general internet is
/// not allowed.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct LoggingSettings {
    #[serde(default = "default_logging")]
    pub enabled: bool,
    #[serde(default = "default_logging_level")]
    pub level: String,
    #[serde(default = "default_logging_send_port")]
    pub send_port: u16,
    #[serde(default = "default_logging_dest_port")]
    pub dest_port: u16,
}

impl Default for LoggingSettings {
    fn default() -> Self {
        LoggingSettings {
            enabled: true,
            level: "INFO".to_string(),
            send_port: 5044,
            dest_port: 514,
        }
    }
}
