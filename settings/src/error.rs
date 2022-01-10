use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

#[derive(Debug)]
pub enum SettingsError {
    TomlError(toml::ser::Error),
    IOError(std::io::Error),
    IpNetworkError(ipnetwork::IpNetworkError),
    SerdeJsonError(serde_json::Error),
    ConfigError(config::ConfigError),
}

impl From<toml::ser::Error> for SettingsError {
    fn from(error: toml::ser::Error) -> Self {
        SettingsError::TomlError(error)
    }
}
impl From<std::io::Error> for SettingsError {
    fn from(error: std::io::Error) -> Self {
        SettingsError::IOError(error)
    }
}
impl From<ipnetwork::IpNetworkError> for SettingsError {
    fn from(error: ipnetwork::IpNetworkError) -> Self {
        SettingsError::IpNetworkError(error)
    }
}
impl From<serde_json::Error> for SettingsError {
    fn from(error: serde_json::Error) -> Self {
        SettingsError::SerdeJsonError(error)
    }
}
impl From<config::ConfigError> for SettingsError {
    fn from(error: config::ConfigError) -> Self {
        SettingsError::ConfigError(error)
    }
}

impl Display for SettingsError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            SettingsError::TomlError(e) => write!(f, "{}", e),
            SettingsError::IOError(e) => write!(f, "{}", e),
            SettingsError::IpNetworkError(e) => write!(f, "{}", e),
            SettingsError::SerdeJsonError(e) => write!(f, "{}", e),
            SettingsError::ConfigError(e) => write!(f, "{}", e),


        }
    }
}

impl Error for SettingsError {}
