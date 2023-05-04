use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

#[derive(Debug)]
pub enum SettingsError {
    TomlSeError(toml::ser::Error),
    TomlDeError(toml::de::Error),
    IOError(std::io::Error),
    IpNetworkError(ipnetwork::IpNetworkError),
    SerdeJsonError(serde_json::Error),
    FileNotFoundError(String),
}

impl From<toml::ser::Error> for SettingsError {
    fn from(error: toml::ser::Error) -> Self {
        SettingsError::TomlSeError(error)
    }
}
impl From<toml::de::Error> for SettingsError {
    fn from(error: toml::de::Error) -> Self {
        SettingsError::TomlDeError(error)
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

impl Display for SettingsError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            SettingsError::TomlSeError(e) => write!(f, "{e}"),
            SettingsError::TomlDeError(e) => write!(f, "{e}"),
            SettingsError::IOError(e) => write!(f, "{e}"),
            SettingsError::IpNetworkError(e) => write!(f, "{e}"),
            SettingsError::SerdeJsonError(e) => write!(f, "{e}"),
            SettingsError::FileNotFoundError(e) => {
                write!(f, "Could not find config file at path {}", e)
            }
        }
    }
}

impl Error for SettingsError {}
