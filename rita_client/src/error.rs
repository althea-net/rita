use althea_kernel_interface::KernelInterfaceError;
use althea_types::ExitEncryptionError;
use althea_types::websockets::encryption::WebsocketEncryptionError;
use awc::error::{JsonPayloadError, SendRequestError};
use babel_monitor::structs::BabelMonitorError;
use compressed_log::builder::LoggerError;
use log::SetLoggerError;
use rita_common::RitaCommonError;
use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
    num::ParseIntError,
    string::FromUtf8Error,
};

#[derive(Debug)]
pub enum RitaClientError {
    MiscStringError(String),
    SendRequestError(String),
    JsonPayloadError(String),
    OldJsonPayloadError(String),
    SerdeJsonError(serde_json::Error),
    FromUtf8Error(FromUtf8Error),
    TimeoutError(String),
    NoExitError(String),
    ExitNotFound(String),
    NoExitIPError(String),
    RitaCommonError(RitaCommonError),
    ParseIntError(ParseIntError),
    ExitEncryptionError(ExitEncryptionError),
    WebsocketEncryptionError(WebsocketEncryptionError),
}

impl From<ExitEncryptionError> for RitaClientError {
    fn from(error: ExitEncryptionError) -> Self {
        RitaClientError::ExitEncryptionError(error)
    }
}

impl From<WebsocketEncryptionError> for RitaClientError {
    fn from(error: WebsocketEncryptionError) -> Self {
        RitaClientError::WebsocketEncryptionError(error)
    }
}
impl From<LoggerError> for RitaClientError {
    fn from(error: LoggerError) -> Self {
        RitaClientError::RitaCommonError(RitaCommonError::LoggerError(error))
    }
}
impl From<SetLoggerError> for RitaClientError {
    fn from(error: SetLoggerError) -> Self {
        RitaClientError::RitaCommonError(RitaCommonError::SetLoggerError(error))
    }
}
impl From<KernelInterfaceError> for RitaClientError {
    fn from(error: KernelInterfaceError) -> Self {
        RitaClientError::RitaCommonError(RitaCommonError::KernelInterfaceError(error))
    }
}
impl From<settings::SettingsError> for RitaClientError {
    fn from(error: settings::SettingsError) -> Self {
        RitaClientError::RitaCommonError(RitaCommonError::SettingsError(error))
    }
}
impl From<SendRequestError> for RitaClientError {
    fn from(error: SendRequestError) -> Self {
        RitaClientError::TimeoutError(error.to_string())
    }
}
impl From<JsonPayloadError> for RitaClientError {
    fn from(error: JsonPayloadError) -> Self {
        RitaClientError::JsonPayloadError(error.to_string())
    }
}
impl From<serde_json::Error> for RitaClientError {
    fn from(error: serde_json::Error) -> Self {
        RitaClientError::SerdeJsonError(error)
    }
}
impl From<FromUtf8Error> for RitaClientError {
    fn from(error: FromUtf8Error) -> Self {
        RitaClientError::FromUtf8Error(error)
    }
}
impl From<RitaCommonError> for RitaClientError {
    fn from(error: RitaCommonError) -> Self {
        RitaClientError::RitaCommonError(error)
    }
}
impl From<BabelMonitorError> for RitaClientError {
    fn from(error: BabelMonitorError) -> Self {
        RitaClientError::RitaCommonError(RitaCommonError::BabelMonitorError(error))
    }
}
impl From<ParseIntError> for RitaClientError {
    fn from(error: ParseIntError) -> Self {
        RitaClientError::ParseIntError(error)
    }
}
impl From<std::io::Error> for RitaClientError {
    fn from(error: std::io::Error) -> Self {
        RitaClientError::RitaCommonError(RitaCommonError::StdError(error))
    }
}

impl Display for RitaClientError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            RitaClientError::MiscStringError(e) => write!(f, "{e}"),
            RitaClientError::SendRequestError(e) => {
                write!(f, "Error with get request for exit info: {e}")
            }
            RitaClientError::JsonPayloadError(e) => write!(f, "{e}"),
            RitaClientError::OldJsonPayloadError(e) => write!(f, "{e}"),
            RitaClientError::SerdeJsonError(e) => write!(f, "{e}"),
            RitaClientError::FromUtf8Error(e) => write!(f, "{e}"),
            RitaClientError::TimeoutError(e) => {
                write!(f, "Error with post request for exit status: {e}")
            }
            RitaClientError::NoExitError(e) => write!(f, "No valid exit for {e}"),
            RitaClientError::ExitNotFound(e) => write!(f, "Could not find exit {e:?}"),
            RitaClientError::NoExitIPError(e) => {
                write!(f, "Found exitServer: {e:?}, but no exit ip")
            }
            RitaClientError::RitaCommonError(e) => write!(f, "{e}"),
            RitaClientError::ParseIntError(e) => write!(f, "{e}"),
            RitaClientError::ExitEncryptionError(e) => write!(f, "{e}"),
            RitaClientError::WebsocketEncryptionError(e) => write!(f, "{e}"),
        }
    }
}

impl Error for RitaClientError {}
