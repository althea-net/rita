use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult}, 
    net::AddrParseError, string::FromUtf8Error,
};

use althea_kernel_interface::KernelInterfaceError;
use awc::error::{SendRequestError, JsonPayloadError};
use babel_monitor::BabelMonitorError;
use compressed_log::builder::LoggerError;
use log::SetLoggerError;
use rita_common::RitaCommonError;

use crate::dashboard;

#[derive(Debug)]
pub enum RitaClientError {
    ConversionError(String), 
    LoggerError(LoggerError),
    SetLoggerError(SetLoggerError),
    InterfaceModeError(String),
    InterfaceToggleError {
        main_error: Vec<KernelInterfaceError>,
        revert_status: Option<KernelInterfaceError>
    },
    KernelInterfaceError(KernelInterfaceError),
    SettingsError(settings::SettingsError),
    AddrParseError(AddrParseError),
    MiscStringError(String),
    ValidationError(dashboard::wifi::ValidationError),
    SendRequestError(SendRequestError),
    JsonPayloadError(JsonPayloadError),
    SerdeJsonError(serde_json::Error),
    FromUtf8Error(FromUtf8Error),
    TimeoutError(SendRequestError),
    NoExitError(String),
    ExitNotFound(String),
    NoExitIPError(String),
    RitaCommonError(RitaCommonError),
    BabelMonitorError(BabelMonitorError),

}

impl From<LoggerError> for RitaClientError {
    fn from(error: LoggerError) -> Self {
        RitaClientError::LoggerError(error)
    }
}
impl From<SetLoggerError> for RitaClientError {
    fn from(error: SetLoggerError) -> Self {
        RitaClientError::SetLoggerError(error)
    }
}
impl From<KernelInterfaceError> for RitaClientError {
    fn from(error: KernelInterfaceError) -> Self {
        RitaClientError::KernelInterfaceError(error)
    }
}
impl From<settings::SettingsError> for RitaClientError {
    fn from(error: settings::SettingsError) -> Self {
        RitaClientError::SettingsError(error)
    }
}
impl From<AddrParseError> for RitaClientError {
    fn from(error: AddrParseError) -> Self {
        RitaClientError::AddrParseError(error)
    }
}
impl From<dashboard::wifi::ValidationError> for RitaClientError {
    fn from(error: dashboard::wifi::ValidationError) -> Self {
        RitaClientError::ValidationError(error)
    }
}
impl From<SendRequestError> for RitaClientError {
    fn from(error: SendRequestError) -> Self {
        RitaClientError::SendRequestError(error);
        RitaClientError::TimeoutError(error)
    }
}
impl From<JsonPayloadError> for RitaClientError {
    fn from(error: JsonPayloadError) -> Self {
        RitaClientError::JsonPayloadError(error)
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
        RitaClientError::BabelMonitorError(error)
    }
}

impl Display for RitaClientError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            RitaClientError::ConversionError(a) => write!(
                f, "Conversion Error: {}", a,
            ),
            RitaClientError::LoggerError(e) => write!(f, "{}", e),
            RitaClientError::SetLoggerError(e) => write!(f, "{}", e),
            RitaClientError::InterfaceModeError(a) => write!(f, "{}", a,),
            RitaClientError::InterfaceToggleError{main_error, revert_status} => {
                write!(f, "Error running UCI commands! {:?} \nRevert attempted: {:?}", main_error, revert_status)
            }
            RitaClientError::KernelInterfaceError(a) => write!(f, "{}", a,),
            RitaClientError::SettingsError(a) => write!(f, "{}", a,),
            RitaClientError::AddrParseError(a) => write!(f, "{}", a,),
            RitaClientError::MiscStringError(e) => write!(f, "{}", e),
            RitaClientError::ValidationError(e) => write!(f, "{}", e),
            RitaClientError::SendRequestError(e) => write!(f, "Error with get request for exit info: {}", e),
            RitaClientError::JsonPayloadError(e) => write!(f, "{}", e),
            RitaClientError::SerdeJsonError(e) => write!(f, "{}", e),
            RitaClientError::FromUtf8Error(e) => write!(f, "{}", e),
            RitaClientError::TimeoutError(e) => write!(f, "Error with post request for exit status: {}", e),
            RitaClientError::NoExitError(e) => write!(f, "No valid exit for {}", e),
            RitaClientError::ExitNotFound(e) => write!(f, "Could not find exit {:?}", e),
            RitaClientError::NoExitIPError(e) => write!(f, "Found exitServer: {:?}, but no exit ip", e),
            RitaClientError::RitaCommonError(e) => write!(f, "{}", e),
            RitaClientError::BabelMonitorError(e) => write!(f, "{}", e),

        }
    }
}

impl Error for RitaClientError {}
