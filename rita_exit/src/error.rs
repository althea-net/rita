use althea_kernel_interface::KernelInterfaceError;
use althea_types::{error::AltheaTypesError, ExitClientIdentity};
use babel_monitor::structs::BabelMonitorError;
use handlebars::RenderError;
use ipnetwork::IpNetworkError;
use rita_common::RitaCommonError;
use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
    net::{AddrParseError, IpAddr},
};

#[derive(Debug)]
pub enum RitaExitError {
    MiscStringError(String),
    EmailNotFound(Box<ExitClientIdentity>),
    AddrParseError(AddrParseError),
    IpAddrError(IpAddr),
    RitaCommonError(RitaCommonError),
    RenderError(RenderError),
    EmailError(lettre::error::Error),
    FileError(lettre::transport::file::Error),
    SmtpError(lettre::transport::smtp::Error),
    IpNetworkError(IpNetworkError),
    PhoneParseError(phonenumber::ParseError),
    ClarityError(clarity::error::Error),
    DeepSpaceError(deep_space::error::AddressError),
    AltheaTypesError(AltheaTypesError),
    KernelInterfaceError(KernelInterfaceError),
    NoClientError,
}

impl From<AddrParseError> for RitaExitError {
    fn from(error: AddrParseError) -> Self {
        RitaExitError::AddrParseError(error)
    }
}
impl From<RitaCommonError> for RitaExitError {
    fn from(error: RitaCommonError) -> Self {
        RitaExitError::RitaCommonError(error)
    }
}
impl From<deep_space::error::AddressError> for RitaExitError {
    fn from(error: deep_space::error::AddressError) -> Self {
        RitaExitError::DeepSpaceError(error)
    }
}
impl From<RenderError> for RitaExitError {
    fn from(error: RenderError) -> Self {
        RitaExitError::RenderError(error)
    }
}
impl From<lettre::error::Error> for RitaExitError {
    fn from(error: lettre::error::Error) -> Self {
        RitaExitError::EmailError(error)
    }
}
impl From<lettre::transport::file::Error> for RitaExitError {
    fn from(error: lettre::transport::file::Error) -> Self {
        RitaExitError::FileError(error)
    }
}
impl From<lettre::transport::smtp::Error> for RitaExitError {
    fn from(error: lettre::transport::smtp::Error) -> Self {
        RitaExitError::SmtpError(error)
    }
}
impl From<IpNetworkError> for RitaExitError {
    fn from(error: IpNetworkError) -> Self {
        RitaExitError::IpNetworkError(error)
    }
}
impl From<phonenumber::ParseError> for RitaExitError {
    fn from(error: phonenumber::ParseError) -> Self {
        RitaExitError::PhoneParseError(error)
    }
}
impl From<clarity::error::Error> for RitaExitError {
    fn from(error: clarity::error::Error) -> Self {
        RitaExitError::ClarityError(error)
    }
}
impl From<AltheaTypesError> for RitaExitError {
    fn from(error: AltheaTypesError) -> Self {
        RitaExitError::AltheaTypesError(error)
    }
}
impl From<KernelInterfaceError> for RitaExitError {
    fn from(error: KernelInterfaceError) -> Self {
        RitaExitError::KernelInterfaceError(error)
    }
}
impl From<BabelMonitorError> for RitaExitError {
    fn from(error: BabelMonitorError) -> Self {
        RitaExitError::RitaCommonError(RitaCommonError::BabelMonitorError(error))
    }
}

impl Display for RitaExitError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            RitaExitError::MiscStringError(a) => write!(f, "{a}",),
            RitaExitError::EmailNotFound(a) => write!(f, "Could not find email for {a:?}"),
            RitaExitError::AddrParseError(a) => write!(f, "{a:?}",),
            RitaExitError::IpAddrError(a) => write!(f, "No route found for mesh ip: {a:?}",),
            RitaExitError::RitaCommonError(a) => write!(f, "{a}",),
            RitaExitError::DeepSpaceError(a) => write!(f, "{a}",),
            RitaExitError::RenderError(a) => write!(f, "{a}",),
            RitaExitError::EmailError(a) => write!(f, "{a}",),
            RitaExitError::FileError(a) => write!(f, "{a}",),
            RitaExitError::SmtpError(a) => write!(f, "{a}",),
            RitaExitError::IpNetworkError(a) => write!(f, "{a}",),
            RitaExitError::PhoneParseError(a) => write!(f, "{a}",),
            RitaExitError::ClarityError(a) => write!(f, "{a}",),
            RitaExitError::AltheaTypesError(a) => write!(f, "{a}",),
            RitaExitError::KernelInterfaceError(a) => write!(f, "{a}",),
            RitaExitError::NoClientError => write!(f, "This client has not registered yet!"),
        }
    }
}

impl Error for RitaExitError {}
