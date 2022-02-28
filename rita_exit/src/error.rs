use althea_kernel_interface::KernelInterfaceError;
use althea_types::{error::AltheaTypesError, ExitClientIdentity};
use babel_monitor::BabelMonitorError;
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
    EmailNotFound(ExitClientIdentity),
    AddrParseError(AddrParseError),
    IpAddrError(IpAddr),
    DieselError(diesel::result::Error),
    RitaCommonError(RitaCommonError),
    RenderError(RenderError),
    EmailError(lettre_email::error::Error),
    FileError(lettre::file::error::Error),
    SmtpError(lettre::smtp::error::Error),
    IpNetworkError(IpNetworkError),
    PhoneParseError(phonenumber::ParseError),
    ClarityError(clarity::error::Error),
    AltheaTypesError(AltheaTypesError),
    KernelInterfaceError(KernelInterfaceError),
}

impl From<diesel::result::Error> for RitaExitError {
    fn from(error: diesel::result::Error) -> Self {
        RitaExitError::DieselError(error)
    }
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
impl From<RenderError> for RitaExitError {
    fn from(error: RenderError) -> Self {
        RitaExitError::RenderError(error)
    }
}
impl From<lettre_email::error::Error> for RitaExitError {
    fn from(error: lettre_email::error::Error) -> Self {
        RitaExitError::EmailError(error)
    }
}
impl From<lettre::file::error::Error> for RitaExitError {
    fn from(error: lettre::file::error::Error) -> Self {
        RitaExitError::FileError(error)
    }
}
impl From<lettre::smtp::error::Error> for RitaExitError {
    fn from(error: lettre::smtp::error::Error) -> Self {
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
            RitaExitError::MiscStringError(a) => write!(f, "{}", a,),
            RitaExitError::EmailNotFound(a) => write!(f, "Could not find email for {:?}", a),
            RitaExitError::AddrParseError(a) => write!(f, "{:?}", a,),
            RitaExitError::IpAddrError(a) => write!(f, "No route found for mesh ip: {:?}", a,),
            RitaExitError::DieselError(a) => write!(f, "{}", a,),
            RitaExitError::RitaCommonError(a) => write!(f, "{}", a,),
            RitaExitError::RenderError(a) => write!(f, "{}", a,),
            RitaExitError::EmailError(a) => write!(f, "{}", a,),
            RitaExitError::FileError(a) => write!(f, "{}", a,),
            RitaExitError::SmtpError(a) => write!(f, "{}", a,),
            RitaExitError::IpNetworkError(a) => write!(f, "{}", a,),
            RitaExitError::PhoneParseError(a) => write!(f, "{}", a,),
            RitaExitError::ClarityError(a) => write!(f, "{}", a,),
            RitaExitError::AltheaTypesError(a) => write!(f, "{}", a,),
            RitaExitError::KernelInterfaceError(a) => write!(f, "{}", a,),
        }
    }
}

impl Error for RitaExitError {}
