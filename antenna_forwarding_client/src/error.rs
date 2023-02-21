use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

use althea_kernel_interface::KernelInterfaceError;
use oping::PingError;

#[derive(Debug)]
pub enum AntennaForwardingClientError {
    IPSetupError,
    AntennaNotFound,
    IPNotSupported,
    BlacklistedAddress,
    KernelInterfaceError(KernelInterfaceError),
    PingError(PingError),
}

impl From<KernelInterfaceError> for AntennaForwardingClientError {
    fn from(error: KernelInterfaceError) -> Self {
        AntennaForwardingClientError::KernelInterfaceError(error)
    }
}
impl From<PingError> for AntennaForwardingClientError {
    fn from(error: PingError) -> Self {
        AntennaForwardingClientError::PingError(error)
    }
}

impl Display for AntennaForwardingClientError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            AntennaForwardingClientError::IPSetupError => write!(f, "IP setup failed",),
            AntennaForwardingClientError::AntennaNotFound => write!(f, "Failed to find Antenna!",),
            AntennaForwardingClientError::IPNotSupported => write!(f, "Not supported!",),
            AntennaForwardingClientError::BlacklistedAddress => write!(f, "Blacklisted address!",),
            AntennaForwardingClientError::KernelInterfaceError(e) => write!(f, "{e}"),
            AntennaForwardingClientError::PingError(e) => write!(f, "{e}"),
        }
    }
}

impl Error for AntennaForwardingClientError {}
