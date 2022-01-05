use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

use althea_kernel_interface::KernelInterfaceError;
use oping::PingError;

#[derive(Debug)]
pub enum AntennaForwardingError {
    IPSetupError, 
    AntennaNotFound, 
    IPNotSupported, 
    BlacklistedAddress, 
    KernelInterfaceError(KernelInterfaceError),
    PingError(PingError),


}


impl From<KernelInterfaceError> for AntennaForwardingError {
    fn from(error: KernelInterfaceError) -> Self {
        AntennaForwardingError::KernelInterfaceError(error)
    }
}
impl From<PingError> for AntennaForwardingError {
    fn from(error: PingError) -> Self {
        AntennaForwardingError::PingError(error)
    }
}

impl Display for AntennaForwardingError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            AntennaForwardingError::IPSetupError => write!(
                f,
                "IP setup failed",
            ),
            AntennaForwardingError::AntennaNotFound => write!(
                f,
                "Failed to find Antenna!",
            ),
            AntennaForwardingError::IPNotSupported => write!(
                f,
                "Not supported!",
            ),
            AntennaForwardingError::BlacklistedAddress => write!(
                f, 
                "Blacklisted address!",
            ),
            AntennaForwardingError::KernelInterfaceError(e) => write!(f, "{}", e),
            AntennaForwardingError::PingError(e) => write!(f, "{}", e),

        }
    }
}

impl Error for AntennaForwardingError {}
