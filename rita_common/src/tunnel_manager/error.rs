use std::fmt;
use std::fmt::Result as FormatResult;

#[derive(Clone, Debug)]
pub enum TunnelManagerError {
    KernelInterfaceError(althea_kernel_interface::KernelInterfaceError),
    NoFreePortsError,
}

impl fmt::Display for TunnelManagerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> FormatResult {
        match self {
            TunnelManagerError::KernelInterfaceError(e) => write!(f, "TunnelManagerError{:?}", e),
            TunnelManagerError::NoFreePortsError => write!(f, "NoFreePortsError"),
        }
    }
}

impl From<althea_kernel_interface::KernelInterfaceError> for TunnelManagerError {
    fn from(value: althea_kernel_interface::KernelInterfaceError) -> Self {
        TunnelManagerError::KernelInterfaceError(value)
    }
}
