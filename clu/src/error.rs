use std::fmt::{Display, Formatter, Result as FmtResult};

use althea_kernel_interface::KernelInterfaceError;

#[derive(Debug)]
pub enum NewCluError {
    RuntimeError(String),
    MeshError(ipgen::Error),
    KernelInterfaceError(KernelInterfaceError),
    StandardError(std::io::Error),
    NoDeviceName(String),
    ClarityError(clarity::Error),
    DeepSpaceError(deep_space::error::PrivateKeyError),
}

impl From<clarity::Error> for NewCluError {
    fn from(error: clarity::Error) -> Self {
        NewCluError::ClarityError(error)
    }
}
impl From<ipgen::Error> for NewCluError {
    fn from(error: ipgen::Error) -> Self {
        NewCluError::MeshError(error)
    }
}
impl From<KernelInterfaceError> for NewCluError {
    fn from(error: KernelInterfaceError) -> Self {
        NewCluError::KernelInterfaceError(error)
    }
}
impl From<std::io::Error> for NewCluError {
    fn from(error: std::io::Error) -> Self {
        NewCluError::StandardError(error)
    }
}
impl From<deep_space::error::PrivateKeyError> for NewCluError {
    fn from(error: deep_space::error::PrivateKeyError) -> Self {
        NewCluError::DeepSpaceError(error)
    }
}

impl Display for NewCluError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            NewCluError::RuntimeError(a) => write!(f, "Runtime Error:\n{a:?}",),
            NewCluError::MeshError(e) => write!(f, "{e}"),
            NewCluError::KernelInterfaceError(e) => write!(f, "{e}"),
            NewCluError::StandardError(e) => write!(f, "{e}"),
            NewCluError::NoDeviceName(a) => {
                write!(f, "Could not obtain device name from line {a:?}",)
            }
            NewCluError::ClarityError(e) => write!(f, "{e}"),
            NewCluError::DeepSpaceError(e) => write!(f, "{e}"),
        }
    }
}
