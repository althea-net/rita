use num256::Uint256;
use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};
use web30::jsonrpc::error::Web3Error;

#[derive(Debug)]
pub enum GravityBridgeError {
    Web3Error(Web3Error),
    CosmosGrpcError(String),
    IbcError(String),
    InsufficientBalance(String),
    InsufficientFunds {
        action: String,
        required: Uint256,
        available: Uint256,
    },
    MissingConfig(String),
}

impl From<Web3Error> for GravityBridgeError {
    fn from(error: Web3Error) -> Self {
        GravityBridgeError::Web3Error(error)
    }
}

impl Display for GravityBridgeError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            GravityBridgeError::Web3Error(e) => write!(f, "Web3 error: {e}"),
            GravityBridgeError::CosmosGrpcError(e) => write!(f, "Cosmos gRPC error: {e}"),
            GravityBridgeError::IbcError(e) => write!(f, "IBC error: {e}"),
            GravityBridgeError::InsufficientBalance(e) => {
                write!(f, "Insufficient balance: {e}")
            }
            GravityBridgeError::InsufficientFunds {
                action,
                required,
                available,
            } => write!(
                f,
                "Insufficient funds for {action}: required {required}, available {available}"
            ),
            GravityBridgeError::MissingConfig(e) => write!(f, "Missing config: {e}"),
        }
    }
}

impl Error for GravityBridgeError {}
