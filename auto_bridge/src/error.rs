use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};
use web30::jsonrpc::error::Web3Error;

#[derive(Debug)]
pub enum TokenBridgeError {
    Web3Error(Web3Error),
    BadUniswapOutput(String),
}

impl From<Web3Error> for TokenBridgeError {
    fn from(error: Web3Error) -> Self {
        TokenBridgeError::Web3Error(error)
    }
}

impl Display for TokenBridgeError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            TokenBridgeError::Web3Error(e) => write!(f, "{}", e),
            TokenBridgeError::BadUniswapOutput(e) => write!(f, "{}", e),
        }
    }
}

impl Error for TokenBridgeError {}
