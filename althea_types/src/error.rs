use base64::DecodeError;
use std::error::Error;
use std::fmt;
use std::fmt::Result as FormatResult;

#[derive(Clone, Debug)]
pub enum AltheaTypesError {
    WgParseError(DecodeError),
    BadEthAbiInput(String),
    InvalidWgKeyLength,
    InvalidIdentityBytesLength,
    ClarityError(String),
}

impl From<clarity::Error> for AltheaTypesError {
    fn from(e: clarity::Error) -> Self {
        AltheaTypesError::ClarityError(e.to_string())
    }
}

impl fmt::Display for AltheaTypesError {
    fn fmt(&self, f: &mut fmt::Formatter) -> FormatResult {
        match self {
            AltheaTypesError::WgParseError(val) => write!(f, "Failed to parse WgKey with {val}"),
            AltheaTypesError::BadEthAbiInput(e) => write!(f, "Bad Eth ABI input: {}", e),
            AltheaTypesError::InvalidWgKeyLength => write!(f, "Invalid WgKey length"),
            AltheaTypesError::InvalidIdentityBytesLength => {
                write!(f, "Invalid identity bytes length")
            }
            AltheaTypesError::ClarityError(val) => write!(f, "Clarity error: {}", val),
        }
    }
}

impl Error for AltheaTypesError {}

impl From<DecodeError> for AltheaTypesError {
    fn from(e: DecodeError) -> Self {
        AltheaTypesError::WgParseError(e)
    }
}
