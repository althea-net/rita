use base64::DecodeError;
use std::error::Error;
use std::fmt;
use std::fmt::Result as FormatResult;

#[derive(Clone, Debug)]
pub enum AltheaTypesError {
    ReleaseFeedParseError(String),
    OperatorActionParseError(String),
    WgParseError(DecodeError),
}

impl fmt::Display for AltheaTypesError {
    fn fmt(&self, f: &mut fmt::Formatter) -> FormatResult {
        match self {
            AltheaTypesError::ReleaseFeedParseError(val) => {
                write!(f, "Failed to parse {} as a release feed", val)
            }
            AltheaTypesError::OperatorActionParseError(val) => {
                write!(f, "Failed to parse {} as an operator Action", val)
            }
            AltheaTypesError::WgParseError(val) => write!(f, "Failed to parse WgKey with {}", val),
        }
    }
}

impl Error for AltheaTypesError {}

impl From<DecodeError> for AltheaTypesError {
    fn from(e: DecodeError) -> Self {
        AltheaTypesError::WgParseError(e)
    }
}
