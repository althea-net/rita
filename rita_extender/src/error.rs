use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

use awc::error::JsonPayloadError;

#[derive(Debug, PartialEq, Eq)]
pub enum RitaExtenderError {
    MiscStringError(String),
    JsonPayloadError(String),
}

impl From<JsonPayloadError> for RitaExtenderError {
    fn from(error: JsonPayloadError) -> Self {
        RitaExtenderError::JsonPayloadError(error.to_string())
    }
}

impl Display for RitaExtenderError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            RitaExtenderError::MiscStringError(e) => write!(f, "{e}"),
            RitaExtenderError::JsonPayloadError(e) => write!(f, "{e}"),
        }
    }
}

impl Error for RitaExtenderError {}
