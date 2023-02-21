use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

use crate::{ForwardingProtocolError, ForwardingProtocolMessage};

#[derive(Debug)]
pub enum AntennaForwardingProtocolError {
    SpaceAllocationError,
    ConnectionDownError,
    EndNotFoundError {
        messages: Vec<ForwardingProtocolMessage>,
        remaining_bytes: Vec<u8>,
    },
    DoubleReadFailure {
        a: ForwardingProtocolError,
        b: ForwardingProtocolError,
    },
    ImpossibleError,
    UnparsedBytesError {
        messages: Vec<ForwardingProtocolMessage>,
        remaining_bytes: Vec<u8>,
    },
    MessageWriteError(std::io::Error),
}

impl From<std::io::Error> for AntennaForwardingProtocolError {
    fn from(error: std::io::Error) -> Self {
        AntennaForwardingProtocolError::MessageWriteError(error)
    }
}

impl Display for AntennaForwardingProtocolError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            AntennaForwardingProtocolError::SpaceAllocationError => {
                write!(f, "Operating system won't allocate buffer space",)
            }
            AntennaForwardingProtocolError::ConnectionDownError => write!(f, "Probably a dead connection",),
            AntennaForwardingProtocolError::EndNotFoundError { .. } => {
                write!(f, "Never found the end of the message",)
            }
            AntennaForwardingProtocolError::DoubleReadFailure { a, b } => {
                write!(f, "Double read failure {a:?} {b:?}")
            }
            AntennaForwardingProtocolError::ImpossibleError => write!(f, "Impossible error",),
            AntennaForwardingProtocolError::UnparsedBytesError {
                messages,
                remaining_bytes,
            } => {
                write!(
                    f,
                    "Unparsed bytes! Messages {messages:#X?} Remaining bytes {remaining_bytes:#X?}"
                )
            }
            AntennaForwardingProtocolError::MessageWriteError(e) => write!(f, "{e}"),
        }
    }
}

impl Error for AntennaForwardingProtocolError {}
