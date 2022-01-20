use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

use crate::{ForwardingProtocolError, ForwardingProtocolMessage};

#[derive(Debug)]
pub enum AntennaForwardingError {
    SpaceAllocationError,
    ConnectionDownError,
    EndNotFoundError,
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

impl From<std::io::Error> for AntennaForwardingError {
    fn from(error: std::io::Error) -> Self {
        AntennaForwardingError::MessageWriteError(error)
    }
}

impl Display for AntennaForwardingError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            AntennaForwardingError::SpaceAllocationError => {
                write!(f, "Operating system won't allocate buffer space",)
            }
            AntennaForwardingError::ConnectionDownError => write!(f, "Probably a dead connection",),
            AntennaForwardingError::EndNotFoundError => {
                write!(f, "Never found the end of the message",)
            }
            AntennaForwardingError::DoubleReadFailure { a, b } => {
                write!(f, "Double read failure {:?} {:?}", a, b)
            }
            AntennaForwardingError::ImpossibleError => write!(f, "Impossible error",),
            AntennaForwardingError::UnparsedBytesError {
                messages,
                remaining_bytes,
            } => {
                write!(
                    f,
                    "Unparsed bytes! Messages {:#X?} Remaining bytes {:#X?}",
                    messages, remaining_bytes
                )
            }
            AntennaForwardingError::MessageWriteError(e) => write!(f, "{}", e),
        }
    }
}

impl Error for AntennaForwardingError {}
