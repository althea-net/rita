//! The protocol structs, definitions and utility functions for the Antenna forwarding system
//! it's easier to put them here than to duplicate work and/or create a dependency structure
//! that involves more extra weight

#![warn(clippy::all)]
#![allow(clippy::pedantic)]
#![forbid(unsafe_code)]

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate failure;

use althea_types::Identity;
use failure::Error;
use std::net::IpAddr;

/// an excessively long protocol magic value that preceeds all
/// control traffic. A u32 would probably be sufficient to ensure
/// that we never try to interpret an actual packet as a control packet
/// but I don't see a reason to be stingy.
const MAGIC: u128 = 266_244_417_876_907_680_150_892_848_205_622_258_774;

pub const IDENTIFICATION_MESSAGE_TYPE: u16 = 0;
pub const FORWARD_MESSAGE_TYPE: u16 = 1;
pub const ERROR_MESSAGE_TYPE: u16 = 2;
pub const CONNECTION_CLOSE_MESSAGE_TYPE: u16 = 3;
pub const CONNECTION_MESSAGE_TYPE: u16 = 4;
pub const FORWARDING_CLOSE_MESSAGE_TYPE: u16 = 5;

pub trait ForwardingProtocolMessage {
    fn get_message(&self) -> Vec<u8>;
    fn read_message(payload: &[u8]) -> Result<(usize, Self), Error>
    where
        Self: std::marker::Sized;
    fn get_type(&self) -> u16;
}

/// The serialized struct sent as the payload
/// for the checkin message (type 0). Used because it's
/// much easier to extend than a hard bytes protocol
/// this is only sent client -> server the server is
/// identified implicitly
#[derive(Copy, Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct IdentificationMessage {
    pub id: Identity,
}

/// The serialized struct sent as the payload
/// for the Forward message (type 1) this is what
/// the server sends the client when it would like an
/// anntenna forwarded it's way. Once opened the forwarding
/// lasts until the server sends a hangup or the connection
/// is otherwise terminated
#[derive(Copy, Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct ForwardMessage {
    /// the ip of the antenna connected to the clietn
    pub ip: IpAddr,
    /// the port that the server will take in requests from
    pub server_port: u16,
    /// the port that the antenna is hosting is server on
    pub antenna_port: u16,
}

/// The serialized struct sent as the payload
/// for the Error message (type 2) this is what is sent
/// back to the server when the antenna can't be forwarded
#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct ErrorMessage {
    pub error: String,
}

/// Used to multiplex connection close events
/// from either end over a single tcp stream
#[derive(Copy, Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct ConnectionClose {
    pub stream_id: u64,
}

/// Used for messages relating to an established
/// stream pair
#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct ConnectionMessage {
    pub stream_id: u64,
    pub payload: Vec<u8>,
}

/// Used to close the forwarding session
#[derive(Clone, Serialize, Deserialize, Debug, Default, Eq, PartialEq)]
pub struct ForwardingCloseMessage;

impl ConnectionMessage {
    pub fn new(stream_id: u64, payload: Vec<u8>) -> ConnectionMessage {
        ConnectionMessage { stream_id, payload }
    }
}

impl ForwardingProtocolMessage for ConnectionMessage {
    fn get_message(&self) -> Vec<u8> {
        let mut message = Vec::new();

        message.extend_from_slice(&MAGIC.to_be_bytes());
        // message type number index 17-18
        message.extend_from_slice(&(self.get_type().to_be_bytes()));
        // length, index 18-19
        // length is payload size, plus stream id size 8 bytes
        let len_bytes = self.payload.len() as u16 + 8;
        message.extend_from_slice(&len_bytes.to_be_bytes());
        // stream id 19-22
        message.extend_from_slice(&self.stream_id.to_be_bytes());
        // copy in the serialized struct
        message.extend_from_slice(&self.payload);

        message
    }

    /// Attempts to read the stream id of what may potentially be a
    /// connection close message, returns bytes read and struct
    fn read_message(payload: &[u8]) -> Result<(usize, ConnectionMessage), Error> {
        if payload.len() < 20 {
            return Err(format_err!("Packet too short!"));
        }

        let mut packet_magic: [u8; 16] = [0; 16];
        packet_magic.clone_from_slice(&payload[0..16]);
        let packet_magic = u128::from_be_bytes(packet_magic);

        let mut packet_type: [u8; 2] = [0; 2];
        packet_type.clone_from_slice(&payload[16..18]);
        let packet_type = u16::from_be_bytes(packet_type);

        let mut packet_len: [u8; 2] = [0; 2];
        packet_len.clone_from_slice(&payload[18..20]);
        let packet_len = u16::from_be_bytes(packet_len);

        if packet_magic != MAGIC {
            return Err(format_err!("Packet magic incorrect!"));
        } else if packet_type != CONNECTION_MESSAGE_TYPE {
            return Err(format_err!("Wrong packet type!"));
        } else if packet_len < 8 {
            return Err(format_err!("Incorrect length for close message"));
        }

        let mut connection_id: [u8; 8] = [0; 8];
        connection_id.clone_from_slice(&payload[20..28]);
        let connection_id = u64::from_be_bytes(connection_id);

        let mut message_value = Vec::new();
        message_value.clone_from_slice(&payload[28..28 + packet_len as usize]);

        let bytes_read = 28 + packet_len as usize;

        Ok((
            bytes_read,
            ConnectionMessage::new(connection_id, message_value),
        ))
    }

    fn get_type(&self) -> u16 {
        CONNECTION_MESSAGE_TYPE
    }
}

impl ConnectionClose {
    pub fn new(stream_id: u64) -> ConnectionClose {
        ConnectionClose { stream_id }
    }
}

impl ForwardingProtocolMessage for ConnectionClose {
    fn get_message(&self) -> Vec<u8> {
        let mut message = Vec::new();

        message.extend_from_slice(&MAGIC.to_be_bytes());
        // message type number index 17-18
        message.extend_from_slice(&self.get_type().to_be_bytes());
        // length, index 18-19
        // length is payload size, plus stream id size 8 bytes
        let len_bytes = 8u16;
        message.extend_from_slice(&len_bytes.to_be_bytes());
        // stream id 19-22
        message.extend_from_slice(&self.stream_id.to_be_bytes());

        message
    }

    /// Attempts to read the stream id of what may potentially be a
    /// connection close message
    fn read_message(payload: &[u8]) -> Result<(usize, ConnectionClose), Error> {
        if payload.len() < 20 {
            return Err(format_err!("Packet too short!"));
        }

        let mut packet_magic: [u8; 16] = [0; 16];
        packet_magic.clone_from_slice(&payload[0..16]);
        let packet_magic = u128::from_be_bytes(packet_magic);

        let mut packet_type: [u8; 2] = [0; 2];
        packet_type.clone_from_slice(&payload[16..18]);
        let packet_type = u16::from_be_bytes(packet_type);

        let mut packet_len: [u8; 2] = [0; 2];
        packet_len.clone_from_slice(&payload[18..20]);
        let packet_len = u16::from_be_bytes(packet_len);

        if packet_magic != MAGIC {
            return Err(format_err!("Packet magic incorrect!"));
        } else if packet_type != CONNECTION_CLOSE_MESSAGE_TYPE {
            return Err(format_err!("Wrong packet type!"));
        } else if packet_len != 8 {
            return Err(format_err!("Incorrect length for close message"));
        }

        let mut connection_id: [u8; 8] = [0; 8];
        connection_id.clone_from_slice(&payload[20..28]);
        let connection_id = u64::from_be_bytes(connection_id);

        let bytes_read = 28;

        Ok((bytes_read, ConnectionClose::new(connection_id)))
    }

    fn get_type(&self) -> u16 {
        CONNECTION_CLOSE_MESSAGE_TYPE
    }
}

impl IdentificationMessage {
    pub fn new(id: Identity) -> IdentificationMessage {
        IdentificationMessage { id }
    }
}

impl ForwardingProtocolMessage for IdentificationMessage {
    /// Gets the identification message that is sent at the
    /// start of each client session. Packet protocol is pretty
    /// similar to babel [Magic, Packet type, Length, Message]
    /// Making up [16 bytes, 2 bytes, 2 bytes, N bytes] the length
    /// field represents only payload length
    fn get_message(&self) -> Vec<u8> {
        // serialize the payload first so that we know it's length
        let payload = self;
        let payload = serde_json::to_vec(&payload).unwrap();

        let mut message = Vec::new();
        message.extend_from_slice(&MAGIC.to_be_bytes());
        // message type number index 17-18
        message.extend_from_slice(&self.get_type().to_be_bytes());
        // length, index 18-19
        let len_bytes = payload.len() as u16;
        message.extend_from_slice(&len_bytes.to_be_bytes());
        // copy in the serialized struct
        message.extend_from_slice(&payload);
        message
    }

    /// takes a byte slice that may potentially contain a IdentificationMessage and
    /// deserializes it
    fn read_message(payload: &[u8]) -> Result<(usize, IdentificationMessage), Error> {
        if payload.len() < 20 {
            return Err(format_err!("Packet too short!"));
        }

        let mut packet_magic: [u8; 16] = [0; 16];
        packet_magic.clone_from_slice(&payload[0..16]);
        let packet_magic = u128::from_be_bytes(packet_magic);

        let mut packet_type: [u8; 2] = [0; 2];
        packet_type.clone_from_slice(&payload[16..18]);
        let packet_type = u16::from_be_bytes(packet_type);

        let mut packet_len: [u8; 2] = [0; 2];
        packet_len.clone_from_slice(&payload[18..20]);
        let packet_len = u16::from_be_bytes(packet_len);

        if packet_magic != MAGIC {
            return Err(format_err!("Packet magic incorrect!"));
        } else if packet_type != IDENTIFICATION_MESSAGE_TYPE {
            return Err(format_err!("Wrong packet type!"));
        }

        let bytes_read = 20 + packet_len as usize;

        match serde_json::from_slice(&payload[20..(20 + packet_len as usize)]) {
            Ok(message) => Ok((bytes_read, message)),
            Err(serde_error) => Err(serde_error.into()),
        }
    }

    fn get_type(&self) -> u16 {
        IDENTIFICATION_MESSAGE_TYPE
    }
}

impl ErrorMessage {
    pub fn new(error: String) -> ErrorMessage {
        ErrorMessage { error }
    }
}

impl ForwardingProtocolMessage for ErrorMessage {
    /// Gets an error message that is sent when the antenna forwarding
    /// can not start successfully
    fn get_message(&self) -> Vec<u8> {
        // serialize the payload first so that we know it's length
        let payload = self;
        let payload = serde_json::to_vec(&payload).unwrap();

        let mut message = Vec::new();
        message.extend_from_slice(&MAGIC.to_be_bytes());
        // message type number index 17-18
        message.extend_from_slice(&self.get_type().to_be_bytes());
        // length, index 18-19
        let len_bytes = payload.len() as u16;
        message.extend_from_slice(&len_bytes.to_be_bytes());
        // copy in the serialized struct
        message.extend_from_slice(&payload);
        message
    }

    /// takes a byte slice that may potentially contain a ErrorMessage and
    /// deserializes it
    fn read_message(payload: &[u8]) -> Result<(usize, ErrorMessage), Error> {
        if payload.len() < 20 {
            return Err(format_err!("Packet too short!"));
        }

        let mut packet_magic: [u8; 16] = [0; 16];
        packet_magic.clone_from_slice(&payload[0..16]);
        let packet_magic = u128::from_be_bytes(packet_magic);

        let mut packet_type: [u8; 2] = [0; 2];
        packet_type.clone_from_slice(&payload[16..18]);
        let packet_type = u16::from_be_bytes(packet_type);

        let mut packet_len: [u8; 2] = [0; 2];
        packet_len.clone_from_slice(&payload[18..20]);
        let packet_len = u16::from_be_bytes(packet_len);

        if packet_magic != MAGIC {
            return Err(format_err!("Packet magic incorrect!"));
        } else if packet_type != ERROR_MESSAGE_TYPE {
            return Err(format_err!("Wrong packet type!"));
        }

        let bytes_read = 20 + packet_len as usize;

        match serde_json::from_slice(&payload[20..(20 + packet_len as usize)]) {
            Ok(message) => Ok((bytes_read, message)),
            Err(serde_error) => Err(serde_error.into()),
        }
    }

    fn get_type(&self) -> u16 {
        ERROR_MESSAGE_TYPE
    }
}

impl ForwardMessage {
    pub fn new(ip: IpAddr, server_port: u16, antenna_port: u16) -> ForwardMessage {
        ForwardMessage {
            ip,
            server_port,
            antenna_port,
        }
    }
}

impl ForwardingProtocolMessage for ForwardMessage {
    /// Gets an error message that is sent when the antenna forwarding
    /// can not start successfully
    fn get_message(&self) -> Vec<u8> {
        // serialize the payload first so that we know it's length
        let payload = self;
        let payload = serde_json::to_vec(&payload).unwrap();

        let mut message = Vec::new();
        message.extend_from_slice(&MAGIC.to_be_bytes());
        // message type number index 17-18
        message.extend_from_slice(&self.get_type().to_be_bytes());
        // length, index 18-19
        let len_bytes = payload.len() as u16;
        message.extend_from_slice(&len_bytes.to_be_bytes());
        // copy in the serialized struct
        message.extend_from_slice(&payload);
        message
    }

    /// takes a byte slice that may potentially contain a ForwardMessage and
    /// deserializes it
    fn read_message(payload: &[u8]) -> Result<(usize, ForwardMessage), Error> {
        if payload.len() < 20 {
            return Err(format_err!("Packet too short!"));
        }

        let mut packet_magic: [u8; 16] = [0; 16];
        packet_magic.clone_from_slice(&payload[0..16]);
        let packet_magic = u128::from_be_bytes(packet_magic);

        let mut packet_type: [u8; 2] = [0; 2];
        packet_type.clone_from_slice(&payload[16..18]);
        let packet_type = u16::from_be_bytes(packet_type);

        let mut packet_len: [u8; 2] = [0; 2];
        packet_len.clone_from_slice(&payload[18..20]);
        let packet_len = u16::from_be_bytes(packet_len);

        if packet_magic != MAGIC {
            return Err(format_err!("Packet magic incorrect!"));
        } else if packet_type != FORWARD_MESSAGE_TYPE {
            return Err(format_err!("Wrong packet type!"));
        }

        let bytes_read = 20 + packet_len as usize;

        match serde_json::from_slice(&payload[20..(20 + packet_len as usize)]) {
            Ok(message) => Ok((bytes_read, message)),
            Err(serde_error) => Err(serde_error.into()),
        }
    }

    fn get_type(&self) -> u16 {
        FORWARD_MESSAGE_TYPE
    }
}

impl ForwardingCloseMessage {
    pub fn new() -> ForwardingCloseMessage {
        ForwardingCloseMessage
    }
}

impl ForwardingProtocolMessage for ForwardingCloseMessage {
    /// Gets an error message that is sent when the antenna forwarding
    /// can not start successfully
    fn get_message(&self) -> Vec<u8> {
        // serialize the payload first so that we know it's length
        let payload = self;
        let payload = serde_json::to_vec(&payload).unwrap();

        let mut message = Vec::new();
        message.extend_from_slice(&MAGIC.to_be_bytes());
        // message type number index 17-18
        message.extend_from_slice(&self.get_type().to_be_bytes());
        // length, index 18-19
        let len_bytes = payload.len() as u16;
        message.extend_from_slice(&len_bytes.to_be_bytes());
        // copy in the serialized struct
        message.extend_from_slice(&payload);
        message
    }

    /// takes a byte slice that may potentially contain a ForwardMessage and
    /// deserializes it
    fn read_message(payload: &[u8]) -> Result<(usize, ForwardingCloseMessage), Error> {
        if payload.len() < 20 {
            return Err(format_err!("Packet too short!"));
        }

        let mut packet_magic: [u8; 16] = [0; 16];
        packet_magic.clone_from_slice(&payload[0..16]);
        let packet_magic = u128::from_be_bytes(packet_magic);

        let mut packet_type: [u8; 2] = [0; 2];
        packet_type.clone_from_slice(&payload[16..18]);
        let packet_type = u16::from_be_bytes(packet_type);

        let mut packet_len: [u8; 2] = [0; 2];
        packet_len.clone_from_slice(&payload[18..20]);
        let packet_len = u16::from_be_bytes(packet_len);

        if packet_magic != MAGIC {
            return Err(format_err!("Packet magic incorrect!"));
        } else if packet_type != FORWARDING_CLOSE_MESSAGE_TYPE {
            return Err(format_err!("Wrong packet type!"));
        }

        let bytes_read = 20 + packet_len as usize;

        match serde_json::from_slice(&payload[20..(20 + packet_len as usize)]) {
            Ok(message) => Ok((bytes_read, message)),
            Err(serde_error) => Err(serde_error.into()),
        }
    }

    fn get_type(&self) -> u16 {
        FORWARDING_CLOSE_MESSAGE_TYPE
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    fn get_test_id() -> Identity {
        Identity {
            mesh_ip: "::1".parse().unwrap(),
            eth_address: "0x4288C538A553357Bb6c3b77Cf1A60Da6E77931F6"
                .parse()
                .unwrap(),
            wg_public_key: "GIaAXDi1PbGq3PsKqBnT6kIPoE2K1Ssv9HSb7++dzl4="
                .parse()
                .unwrap(),
            nickname: None,
        }
    }

    fn get_forward_message() -> ForwardMessage {
        ForwardMessage::new("192.168.10.1".parse().unwrap(), 6823, 443)
    }

    #[test]
    fn test_message_types() {
        assert_eq!(
            IDENTIFICATION_MESSAGE_TYPE,
            IdentificationMessage::new(get_test_id()).get_type()
        );
        assert_eq!(FORWARD_MESSAGE_TYPE, get_forward_message().get_type());
        assert_eq!(
            ERROR_MESSAGE_TYPE,
            ErrorMessage::new("test".to_string()).get_type()
        );
        assert_eq!(
            CONNECTION_CLOSE_MESSAGE_TYPE,
            ConnectionClose::new(50).get_type()
        );
        assert_eq!(
            CONNECTION_MESSAGE_TYPE,
            ConnectionMessage::new(50, vec![0]).get_type()
        );
        assert_eq!(
            FORWARDING_CLOSE_MESSAGE_TYPE,
            ForwardingCloseMessage::new().get_type()
        );
    }

    #[test]
    fn test_id_message() {
        let message = IdentificationMessage::new(get_test_id());
        let out = message.get_message();
        let (size, parsed) = IdentificationMessage::read_message(&out).expect("Failed to parse!");
        assert_eq!(parsed, message);
    }

    #[test]
    fn test_forward_message() {
        let message = get_forward_message();
        let out = message.get_message();
        let (size, parsed) = ForwardMessage::read_message(&out).expect("Failed to parse!");
        assert_eq!(parsed, message);
    }

    #[test]
    fn test_error_message() {
        let message = ErrorMessage::new("test".to_string());
        let out = message.get_message();
        let (size, parsed) = ErrorMessage::read_message(&out).expect("Failed to parse!");
        assert_eq!(parsed, message);
    }

    #[test]
    fn test_connecton_close_message() {
        let message = ConnectionClose::new(50);
        let out = message.get_message();
        let (size, parsed) = ConnectionClose::read_message(&out).expect("Failed to parse!");
        assert_eq!(parsed, message);
    }

    #[test]
    fn test_connecton_message() {
        let message = ConnectionMessage::new(50, vec![0]);
        let out = message.get_message();
        let (size, parsed) = ConnectionMessage::read_message(&out).expect("Failed to parse!");
        assert_eq!(parsed, message);
    }

    #[test]
    fn test_close_message() {
        let message = ForwardingCloseMessage::new();
        let out = message.get_message();
        let (size, parsed) = ForwardingCloseMessage::read_message(&out).expect("Failed to parse!");
        assert_eq!(parsed, message);
    }
}
