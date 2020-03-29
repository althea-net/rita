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
use std::io::ErrorKind::WouldBlock;
use std::io::Read;
use std::io::Write;
use std::net::IpAddr;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

/// The amount of time to sleep a thread that's spinlocking on somthing
pub const SPINLOCK_TIME: Duration = Duration::from_millis(10);

/// The size of the memory buffer for reading and writing packets
/// currently 100kbytes
pub const BUFFER_SIZE: usize = 100_000;

/// The size in bytes of our packet header, 16 byte magic, 2 byte type, 2 byte len
pub const HEADER_LEN: usize = 20;

/// Writes data to a stream keeping in mind that we may encounter
/// a buffer limit and have to partially complete our write
pub fn write_all_spinlock(stream: &mut TcpStream, buffer: &[u8]) -> Result<(), Error> {
    loop {
        let res = stream.write_all(buffer);
        match res {
            Ok(_val) => return Ok(()),
            Err(e) => {
                if e.kind() != WouldBlock {
                    return Err(e.into());
                }
            }
        }
        thread::sleep(SPINLOCK_TIME);
    }
}

/// Reads the entire contents of a tcpstream into a buffer until it blocks
pub fn read_till_block(input: &mut TcpStream) -> Result<Vec<u8>, Error> {
    input.set_nonblocking(true)?;
    let mut out = Vec::new();
    loop {
        let mut buffer: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];
        match input.read(&mut buffer) {
            Ok(_bytes) => out.extend_from_slice(&buffer),
            Err(e) => {
                if e.kind() == WouldBlock {
                    return Ok(out);
                } else {
                    return Err(e.into());
                }
            }
        }
    }
}

/// Reads all the currently available messages from the provided stream, this function will
/// also block until a currently in flight message is delivered, for a maximum of 500ms
pub fn read_message(input: &mut TcpStream) -> Result<Vec<ForwardingProtocolMessage>, Error> {
    read_message_internal(input, Vec::new(), Vec::new())
}

fn read_message_internal(
    input: &mut TcpStream,
    remaining_bytes: Vec<u8>,
    messages: Vec<ForwardingProtocolMessage>,
) -> Result<Vec<ForwardingProtocolMessage>, Error> {
    // these should match the full list of message types defined above
    let mut messages = messages;
    let mut remaining_bytes = remaining_bytes;

    remaining_bytes.extend_from_slice(&read_till_block(input)?);

    if let Ok((bytes, msg)) = ForwardingProtocolMessage::read_message(&remaining_bytes) {
        messages.push(msg);
        if bytes < remaining_bytes.len() {
            read_message_internal(input, remaining_bytes[bytes..].to_vec(), messages)
        } else {
            Ok(messages)
        }
    } else {
        Ok(messages)
    }
}

/// All valid packet types for the forwarding protocool, two of these
/// types, ConnectionCloseMessage and ConnectionDataMessage are raw byte packets
/// the rest have the byte based header but are followed by a struct object to
/// deserialize, these structs can be changed to extend or modify the protocol in
/// the future.
#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub enum ForwardingProtocolMessage {
    /// The serialized struct sent as the payload
    /// for the checkin message (type 0). Used because it's
    /// much easier to extend than a hard bytes protocol
    /// this is only sent client -> server the server is
    /// identified implicitly
    IdentificationMessage { id: Identity },
    /// The serialized struct sent as the payload
    /// for the Forward message (type 1) this is what
    /// the server sends the client when it would like an
    /// anntenna forwarded it's way. Once opened the forwarding
    /// lasts until the server sends a hangup or the connection
    /// is otherwise terminated
    ForwardMessage {
        ip: IpAddr,
        server_port: u16,
        antenna_port: u16,
    },
    /// The serialized struct sent as the payload
    /// for the Error message (type 2) this is what is sent
    /// back to the server when the antenna can't be forwarde
    ErrorMessage { error: String },
    /// Used to multiplex connection close events
    /// from either end over a single tcp stream this does not
    /// contain a struct but is instead raw bytes only and is
    /// not extensible
    ConnectionCloseMessage { stream_id: u64 },
    /// Used for messages relating to an established
    /// stream pair. This is message does not contain a struct
    /// and is not extensible, this makes the payload much more
    /// compact than being sent through serde
    ConnectionDataMessage { stream_id: u64, payload: Vec<u8> },
    /// This struct is serialized and set as the payload to close
    /// the connection
    ForwardingCloseMessage,
    /// Used to determine the liveness of each end, not currently used
    /// sent as serialized struct and is extensible
    KeepAliveMessage,
}

impl ForwardingProtocolMessage {
    /// an excessively long protocol magic value that preceeds all
    /// control traffic. A u32 would probably be sufficient to ensure
    /// that we never try to interpret an actual packet as a control packet
    /// but I don't see a reason to be stingy. This is totally random, but you
    /// can never change it once there's a device deployed with it
    pub const MAGIC: u128 = 266_244_417_876_907_680_150_892_848_205_622_258_774;

    pub const IDENTIFICATION_MESSAGE_TYPE: u16 = 0;
    pub const FORWARD_MESSAGE_TYPE: u16 = 1;
    pub const ERROR_MESSAGE_TYPE: u16 = 2;
    pub const CONNECTION_CLOSE_MESSAGE_TYPE: u16 = 3;
    pub const CONNECTION_DATA_MESSAGE_TYPE: u16 = 4;
    pub const FORWARDING_CLOSE_MESSAGE_TYPE: u16 = 5;
    pub const KEEPALIVE_MESSAGE_TYPE: u16 = 6;

    pub fn new_identification_message(id: Identity) -> ForwardingProtocolMessage {
        ForwardingProtocolMessage::IdentificationMessage { id }
    }

    pub fn new_forward_message(
        ip: IpAddr,
        server_port: u16,
        antenna_port: u16,
    ) -> ForwardingProtocolMessage {
        ForwardingProtocolMessage::ForwardMessage {
            ip,
            server_port,
            antenna_port,
        }
    }

    pub fn new_error_message(error: String) -> ForwardingProtocolMessage {
        ForwardingProtocolMessage::ErrorMessage { error }
    }

    pub fn new_connection_close_message(stream_id: u64) -> ForwardingProtocolMessage {
        ForwardingProtocolMessage::ConnectionCloseMessage { stream_id }
    }

    pub fn new_connection_data_message(
        stream_id: u64,
        payload: Vec<u8>,
    ) -> ForwardingProtocolMessage {
        ForwardingProtocolMessage::ConnectionDataMessage { stream_id, payload }
    }

    pub fn new_forwarding_close_message() -> ForwardingProtocolMessage {
        ForwardingProtocolMessage::ForwardingCloseMessage
    }

    pub fn new_keepalive_message() -> ForwardingProtocolMessage {
        ForwardingProtocolMessage::KeepAliveMessage
    }

    /// helper function to de-duplcate some arms of get_message
    fn make_serde_packet(message_type: u16, payload: &ForwardingProtocolMessage) -> Vec<u8> {
        // serialize the payload first so that we know it's length
        let payload = serde_json::to_vec(payload).unwrap();

        let mut message = Vec::new();
        message.extend_from_slice(&ForwardingProtocolMessage::MAGIC.to_be_bytes());
        // message type number index 16-18
        message.extend_from_slice(&message_type.to_be_bytes());
        // length, index 18-20
        let len_bytes = payload.len() as u16;
        message.extend_from_slice(&len_bytes.to_be_bytes());
        // copy in the serialized struct
        message.extend_from_slice(&payload);
        message
    }

    pub fn get_message(&self) -> Vec<u8> {
        match self {
            ForwardingProtocolMessage::IdentificationMessage { .. } => {
                ForwardingProtocolMessage::make_serde_packet(
                    ForwardingProtocolMessage::IDENTIFICATION_MESSAGE_TYPE,
                    self,
                )
            }
            ForwardingProtocolMessage::ForwardMessage { .. } => {
                ForwardingProtocolMessage::make_serde_packet(
                    ForwardingProtocolMessage::FORWARD_MESSAGE_TYPE,
                    self,
                )
            }
            ForwardingProtocolMessage::ErrorMessage { .. } => {
                ForwardingProtocolMessage::make_serde_packet(
                    ForwardingProtocolMessage::ERROR_MESSAGE_TYPE,
                    self,
                )
            }
            ForwardingProtocolMessage::ConnectionCloseMessage { stream_id } => {
                let mut message = Vec::new();

                message.extend_from_slice(&ForwardingProtocolMessage::MAGIC.to_be_bytes());
                message.extend_from_slice(
                    &ForwardingProtocolMessage::CONNECTION_CLOSE_MESSAGE_TYPE.to_be_bytes(),
                );
                // len is only 8 byte stream id
                let len_bytes = 8u16;
                message.extend_from_slice(&len_bytes.to_be_bytes());
                message.extend_from_slice(&stream_id.to_be_bytes());

                message
            }
            ForwardingProtocolMessage::ConnectionDataMessage { stream_id, payload } => {
                let mut message = Vec::new();

                message.extend_from_slice(&ForwardingProtocolMessage::MAGIC.to_be_bytes());
                message.extend_from_slice(
                    &(ForwardingProtocolMessage::CONNECTION_DATA_MESSAGE_TYPE.to_be_bytes()),
                );
                // length is the stream id followed by the payload bytes
                let len_bytes = payload.len() as u16 + 8;
                message.extend_from_slice(&len_bytes.to_be_bytes());
                // copy in stream id
                message.extend_from_slice(&stream_id.to_be_bytes());
                // copy in byte format payload
                message.extend_from_slice(&payload);

                message
            }
            ForwardingProtocolMessage::ForwardingCloseMessage => {
                ForwardingProtocolMessage::make_serde_packet(
                    ForwardingProtocolMessage::FORWARDING_CLOSE_MESSAGE_TYPE,
                    self,
                )
            }
            ForwardingProtocolMessage::KeepAliveMessage => {
                ForwardingProtocolMessage::make_serde_packet(
                    ForwardingProtocolMessage::KEEPALIVE_MESSAGE_TYPE,
                    self,
                )
            }
        }
    }

    pub fn read_message(payload: &[u8]) -> Result<(usize, ForwardingProtocolMessage), Error> {
        if payload.len() < HEADER_LEN {
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

        // this needs to be updated when new packet types are added
        if packet_magic != ForwardingProtocolMessage::MAGIC {
            return Err(format_err!("Packet magic incorrect!"));
        } else if packet_type > 6 {
            return Err(format_err!("Wrong packet type!"));
        } else if packet_len as usize + HEADER_LEN > payload.len() {
            return Err(format_err!(
                "Our slice is {} bytes, but our packet_len {} bytes",
                payload.len(),
                packet_len as usize + HEADER_LEN
            ));
        }

        match packet_type {
            ForwardingProtocolMessage::IDENTIFICATION_MESSAGE_TYPE => {
                let bytes_read = 20 + packet_len as usize;

                match serde_json::from_slice(&payload[HEADER_LEN..bytes_read]) {
                    Ok(message) => Ok((bytes_read, message)),
                    Err(serde_error) => Err(serde_error.into()),
                }
            }
            ForwardingProtocolMessage::FORWARD_MESSAGE_TYPE => {
                let bytes_read = HEADER_LEN + packet_len as usize;

                match serde_json::from_slice(&payload[HEADER_LEN..bytes_read]) {
                    Ok(message) => Ok((bytes_read, message)),
                    Err(serde_error) => Err(serde_error.into()),
                }
            }
            ForwardingProtocolMessage::ERROR_MESSAGE_TYPE => {
                let bytes_read = HEADER_LEN + packet_len as usize;

                match serde_json::from_slice(&payload[HEADER_LEN..bytes_read]) {
                    Ok(message) => Ok((bytes_read, message)),
                    Err(serde_error) => Err(serde_error.into()),
                }
            }
            ForwardingProtocolMessage::CONNECTION_CLOSE_MESSAGE_TYPE => {
                if packet_len != 8 {
                    return Err(format_err!("Incorrect length for close message"));
                }

                let mut connection_id: [u8; 8] = [0; 8];
                connection_id.clone_from_slice(&payload[20..28]);
                let connection_id = u64::from_be_bytes(connection_id);

                let bytes_read = 28;

                Ok((
                    bytes_read,
                    ForwardingProtocolMessage::new_connection_close_message(connection_id),
                ))
            }
            ForwardingProtocolMessage::CONNECTION_DATA_MESSAGE_TYPE => {
                let mut connection_id: [u8; 8] = [0; 8];
                connection_id.clone_from_slice(&payload[20..28]);
                let connection_id = u64::from_be_bytes(connection_id);

                let payload_bytes = packet_len as usize - 8;
                let end = HEADER_LEN + 8 + payload_bytes;
                let mut message_value = Vec::new();
                message_value.extend_from_slice(&payload[28..end]);

                Ok((
                    end,
                    ForwardingProtocolMessage::new_connection_data_message(
                        connection_id,
                        message_value,
                    ),
                ))
            }
            ForwardingProtocolMessage::FORWARDING_CLOSE_MESSAGE_TYPE => {
                let bytes_read = HEADER_LEN + packet_len as usize;

                match serde_json::from_slice(&payload[HEADER_LEN..bytes_read]) {
                    Ok(message) => Ok((bytes_read, message)),
                    Err(serde_error) => Err(serde_error.into()),
                }
            }
            ForwardingProtocolMessage::KEEPALIVE_MESSAGE_TYPE => {
                let bytes_read = HEADER_LEN + packet_len as usize;

                match serde_json::from_slice(&payload[HEADER_LEN..bytes_read]) {
                    Ok(message) => Ok((bytes_read, message)),
                    Err(serde_error) => Err(serde_error.into()),
                }
            }
            _ => bail!("Unknown packet type!"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand;
    use rand::Rng;

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

    fn get_forward_message() -> ForwardingProtocolMessage {
        ForwardingProtocolMessage::new_forward_message("192.168.10.1".parse().unwrap(), 6823, 443)
    }

    fn get_random_test_vector() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        // should be small enough to be fast but long enough
        // to cause issues
        let len: u16 = rng.gen();
        let mut out = Vec::new();
        for _ in 0..len {
            let byte: u8 = rng.gen();
            out.push(byte);
        }
        out
    }

    fn get_random_stream_id() -> u64 {
        let mut rng = rand::thread_rng();
        let out: u64 = rng.gen();
        out
    }

    #[test]
    fn test_id_message() {
        let message = ForwardingProtocolMessage::new_identification_message(get_test_id());
        let message_bytes = message.get_message();
        let (number_of_bytes_parsed, parsed_message_contents) =
            ForwardingProtocolMessage::read_message(&message_bytes).expect("Failed to parse!");
        assert_eq!(message, parsed_message_contents);
        assert_eq!(number_of_bytes_parsed, message_bytes.len());
    }

    #[test]
    fn test_id_message_trailing_bytes() {
        let message = ForwardingProtocolMessage::new_identification_message(get_test_id());
        let mut message_bytes = message.get_message();
        let actual_message_length = message_bytes.len();
        // add some random trailing bytes
        message_bytes.extend_from_slice(&get_random_test_vector());
        let (message_bytes_parsed, parsed_message_contents) =
            ForwardingProtocolMessage::read_message(&message_bytes).expect("Failed to parse!");
        assert_eq!(parsed_message_contents, message);
        assert_eq!(message_bytes_parsed, actual_message_length);
    }

    #[test]
    fn test_forward_message() {
        let message = get_forward_message();
        let message_bytes = message.get_message();
        let (message_bytes_parsed, parsed_message_contents) =
            ForwardingProtocolMessage::read_message(&message_bytes).expect("Failed to parse!");
        assert_eq!(message, parsed_message_contents);
        assert_eq!(message_bytes_parsed, message_bytes.len());
    }

    #[test]
    fn test_forward_message_trailing_bytes() {
        let message = get_forward_message();
        let mut message_bytes = message.get_message();
        let actual_message_length = message_bytes.len();
        message_bytes.extend_from_slice(&get_random_test_vector());
        let (message_bytes_parsed, parsed_message_contents) =
            ForwardingProtocolMessage::read_message(&message_bytes).expect("Failed to parse!");
        assert_eq!(parsed_message_contents, message);
        assert_eq!(message_bytes_parsed, actual_message_length);
    }

    #[test]
    fn test_error_message() {
        let message = ForwardingProtocolMessage::new_error_message("test".to_string());
        let out = message.get_message();
        let (size, parsed) =
            ForwardingProtocolMessage::read_message(&out).expect("Failed to parse!");
        assert_eq!(parsed, message);
        assert_eq!(size, out.len());
    }

    #[test]
    fn test_error_message_trailing_bytes() {
        let message = ForwardingProtocolMessage::new_error_message("test".to_string());
        let mut out = message.get_message();
        let actual_message_length = out.len();
        out.extend_from_slice(&get_random_test_vector());
        let (size, parsed) =
            ForwardingProtocolMessage::read_message(&out).expect("Failed to parse!");
        assert_eq!(parsed, message);
        assert_eq!(size, actual_message_length);
    }

    #[test]
    fn test_connecton_close_message() {
        let message =
            ForwardingProtocolMessage::new_connection_close_message(get_random_stream_id());
        let out = message.get_message();
        let (size, parsed) =
            ForwardingProtocolMessage::read_message(&out).expect("Failed to parse!");
        assert_eq!(parsed, message);
        assert_eq!(size, out.len());
    }

    #[test]
    fn test_connecton_close_message_trailing_bytes() {
        let message =
            ForwardingProtocolMessage::new_connection_close_message(get_random_stream_id());
        let mut out = message.get_message();
        let actual_message_length = out.len();
        out.extend_from_slice(&get_random_test_vector());
        let (size, parsed) =
            ForwardingProtocolMessage::read_message(&out).expect("Failed to parse!");
        assert_eq!(parsed, message);
        assert_eq!(size, actual_message_length);
    }

    #[test]
    fn test_connecton_message() {
        let message = ForwardingProtocolMessage::new_connection_data_message(
            get_random_stream_id(),
            get_random_test_vector(),
        );
        let out = message.get_message();
        let (size, parsed) =
            ForwardingProtocolMessage::read_message(&out).expect("Failed to parse!");
        assert_eq!(parsed, message);
        assert_eq!(size, out.len());
    }

    #[test]
    fn test_connecton_message_trailing_bytes() {
        let message = ForwardingProtocolMessage::new_connection_data_message(
            get_random_stream_id(),
            get_random_test_vector(),
        );
        let mut out = message.get_message();
        let actual_message_length = out.len();
        out.extend_from_slice(&get_random_test_vector());
        let (size, parsed) =
            ForwardingProtocolMessage::read_message(&out).expect("Failed to parse!");
        assert_eq!(parsed, message);
        assert_eq!(size, actual_message_length);
    }

    #[test]
    fn test_close_message() {
        let message = ForwardingProtocolMessage::new_forwarding_close_message();
        let out = message.get_message();
        let (size, parsed) =
            ForwardingProtocolMessage::read_message(&out).expect("Failed to parse!");
        assert_eq!(parsed, message);
        assert_eq!(size, out.len());
    }

    #[test]
    fn test_close_message_trailing_bytes() {
        let message = ForwardingProtocolMessage::new_forwarding_close_message();
        let mut out = message.get_message();
        let actual_message_length = out.len();
        out.extend_from_slice(&get_random_test_vector());
        let (size, parsed) =
            ForwardingProtocolMessage::read_message(&out).expect("Failed to parse!");
        assert_eq!(parsed, message);
        assert_eq!(size, actual_message_length);
    }

    #[test]
    fn test_keepalive_message() {
        let message = ForwardingProtocolMessage::new_keepalive_message();
        let out = message.get_message();
        let (size, parsed) =
            ForwardingProtocolMessage::read_message(&out).expect("Failed to parse!");
        assert_eq!(parsed, message);
        assert_eq!(size, out.len());
    }

    #[test]
    fn test_keepalive_message_trailing_bytes() {
        let message = ForwardingProtocolMessage::new_keepalive_message();
        let mut out = message.get_message();
        let actual_message_length = out.len();
        out.extend_from_slice(&get_random_test_vector());
        let (size, parsed) =
            ForwardingProtocolMessage::read_message(&out).expect("Failed to parse!");
        assert_eq!(parsed, message);
        assert_eq!(size, actual_message_length);
    }

    #[test]
    fn test_multiple_message_types() {
        let mut multi_message = Vec::new();
        let message1 =
            ForwardingProtocolMessage::new_connection_close_message(get_random_stream_id());
        multi_message.extend_from_slice(&message1.get_message());
        let message2 = ForwardingProtocolMessage::new_connection_data_message(
            get_random_stream_id(),
            get_random_test_vector(),
        );
        multi_message.extend_from_slice(&message2.get_message());
        let message3 = ForwardingProtocolMessage::new_identification_message(get_test_id());
        multi_message.extend_from_slice(&message3.get_message());
        let (size1, parsed) =
            ForwardingProtocolMessage::read_message(&multi_message[0..]).expect("Failed to parse!");
        assert_eq!(parsed, message1);
        let (size2, parsed) = ForwardingProtocolMessage::read_message(&multi_message[size1..])
            .expect("Failed to parse!");
        assert_eq!(parsed, message2);
        let (size3, parsed) =
            ForwardingProtocolMessage::read_message(&multi_message[size1 + size2..])
                .expect("Failed to parse!");
        assert_eq!(parsed, message3);
        assert_eq!(size1 + size2 + size3, multi_message.len());
    }

    #[test]
    fn test_multiple_connection_types() {
        let mut multi_message = Vec::new();
        let message1 = ForwardingProtocolMessage::new_connection_data_message(
            get_random_stream_id(),
            get_random_test_vector(),
        );
        multi_message.extend_from_slice(&message1.get_message());
        let message2 = ForwardingProtocolMessage::new_connection_data_message(
            get_random_stream_id(),
            get_random_test_vector(),
        );
        multi_message.extend_from_slice(&message2.get_message());
        let message3 = ForwardingProtocolMessage::new_connection_data_message(
            get_random_stream_id(),
            get_random_test_vector(),
        );
        multi_message.extend_from_slice(&message3.get_message());
        let (size1, parsed) =
            ForwardingProtocolMessage::read_message(&multi_message[0..]).expect("Failed to parse!");
        assert_eq!(parsed, message1);
        let (size2, parsed) = ForwardingProtocolMessage::read_message(&multi_message[size1..])
            .expect("Failed to parse!");
        assert_eq!(parsed, message2);
        let (size3, parsed) =
            ForwardingProtocolMessage::read_message(&multi_message[size1 + size2..])
                .expect("Failed to parse!");
        assert_eq!(parsed, message3);
        assert_eq!(size1 + size2 + size3, multi_message.len());
    }

    #[test]
    fn test_junk() {
        let mut junk = Vec::new();
        junk.extend_from_slice(&get_random_test_vector());
        assert!(ForwardingProtocolMessage::read_message(&junk).is_err());
        assert!(ForwardingProtocolMessage::read_message(&junk).is_err());
    }
}
