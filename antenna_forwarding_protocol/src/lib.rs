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

pub const IDENTIFICATION_MESSAGE_TYPE: u16 = 0;
pub const FORWARD_MESSAGE_TYPE: u16 = 1;
pub const ERROR_MESSAGE_TYPE: u16 = 2;
pub const CONNECTION_CLOSE_MESSAGE_TYPE: u16 = 3;
pub const CONNECTION_MESSAGE_TYPE: u16 = 4;
pub const FORWARDING_CLOSE_MESSAGE_TYPE: u16 = 5;
pub const KEEPALIVE_MESSAGE_TYPE: u16 = 6;

/// Reads all the currently available messages from the provided stream, this function will
/// also block until a currently in flight message is delivered, for a maximum of 500ms
pub fn read_message<T: ForwardingProtocolMessage + Clone>(
    input: &mut TcpStream,
) -> Result<Vec<T>, Error> {
    read_message_internal(input, Vec::new(), Vec::new())
}

fn read_message_internal<T: ForwardingProtocolMessage + Clone>(
    input: &mut TcpStream,
    remaining_bytes: Vec<u8>,
    messages: Vec<T>,
) -> Result<Vec<T>, Error> {
    // these should match the full list of message types defined above
    let mut messages = messages;
    let mut unfinished_message = false;

    remaining_bytes.extend_from_slice(&read_till_block(input)?);

    let mut possible_messages: Vec<Result<(usize, T), Error>> = Vec::new();
    possible_messages.push(IdentificationMessage::read_message(&remaining_bytes));
    let forward = ForwardMessage::read_message(&remaining_bytes);
    let error = ErrorMessage::read_message(&remaining_bytes);
    let close = ConnectionClose::read_message(&remaining_bytes);
    let connection = ConnectionMessage::read_message(&remaining_bytes);
    let forwarding_close = ForwardingCloseMessage::read_message(&remaining_bytes);
    let keepalive = KeepAliveMessage::read_message(&remaining_bytes);
    if let Ok((bytes, id)) = id {
        (bytes, message) = get_successfull_message();

        if bytes < remaining_bytes.len() {
            read_message_internal(input, remaining_bytes[bytes..].to_vec(), messages)
        } else {
            Ok(messages)
        }
    } else {
        Ok(messages)
    }
}

/// Takes a vec of message parse results and returns the successful one, and error if
/// more than one is successful
fn get_successfull_message<T: ForwardingProtocolMessage + Clone>(
    possible_messages: Vec<Result<(usize, T), Error>>,
) -> Result<(usize, T), Error> {
    // this doesn't really need to be here, the same set of bytes
    // should never parse to two messages successfully, so guarding
    // is a little excessive.
    let mut num_ok = 0;
    let mut res: Option<(usize, T)> = None;
    for item in possible_messages {
        if let Ok(val) = item {
            num_ok += 1;
            res = Some(val)
        }
    }
    if num_ok > 1 {
        panic!("The same message parsed two ways!");
    } else if num_ok == 0 {
        bail!("No successful messages");
    } else {
        // we have exactly one success, this can't panic
        // because we must have found one to reach this block
        Ok(res.unwrap())
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

/// an excessively long protocol magic value that preceeds all
/// control traffic. A u32 would probably be sufficient to ensure
/// that we never try to interpret an actual packet as a control packet
/// but I don't see a reason to be stingy. This is totally random, but you
/// can never change it once there's a device deployed with it
const MAGIC: u128 = 266_244_417_876_907_680_150_892_848_205_622_258_774;

pub enum ForwardingMessageType {
    IdentificationMessage,
}

pub trait ForwardingProtocolMessage {
    fn get_message(&self) -> Vec<u8>;
    fn read_message(payload: &[u8]) -> Result<(usize, Self), Error>
    where
        Self: std::marker::Sized;
    fn get_type(&self) -> u16;
    fn get_payload(&self) -> Option<Vec<u8>>;
    fn get_stream_id(&self) -> Option<u64>;
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

/// Used to determine the liveness of each end
#[derive(Clone, Serialize, Deserialize, Debug, Default, Eq, PartialEq)]
pub struct KeepAliveMessage;

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

        if packet_magic != MAGIC {
            return Err(format_err!("Packet magic incorrect!"));
        } else if packet_type != CONNECTION_MESSAGE_TYPE {
            return Err(format_err!("Wrong packet type!"));
        } else if packet_len as usize + HEADER_LEN > payload.len() {
            return Err(format_err!(
                "Our slice is {} bytes, but our packet_len {} bytes",
                payload.len(),
                packet_len as usize + HEADER_LEN
            ));
        }

        let mut connection_id: [u8; 8] = [0; 8];
        connection_id.clone_from_slice(&payload[20..28]);
        let connection_id = u64::from_be_bytes(connection_id);

        let payload_bytes = packet_len as usize - 8;
        let end = HEADER_LEN + 8 + payload_bytes;
        let mut message_value = Vec::new();
        message_value.extend_from_slice(&payload[28..end]);

        Ok((end, ConnectionMessage::new(connection_id, message_value)))
    }

    fn get_type(&self) -> u16 {
        CONNECTION_MESSAGE_TYPE
    }

    fn get_payload(&self) -> Option<Vec<u8>> {
        Some(self.payload)
    }

    fn get_stream_id(&self) -> Option<u64> {
        Some(self.stream_id)
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

    fn get_payload(&self) -> Option<Vec<u8>> {
        None
    }

    fn get_stream_id(&self) -> Option<u64> {
        Some(self.stream_id)
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

        if packet_magic != MAGIC {
            return Err(format_err!("Packet magic incorrect!"));
        } else if packet_type != IDENTIFICATION_MESSAGE_TYPE {
            return Err(format_err!("Wrong packet type!"));
        }

        let bytes_read = 20 + packet_len as usize;

        match serde_json::from_slice(&payload[HEADER_LEN..bytes_read]) {
            Ok(message) => Ok((bytes_read, message)),
            Err(serde_error) => Err(serde_error.into()),
        }
    }

    fn get_type(&self) -> u16 {
        IDENTIFICATION_MESSAGE_TYPE
    }

    fn get_payload(&self) -> Option<Vec<u8>> {
        None
    }

    fn get_stream_id(&self) -> Option<u64> {
        None
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

        if packet_magic != MAGIC {
            return Err(format_err!("Packet magic incorrect!"));
        } else if packet_type != ERROR_MESSAGE_TYPE {
            return Err(format_err!("Wrong packet type!"));
        }

        let bytes_read = HEADER_LEN + packet_len as usize;

        match serde_json::from_slice(&payload[HEADER_LEN..bytes_read]) {
            Ok(message) => Ok((bytes_read, message)),
            Err(serde_error) => Err(serde_error.into()),
        }
    }

    fn get_type(&self) -> u16 {
        ERROR_MESSAGE_TYPE
    }

    fn get_payload(&self) -> Option<Vec<u8>> {
        None
    }

    fn get_stream_id(&self) -> Option<u64> {
        None
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

        if packet_magic != MAGIC {
            return Err(format_err!("Packet magic incorrect!"));
        } else if packet_type != FORWARD_MESSAGE_TYPE {
            return Err(format_err!("Wrong packet type!"));
        }

        let bytes_read = HEADER_LEN + packet_len as usize;

        match serde_json::from_slice(&payload[HEADER_LEN..bytes_read]) {
            Ok(message) => Ok((bytes_read, message)),
            Err(serde_error) => Err(serde_error.into()),
        }
    }

    fn get_type(&self) -> u16 {
        FORWARD_MESSAGE_TYPE
    }

    fn get_payload(&self) -> Option<Vec<u8>> {
        None
    }

    fn get_stream_id(&self) -> Option<u64> {
        None
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

        if packet_magic != MAGIC {
            return Err(format_err!("Packet magic incorrect!"));
        } else if packet_type != FORWARDING_CLOSE_MESSAGE_TYPE {
            return Err(format_err!("Wrong packet type!"));
        }

        let bytes_read = HEADER_LEN + packet_len as usize;

        match serde_json::from_slice(&payload[HEADER_LEN..bytes_read]) {
            Ok(message) => Ok((bytes_read, message)),
            Err(serde_error) => Err(serde_error.into()),
        }
    }

    fn get_type(&self) -> u16 {
        FORWARDING_CLOSE_MESSAGE_TYPE
    }

    fn get_payload(&self) -> Option<Vec<u8>> {
        None
    }

    fn get_stream_id(&self) -> Option<u64> {
        None
    }
}

impl KeepAliveMessage {
    pub fn new() -> KeepAliveMessage {
        KeepAliveMessage
    }
}

impl ForwardingProtocolMessage for KeepAliveMessage {
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
    fn read_message(payload: &[u8]) -> Result<(usize, KeepAliveMessage), Error> {
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

        if packet_magic != MAGIC {
            return Err(format_err!("Packet magic incorrect!"));
        } else if packet_type != KEEPALIVE_MESSAGE_TYPE {
            return Err(format_err!("Wrong packet type!"));
        }

        let bytes_read = HEADER_LEN + packet_len as usize;

        match serde_json::from_slice(&payload[HEADER_LEN..bytes_read]) {
            Ok(message) => Ok((bytes_read, message)),
            Err(serde_error) => Err(serde_error.into()),
        }
    }

    fn get_type(&self) -> u16 {
        KEEPALIVE_MESSAGE_TYPE
    }

    fn get_payload(&self) -> Option<Vec<u8>> {
        None
    }

    fn get_stream_id(&self) -> Option<u64> {
        None
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
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

    fn get_forward_message() -> ForwardMessage {
        ForwardMessage::new("192.168.10.1".parse().unwrap(), 6823, 443)
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
            ConnectionClose::new(get_random_stream_id()).get_type()
        );
        assert_eq!(
            CONNECTION_MESSAGE_TYPE,
            ConnectionMessage::new(get_random_stream_id(), get_random_test_vector()).get_type()
        );
        assert_eq!(
            FORWARDING_CLOSE_MESSAGE_TYPE,
            ForwardingCloseMessage::new().get_type()
        );
        assert_eq!(KEEPALIVE_MESSAGE_TYPE, KeepAliveMessage::new().get_type());
    }

    #[test]
    fn test_id_message() {
        let message = IdentificationMessage::new(get_test_id());
        let message_bytes = message.get_message();
        let (number_of_bytes_parsed, parsed_message_contents) =
            IdentificationMessage::read_message(&message_bytes).expect("Failed to parse!");
        assert_eq!(message, parsed_message_contents);
        assert_eq!(number_of_bytes_parsed, message_bytes.len());
    }

    #[test]
    fn test_id_message_trailing_bytes() {
        let message = IdentificationMessage::new(get_test_id());
        let mut message_bytes = message.get_message();
        let actual_message_length = message_bytes.len();
        // add some random trailing bytes
        message_bytes.extend_from_slice(&get_random_test_vector());
        let (message_bytes_parsed, parsed_message_contents) =
            IdentificationMessage::read_message(&message_bytes).expect("Failed to parse!");
        assert_eq!(parsed_message_contents, message);
        assert_eq!(message_bytes_parsed, actual_message_length);
    }

    #[test]
    fn test_forward_message() {
        let message = get_forward_message();
        let message_bytes = message.get_message();
        let (message_bytes_parsed, parsed_message_contents) =
            ForwardMessage::read_message(&message_bytes).expect("Failed to parse!");
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
            ForwardMessage::read_message(&message_bytes).expect("Failed to parse!");
        assert_eq!(parsed_message_contents, message);
        assert_eq!(message_bytes_parsed, actual_message_length);
    }

    #[test]
    fn test_error_message() {
        let message = ErrorMessage::new("test".to_string());
        let out = message.get_message();
        let (size, parsed) = ErrorMessage::read_message(&out).expect("Failed to parse!");
        assert_eq!(parsed, message);
        assert_eq!(size, out.len());
    }

    #[test]
    fn test_error_message_trailing_bytes() {
        let message = ErrorMessage::new("test".to_string());
        let mut out = message.get_message();
        let actual_message_length = out.len();
        out.extend_from_slice(&get_random_test_vector());
        let (size, parsed) = ErrorMessage::read_message(&out).expect("Failed to parse!");
        assert_eq!(parsed, message);
        assert_eq!(size, actual_message_length);
    }

    #[test]
    fn test_connecton_close_message() {
        let message = ConnectionClose::new(get_random_stream_id());
        let out = message.get_message();
        let (size, parsed) = ConnectionClose::read_message(&out).expect("Failed to parse!");
        assert_eq!(parsed, message);
        assert_eq!(size, out.len());
    }

    #[test]
    fn test_connecton_close_message_trailing_bytes() {
        let message = ConnectionClose::new(get_random_stream_id());
        let mut out = message.get_message();
        let actual_message_length = out.len();
        out.extend_from_slice(&get_random_test_vector());
        let (size, parsed) = ConnectionClose::read_message(&out).expect("Failed to parse!");
        assert_eq!(parsed, message);
        assert_eq!(size, actual_message_length);
    }

    #[test]
    fn test_connecton_message() {
        let message = ConnectionMessage::new(get_random_stream_id(), get_random_test_vector());
        let out = message.get_message();
        let (size, parsed) = ConnectionMessage::read_message(&out).expect("Failed to parse!");
        assert_eq!(parsed, message);
        assert_eq!(size, out.len());
    }

    #[test]
    fn test_connecton_message_trailing_bytes() {
        let message = ConnectionMessage::new(get_random_stream_id(), get_random_test_vector());
        let mut out = message.get_message();
        let actual_message_length = out.len();
        out.extend_from_slice(&get_random_test_vector());
        let (size, parsed) = ConnectionMessage::read_message(&out).expect("Failed to parse!");
        assert_eq!(parsed, message);
        assert_eq!(size, actual_message_length);
    }

    #[test]
    fn test_close_message() {
        let message = ForwardingCloseMessage::new();
        let out = message.get_message();
        let (size, parsed) = ForwardingCloseMessage::read_message(&out).expect("Failed to parse!");
        assert_eq!(parsed, message);
        assert_eq!(size, out.len());
    }

    #[test]
    fn test_close_message_trailing_bytes() {
        let message = ForwardingCloseMessage::new();
        let mut out = message.get_message();
        let actual_message_length = out.len();
        out.extend_from_slice(&get_random_test_vector());
        let (size, parsed) = ForwardingCloseMessage::read_message(&out).expect("Failed to parse!");
        assert_eq!(parsed, message);
        assert_eq!(size, actual_message_length);
    }

    #[test]
    fn test_keepalive_message() {
        let message = KeepAliveMessage::new();
        let out = message.get_message();
        let (size, parsed) = KeepAliveMessage::read_message(&out).expect("Failed to parse!");
        assert_eq!(parsed, message);
        assert_eq!(size, out.len());
    }

    #[test]
    fn test_keepalive_message_trailing_bytes() {
        let message = KeepAliveMessage::new();
        let mut out = message.get_message();
        let actual_message_length = out.len();
        out.extend_from_slice(&get_random_test_vector());
        let (size, parsed) = KeepAliveMessage::read_message(&out).expect("Failed to parse!");
        assert_eq!(parsed, message);
        assert_eq!(size, actual_message_length);
    }

    #[test]
    fn test_multiple_message_types() {
        let mut multi_message = Vec::new();
        let message1 = ConnectionClose::new(get_random_stream_id());
        multi_message.extend_from_slice(&message1.get_message());
        let message2 = ConnectionMessage::new(get_random_stream_id(), get_random_test_vector());
        multi_message.extend_from_slice(&message2.get_message());
        let message3 = IdentificationMessage::new(get_test_id());
        multi_message.extend_from_slice(&message3.get_message());
        let (size1, parsed) =
            ConnectionClose::read_message(&multi_message[0..]).expect("Failed to parse!");
        assert_eq!(parsed, message1);
        let (size2, parsed) =
            ConnectionMessage::read_message(&multi_message[size1..]).expect("Failed to parse!");
        assert_eq!(parsed, message2);
        let (size3, parsed) = IdentificationMessage::read_message(&multi_message[size1 + size2..])
            .expect("Failed to parse!");
        assert_eq!(parsed, message3);
        assert_eq!(size1 + size2 + size3, multi_message.len());
    }

    #[test]
    fn test_multiple_connection_types() {
        let mut multi_message = Vec::new();
        let message1 = ConnectionMessage::new(get_random_stream_id(), get_random_test_vector());
        multi_message.extend_from_slice(&message1.get_message());
        let message2 = ConnectionMessage::new(get_random_stream_id(), get_random_test_vector());
        multi_message.extend_from_slice(&message2.get_message());
        let message3 = ConnectionMessage::new(get_random_stream_id(), get_random_test_vector());
        multi_message.extend_from_slice(&message3.get_message());
        let (size1, parsed) =
            ConnectionMessage::read_message(&multi_message[0..]).expect("Failed to parse!");
        assert_eq!(parsed, message1);
        let (size2, parsed) =
            ConnectionMessage::read_message(&multi_message[size1..]).expect("Failed to parse!");
        assert_eq!(parsed, message2);
        let (size3, parsed) = ConnectionMessage::read_message(&multi_message[size1 + size2..])
            .expect("Failed to parse!");
        assert_eq!(parsed, message3);
        assert_eq!(size1 + size2 + size3, multi_message.len());
    }

    #[test]
    fn test_junk() {
        let mut junk = Vec::new();
        junk.extend_from_slice(&get_random_test_vector());
        assert!(ConnectionMessage::read_message(&junk).is_err());
        assert!(ConnectionMessage::read_message(&junk).is_err());
    }
}
