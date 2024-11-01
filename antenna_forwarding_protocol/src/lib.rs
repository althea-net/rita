//! The protocol structs, definitions and utility functions for the Antenna forwarding system
//! it's easier to put them here than to duplicate work and/or create a dependency structure
//! that involves more extra weight

#![warn(clippy::all)]
#![allow(clippy::pedantic)]
#![forbid(unsafe_code)]

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;
#[cfg(test)]
#[macro_use]
extern crate lazy_static;

use althea_types::Identity;
use althea_types::WgKey;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::Nonce;
use sodiumoxide::crypto::box_::NONCEBYTES;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Error as IoError;
use std::io::ErrorKind::WouldBlock;
use std::io::Read;
use std::io::Write;
use std::net::IpAddr;
use std::net::Shutdown;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;
use std::time::Instant;

mod error;
pub use error::AntennaForwardingError;

/// The amount of time to sleep a thread that's spinlocking on somthing
pub const SPINLOCK_TIME: Duration = Duration::from_millis(100);

/// The amount of time to wait for a blocking read
pub const NET_TIMEOUT: Duration = Duration::from_secs(1);

/// The size in bytes of our packet header, 16 byte magic, 2 byte type, 4 byte len
pub const HEADER_LEN: usize = 22;

/// The amount of time before we close a stream that has not gotten a message
/// from an antenna or a client
pub const STREAM_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub enum ForwardingProtocolError {
    SliceTooSmall { expected: u32, actual: u32 },
    SerdeError { message: String },
    BadMagic,
    InvalidLen,
    WrongPacketType,
    UnknownPacketType,
    DecryptionFailed,
}

impl Error for ForwardingProtocolError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl Display for ForwardingProtocolError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            ForwardingProtocolError::SliceTooSmall { expected, actual } => write!(
                f,
                "SliceTooSmall expected {expected} bytes, got {actual} bytes"
            ),
            ForwardingProtocolError::BadMagic => write!(f, "BadMagic"),
            ForwardingProtocolError::InvalidLen => write!(f, "InvalidLen"),
            ForwardingProtocolError::WrongPacketType => write!(f, "WrongPacketType"),
            ForwardingProtocolError::UnknownPacketType => write!(f, "UnknownPacketType"),
            ForwardingProtocolError::DecryptionFailed => write!(f, "DecryptionFailed"),
            ForwardingProtocolError::SerdeError { message } => write!(f, "SerdeError {message}"),
        }
    }
}

/// Writes data to a stream keeping in mind that we may encounter
/// a buffer limit and have to partially complete our write
pub fn write_all_spinlock(stream: &mut TcpStream, mut buffer: &[u8]) -> Result<(), IoError> {
    assert!(!buffer.is_empty());
    const SPINLOCK_TIMEOUT: Duration = Duration::from_secs(600);

    stream.set_nonblocking(true)?;
    stream.set_nodelay(true)?;
    let start = Instant::now();
    loop {
        if Instant::now() - start > SPINLOCK_TIMEOUT {
            return Err(IoError::new(
                std::io::ErrorKind::WriteZero,
                AntennaForwardingError::SpaceAllocationError,
            ));
        }

        let res = stream.write(buffer);
        match res {
            Ok(bytes) => {
                trace!("Spinlock wrote {} bytes of {}", bytes, buffer.len());
                if buffer.len() == bytes {
                    return Ok(());
                } else if bytes == 0 {
                    return Err(IoError::new(
                        std::io::ErrorKind::WriteZero,
                        AntennaForwardingError::ConnectionDownError,
                    ));
                } else {
                    trace!("Did not write all, trying again",);
                    // truncate the buffer with the bytes we have written
                    buffer = &buffer[bytes..];
                }
            }
            Err(e) => {
                error!(
                    "Problem {:?} in spinlock trying to write {} bytes",
                    e,
                    buffer.len()
                );
                if e.kind() == WouldBlock {
                    // wait for the operating system to clear up some buffer space
                    thread::sleep(SPINLOCK_TIME);
                } else {
                    error!("Socket write error is {:?}", e);
                    return Err(e);
                }
            }
        }
    }
}

/// Reads the entire contents of a tcpstream into a buffer until it blocks
/// if someone is sending a huge amount of TCP traffic this routine will
/// run until you run out of memory
pub fn read_till_block(input: &mut TcpStream) -> Result<Vec<u8>, IoError> {
    input.set_nonblocking(true)?;
    let mut out = Vec::new();
    match input.read_to_end(&mut out) {
        Ok(_bytes) => Ok(out),
        Err(e) => {
            if e.kind() == WouldBlock {
                Ok(out)
            } else {
                error!("Broken! {:?}", e);
                Err(e)
            }
        }
    }
}

pub struct ExternalStream {
    pub stream: TcpStream,
    pub last_message: Instant,
}

/// This function processes the antenna streams, meaning it handles taking messages from
/// known streams, packaging them, and sending them down the line to the server. It also handles
/// details like closing those streams when they hangup and notifying the other end.
pub fn process_streams<S: ::std::hash::BuildHasher>(
    streams: &mut HashMap<u64, ExternalStream, S>,
    server_stream: &mut TcpStream,
) {
    let mut streams_to_remove: Vec<u64> = Vec::new();
    // First we we have to iterate over all of these connections
    // and read to send messages up the server pipe. We need to do
    // this first because we may exit in the next section if there's
    // nothing to write
    for (stream_id, antenna_stream) in streams.iter_mut() {
        // in theory we will figure out if the connection is closed here
        // and then send a closed message
        match read_till_block(&mut antenna_stream.stream) {
            Ok(bytes) => {
                if !bytes.is_empty() {
                    trace!(
                        "Got {} bytes for stream id {} from antenna/client",
                        bytes.len(),
                        stream_id
                    );
                    let msg =
                        ForwardingProtocolMessage::new_connection_data_message(*stream_id, bytes);
                    if let Err(e) = write_all_spinlock(server_stream, &msg.get_message()) {
                        error!("Failed to write with stream {} with {:?}", *stream_id, e);
                    }
                    antenna_stream.last_message = Instant::now();
                }
            }
            Err(e) => {
                if e.kind() != WouldBlock {
                    error!("Closing antenna/client connection with {:?}", e);
                    let msg = ForwardingProtocolMessage::new_connection_close_message(*stream_id);
                    if let Err(e) = write_all_spinlock(server_stream, &msg.get_message()) {
                        error!("Failed to close stream {} with {:?}", *stream_id, e);
                    }
                    let _ = antenna_stream.stream.shutdown(Shutdown::Write);
                    streams_to_remove.push(*stream_id);
                }
            }
        }

        // this check is here because while I'm pretty sure this struct
        // is only modified in this thread I'm not positive, don't remove
        // the extra check unless you are positive. Becuase negative durations
        // mean a panic
        if Instant::now() > antenna_stream.last_message
            && Instant::now() - antenna_stream.last_message > STREAM_TIMEOUT
        {
            error!("Closing antenna/client connection due to STREAM_TIMEOUT");
            let msg = ForwardingProtocolMessage::new_connection_close_message(*stream_id);
            if let Err(e) = write_all_spinlock(server_stream, &msg.get_message()) {
                error!("Failed to close stream {} with {:?}", *stream_id, e);
            }
            let _ = antenna_stream.stream.shutdown(Shutdown::Write);
            streams_to_remove.push(*stream_id);
        }
    }
    for i in streams_to_remove {
        streams.remove(&i);
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
    IdentificationMessage { id: Box<Identity> },
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
    /// back to the server when the antenna can't be forwarded
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
        let boxed_id = Box::new(id);
        ForwardingProtocolMessage::IdentificationMessage { id: boxed_id }
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
        let len_bytes = payload.len() as u32;
        message.extend_from_slice(&len_bytes.to_be_bytes());
        // copy in the serialized struct
        message.extend_from_slice(&payload);
        message
    }

    pub fn get_encrypted_forward_message(
        &self,
        server_secretkey: WgKey,
        client_publickey: WgKey,
    ) -> Result<Vec<u8>, ForwardingProtocolError> {
        if let ForwardingProtocolMessage::ForwardMessage { .. } = self {
            let client_publickey = client_publickey.into();
            let server_secretkey = server_secretkey.into();
            let plaintext = serde_json::to_vec(self).unwrap();
            let nonce = box_::gen_nonce();
            let ciphertext = box_::seal(&plaintext, &nonce, &client_publickey, &server_secretkey);
            let mut payload = Vec::new();
            payload.extend_from_slice(&nonce.0);
            payload.extend_from_slice(&ciphertext);

            let mut message = Vec::new();
            message.extend_from_slice(&ForwardingProtocolMessage::MAGIC.to_be_bytes());
            // message type number index 16-18
            message
                .extend_from_slice(&ForwardingProtocolMessage::FORWARD_MESSAGE_TYPE.to_be_bytes());
            // length, index 18-20
            let len_bytes = payload.len() as u32;
            message.extend_from_slice(&len_bytes.to_be_bytes());
            // copy in the encrypted struct
            message.extend_from_slice(&payload);
            Ok(message)
        } else {
            Err(ForwardingProtocolError::WrongPacketType)
        }
    }

    pub fn read_encrypted_forward_message(
        payload: &[u8],
        server_publickey: WgKey,
        client_secretkey: WgKey,
    ) -> Result<(usize, ForwardingProtocolMessage), ForwardingProtocolError> {
        if payload.len() < HEADER_LEN {
            return Err(ForwardingProtocolError::InvalidLen);
        }

        let mut packet_magic: [u8; 16] = [0; 16];
        packet_magic.clone_from_slice(&payload[0..16]);
        let packet_magic = u128::from_be_bytes(packet_magic);

        let mut packet_type: [u8; 2] = [0; 2];
        packet_type.clone_from_slice(&payload[16..18]);
        let packet_type = u16::from_be_bytes(packet_type);

        let mut packet_len: [u8; 4] = [0; 4];
        packet_len.clone_from_slice(&payload[18..22]);
        let packet_len = u32::from_be_bytes(packet_len);

        // this needs to be updated when new packet types are added
        if packet_magic != ForwardingProtocolMessage::MAGIC {
            return Err(ForwardingProtocolError::BadMagic);
        } else if packet_type != ForwardingProtocolMessage::FORWARD_MESSAGE_TYPE {
            return Err(ForwardingProtocolError::WrongPacketType);
        } else if packet_len as usize + HEADER_LEN > payload.len() {
            return Err(ForwardingProtocolError::SliceTooSmall {
                actual: payload.len() as u32,
                expected: { packet_len + HEADER_LEN as u32 },
            });
        }

        // nonce is 24 bytes
        let nonce_end = HEADER_LEN + NONCEBYTES;
        let mut nonce: [u8; NONCEBYTES] = [0; NONCEBYTES];
        nonce.clone_from_slice(&payload[HEADER_LEN..nonce_end]);
        let nonce = Nonce(nonce);
        let end_bytes = HEADER_LEN + packet_len as usize;
        let ciphertext = &payload[nonce_end..end_bytes];
        let sk = client_secretkey.into();
        let pk = server_publickey.into();
        match box_::open(ciphertext, &nonce, &pk, &sk) {
            Ok(plaintext) => match serde_json::from_slice(&plaintext) {
                Ok(forward_message) => Ok((end_bytes, forward_message)),
                Err(e) => Err(ForwardingProtocolError::SerdeError {
                    message: e.to_string(),
                }),
            },
            Err(_) => Err(ForwardingProtocolError::DecryptionFailed),
        }
    }

    pub fn get_message(&self) -> Vec<u8> {
        match self {
            ForwardingProtocolMessage::IdentificationMessage { .. } => {
                ForwardingProtocolMessage::make_serde_packet(
                    ForwardingProtocolMessage::IDENTIFICATION_MESSAGE_TYPE,
                    self,
                )
            }
            // forward messages must be encrypted!
            ForwardingProtocolMessage::ForwardMessage { .. } => unimplemented!(),
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
                let len_bytes = 8u32;
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
                let len_bytes = payload.len() as u32 + 8;
                message.extend_from_slice(&len_bytes.to_be_bytes());
                // copy in stream id
                message.extend_from_slice(&stream_id.to_be_bytes());
                // copy in byte format payload
                message.extend_from_slice(payload);

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

    pub fn read_message(
        payload: &[u8],
    ) -> Result<(usize, ForwardingProtocolMessage), ForwardingProtocolError> {
        if payload.len() < HEADER_LEN {
            return Err(ForwardingProtocolError::InvalidLen);
        }

        let mut packet_magic: [u8; 16] = [0; 16];
        packet_magic.clone_from_slice(&payload[0..16]);
        let packet_magic = u128::from_be_bytes(packet_magic);

        let mut packet_type: [u8; 2] = [0; 2];
        packet_type.clone_from_slice(&payload[16..18]);
        let packet_type = u16::from_be_bytes(packet_type);

        let mut packet_len: [u8; 4] = [0; 4];
        packet_len.clone_from_slice(&payload[18..HEADER_LEN]);
        let packet_len = u32::from_be_bytes(packet_len);

        // this needs to be updated when new packet types are added
        if packet_magic != ForwardingProtocolMessage::MAGIC {
            return Err(ForwardingProtocolError::BadMagic);
        } else if packet_type > 6 {
            return Err(ForwardingProtocolError::WrongPacketType);
        } else if packet_len as usize + HEADER_LEN > payload.len() {
            // look here for strange errors with identity packets if you're trying
            // to make them larger
            if packet_type == ForwardingProtocolMessage::IDENTIFICATION_MESSAGE_TYPE
                && packet_len > 10000
            {
                // identity is fixed size struct, if we get a bs big packet like this
                // we are probably dealing with an old client that has 2 byte packet len
                return Err(ForwardingProtocolError::WrongPacketType);
            }

            return Err(ForwardingProtocolError::SliceTooSmall {
                actual: payload.len() as u32,
                expected: { packet_len + HEADER_LEN as u32 },
            });
        }

        match packet_type {
            ForwardingProtocolMessage::IDENTIFICATION_MESSAGE_TYPE => {
                let bytes_read = HEADER_LEN + packet_len as usize;

                match serde_json::from_slice(&payload[HEADER_LEN..bytes_read]) {
                    Ok(message) => Ok((bytes_read, message)),
                    Err(serde_error) => Err(ForwardingProtocolError::SerdeError {
                        message: serde_error.to_string(),
                    }),
                }
            }
            // you can not read encrypted packets with this function
            ForwardingProtocolMessage::FORWARD_MESSAGE_TYPE => {
                Err(ForwardingProtocolError::WrongPacketType)
            }
            ForwardingProtocolMessage::ERROR_MESSAGE_TYPE => {
                let bytes_read = HEADER_LEN + packet_len as usize;

                match serde_json::from_slice(&payload[HEADER_LEN..bytes_read]) {
                    Ok(message) => Ok((bytes_read, message)),
                    Err(serde_error) => Err(ForwardingProtocolError::SerdeError {
                        message: serde_error.to_string(),
                    }),
                }
            }
            ForwardingProtocolMessage::CONNECTION_CLOSE_MESSAGE_TYPE => {
                if packet_len != 8 {
                    return Err(ForwardingProtocolError::InvalidLen);
                }

                let mut connection_id: [u8; 8] = [0; 8];
                connection_id.clone_from_slice(&payload[HEADER_LEN..HEADER_LEN + 8]);
                let connection_id = u64::from_be_bytes(connection_id);

                let bytes_read = HEADER_LEN + 8;

                Ok((
                    bytes_read,
                    ForwardingProtocolMessage::new_connection_close_message(connection_id),
                ))
            }
            ForwardingProtocolMessage::CONNECTION_DATA_MESSAGE_TYPE => {
                let mut connection_id: [u8; 8] = [0; 8];
                connection_id.clone_from_slice(&payload[HEADER_LEN..HEADER_LEN + 8]);
                let connection_id = u64::from_be_bytes(connection_id);

                let payload_bytes = packet_len as usize - 8;
                let end = HEADER_LEN + 8 + payload_bytes;
                let mut message_value = Vec::new();
                message_value.extend_from_slice(&payload[HEADER_LEN + 8..end]);

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
                    Err(serde_error) => Err(ForwardingProtocolError::SerdeError {
                        message: serde_error.to_string(),
                    }),
                }
            }
            ForwardingProtocolMessage::KEEPALIVE_MESSAGE_TYPE => {
                let bytes_read = HEADER_LEN + packet_len as usize;

                match serde_json::from_slice(&payload[HEADER_LEN..bytes_read]) {
                    Ok(message) => Ok((bytes_read, message)),
                    Err(serde_error) => Err(ForwardingProtocolError::SerdeError {
                        message: serde_error.to_string(),
                    }),
                }
            }
            _ => Err(ForwardingProtocolError::UnknownPacketType),
        }
    }

    /// Reads messages using read_messages, but expecting the first message to be an encrypted fowarding message
    /// this is useful at the start of a forwarding session to simplify verification
    pub fn read_messages_start(
        input: &mut TcpStream,
        server_publickey: WgKey,
        client_secretkey: WgKey,
    ) -> Result<Vec<ForwardingProtocolMessage>, AntennaForwardingError> {
        trace!("read messages start");
        ForwardingProtocolMessage::read_messages_start_internal(
            input,
            server_publickey,
            client_secretkey,
            Vec::new(),
            0,
        )
    }

    fn read_messages_start_internal(
        input: &mut TcpStream,
        server_publickey: WgKey,
        client_secretkey: WgKey,
        bytes: Vec<u8>,
        depth: u8,
    ) -> Result<Vec<ForwardingProtocolMessage>, AntennaForwardingError> {
        // don't wait the first time in order to speed up execution
        // if we are recursing we want to wait for the message to finish
        // being written as the only reason we recuse is becuase we found
        // a write in progress
        const WAIT_TIME: u8 = 10;
        if depth > 1 && depth <= WAIT_TIME {
            thread::sleep(SPINLOCK_TIME);
        } else if depth > WAIT_TIME {
            error!("Never found the end of the message");
            return Err(AntennaForwardingError::EndNotFoundError);
        }

        let mut bytes = bytes;
        bytes.extend_from_slice(&read_till_block(input)?);

        match (
            ForwardingProtocolMessage::read_message(&bytes),
            ForwardingProtocolMessage::read_encrypted_forward_message(
                &bytes,
                server_publickey,
                client_secretkey,
            ),
        ) {
            (Ok((_bytes, ForwardingProtocolMessage::ForwardingCloseMessage)), _) => {
                trace!("Got close message, not starting");
                Ok(vec![ForwardingProtocolMessage::ForwardingCloseMessage])
            }
            (_, Ok((bytes_read, msg))) => {
                trace!(
                    "Got a forward message, recursing with {} bytes",
                    bytes.len() - bytes_read
                );
                ForwardingProtocolMessage::read_messages_internal(
                    input,
                    bytes[bytes_read..].to_vec(),
                    vec![msg],
                    0,
                    None,
                )
            }
            (Err(ForwardingProtocolError::SliceTooSmall { .. }), _) => {
                trace!("Got partial close message");
                ForwardingProtocolMessage::read_messages_start_internal(
                    input,
                    server_publickey,
                    client_secretkey,
                    bytes,
                    depth + 1,
                )
            }
            (_, Err(ForwardingProtocolError::SliceTooSmall { .. })) => {
                trace!("Got partial forward message");
                ForwardingProtocolMessage::read_messages_start_internal(
                    input,
                    server_publickey,
                    client_secretkey,
                    bytes,
                    depth + 1,
                )
            }
            (Err(a), Err(b)) => {
                trace!("Double read failure {:?} {:?}", a, b);
                Err(AntennaForwardingError::DoubleReadFailure { a, b })
            }
            (_, _) => {
                trace!("Impossible error");
                Err(AntennaForwardingError::ImpossibleError)
            }
        }
    }

    /// Reads all the currently available messages from the provided stream, this function will
    /// also block until a currently in flight message is delivered
    pub fn read_messages(
        input: &mut TcpStream,
    ) -> Result<Vec<ForwardingProtocolMessage>, AntennaForwardingError> {
        ForwardingProtocolMessage::read_messages_internal(input, Vec::new(), Vec::new(), 0, None)
    }

    /// internal helper function designed to handle the complexities of reading off of a buffer and breaking down into messages, if we find a message
    /// it is pushed onto the messages vec, if we have bytes left over from our read we recurse and try and parse a message out of them, if we have a
    /// packet that promises more bytes than we have that means we need to wait for the remainder by sleeping for spinlock time. In very bad situations
    /// the connection may actually be that slow and we use last_read_bytes to ensure that if any packets are delivered in a minute we keep trying
    /// last read bytes is only filled out when we recurse for an unfinished message
    fn read_messages_internal(
        input: &mut TcpStream,
        remaining_bytes: Vec<u8>,
        messages: Vec<ForwardingProtocolMessage>,
        depth: u16,
        last_read_bytes: Option<u32>,
    ) -> Result<Vec<ForwardingProtocolMessage>, AntennaForwardingError> {
        // don't wait the first time in order to speed up execution
        // if we are recursing we want to wait for the message to finish
        // being written as the only reason we recuse is becuase we found
        // a write in progress
        // we wait up to 60 seconds, this may seem absurdly long but on very
        // bad connections it's better to trust in the transport (TCP) to resume
        // and keep the packets flowing
        const WAIT_TIME: u16 = 600;
        if depth > 1 && depth <= WAIT_TIME {
            thread::sleep(SPINLOCK_TIME);
        } else if depth > WAIT_TIME {
            error!("Never found the end of the message");
            return Err(AntennaForwardingError::EndNotFoundError);
        }
        // these should match the full list of message types defined above
        let mut messages = messages;
        let mut remaining_bytes = remaining_bytes;

        remaining_bytes.extend_from_slice(&read_till_block(input)?);

        match ForwardingProtocolMessage::read_message(&remaining_bytes) {
            Ok((bytes, msg)) => {
                messages.push(msg);
                let num_remaining_bytes = remaining_bytes.len() - bytes;

                if num_remaining_bytes != 0 {
                    trace!(
                        "Got message of size {} recursing for remaining bytes {}",
                        bytes,
                        num_remaining_bytes
                    );
                    ForwardingProtocolMessage::read_messages_internal(
                        input,
                        remaining_bytes[bytes..].to_vec(),
                        messages,
                        depth + 1,
                        None,
                    )
                } else {
                    Ok(messages)
                }
            }
            Err(e) => match e {
                ForwardingProtocolError::SliceTooSmall { expected, actual } => {
                    error!("Expected {} bytes, got {} bytes", expected, actual);
                    if let Some(last_actual) = last_read_bytes {
                        // we got some new bytes, reset the counter
                        if actual > last_actual {
                            return ForwardingProtocolMessage::read_messages_internal(
                                input,
                                remaining_bytes,
                                messages,
                                0,
                                Some(actual),
                            );
                        }
                    }
                    ForwardingProtocolMessage::read_messages_internal(
                        input,
                        remaining_bytes,
                        messages,
                        depth + 1,
                        Some(actual),
                    )
                }
                _ => {
                    if !remaining_bytes.is_empty() {
                        Err(AntennaForwardingError::UnparsedBytesError {
                            messages,
                            remaining_bytes,
                        })
                    } else {
                        Ok(messages)
                    }
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ForwardingProtocolMessage;
    use super::Identity;
    use super::WgKey;
    use rand::Rng;

    lazy_static! {
        pub static ref FORWARDING_SERVER_PUBLIC_KEY: WgKey =
            "TynZVeTrJIDjIYGuUrcwgMFuf+Q2v/Hi5op2/guNB2U="
                .parse()
                .unwrap();
        pub static ref FORWARDING_SERVER_PRIVATE_KEY: WgKey =
            "AHbAX9bKPK7v7GMdS1oR7fwWpAsg8uI3gKduoIuMck4="
                .parse()
                .unwrap();
        pub static ref FORWARDING_CLIENT_PUBLIC_KEY: WgKey =
            "YVxkADnFUCTSjKn2X6ljAp1jppZgsatGzJETF3UAcQA="
                .parse()
                .unwrap();
        pub static ref FORWARDING_CLIENT_PRIVATE_KEY: WgKey =
            "aHazoPtmnS2ksW926jvss53+GQbyaXBkVLCfm5OVjnM="
                .parse()
                .unwrap();
    }

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
        let mut len: u32 = rng.gen();
        while len > u16::MAX as u32 * 4 {
            len = rng.gen();
        }
        let mut out = Vec::new();
        for _ in 0..len {
            let byte: u8 = rng.gen();
            out.push(byte);
        }
        out
    }

    fn get_random_long_test_vector() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        // should be small enough to be fast but long enough
        // to cause issues
        let mut len: u32 = rng.gen();
        while len > u16::MAX as u32 * 4 || len < u16::MAX as u32 {
            len = rng.gen();
        }
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
        let message_bytes = message
            .get_encrypted_forward_message(
                *FORWARDING_SERVER_PRIVATE_KEY,
                *FORWARDING_CLIENT_PUBLIC_KEY,
            )
            .expect("Failed to decrypt");
        let (message_bytes_parsed, parsed_message_contents) =
            ForwardingProtocolMessage::read_encrypted_forward_message(
                &message_bytes,
                *FORWARDING_SERVER_PUBLIC_KEY,
                *FORWARDING_CLIENT_PRIVATE_KEY,
            )
            .expect("Failed to parse!");
        assert_eq!(message, parsed_message_contents);
        assert_eq!(message_bytes_parsed, message_bytes.len());
    }

    #[test]
    fn test_forward_message_trailing_bytes() {
        let message = get_forward_message();
        let mut message_bytes = message
            .get_encrypted_forward_message(
                *FORWARDING_SERVER_PRIVATE_KEY,
                *FORWARDING_CLIENT_PUBLIC_KEY,
            )
            .expect("Failed to decrypt");
        let actual_message_length = message_bytes.len();
        message_bytes.extend_from_slice(&get_random_test_vector());
        let (message_bytes_parsed, parsed_message_contents) =
            ForwardingProtocolMessage::read_encrypted_forward_message(
                &message_bytes,
                *FORWARDING_SERVER_PUBLIC_KEY,
                *FORWARDING_CLIENT_PRIVATE_KEY,
            )
            .expect("Failed to parse!");
        assert_eq!(message, parsed_message_contents);
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

    #[test]
    fn test_multiple_big_connection_messages() {
        let message_a = ForwardingProtocolMessage::new_connection_data_message(
            get_random_stream_id(),
            get_random_long_test_vector(),
        );
        let message_b = ForwardingProtocolMessage::new_connection_data_message(
            get_random_stream_id(),
            get_random_long_test_vector(),
        );
        let message_c = ForwardingProtocolMessage::new_connection_data_message(
            get_random_stream_id(),
            get_random_test_vector(),
        );
        let mut out = message_a.get_message();
        out.extend_from_slice(&message_b.get_message());
        out.extend_from_slice(&message_c.get_message());
        let (size_a, parsed) =
            ForwardingProtocolMessage::read_message(&out).expect("Failed to parse!");
        assert_eq!(parsed, message_a);
        let (size_b, parsed) =
            ForwardingProtocolMessage::read_message(&out[size_a..]).expect("Failed to parse!");
        assert_eq!(parsed, message_b);
        let (_size_c, parsed) = ForwardingProtocolMessage::read_message(&out[size_a + size_b..])
            .expect("Failed to parse!");
        assert_eq!(parsed, message_c);
    }
}
