use byteorder::{BigEndian, ReadBytesExt};
use bytes::BufMut;
use std::convert::From;
use std::error::Error;
use std::io::Cursor;
use std::net::Ipv6Addr;
use std::{fmt, io};

#[derive(Debug)]
pub enum MessageError {
    /// Doesn't have enough bytes to decode a correct message
    InvalidPayloadError,
    /// Insufficient bytes in to decode a full message
    BufferUnderflow,
    /// Unknown message code indicates a possible unsupported message
    InvalidMagic,
    /// General I/O error
    IoError(io::Error),
    /// MSG_IM_HERE: Received IP address is invalid
    InvalidIpAddress,
}

impl Error for MessageError {
    fn description(&self) -> &str {
        match *self {
            MessageError::InvalidPayloadError => "Invalid payload detected",
            MessageError::InvalidMagic => "Invalid magic value received",
            MessageError::BufferUnderflow => "Buffer underflow while reading message",
            MessageError::IoError(ref e) => e.description(),
            MessageError::InvalidIpAddress => "Received ImHere with invalid IP address",
        }
    }
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        self.description().fmt(f)
    }
}

impl From<io::Error> for MessageError {
    fn from(error: io::Error) -> Self {
        MessageError::IoError(error)
    }
}

#[test]
fn test_message_error() {
    assert_eq!(
        MessageError::InvalidPayloadError.description(),
        "Invalid payload detected"
    );
}

const MSG_IM_HERE: u8 = 0x5b;
const MSG_IM_HERE_LEN: u16 = 19;

/**
 * An enum that contains all supported p2p packets
 */
#[derive(Debug, PartialEq)]
pub enum PeerMessage {
    ImHere(Ipv6Addr),
}

impl PeerMessage {
    /**
     * Encode an ImHere message
     * Message format is very simple
     * Magic <u8>, Size <u16>, Ipaddr &[u16; 8]
     */
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        match *self {
            PeerMessage::ImHere(addr) => {
                buf.put_u8(MSG_IM_HERE);
                buf.put_u16_be(MSG_IM_HERE_LEN);
                let ipaddr_bytes: [u8; 16] = addr.octets();
                for i in 0..16 {
                    buf.put_u8(ipaddr_bytes[i]);
                }
                trace!("Encoded ImHere packet {:x?}", buf);
                return buf;
            }
        }
    }
    /**
     * Decode buffer of data into a ImHere message
     * Message format is very simple
     * Magic <u8>, Size <u16>, Ipaddr &[u16; 8]
     */
    pub fn decode(buf: &Vec<u8>) -> Result<PeerMessage, MessageError> {
        trace!("Starting ImHere packet decode!");
        // Check if buffer is empty
        if buf.is_empty() {
            trace!("Recieved an empty ImHere packet!");
            return Err(MessageError::InvalidPayloadError);
        }
        let mut pointer = Cursor::new(&buf);
        let packet_magic = pointer.read_u8()?;

        match packet_magic {
            MSG_IM_HERE => {
                let packet_size = pointer.read_u16::<BigEndian>()?;
                if packet_size < MSG_IM_HERE_LEN {
                    trace!(
                        "Recieved an ImHere packet with an invalid size: {:?}",
                        packet_size
                    );
                    return Err(MessageError::BufferUnderflow);
                }

                let mut peer_address_arr: [u16; 8] = [0xFFFF; 8];
                for i in (0..8).rev() {
                    peer_address_arr[i] = pointer.read_u16::<BigEndian>()?;
                }
                let peer_address = Ipv6Addr::new(
                    peer_address_arr[7],
                    peer_address_arr[6],
                    peer_address_arr[5],
                    peer_address_arr[4],
                    peer_address_arr[3],
                    peer_address_arr[2],
                    peer_address_arr[1],
                    peer_address_arr[0],
                );

                if peer_address.is_unspecified()
                    || peer_address.is_loopback()
                    || peer_address.is_multicast()
                {
                    trace!(
                        "Recieved a valid ImHere with an invalid ip address: {:?}",
                        peer_address,
                    );
                    return Err(MessageError::InvalidIpAddress);
                }

                trace!("ImHere decoding completed successfully {:?}", peer_address);
                Ok(PeerMessage::ImHere(peer_address))
            }
            _ => {
                trace!("Recieved packet with an unknown magic: {:X?}", packet_magic);
                return Err(MessageError::InvalidMagic);
            }
        }
    }
}

#[test]
fn test_encode_im_here() {
    let data = PeerMessage::ImHere(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff)).encode();
    assert_eq!(
        data,
        vec![
            91, 0, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 10, 2, 255,
        ]
    );
}

#[test]
fn test_decode_imhere() {
    let result = PeerMessage::decode(&vec![
        91, 0, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 10, 2, 255,
    ]);
    match result {
        Ok(PeerMessage::ImHere(addr)) => {
            assert_eq!(addr, Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff))
        }
        Err(e) => panic!("Unexpected error: {:?}", e),
    }
}

#[test]
fn test_decode_imhere_with_empty_buf() {
    let result = PeerMessage::decode(&vec![] as &Vec<u8>);
    match result {
        Ok(msg) => panic!("Expected error, got message {:?}", msg),
        Err(MessageError::InvalidPayloadError) => assert!(true),
        Err(e) => panic!("Unexpected error received: {:?}", e),
    }
}

#[test]
fn test_decode_imhere_with_wrong_magic() {
    match PeerMessage::decode(&vec![1, 2, 3, 4]) {
        Ok(msg) => assert!(false, "Unexpected success {:?}", msg),
        Err(MessageError::InvalidMagic) => assert!(true),
        Err(_) => panic!("Invalid error"),
    }
}

#[test]
fn test_decode_imhere_with_multicast_interface() {
    let multicast_addr = Ipv6Addr::new(0xff00, 0xde, 0xad, 0xbe, 0xef, 0xb4, 0xdc, 0x0d);
    assert!(multicast_addr.is_multicast());
    let data = PeerMessage::ImHere(multicast_addr).encode();
    let msg = PeerMessage::decode(&data);
    match msg {
        Ok(msg) => panic!("Unexpected Ok: {:?}", msg),
        Err(MessageError::InvalidIpAddress) => assert!(true),
        Err(e) => panic!("Unexpected error: {:?}", e),
    }
}
