use althea_types::LocalIdentity;
use bincode;
use byteorder::{BigEndian, ReadBytesExt};
use bytes::BufMut;
use serde_derive::{Deserialize, Serialize};
use std::convert::From;
use std::error::Error;
use std::fmt::Display;
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
    // Deserialization Error in Decode
    DeserializationError,
}

impl Error for MessageError {}

impl Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            MessageError::InvalidPayloadError => write!(f, "Invalid payload detected"),
            MessageError::InvalidMagic => write!(f, "Invalid magic value received"),
            MessageError::BufferUnderflow => write!(f, "Buffer underflow while reading message"),
            MessageError::IoError(ref e) => write!(f, "{e}"),
            MessageError::InvalidIpAddress => write!(f, "Received ImHere with invalid IP address"),
            MessageError::DeserializationError => {
                write!(f, "Error when Deserializing Hello Message")
            }
        }
    }
}

impl From<io::Error> for MessageError {
    fn from(error: io::Error) -> Self {
        MessageError::IoError(error)
    }
}

const MSG_IM_HERE: u8 = 0x5b;
const MSG_IM_HERE_LEN: u16 = 19;
const MSG_HELLO: u8 = 0x6c;

/**
 * An enum that contains all supported p2p packets
 */
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerMessage {
    ImHere(Ipv6Addr),
    /// This is the message sent over the udp socket. It contains the necessary information to set up a tunnel
    /// from the respective side of connection
    Hello {
        my_id: Box<LocalIdentity>,
        response: bool,
        sender_wgport: u16,
    },
}

impl PeerMessage {
    /**
     * Encode an ImHere or Hello message
     * Message format is very simple
     * Magic <u8>, Size <u16>, Payload (Ipaddr &[u16; 8] for ImHere)
     */
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        match *self {
            PeerMessage::ImHere(addr) => {
                buf.put_u8(MSG_IM_HERE);
                buf.put_u16(MSG_IM_HERE_LEN);
                let ipaddr_bytes: [u8; 16] = addr.octets();
                for i in ipaddr_bytes.iter() {
                    buf.put_u8(*i);
                }
                trace!("Encoded ImHere packet {:x?}", buf);
                buf
            }

            //This is a PeerMessage::Hello{ }
            _ => {
                buf.put_u8(MSG_HELLO);
                let encoded_hello = match bincode::serialize(self) {
                    Ok(a) => a,
                    Err(_) => {
                        info!(
                            "Unable to serialize the PeerMessage for hello, returning empty buffer"
                        );
                        return Vec::new();
                    }
                };
                let buf_len: u16 = 1 + 2 + encoded_hello.len() as u16;
                buf.put_u16(buf_len);
                for i in encoded_hello.iter() {
                    buf.put_u8(*i);
                }
                trace!("Encoded Hello packet {:x?}", buf);
                buf
            }
        }
    }
    /**
     * Decode buffer of data into a ImHere message
     * Message format is very simple
     * Magic <u8>, Size <u16>, Payload (Ipaddr &[u16; 8] for ImHere)
     */
    pub fn decode(buf: &[u8]) -> Result<PeerMessage, MessageError> {
        trace!("Starting packet decode!");
        // Check if buffer is empty
        if buf.is_empty() {
            trace!("Received an empty packet!");
            return Err(MessageError::InvalidPayloadError);
        }
        let mut pointer = Cursor::new(&buf);
        let packet_magic = pointer.read_u8()?;

        match packet_magic {
            MSG_IM_HERE => {
                let packet_size = pointer.read_u16::<BigEndian>()?;
                if packet_size < MSG_IM_HERE_LEN {
                    trace!(
                        "Received an ImHere packet with an invalid size: {:?}",
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
                        "Received a valid ImHere with an invalid ip address: {:?}",
                        peer_address,
                    );
                    return Err(MessageError::InvalidIpAddress);
                }

                trace!("ImHere decoding completed successfully {:?}", peer_address);
                Ok(PeerMessage::ImHere(peer_address))
            }

            MSG_HELLO => {
                let _packet_size = pointer.read_u16::<BigEndian>()?;

                // First 3 bytes are overhead (Magic <u8>, Size <u16>)
                let des_buf = &buf[3..];
                let hello_peer_message = match bincode::deserialize(des_buf) {
                    Ok(a) => a,
                    Err(_) => {
                        return Err(MessageError::DeserializationError);
                    }
                };

                Ok(hello_peer_message)
            }
            _ => {
                trace!("Received packet with an unknown magic: {:X?}", packet_magic);
                Err(MessageError::InvalidMagic)
            }
        }
    }
}

#[test]
fn test_encode_im_here() {
    let data = PeerMessage::ImHere(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff)).encode();
    assert_eq!(
        data,
        vec![91, 0, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 10, 2, 255,]
    );
}

#[test]
fn test_decode_imhere() {
    let result = PeerMessage::decode(&[
        91, 0, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 10, 2, 255,
    ]);
    match result {
        Ok(PeerMessage::ImHere(addr)) => {
            assert_eq!(addr, Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff))
        }
        Err(e) => panic!("Unexpected error: {:?}", e),
        _ => {}
    }
}

#[test]
fn test_decode_imhere_with_empty_buf() {
    let result = PeerMessage::decode(&vec![] as &Vec<u8>);
    match result {
        Ok(msg) => panic!("Expected error, got message {:?}", msg),
        Err(MessageError::InvalidPayloadError) => (),
        Err(e) => panic!("Unexpected error received: {:?}", e),
    }
}

#[test]
fn test_decode_imhere_with_wrong_magic() {
    match PeerMessage::decode(&[1, 2, 3, 4]) {
        Ok(msg) => panic!("Unexpected success {:?}", msg),
        Err(MessageError::InvalidMagic) => (),
        Err(e) => panic!("Invalid error {:?}", e),
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
        Err(MessageError::InvalidIpAddress) => (),
        Err(e) => panic!("Unexpected error: {:?}", e),
    }
}

#[test]
fn test_hello_serde() {
    use crate::peer_listener::Hello;
    use crate::peer_listener::Peer;
    use althea_types::identity::Identity;
    use althea_types::LocalIdentity;
    use althea_types::WgKey;
    use bincode;
    use clarity::Address;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::str::FromStr;

    //make random hello struct
    let address: [u8; 20] = [
        0x10, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42,
    ];
    let wgkey = "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk=";
    let hello_struct = Hello {
        my_id: LocalIdentity {
            global: Identity::new(
                IpAddr::V6(Ipv6Addr::new(
                    0xff00, 0xde, 0xad, 0xbe, 0xef, 0xb4, 0xdc, 0x0d,
                )),
                Address::from_slice(&address).unwrap(),
                WgKey::from_str(wgkey).unwrap(),
                None,
            ),
            wg_port: 0x3b23,
            have_tunnel: None,
        },
        to: Peer {
            contact_socket: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            ifidx: 0x34139832_u32,
        },
        response: false,
    };

    let serialized_cbor = serde_cbor::to_vec(&hello_struct).unwrap();
    let serialized_json = serde_json::to_vec(&hello_struct).unwrap();
    let serialized_bincode = bincode::serialize(&hello_struct).unwrap();
    assert!(serialized_cbor.len() < serialized_json.len());
    assert!(serialized_bincode.len() < serialized_cbor.len());
}

#[test]
fn test_encoded_hello_size() {
    use crate::peer_listener::Hello;
    use crate::peer_listener::Peer;
    use althea_types::identity::Identity;
    use althea_types::LocalIdentity;
    use althea_types::WgKey;
    use clarity::Address;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::str::FromStr;

    //make random hello struct
    let address: [u8; 20] = [
        0x10, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42,
    ];
    let wgkey = "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk=";
    let hello_struct = Hello {
        my_id: LocalIdentity {
            global: Identity::new(
                IpAddr::V6(Ipv6Addr::new(
                    0xff00, 0xde, 0xad, 0xbe, 0xef, 0xb4, 0xdc, 0x0d,
                )),
                Address::from_slice(&address).unwrap(),
                WgKey::from_str(wgkey).unwrap(),
                None,
            ),
            wg_port: 0x3b23,
            have_tunnel: None,
        },
        to: Peer {
            contact_socket: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            ifidx: 0x34139832_u32,
        },
        response: false,
    };

    let res = PeerMessage::Hello {
        my_id: Box::new(hello_struct.my_id),
        response: hello_struct.response,
        sender_wgport: hello_struct.my_id.wg_port,
    };
    let result = PeerMessage::encode(&res);

    //check that it is a hello message
    assert_eq!(result[0], MSG_HELLO);

    //check that size of message is correct
    let size = ((result[1] as u16) << 8) | result[2] as u16;
    assert_eq!(size, result.len() as u16);

    //check that size is less that 1500
    assert!(size < 1500);
}

#[test]
fn test_hello_encode_decode() {
    use crate::peer_listener::Hello;
    use crate::peer_listener::Peer;
    use althea_types::identity::Identity;
    use althea_types::LocalIdentity;
    use althea_types::WgKey;
    use clarity::Address;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::str::FromStr;

    //make random hello struct
    let address: [u8; 20] = [
        0x10, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42,
    ];
    let wgkey = "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk=";
    let hello_struct = Hello {
        my_id: LocalIdentity {
            global: Identity::new(
                IpAddr::V6(Ipv6Addr::new(
                    0xff00, 0xde, 0xad, 0xbe, 0xef, 0xb4, 0xdc, 0x0d,
                )),
                Address::from_slice(&address).unwrap(),
                WgKey::from_str(wgkey).unwrap(),
                None,
            ),
            wg_port: 0x3b23,
            have_tunnel: None,
        },
        to: Peer {
            contact_socket: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            ifidx: 0x34139832_u32,
        },

        response: false,
    };

    //Encode the message
    let s_wgport = 0x1232;
    let res = PeerMessage::Hello {
        my_id: Box::new(hello_struct.my_id),
        response: hello_struct.response,
        sender_wgport: s_wgport,
    };
    let result = PeerMessage::encode(&res).to_vec();

    //Decode the message and check equality
    let deserialized_peermessage = PeerMessage::decode(&result.to_vec()).unwrap();

    match deserialized_peermessage {
        PeerMessage::Hello {
            my_id,
            response,
            sender_wgport,
        } => {
            assert_eq!(my_id, Box::new(hello_struct.my_id));
            assert_eq!(response, hello_struct.response);
            assert_eq!(sender_wgport, s_wgport);
        }
        _ => panic!("Error, should receive a PeerMessage::Hello"),
    }
}

#[test]
fn test_deserialize_with_wrong_serialization() {
    use crate::peer_listener::Hello;
    use crate::peer_listener::Peer;
    use althea_types::identity::Identity;
    use althea_types::LocalIdentity;
    use althea_types::WgKey;
    use clarity::Address;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::str::FromStr;

    //make random hello struct
    let address: [u8; 20] = [
        0x10, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42,
    ];
    let wgkey = "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk=";
    let hello_struct = Hello {
        my_id: LocalIdentity {
            global: Identity::new(
                IpAddr::V6(Ipv6Addr::new(
                    0xff00, 0xde, 0xad, 0xbe, 0xef, 0xb4, 0xdc, 0x0d,
                )),
                Address::from_slice(&address).unwrap(),
                WgKey::from_str(wgkey).unwrap(),
                None,
            ),
            wg_port: 0x3b23,
            have_tunnel: None,
        },
        to: Peer {
            contact_socket: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            ifidx: 0x34139832_u32,
        },

        response: false,
    };

    //Encode the message
    let res = PeerMessage::Hello {
        my_id: Box::new(hello_struct.my_id),
        response: hello_struct.response,
        sender_wgport: hello_struct.my_id.wg_port,
    };
    let mut result = PeerMessage::encode(&res);

    //corrupt the vector
    result[3] += 1;

    //decode should not work
    match PeerMessage::decode(&result) {
        Ok(_) => panic!("Expected error"),
        Err(MessageError::DeserializationError) => (),
        Err(_) => panic!("Wrong Error"),
    };
}
