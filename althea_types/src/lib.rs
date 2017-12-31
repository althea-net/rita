extern crate serde;
extern crate serde_json;
extern crate base64;
extern crate hex;
use std::ops::Deref;
use std::error::Error;
//e().map_err(|e| eprintln!("{}", e.description())).unwrap();
#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate array_serialization_derive;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;
use std::fmt;

#[derive(ArrayTupleDeref, ArrayTupleBase64, PartialEq)]
pub struct Bytes32([u8; 32]);

impl fmt::Debug for Bytes32 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Bytes32 {:?}", &&self.0[..])
    }
}

#[derive(ArrayTupleDeref, Copy, Clone, Hash, Eq, PartialEq)]
pub struct EthAddress([u8; 20]);

impl FromStr for EthAddress {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex::decode(&s[2..]).map(|v| {
            let mut arr = [0u8; 20];
            arr.clone_from_slice(&v);
            EthAddress(arr)
        })
    }
}

impl fmt::Debug for EthAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "EthAddress {}", self.to_string())
    }
}

impl fmt::Display for EthAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0.as_ref()))
    }
}

impl Serialize for EthAddress {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for EthAddress {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <&str>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}


#[derive(ArrayTupleDeref, ArrayTupleBase64)]
pub struct EthSignature([u8; 65]);

impl PartialEq for EthSignature {
    fn eq(&self, other: &EthSignature) -> bool {
        self.0[..] == other.0[..]
    }
}

impl fmt::Debug for EthSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "EthSignature {:?}", &&self.0[..])
    }
}

#[derive(ArrayTupleDeref, ArrayTupleBase64)]
pub struct EthPrivateKey([u8; 64]);

impl PartialEq for EthPrivateKey {
    fn eq(&self, other: &EthPrivateKey) -> bool {
        self.0[..] == other.0[..]
    }
}


impl fmt::Debug for EthPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "EthPrivateKey {:?}", &&self.0[..])
    }
}

#[cfg(test)]
mod tests {
    extern crate serde_json;
    use super::{EthSignature, EthPrivateKey, EthAddress};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct MyStruct {
        addr: EthAddress,
        sig: EthSignature,
        key: EthPrivateKey
    }

    #[test]
    fn serialize() {
        // Some data structure.
        let my_struct = MyStruct {
            addr: "0x0707070707070707070707070707070707070707".parse().unwrap(),
            sig: EthSignature([8; 65]),
            key: EthPrivateKey([7; 64])
        };

        // Serialize it to a JSON string.
        let j = serde_json::to_string(&my_struct).unwrap();

        let s = "{\"addr\":\"0x0707070707070707070707070707070707070707\",\"sig\":\"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg=\",\"key\":\"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBw==\"}";

        // Print, write to a file, or send to an HTTP server.
        assert_eq!(s, j);

        assert_eq!(serde_json::from_str::<MyStruct>(s).unwrap(), my_struct);
    }
}
