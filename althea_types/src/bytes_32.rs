use hex;
use serde;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::str::FromStr;

#[derive(Copy, Clone)]
pub struct Bytes32(pub [u8; 32]);

impl Hash for Bytes32 {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl PartialEq for Bytes32 {
    fn eq(&self, other: &Bytes32) -> bool {
        self.0[..] == other.0[..]
    }
}
impl Eq for Bytes32 {}

impl Deref for Bytes32 {
    type Target = [u8; 32 as usize];

    fn deref(&self) -> &[u8; 32 as usize] {
        &self.0
    }
}

impl FromStr for Bytes32 {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex::decode(&s[2..]).map(|v| {
            let mut arr = [0u8; 32];
            arr.clone_from_slice(&v);
            Bytes32(arr)
        })
    }
}

impl fmt::Debug for Bytes32 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Bytes32 {}", self.to_string())
    }
}

impl fmt::Display for Bytes32 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0.as_ref()))
    }
}

impl Serialize for Bytes32 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for Bytes32 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <&str>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}
