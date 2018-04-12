use hex;
use serde;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::str::FromStr;

#[derive(Copy, Clone)]
pub struct EthAddress(pub [u8; 20]);

impl Hash for EthAddress {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl PartialEq for EthAddress {
    fn eq(&self, other: &EthAddress) -> bool {
        self.0[..] == other.0[..]
    }
}
impl Eq for EthAddress {}

impl Deref for EthAddress {
    type Target = [u8; 20 as usize];

    fn deref(&self) -> &[u8; 20 as usize] {
        &self.0
    }
}

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

impl<'de> Deserialize<'de> for EthAddress {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}
