use std::ops::Deref;
use std::str::FromStr;
use std::fmt;
use hex;
use serde;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::hash::{Hash, Hasher};

#[derive(Copy, Clone)]
pub struct EthSignature(pub [u8; 65]);

impl Hash for EthSignature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl PartialEq for EthSignature {
    fn eq(&self, other: &EthSignature) -> bool {
        self.0[..] == other.0[..]
    }
}
impl Eq for EthSignature {}

impl Deref for EthSignature {
    type Target = [u8; 65 as usize];

    fn deref(&self) -> &[u8; 65 as usize] {
        &self.0
    }
}

impl FromStr for EthSignature {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex::decode(&s[2..]).map(|v| {
            let mut arr = [0u8; 65];
            arr.clone_from_slice(&v);
            EthSignature(arr)
        })
    }
}

impl fmt::Debug for EthSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "EthSignature {}", self.to_string())
    }
}

impl fmt::Display for EthSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0.as_ref()))
    }
}

impl Serialize for EthSignature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for EthSignature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <&str>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}
