use hex;
use serde;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::str::FromStr;

#[derive(Copy, Clone)]
pub struct EthPrivateKey(pub [u8; 64]);

impl Hash for EthPrivateKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl PartialEq for EthPrivateKey {
    fn eq(&self, other: &EthPrivateKey) -> bool {
        self.0[..] == other.0[..]
    }
}
impl Eq for EthPrivateKey {}

impl Deref for EthPrivateKey {
    type Target = [u8; 64 as usize];

    fn deref(&self) -> &[u8; 64 as usize] {
        &self.0
    }
}

impl FromStr for EthPrivateKey {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex::decode(&s[2..]).map(|v| {
            let mut arr = [0u8; 64];
            arr.clone_from_slice(&v);
            EthPrivateKey(arr)
        })
    }
}

impl fmt::Debug for EthPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "EthPrivateKey {}", self.to_string())
    }
}

impl fmt::Display for EthPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0.as_ref()))
    }
}

impl Serialize for EthPrivateKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for EthPrivateKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <&str>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}
