/// This file under Apache 2.0
use crate::error::AltheaTypesError;
use crypto_box::PublicKey;
use crypto_box::SecretKey;
use num256::Uint256;
use serde::de::{Deserialize, Error, Unexpected, Visitor};
use serde::ser::{Serialize, Serializer};
use serde::Deserializer;
#[cfg(test)]
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey as NaclPublicKey;
#[cfg(test)]
use sodiumoxide::crypto::box_::SecretKey as NaclSecretKey;
use std::fmt;
use std::str::FromStr;

#[derive(Hash, Copy, Clone, Eq, PartialEq)]
pub struct WgKey([u8; 32]);

impl AsRef<[u8]> for WgKey {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl From<WgKey> for [u8; 32] {
    fn from(val: WgKey) -> [u8; 32] {
        val.0
    }
}

/// This is somewhat dangerous, since libsodium provides seperate
/// public and private key types while we don't have those here.
/// Be very careful not to use this on the public key! That would be bad
impl From<WgKey> for SecretKey {
    fn from(val: WgKey) -> SecretKey {
        SecretKey::from_bytes(val.0)
    }
}

impl From<WgKey> for PublicKey {
    fn from(val: WgKey) -> PublicKey {
        PublicKey::from_bytes(val.0)
    }
}

// test implementations for libsodium
#[cfg(test)]
impl From<WgKey> for NaclSecretKey {
    fn from(val: WgKey) -> NaclSecretKey {
        NaclSecretKey(val.0)
    }
}

#[cfg(test)]
impl From<WgKey> for NaclPublicKey {
    fn from(val: WgKey) -> NaclPublicKey {
        NaclPublicKey(val.0)
    }
}

impl From<[u8; 32]> for WgKey {
    fn from(val: [u8; 32]) -> WgKey {
        WgKey(val)
    }
}

impl From<Uint256> for WgKey {
    fn from(val: Uint256) -> WgKey {
        WgKey(val.to_be_bytes())
    }
}

impl From<WgKey> for Uint256 {
    fn from(val: WgKey) -> Uint256 {
        Uint256::from_be_bytes(&val.0)
    }
}

impl fmt::Display for WgKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base64::encode(self))
    }
}

impl fmt::Debug for WgKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base64::encode(self))
    }
}

impl FromStr for WgKey {
    type Err = AltheaTypesError;

    fn from_str(s: &str) -> Result<WgKey, Self::Err> {
        let mut output = [0u8; 32];

        if s.len() != 44 {
            return Err(base64::DecodeError::InvalidLength.into());
        }

        match base64::decode_config_slice(s, base64::STANDARD, &mut output) {
            Ok(_) => Ok(WgKey(output)),
            Err(e) => Err(e.into()),
        }
    }
}

impl Serialize for WgKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

struct WgKeyVisitor;

impl<'de> Visitor<'de> for WgKeyVisitor {
    type Value = WgKey;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "expects a valid base64-encoded string with length of 44"
        )
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        match WgKey::from_str(s) {
            Ok(wg_key) => Ok(wg_key),
            Err(_) => Err(Error::invalid_value(Unexpected::Str(s), &self)),
        }
    }
}

impl<'de> Deserialize<'de> for WgKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(WgKeyVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wgkey_from_valid_string() {
        let valid_key = "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk=";

        assert!(WgKey::from_str(valid_key).is_ok())
    }

    #[test]
    fn test_wgkey_from_invalid_string() {
        let bad_key1 = "look at me, I'm the same length as a key but";
        let bad_key2 = "8BeCExnthLe5ou0EYe 5jNqJ/PduZ1x2o7lpXJOpXkk=";

        assert!(WgKey::from_str(bad_key1).is_err());
        assert!(WgKey::from_str(bad_key2).is_err());
    }

    #[test]
    fn test_wgkey_to_string() {
        let key = WgKey::from_str("8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk=").unwrap();
        assert_eq!(
            key.to_string(),
            "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk="
        );
    }

    #[test]
    #[should_panic]
    fn test_wgkey_panic_from_short_string() {
        WgKey::from_str("ABCDE").unwrap();
    }

    #[test]
    fn test_wgkey_to_from_uint256() {
        let key = WgKey::from_str("8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk=").unwrap();
        let uint: Uint256 = key.into();
        let converted_key: WgKey = uint.into();
        assert_eq!(converted_key, key);
    }
}
