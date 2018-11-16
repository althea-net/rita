use std::fmt;
use std::str::FromStr;

struct WgKey([u8; 32]);

impl AsRef<[u8]> for WgKey {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl fmt::Display for WgKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", base64::encode(&self))
    }
}

impl FromStr for WgKey {
    type Err = base64::DecodeError;

    fn from_str(s: &str) -> Result<WgKey, Self::Err> {
        let mut output = [0u8; 32];

        match base64::decode_config_slice(s, base64::STANDARD, &mut output) {
            Ok(_) => Ok(WgKey(output)),
            Err(e) => Err(e)
        }
    }
}


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

    assert_eq!(key.to_string(), "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk=");
}

