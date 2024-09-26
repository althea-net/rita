//! This file handles encryption and decryption of websocket related data types (all data
//! sent to ops tools from a router)

use super::{
    EncryptedOpsWebsocketMessage, EncryptedRouterWebsocketMessage, OperatorWebsocketMessage,
    RouterWebsocketMessage,
};
use crate::WgKey;
use crypto_box::{
    aead::{Aead, AeadCore},
    PublicKey, SalsaBox, SecretKey,
};
use rand::rngs::OsRng;
use std::fmt::Display;

#[derive(Debug, Clone)]
pub enum WebsocketEncryptionError {
    DecryptionError { e: String },
    Utf8Error { e: String },
}

impl Display for WebsocketEncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            WebsocketEncryptionError::DecryptionError { e } => {
                write!(f, "Failed to decrypt websocket message: {}", e)
            }
            WebsocketEncryptionError::Utf8Error { e } => {
                write!(f, "UTF-8 Conversion error: {}", e)
            }
        }
    }
}

impl RouterWebsocketMessage {
    pub fn encrypt(
        &self,
        our_publickey: WgKey,
        our_secretkey: &SecretKey,
        ops_pubkey: &PublicKey,
    ) -> EncryptedRouterWebsocketMessage {
        let plaintext = serde_json::to_string(self)
            .expect("Failed to serialize router websocket message")
            .into_bytes();
        let nonce = SalsaBox::generate_nonce(&mut OsRng);
        let b = SalsaBox::new(ops_pubkey, our_secretkey);
        let ciphertext = b.encrypt(&nonce, plaintext.as_ref()).unwrap();
        EncryptedRouterWebsocketMessage {
            pubkey: our_publickey,
            nonce: nonce.into(),
            encrypted_router_websocket_msg: ciphertext,
        }
    }
}
impl EncryptedRouterWebsocketMessage {
    pub fn decrypt(
        &self,
        our_secretkey: &SecretKey,
    ) -> Result<RouterWebsocketMessage, WebsocketEncryptionError> {
        let their_nacl_pubkey = PublicKey::from(self.pubkey);
        let their_nonce = self.nonce;
        let ciphertext = self.encrypted_router_websocket_msg.clone();
        let b = SalsaBox::new(&their_nacl_pubkey, our_secretkey);
        let decrypted_bytes = match b.decrypt(their_nonce.as_ref().into(), ciphertext.as_ref()) {
            Ok(value) => value,
            Err(_) => {
                return Err(WebsocketEncryptionError::DecryptionError {
                    e: "Could not decrypt websocket message".to_string(),
                })
            }
        };
        let decrypted_string = match String::from_utf8(decrypted_bytes) {
            Ok(value) => value,
            Err(_) => {
                return Err(WebsocketEncryptionError::Utf8Error {
                    e: "Could not convert decrypted bytes to string".to_string(),
                })
            }
        };
        let decrypted_message = match serde_json::from_str(&decrypted_string) {
            Ok(value) => value,
            Err(_) => {
                return Err(WebsocketEncryptionError::DecryptionError {
                    e: "Could not deserialize decrypted string".to_string(),
                })
            }
        };

        Ok(decrypted_message)
    }
    pub fn json(&self) -> String {
        serde_json::to_string(self).expect("Failed to serialize encrypted message?")
    }
}

impl OperatorWebsocketMessage {
    pub fn encrypt(
        &self,
        our_publickey: WgKey,
        our_secretkey: &SecretKey,
        their_publickey: &PublicKey,
    ) -> EncryptedOpsWebsocketMessage {
        let plaintext = serde_json::to_string(&self)
            .expect("Failed to serialize operator websocket message")
            .into_bytes();
        let nonce = SalsaBox::generate_nonce(&mut OsRng);
        let b = SalsaBox::new(their_publickey, our_secretkey);
        let ciphertext = b.encrypt(&nonce, plaintext.as_ref()).unwrap();
        EncryptedOpsWebsocketMessage {
            nonce: nonce.into(),
            encrypted_ops_websocket_msg: ciphertext,
            pubkey: our_publickey,
        }
    }
}
impl EncryptedOpsWebsocketMessage {
    pub fn decrypt(
        &self,
        our_secretkey: &SecretKey,
        ops_publickey: &PublicKey,
    ) -> Result<OperatorWebsocketMessage, WebsocketEncryptionError> {
        let nonce = self.nonce;
        let ciphertext = &self.encrypted_ops_websocket_msg;
        let b = SalsaBox::new(ops_publickey, our_secretkey);
        let decrypted_bytes = match b.decrypt(nonce.as_ref().into(), ciphertext.as_ref()) {
            Ok(value) => value,
            Err(_) => {
                return Err(WebsocketEncryptionError::DecryptionError {
                    e: "Could not decrypt ops websocket message".to_string(),
                })
            }
        };
        let decrypted_string = match String::from_utf8(decrypted_bytes) {
            Ok(value) => value,
            Err(_) => {
                return Err(WebsocketEncryptionError::Utf8Error {
                    e: "Could not convert decrypted bytes to string".to_string(),
                })
            }
        };
        let decrypted_message = match serde_json::from_str(&decrypted_string) {
            Ok(value) => value,
            Err(_) => {
                return Err(WebsocketEncryptionError::DecryptionError {
                    e: "Could not deserialize decrypted string".to_string(),
                })
            }
        };

        Ok(decrypted_message)
    }
    pub fn json(&self) -> String {
        serde_json::to_string(self).expect("Failed to serialize encrypted message?")
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use crate::{
        websockets::{OperatorWebsocketMessage, RouterWebsocketMessage},
        Identity, WgKey,
    };

    // test encryption and decryption of router messages
    #[test]
    fn test_router_encryption() {
        use crypto_box::SecretKey;
        use rand::rngs::OsRng;


        let ip: IpAddr = IpAddr::V6("::1".parse().unwrap());

        // generate keys
        let router_secretkey = SecretKey::generate(&mut OsRng);
        let router_publickey = router_secretkey.public_key();
        let router_wg_pub = WgKey::from(*router_publickey.as_bytes());

        let ops_secretkey = SecretKey::generate(&mut OsRng);
        let ops_publickey = ops_secretkey.public_key();
        let ops_wg_pub = WgKey::from(*ops_publickey.as_bytes());

        let message = RouterWebsocketMessage::OperatorAddress {
            id: Identity {
                mesh_ip: ip,
                eth_address: "0x0000000000000000000000000000000000000001"
                    .parse()
                    .unwrap(),
                wg_public_key: router_wg_pub,
                nickname: None,
            },
            address: None,
            chain: crate::SystemChain::Xdai,
        };

        // router encrypts this
        let encrypted_message = message.encrypt(router_wg_pub, &router_secretkey, &ops_publickey);

        // ops decrypts this
        let decrypted_message = encrypted_message
            .decrypt(&ops_secretkey)
            .expect("Failed to decrypt router message");

        assert_eq!(message, decrypted_message);

        // now we test the ops message:
        let message = OperatorWebsocketMessage::OperatorFee(123);
        let encrypted_message = message.encrypt(ops_wg_pub, &ops_secretkey, &router_publickey);
        let decrypted_message = encrypted_message
            .decrypt(&router_secretkey, &ops_publickey)
            .expect("Failed to decrypt ops message");
        assert_eq!(message, decrypted_message);
    }
}
