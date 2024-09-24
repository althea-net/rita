//! This file handles encryption and decryption of websocket related data types (all data
//! sent to ops tools from a router)

use std::fmt::Display;

use crypto_box::{
    aead::{Aead, AeadCore},
    PublicKey, SalsaBox, SecretKey,
};
use rand::rngs::OsRng;

use crate::WgKey;

use super::{
    EncryptedOpsWebsocketMessage, EncryptedRouterWebsocketMessage, OperatorWebsocketMessage,
    RouterWebsocketMessage,
};

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

pub fn encrypt_router_websocket_msg(
    our_publickey: WgKey,
    our_secretkey: &SecretKey,
    ops_pubkey: &PublicKey,
    message: RouterWebsocketMessage,
) -> EncryptedRouterWebsocketMessage {
    let plaintext = serde_json::to_string(&message)
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

pub fn decrypt_router_websocket_msg(
    our_secretkey: &SecretKey,
    message: EncryptedRouterWebsocketMessage,
) -> Result<RouterWebsocketMessage, WebsocketEncryptionError> {
    let their_nacl_pubkey = PublicKey::from(message.pubkey);
    let their_nonce = message.nonce;
    let ciphertext = message.encrypted_router_websocket_msg;
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

/// This message goes from ops to the router
pub fn encrypt_ops_websocket_msg(
    our_publickey: WgKey,
    our_secretkey: &SecretKey,
    their_publickey: &PublicKey,
    message: OperatorWebsocketMessage,
) -> EncryptedOpsWebsocketMessage {
    let plaintext = serde_json::to_string(&message)
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

pub fn decrypt_ops_websocket_msg(
    our_secretkey: &SecretKey,
    ops_publickey: &PublicKey,
    message: EncryptedOpsWebsocketMessage,
) -> Result<OperatorWebsocketMessage, WebsocketEncryptionError> {
    let nonce = message.nonce;
    let ciphertext = message.encrypted_ops_websocket_msg;
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

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use crate::{
        websockets::{
            encryption::{decrypt_ops_websocket_msg, encrypt_ops_websocket_msg},
            OperatorWebsocketMessage, RouterWebsocketMessage,
        },
        Identity, WgKey,
    };

    // test encryption and decryption of router messages
    #[test]
    fn test_router_encryption() {
        use crate::websockets::encryption::{
            decrypt_router_websocket_msg, encrypt_router_websocket_msg,
        };
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
        let encrypted_message = encrypt_router_websocket_msg(
            router_wg_pub,
            &router_secretkey,
            &ops_publickey,
            message.clone(),
        );

        // ops decrypts this
        let decrypted_message = decrypt_router_websocket_msg(&ops_secretkey, encrypted_message)
            .expect("Failed to decrypt router message");

        assert_eq!(message, decrypted_message);

        // now we test the ops message:
        let message = OperatorWebsocketMessage::OperatorFee(123);
        let encrypted_message = encrypt_ops_websocket_msg(
            ops_wg_pub,
            &ops_secretkey,
            &router_publickey,
            message.clone(),
        );
        let decrypted_message =
            decrypt_ops_websocket_msg(&router_secretkey, &ops_publickey, encrypted_message)
                .expect("Failed to decrypt ops message");
        assert_eq!(message, decrypted_message);
    }
}
