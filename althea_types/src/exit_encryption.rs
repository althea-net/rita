//! this file contains utility functions for the exit communcaiton which requires encrypting/decrypting requests
//! to secure them as the pass over the babel network
use crate::EncryptedExitList;
use crate::ExitList;
use crate::ExitListV2;
use crate::WgKey;
use crate::{EncryptedExitClientIdentity, EncryptedExitState};
use crate::{ExitClientIdentity, ExitState};
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::Nonce;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey;
use sodiumoxide::crypto::box_::SecretKey;
use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;

#[derive(Debug, Clone)]
pub enum ExitEncryptionError {
    ExitStateDecryptionError { e: String },
    ExitClientIdDecryptionError { e: String },
    ExitListDecryptionError { e: String },
    Utf8Error { e: String },
    SerdeError { e: String },
}

impl Display for ExitEncryptionError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            ExitEncryptionError::ExitStateDecryptionError { e } => {
                write!(f, "Failed to decrypt exit state: {}", e)
            }
            ExitEncryptionError::ExitListDecryptionError { e } => {
                write!(f, "Failed to decrypt exit list: {}", e)
            }
            ExitEncryptionError::Utf8Error { e } => {
                write!(f, "UTF-8 conversion error: {}", e)
            }
            ExitEncryptionError::SerdeError { e } => {
                write!(f, "Serialization/Deserialization error: {}", e)
            }
            ExitEncryptionError::ExitClientIdDecryptionError { e } => {
                write!(f, "Failed to decrypt exit client id: {}", e)
            }
        }
    }
}

pub fn encrypt_exit_client_id(
    our_publickey: WgKey,
    our_secretkey: &SecretKey,
    exit_pubkey: &PublicKey,
    id: ExitClientIdentity,
) -> EncryptedExitClientIdentity {
    let plaintext = serde_json::to_string(&id)
        .expect("Failed to serialize ExitState!")
        .into_bytes();
    let nonce = box_::gen_nonce();
    let ciphertext = box_::seal(&plaintext, &nonce, exit_pubkey, our_secretkey);

    EncryptedExitClientIdentity {
        nonce: nonce.0,
        pubkey: our_publickey,
        encrypted_exit_client_id: ciphertext,
    }
}

pub fn decrypt_exit_client_id(
    val: EncryptedExitClientIdentity,
    our_secretkey: &SecretKey,
) -> Result<ExitClientIdentity, ExitEncryptionError> {
    let their_nacl_pubkey = val.pubkey.into();
    let their_nonce = Nonce(val.nonce);
    let ciphertext = val.encrypted_exit_client_id;

    let decrypted_bytes =
        match box_::open(&ciphertext, &their_nonce, &their_nacl_pubkey, our_secretkey) {
            Ok(value) => value,
            Err(_) => {
                return Err(ExitEncryptionError::ExitClientIdDecryptionError {
                    e: "Cloud not decrypt exit client id".to_string(),
                });
            }
        };

    let decrypted_string = match String::from_utf8(decrypted_bytes) {
        Ok(value) => value,
        Err(e) => {
            return Err(ExitEncryptionError::Utf8Error { e: e.to_string() });
        }
    };

    let decrypted_id = match serde_json::from_str(&decrypted_string) {
        Ok(value) => value,
        Err(e) => {
            return Err(ExitEncryptionError::SerdeError { e: e.to_string() });
        }
    };

    Ok(decrypted_id)
}

pub fn decrypt_exit_state(
    our_secretkey: &SecretKey,
    exit_state: EncryptedExitState,
    exit_pubkey: &PublicKey,
) -> Result<ExitState, ExitEncryptionError> {
    let ciphertext = exit_state.encrypted_exit_state;
    let nonce = Nonce(exit_state.nonce);
    let decrypted_exit_state: ExitState =
        match box_::open(&ciphertext, &nonce, exit_pubkey, our_secretkey) {
            Ok(decrypted_bytes) => match String::from_utf8(decrypted_bytes) {
                Ok(json_string) => match serde_json::from_str(&json_string) {
                    Ok(exit_state) => exit_state,
                    Err(e) => {
                        return Err(ExitEncryptionError::SerdeError { e: e.to_string() });
                    }
                },
                Err(e) => {
                    return Err(ExitEncryptionError::Utf8Error { e: e.to_string() });
                }
            },
            Err(_) => {
                return Err(ExitEncryptionError::ExitStateDecryptionError {
                    e: "Could not decrypt exit state".to_string(),
                });
            }
        };
    Ok(decrypted_exit_state)
}

pub fn decrypt_exit_list(
    our_secretkey: &SecretKey,
    exit_list: EncryptedExitList,
    exit_pubkey: &PublicKey,
) -> Result<ExitListV2, ExitEncryptionError> {
    let ciphertext = exit_list.exit_list;
    let nonce = Nonce(exit_list.nonce);
    let ret: ExitListV2 = match box_::open(&ciphertext, &nonce, exit_pubkey, our_secretkey) {
        Ok(decrypted_bytes) => match String::from_utf8(decrypted_bytes) {
            Ok(json_string) => match serde_json::from_str(&json_string) {
                Ok(ip_list) => ip_list,
                Err(e) => {
                    return Err(ExitEncryptionError::SerdeError { e: e.to_string() });
                }
            },
            Err(e) => {
                return Err(ExitEncryptionError::Utf8Error { e: e.to_string() });
            }
        },
        Err(_) => {
            return Err(ExitEncryptionError::ExitListDecryptionError {
                e: "Could not decrypt exit list".to_string(),
            });
        }
    };
    Ok(ret)
}

pub fn encrypt_setup_return(
    ret: ExitState,
    our_secretkey: &SecretKey,
    their_pubkey: PublicKey,
) -> EncryptedExitState {
    let plaintext = serde_json::to_string(&ret)
        .expect("Failed to serialize ExitState!")
        .into_bytes();
    let nonce = box_::gen_nonce();
    let ciphertext = box_::seal(&plaintext, &nonce, &their_pubkey, our_secretkey);
    EncryptedExitState {
        nonce: nonce.0,
        encrypted_exit_state: ciphertext,
    }
}

pub fn encrypt_exit_list_v2(
    ret: &ExitListV2,
    our_secretkey: &SecretKey,
    their_pubkey: &PublicKey,
) -> EncryptedExitList {
    let plaintext = serde_json::to_string(&ret)
        .expect("Failed to serialize ExitList!")
        .into_bytes();
    let nonce = box_::gen_nonce();
    let ciphertext = box_::seal(&plaintext, &nonce, their_pubkey, our_secretkey);
    EncryptedExitList {
        nonce: nonce.0,
        exit_list: ciphertext,
    }
}

pub fn encrypt_exit_list(
    ret: &ExitList,
    our_secretkey: &SecretKey,
    their_pubkey: &PublicKey,
) -> EncryptedExitList {
    let plaintext = serde_json::to_string(&ret)
        .expect("Failed to serialize ExitList!")
        .into_bytes();
    let nonce = box_::gen_nonce();
    let ciphertext = box_::seal(&plaintext, &nonce, their_pubkey, our_secretkey);
    EncryptedExitList {
        nonce: nonce.0,
        exit_list: ciphertext,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ExitIdentity;
    use crate::ExitRegistrationDetails;
    use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::gen_keypair;
    use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::SecretKey;
    use std::collections::HashSet;

    /// generates a random identity, never use in production, your money will be stolen
    pub fn random_exit_identity() -> ExitIdentity {
        use clarity::PrivateKey;

        let secret: [u8; 32] = rand::random();
        let mut ip: [u8; 16] = [0; 16];
        ip.copy_from_slice(&secret[0..16]);

        // the starting location of the funds
        let eth_key = PrivateKey::from_bytes(secret).unwrap();
        let eth_address = eth_key.to_address();

        let payment_types = HashSet::new();
        let allowed_regions = HashSet::new();

        ExitIdentity {
            mesh_ip: ip.into(),
            eth_addr: eth_address,
            wg_key: secret.into(),
            registration_port: 0,
            wg_exit_listen_port: 0,
            allowed_regions,
            payment_types,
        }
    }

    #[test]
    fn test_encrypt_decrypt_exit_client_id() {
        sodiumoxide::init().unwrap();

        let (our_pubkey, our_seckey) = (
            "aW55dFzovr/cwcOYkWyDXRoE+9etyIC+ZBbQo4gUmmc="
                .parse()
                .unwrap(),
            "cLkLyDCw+3nMu9N/FS/tzD5LBFEc9OySw1db4kBhLHI="
                .parse()
                .unwrap(),
        );
        let our_seckey: WgKey = our_seckey;
        let our_seckey: SecretKey = our_seckey.into();
        let (exit_pubkey, exit_seckey) = gen_keypair();
        let identity = ExitClientIdentity {
            wg_port: 42,
            global: random_exit_identity().into(),
            reg_details: ExitRegistrationDetails {
                email: None,
                email_code: None,
                phone: None,
                phone_code: None,
                sequence_number: None,
            },
        };

        let encrypted_identity =
            encrypt_exit_client_id(our_pubkey, &our_seckey, &exit_pubkey, identity.clone());

        let decrypted_identity = decrypt_exit_client_id(encrypted_identity, &exit_seckey).unwrap();

        assert_eq!(identity, decrypted_identity);
    }

    #[test]
    fn test_encrypt_decrypt_exit_state() {
        sodiumoxide::init().unwrap();

        let (_, our_seckey) = gen_keypair();
        let (exit_pubkey, _) = gen_keypair();
        let state = ExitState::New;

        let encrypted_state = encrypt_setup_return(state.clone(), &our_seckey, exit_pubkey);

        let decrypted_state =
            decrypt_exit_state(&our_seckey, encrypted_state, &exit_pubkey).unwrap();

        assert_eq!(state, decrypted_state);
    }

    #[test]
    fn test_encrypt_decrypt_exit_list() {
        sodiumoxide::init().unwrap();

        let (our_pubkey, our_seckey) = gen_keypair();
        let (exit_pubkey, exit_seckey) = gen_keypair();
        let list = ExitList {
            exit_list: Vec::new(),
            wg_exit_listen_port: 42,
        };

        let encrypted_list = encrypt_exit_list(&list, &our_seckey, &exit_pubkey);
        let nonce = Nonce(encrypted_list.nonce);

        let decrypted_list_bytes =
            box_::open(&encrypted_list.exit_list, &nonce, &our_pubkey, &exit_seckey).unwrap();
        let decrypted_list: ExitList = serde_json::from_slice(&decrypted_list_bytes).unwrap();

        assert_eq!(list, decrypted_list);
    }

    #[test]
    fn test_encrypt_decrypt_exit_list_v2() {
        sodiumoxide::init().unwrap();

        let (_, our_seckey) = gen_keypair();
        let (exit_pubkey, _) = gen_keypair();
        let list_v2 = ExitListV2 {
            exit_list: Vec::new(),
        };

        let encrypted_list_v2 = encrypt_exit_list_v2(&list_v2, &our_seckey, &exit_pubkey);

        let decrypted_list_v2 =
            decrypt_exit_list(&our_seckey, encrypted_list_v2, &exit_pubkey).unwrap();

        assert_eq!(list_v2, decrypted_list_v2);
    }
}
