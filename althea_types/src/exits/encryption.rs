//! this file contains utility functions for the exit communcaiton which requires encrypting/decrypting requests
//! to secure them as the pass over the babel network
use crate::SignedExitServerList;
use crate::WgKey;
use crypto_box::aead::Aead;
use crypto_box::aead::AeadCore;
use crypto_box::aead::OsRng;
use crypto_box::PublicKey;
use crypto_box::SalsaBox;
use crypto_box::SecretKey;
use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;

use super::EncryptedExitClientIdentity;
use super::EncryptedExitServerList;
use super::EncryptedExitState;
use super::ExitClientIdentity;
use super::ExitState;

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
    let nonce = SalsaBox::generate_nonce(&mut OsRng);
    let b = SalsaBox::new(exit_pubkey, our_secretkey);
    let ciphertext = b.encrypt(&nonce, plaintext.as_ref()).unwrap();

    EncryptedExitClientIdentity {
        nonce: nonce.into(),
        pubkey: our_publickey,
        encrypted_exit_client_id: ciphertext,
    }
}

pub fn decrypt_exit_client_id(
    val: EncryptedExitClientIdentity,
    our_secretkey: &SecretKey,
) -> Result<ExitClientIdentity, ExitEncryptionError> {
    let their_nacl_pubkey = val.pubkey.into();
    let their_nonce = val.nonce;
    let ciphertext = val.encrypted_exit_client_id;

    let b = SalsaBox::new(&their_nacl_pubkey, our_secretkey);

    let decrypted_bytes = match b.decrypt(their_nonce.as_ref().into(), ciphertext.as_ref()) {
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
    let nonce = exit_state.nonce;

    let b = SalsaBox::new(exit_pubkey, our_secretkey);

    let decrypted_exit_state: ExitState =
        match b.decrypt(nonce.as_ref().into(), ciphertext.as_ref()) {
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

pub fn encrypt_setup_return(
    ret: ExitState,
    our_secretkey: &SecretKey,
    their_pubkey: &PublicKey,
) -> EncryptedExitState {
    let plaintext = serde_json::to_string(&ret)
        .expect("Failed to serialize ExitState!")
        .into_bytes();
    let nonce = SalsaBox::generate_nonce(&mut OsRng);
    let b = SalsaBox::new(their_pubkey, our_secretkey);
    let ciphertext = b.encrypt(&nonce, plaintext.as_ref()).unwrap();
    EncryptedExitState {
        nonce: nonce.into(),
        encrypted_exit_state: ciphertext,
    }
}

impl EncryptedExitServerList {
    pub fn decrypt(
        &self,
        our_secretkey: &SecretKey,
    ) -> Result<SignedExitServerList, ExitEncryptionError> {
        let ciphertext = self.encrypted_exit_server_list.clone();
        let nonce = self.nonce;

        let b = SalsaBox::new(&self.pubkey.into(), our_secretkey);

        let ret: SignedExitServerList = match b.decrypt(nonce.as_ref().into(), ciphertext.as_ref())
        {
            Ok(decrypted_bytes) => match String::from_utf8(decrypted_bytes) {
                Ok(json_string) => match serde_json::from_str(&json_string) {
                    Ok(exit_list) => exit_list,
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
}

impl SignedExitServerList {
    pub fn encrypt(
        &self,
        our_secretkey: &SecretKey,
        their_pubkey: &PublicKey,
    ) -> EncryptedExitServerList {
        let plaintext = serde_json::to_string(&self)
            .expect("Failed to serialize ExitServerList!")
            .into_bytes();
        let nonce = SalsaBox::generate_nonce(&mut OsRng);
        let b = SalsaBox::new(their_pubkey, our_secretkey);
        let ciphertext = b.encrypt(&nonce, plaintext.as_ref()).unwrap();
        EncryptedExitServerList {
            pubkey: WgKey::from(*their_pubkey.as_bytes()),
            nonce: nonce.into(),
            encrypted_exit_server_list: ciphertext,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exits::identity::random_exit_identity;
    use crate::exits::ExitRegistrationDetails;
    use crate::ExitClientIdentity;
    use crypto_box::PublicKey;
    use crypto_box::SecretKey;
    use sodiumoxide::crypto::box_;
    use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::Nonce;
    use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey as NaclPublicKey;
    use sodiumoxide::crypto::box_::SecretKey as NaclSecretKey;

    pub fn gen_keypair() -> (PublicKey, SecretKey) {
        let secret_key = SecretKey::generate(&mut OsRng);
        let public_key = PublicKey::from(&secret_key);
        (public_key, secret_key)
    }

    /// Used to test cross compatibility with libsodium
    pub fn encrypt_exit_client_id_libsodium(
        our_publickey: WgKey,
        our_secretkey: &NaclSecretKey,
        exit_pubkey: &NaclPublicKey,
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

    pub fn decrypt_exit_client_id_libsodium(
        val: EncryptedExitClientIdentity,
        our_secretkey: &NaclSecretKey,
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

    #[test]
    fn test_encrypt_decrypt_exit_client_id() {
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

    // this test ensure that libsodium and crypto_box are compatible
    #[test]
    fn test_crypto_box_lib_sodium_cross_encrypt_decrypt() {
        let (our_pubkey, our_seckey) = (
            "aW55dFzovr/cwcOYkWyDXRoE+9etyIC+ZBbQo4gUmmc="
                .parse()
                .unwrap(),
            "cLkLyDCw+3nMu9N/FS/tzD5LBFEc9OySw1db4kBhLHI="
                .parse()
                .unwrap(),
        );
        let (exit_pubkey, exit_seckey) = (
            "w7ssizK/zKtWePycU1gKzf391awexkbi31Bsets8HVs="
                .parse()
                .unwrap(),
            "qLDPAl/IDgK5ZHmU+GH9wXThoFUuplLxFEcGcz/FMkw="
                .parse()
                .unwrap(),
        );
        let exit_pubkey: WgKey = exit_pubkey;
        let exit_seckey: WgKey = exit_seckey;
        let our_seckey: WgKey = our_seckey;
        let our_seckey_nacl: NaclSecretKey = our_seckey.into();
        let exit_seckey_nacl: NaclSecretKey = exit_seckey.into();
        let our_seckey: SecretKey = our_seckey.into();
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

        let encrypted_identity = encrypt_exit_client_id(
            our_pubkey,
            &our_seckey,
            &exit_pubkey.into(),
            identity.clone(),
        );

        let decrypted_identity =
            decrypt_exit_client_id_libsodium(encrypted_identity, &exit_seckey_nacl).unwrap();

        assert_eq!(identity, decrypted_identity);

        let encrypted_identity = encrypt_exit_client_id_libsodium(
            our_pubkey,
            &our_seckey_nacl,
            &exit_pubkey.into(),
            identity.clone(),
        );

        let decrypted_identity =
            decrypt_exit_client_id(encrypted_identity, &exit_seckey.into()).unwrap();

        assert_eq!(identity, decrypted_identity);
    }

    #[test]
    fn test_encrypt_decrypt_exit_state() {
        let (_, our_seckey) = gen_keypair();
        let (exit_pubkey, _) = gen_keypair();
        let state = ExitState::New;

        let encrypted_state = encrypt_setup_return(state.clone(), &our_seckey, &exit_pubkey);

        let decrypted_state =
            decrypt_exit_state(&our_seckey, encrypted_state, &exit_pubkey).unwrap();

        assert_eq!(state, decrypted_state);
    }
}
