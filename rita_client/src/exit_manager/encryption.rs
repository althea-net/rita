use crate::RitaClientError;
use actix_web_async::Result;
use althea_types::EncryptedExitList;
use althea_types::ExitListV2;
use althea_types::{EncryptedExitClientIdentity, EncryptedExitState};
use althea_types::{ExitClientIdentity, ExitState};
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::Nonce;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey;

pub fn encrypt_exit_client_id(
    exit_pubkey: &PublicKey,
    id: ExitClientIdentity,
) -> EncryptedExitClientIdentity {
    let network_settings = settings::get_rita_client().network;
    let our_publickey = network_settings.wg_public_key.expect("No public key?");
    let our_secretkey = network_settings
        .wg_private_key
        .expect("No private key?")
        .into();

    let plaintext = serde_json::to_string(&id)
        .expect("Failed to serialize ExitState!")
        .into_bytes();
    let nonce = box_::gen_nonce();
    let ciphertext = box_::seal(&plaintext, &nonce, exit_pubkey, &our_secretkey);

    EncryptedExitClientIdentity {
        nonce: nonce.0,
        pubkey: our_publickey,
        encrypted_exit_client_id: ciphertext,
    }
}

pub fn decrypt_exit_state(
    exit_state: EncryptedExitState,
    exit_pubkey: PublicKey,
) -> Result<ExitState, RitaClientError> {
    let rita_client = settings::get_rita_client();
    let network_settings = rita_client.network;
    let our_secretkey = network_settings
        .wg_private_key
        .expect("No private key?")
        .into();
    let ciphertext = exit_state.encrypted_exit_state;
    let nonce = Nonce(exit_state.nonce);
    let decrypted_exit_state: ExitState =
        match box_::open(&ciphertext, &nonce, &exit_pubkey, &our_secretkey) {
            Ok(decrypted_bytes) => match String::from_utf8(decrypted_bytes) {
                Ok(json_string) => match serde_json::from_str(&json_string) {
                    Ok(exit_state) => exit_state,
                    Err(e) => {
                        return Err(e.into());
                    }
                },
                Err(e) => {
                    error!("Could not deserialize exit state with {:?}", e);
                    return Err(e.into());
                }
            },
            Err(_) => {
                error!("Could not decrypt exit state");
                return Err(RitaClientError::MiscStringError(
                    "Could not decrypt exit state".to_string(),
                ));
            }
        };
    Ok(decrypted_exit_state)
}

pub fn decrypt_exit_list(
    exit_list: EncryptedExitList,
    exit_pubkey: PublicKey,
) -> Result<ExitListV2, RitaClientError> {
    let rita_client = settings::get_rita_client();
    let network_settings = rita_client.network;
    let our_secretkey = network_settings
        .wg_private_key
        .expect("No private key?")
        .into();
    let ciphertext = exit_list.exit_list;
    let nonce = Nonce(exit_list.nonce);
    let ret: ExitListV2 = match box_::open(&ciphertext, &nonce, &exit_pubkey, &our_secretkey) {
        Ok(decrypted_bytes) => match String::from_utf8(decrypted_bytes) {
            Ok(json_string) => match serde_json::from_str(&json_string) {
                Ok(ip_list) => ip_list,
                Err(e) => {
                    return Err(e.into());
                }
            },
            Err(e) => {
                error!("Could not deserialize exit state with {:?}", e);
                return Err(e.into());
            }
        },
        Err(_) => {
            error!("Could not decrypt exit state");
            return Err(RitaClientError::MiscStringError(
                "Could not decrypt exit state".to_string(),
            ));
        }
    };
    Ok(ret)
}
