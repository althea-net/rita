use crate::interop::default_system_chain;
use crate::regions::Regions;
use crate::wg_key::WgKey;
use crate::{Identity, SystemChain};
use clarity::Address;
use ipnetwork::IpNetwork;
use serde::Deserialize;
use sodiumoxide::crypto::box_::{self, Nonce, PublicKey};
use std::collections::HashSet;
use std::fmt::Display;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::string::FromUtf8Error;
use std::time::SystemTime;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitIdentity {
    pub mesh_ip: IpAddr,
    pub wg_key: WgKey,
    pub eth_addr: Address,
    // The port the client uses to query exit endpoints
    pub registration_port: u16,
    // The port the clients uses for exit wg tunnel setup
    pub wg_exit_listen_port: u16,
    pub allowed_regions: HashSet<Regions>,
    pub payment_types: HashSet<SystemChain>,
}

// Custom hash implementation that also ignores nickname. There should be no collding exits with
// the same mesh, wgkey and ethaddr
impl Hash for ExitIdentity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.mesh_ip.hash(state);
        self.eth_addr.hash(state);
        self.wg_key.hash(state);
    }
}

pub fn exit_identity_to_id(exit_id: ExitIdentity) -> Identity {
    Identity {
        mesh_ip: exit_id.mesh_ip,
        eth_address: exit_id.eth_addr,
        wg_public_key: exit_id.wg_key,
        nickname: None,
    }
}

/// An exit's unix time stamp that can be queried by a downstream router
/// Many routers have no built in clock and need to set their time at boot
/// in order for wireguard tunnels to work correctly
#[derive(Debug, Serialize, Deserialize)]
pub struct ExitSystemTime {
    pub system_time: SystemTime,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash, Default)]
pub struct ExitRegistrationDetails {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub email_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub phone_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sequence_number: Option<u32>,
}

/// This is the state an exit can be in
#[derive(Default, Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
#[serde(tag = "state")]
pub enum ExitState {
    /// the default state of the struct in the config
    #[default]
    New,
    /// we have successfully contacted the exit and gotten basic info. This is
    /// kept around for backwards compatitbility, it should be removed once all clients are
    /// updated
    GotInfo {
        general_details: ExitDetails,
        message: String,
    },
    /// We are awaiting user action to enter the phone or email code
    Pending {
        general_details: ExitDetails,
        message: String,
        #[serde(default)]
        email_code: Option<String>,
        phone_code: Option<String>,
    },
    /// we are currently registered and operating, update this state
    /// incase the exit for example wants to assign us a new ip
    Registered {
        general_details: ExitDetails,
        our_details: ExitClientDetails,
        message: String,
    },
    /// we have been denied
    Denied { message: String },
}

impl ExitState {
    pub fn general_details(&self) -> Option<&ExitDetails> {
        match *self {
            ExitState::GotInfo {
                ref general_details,
                ..
            } => Some(general_details),
            ExitState::Pending {
                ref general_details,
                ..
            } => Some(general_details),
            ExitState::Registered {
                ref general_details,
                ..
            } => Some(general_details),
            _ => None,
        }
    }

    pub fn our_details(&self) -> Option<&ExitClientDetails> {
        match *self {
            ExitState::Registered {
                ref our_details, ..
            } => Some(our_details),
            _ => None,
        }
    }

    pub fn message(&self) -> String {
        match *self {
            ExitState::New => "New exit".to_string(),
            ExitState::GotInfo { ref message, .. } => message.clone(),
            ExitState::Pending { ref message, .. } => message.clone(),
            ExitState::Registered { ref message, .. } => message.clone(),
            ExitState::Denied { ref message, .. } => message.clone(),
        }
    }
}

/// This is all the data we need to send to an exit, for our registration or update
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct ExitRegistrationIdentity {
    pub wg_port: u16,
    pub global: Identity,
    pub reg_details: ExitRegistrationDetails,
}

/// Wrapper for secure box containing an exit client identity
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct EncryptedExitRegistrationIdentity {
    pub pubkey: WgKey,
    pub nonce: [u8; 24],
    pub encrypted_exit_client_id: Vec<u8>,
}

/// A simple mesasge wrapper for authentication only, wrapping a WgKey type
/// this is for requests to the exit where the responses should be authenticated
/// but that do not require any other request payload
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct EncryptedAuthMessage {
    pub pubkey: WgKey,
    pub nonce: [u8; 24],
    pub encrypted_wg_key: Vec<u8>,
}

/// Wrapper for secure box containing an exit state
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct EncryptedExitState {
    pub nonce: [u8; 24],
    pub encrypted_exit_state: Vec<u8>,
}

/// Wrapper for secure box containing a list of ips
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct EncryptedExitList {
    pub nonce: [u8; 24],
    pub exit_list: Vec<u8>,
}

/// Struct returned when hitting exit_list endpoint
#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct ExitList {
    pub exit_list: Vec<Identity>,
    // All exits in a cluster listen on same port
    pub wg_exit_listen_port: u16,
}

/// Struct returned when hitting exit_list_V2 endpoint
#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct ExitListV2 {
    pub exit_list: Vec<ExitIdentity>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ExitVerifMode {
    Phone,
    Email,
    Off,
}

fn default_verif_mode() -> ExitVerifMode {
    ExitVerifMode::Off
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct ExitDetails {
    pub server_mesh_ip: IpAddr,
    pub server_wg_pubkey: WgKey,
    pub server_internal_ip: IpAddr,
    pub netmask: u8,
    pub wg_exit_port: u16,
    pub exit_price: u64,
    #[serde(default = "default_system_chain")]
    pub exit_currency: SystemChain,
    pub description: String,
    #[serde(default = "default_verif_mode")]
    pub verif_mode: ExitVerifMode,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
pub struct ExitClientDetails {
    pub client_internal_ip: IpAddr,
    pub internet_ipv6_subnet: Option<IpNetwork>,
}

/// Operator update that we get from the operator server during our checkin
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OperatorExitUpdateMessage {
    /// List of routers for this exit to register
    pub to_register: Vec<ExitRegistrationIdentity>,
}

#[derive(Debug)]
pub enum ExitMessageEncryptionError {
    FromUtf8Error(FromUtf8Error),
    SerdeJsonError(serde_json::Error),
    DecryptionError,
}

impl Display for ExitMessageEncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExitMessageEncryptionError::FromUtf8Error(e) => write!(f, "FromUtf8Error: {}", e),
            ExitMessageEncryptionError::SerdeJsonError(e) => write!(f, "SerdeJsonError: {}", e),
            ExitMessageEncryptionError::DecryptionError => write!(f, "DecryptionError"),
        }
    }
}

impl From<FromUtf8Error> for ExitMessageEncryptionError {
    fn from(error: FromUtf8Error) -> Self {
        ExitMessageEncryptionError::FromUtf8Error(error)
    }
}

impl From<serde_json::Error> for ExitMessageEncryptionError {
    fn from(error: serde_json::Error) -> Self {
        ExitMessageEncryptionError::SerdeJsonError(error)
    }
}

/// Decrypts an encrypted exit list
pub fn decrypt_exit_list(
    exit_list: EncryptedExitList,
    exit_pubkey: PublicKey,
    our_secretkey: &box_::SecretKey,
) -> Result<ExitListV2, ExitMessageEncryptionError> {
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
                return Err(e.into());
            }
        },
        Err(_) => {
            return Err(ExitMessageEncryptionError::DecryptionError);
        }
    };
    Ok(ret)
}

/// Encrypts a provided exit list
pub fn encrypt_exit_list(
    exit_list: ExitListV2,
    their_pubkey: PublicKey,
    our_secretkey: &box_::SecretKey,
) -> EncryptedExitList {
    let plaintext = serde_json::to_string(&exit_list)
        .expect("Failed to serialize ExitList!")
        .into_bytes();
    let nonce = box_::gen_nonce();
    let ciphertext = box_::seal(&plaintext, &nonce, &their_pubkey, our_secretkey);

    EncryptedExitList {
        nonce: nonce.0,
        exit_list: ciphertext,
    }
}

/// Decrypts an encrypted exit state
pub fn decrypt_exit_state(
    exit_state: EncryptedExitState,
    exit_pubkey: PublicKey,
    our_secretkey: &box_::SecretKey,
) -> Result<ExitState, ExitMessageEncryptionError> {
    let ciphertext = exit_state.encrypted_exit_state;
    let nonce = Nonce(exit_state.nonce);
    let decrypted_exit_state: ExitState =
        match box_::open(&ciphertext, &nonce, &exit_pubkey, &our_secretkey) {
            Ok(decrypted_bytes) => match String::from_utf8(decrypted_bytes) {
                Ok(json_string) => match serde_json::from_str(&json_string) {
                    Ok(exit_state) => exit_state,
                    Err(e) => {
                        return Err(ExitMessageEncryptionError::from(e));
                    }
                },
                Err(e) => {
                    return Err(ExitMessageEncryptionError::from(e));
                }
            },
            Err(_) => {
                return Err(ExitMessageEncryptionError::DecryptionError);
            }
        };
    Ok(decrypted_exit_state)
}

/// Encrypts a provided exit state
pub fn encrypt_exit_state(
    exit_state: ExitState,
    their_pubkey: PublicKey,
    our_secretkey: &box_::SecretKey,
) -> EncryptedExitState {
    let plaintext = serde_json::to_string(&exit_state)
        .expect("Failed to serialize ExitState!")
        .into_bytes();
    let nonce = box_::gen_nonce();
    let ciphertext = box_::seal(&plaintext, &nonce, &their_pubkey, our_secretkey);

    EncryptedExitState {
        nonce: nonce.0,
        encrypted_exit_state: ciphertext,
    }
}

pub fn encrypt_exit_registration_id(
    exit_pubkey: &PublicKey,
    id: ExitRegistrationIdentity,
    our_secretkey: &box_::SecretKey,
) -> EncryptedExitRegistrationIdentity {
    let plaintext = serde_json::to_string(&id)
        .expect("Failed to serialize ExitState!")
        .into_bytes();
    let nonce = box_::gen_nonce();
    let ciphertext = box_::seal(&plaintext, &nonce, exit_pubkey, &our_secretkey);

    EncryptedExitRegistrationIdentity {
        nonce: nonce.0,
        pubkey: id.global.wg_public_key,
        encrypted_exit_client_id: ciphertext,
    }
}

pub fn decrypt_exit_registration_id(
    val: EncryptedExitRegistrationIdentity,
    our_secretkey: &box_::SecretKey,
) -> Result<ExitRegistrationIdentity, ExitMessageEncryptionError> {
    let their_nacl_pubkey = val.pubkey.into();
    let their_nonce = Nonce(val.nonce);
    let ciphertext = val.encrypted_exit_client_id;

    let decrypted_bytes =
        match box_::open(&ciphertext, &their_nonce, &their_nacl_pubkey, our_secretkey) {
            Ok(value) => value,
            Err(_) => {
                return Err(ExitMessageEncryptionError::DecryptionError);
            }
        };

    let decrypted_string = match String::from_utf8(decrypted_bytes) {
        Ok(value) => value,
        Err(_) => {
            return Err(ExitMessageEncryptionError::DecryptionError);
        }
    };

    let decrypted_id = match serde_json::from_str(&decrypted_string) {
        Ok(value) => value,
        Err(_) => {
            return Err(ExitMessageEncryptionError::DecryptionError);
        }
    };

    Ok(decrypted_id)
}
#[cfg(test)]
mod tests {
    use super::*;

    pub struct TestWgKeypair {
        pub public: WgKey,
        pub private: WgKey,
    }

    fn get_test_key_a() -> TestWgKeypair {
        TestWgKeypair {
            private: "ABnAZPHMTpJzWfu5Xw6yAeJlKxeR8au8Q7HEwQT5Z2s="
                .parse()
                .unwrap(),
            public: "Cl+k3xrldb1JQsN8BnysvBWvCCkkGreNObjfLP27NXw="
                .parse()
                .unwrap(),
        }
    }
    fn get_test_key_b() -> TestWgKeypair {
        TestWgKeypair {
            private: "SGTR7qoC6XYM/HHom+h46FJIupyzm0nv1Ehz47aIBkc="
                .parse()
                .unwrap(),
            public: "y/xPzlZ5L6finF+VKNyATafQrn5KSuom9YM+f1d9j0Y="
                .parse()
                .unwrap(),
        }
    }

    /// generates a random identity, never use in production, your money will be stolen
    fn random_identity() -> Identity {
        use clarity::PrivateKey;

        let secret: [u8; 32] = rand::random();
        let mut ip: [u8; 16] = [0; 16];
        ip.copy_from_slice(&secret[0..16]);

        // the starting location of the funds
        let eth_key = PrivateKey::from_bytes(secret).unwrap();
        let eth_address = eth_key.to_address();

        Identity {
            mesh_ip: ip.into(),
            eth_address,
            wg_public_key: secret.into(),
            nickname: None,
        }
    }

    #[test]
    fn test_encrypt_decrypt_exit_registration_id() {
        let mut client_identity = random_identity();
        let mut exit_identity = random_identity();
        client_identity.wg_public_key = get_test_key_a().public;
        exit_identity.wg_public_key = get_test_key_b().public;

        // Create a sample ExitRegistrationIdentity
        let exit_registration_id = ExitRegistrationIdentity {
            wg_port: 55,
            global: client_identity.clone(),
            reg_details: ExitRegistrationDetails {
                email: None,
                email_code: None,
                phone: None,
                phone_code: None,
                sequence_number: None,
            },
        };

        // Encrypt the ExitRegistrationIdentity
        let encrypted_exit_registration_id = encrypt_exit_registration_id(
            &exit_identity.wg_public_key.into(),
            exit_registration_id.clone(),
            &get_test_key_a().private.into(),
        );

        // Decrypt the encrypted ExitRegistrationIdentity
        let decrypted_exit_registration_id = decrypt_exit_registration_id(
            encrypted_exit_registration_id,
            &get_test_key_b().private.into(),
        )
        .unwrap();

        // Check if the decrypted ExitRegistrationIdentity matches the original one
        assert_eq!(exit_registration_id, decrypted_exit_registration_id);
    }

    #[test]
    fn test_encrypt_decrypt_exit_state() {
        // Create a sample ExitState
        let exit_state = ExitState::New;

        // Encrypt the ExitState
        let encrypted_exit_state = encrypt_exit_state(
            exit_state.clone(),
            get_test_key_b().public.into(),
            &get_test_key_a().private.into(),
        );

        // Decrypt the encrypted ExitState
        let decrypted_exit_state = decrypt_exit_state(
            encrypted_exit_state,
            get_test_key_a().public.into(),
            &get_test_key_b().private.into(),
        ).unwrap();

        // Check if the decrypted ExitState matches the original one
        assert_eq!(exit_state, decrypted_exit_state);
    }

    #[test]
    fn test_encrypt_decrypt_exit_list() {
        // Create a sample ExitList
        let exit_list = ExitListV2 {
            exit_list: vec![],
        };

        // Encrypt the ExitList
        let encrypted_exit_list = encrypt_exit_list(
            exit_list.clone(),
            get_test_key_b().public.into(),
            &get_test_key_a().private.into(),
        );

        // Decrypt the encrypted ExitList
        let decrypted_exit_list = decrypt_exit_list(
            encrypted_exit_list,
            get_test_key_a().public.into(),
            &get_test_key_b().private.into(),
        ).unwrap();

        // Check if the decrypted ExitState matches the original one
        assert_eq!(exit_list, decrypted_exit_list);
    }
}
