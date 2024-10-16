//! this file contains the structs and functions use to sign the exit server list data as seent by the exit root of trust server
//! To do this we use ethereum style addresses and signatures to verify the data
use crate::exits::identity::ExitIdentity;
use clarity::{
    abi::{encode_tokens, AbiToken},
    utils::get_ethereum_msg_hash,
    Address, PrivateKey, Signature,
};
use std::time::SystemTime;

/// The signed payload struct from the exit root of trust server. Contains the exit list, and the contract
/// that this list contains data for and the time at which the signature was created
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct ExitServerList {
    /// The exit database smart contract this list contains data for
    pub contract: Address,
    /// The list of exits that where active on this contract at the time of creation
    pub exit_list: Vec<ExitIdentity>,
    /// The time at which this list was created
    pub created: SystemTime,
}

impl Default for ExitServerList {
    fn default() -> Self {
        ExitServerList {
            contract: Address::default(),
            exit_list: Vec::new(),
            created: SystemTime::now(),
        }
    }
}

impl ExitServerList {
    /// Returns the ExitServerList as an Ethereum ABI token
    pub fn encode_to_eth_abi_token(&self) -> AbiToken {
        AbiToken::Struct(vec![
            self.contract.into(),
            ExitIdentity::encode_array_to_eth_abi(self.exit_list.clone()).into(),
            self.created
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .into(),
        ])
    }

    /// Returns the eth abi encoded binary version of this struct
    pub fn encode_to_eth_abi(&self) -> Vec<u8> {
        encode_tokens(&[self.encode_to_eth_abi_token()])
    }

    /// Returns a signed exit server list using the provided private key
    pub fn sign(&self, key: PrivateKey) -> SignedExitServerList {
        let sig = key.sign_ethereum_msg(&self.encode_to_eth_abi());
        SignedExitServerList {
            signature: sig,
            data: self.clone(),
        }
    }

    /// Verifies a provided signature against the provided key against this exit server list
    pub fn verify(&self, key: Address, sig: Signature) -> bool {
        if sig.is_valid() {
            let hash = get_ethereum_msg_hash(&self.encode_to_eth_abi());
            match sig.recover(&hash) {
                Ok(addr) => {
                    println!("Recovered address is {:?}", addr);
                    addr == key},
                Err(_) => {
                    println!("Failed to recover address from signature");
                    false},
            }
        } else {
            println!("Signature is invalid");
            false
        }
    }
}

/// Signed format of the exit server list
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct SignedExitServerList {
    pub signature: Signature,
    pub data: ExitServerList,
}

impl SignedExitServerList {
    /// Verifies the signature on this signed exit server list
    pub fn verify(&self, key: Address) -> bool {
        self.data.verify(key, self.signature.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random_exit_identity_with_private_key;
    use rand::thread_rng;
    use rand::Rng;

    #[test]
    fn test_exit_server_list_serialization() {
        let contract: Address = "0x1234567890abcdef1234567890abcdef12345678"
            .parse()
            .unwrap();
        let exit_identity = random_exit_identity_with_private_key().0;
        let created = SystemTime::now();

        let exit_server_list = ExitServerList {
            contract,
            exit_list: vec![exit_identity],
            created,
        };

        let signed_exit_server_list = SignedExitServerList {
            signature: Signature::new(false, 0u8.into(), 0u8.into()),
            data: exit_server_list.clone(),
        };

        // Serialize the signed exit server list
        let serialized = serde_json::to_string(&signed_exit_server_list).unwrap();

        println!("{}", serialized);

        // Deserialize the serialized string back into a signed exit server list
        let deserialized: SignedExitServerList = serde_json::from_str(&serialized).unwrap();

        // Ensure that the deserialized signed exit server list matches the original one
        assert_eq!(deserialized, signed_exit_server_list);
    }

    #[test]
    fn test_signature_verification() {
        let contract: Address = "0x1234567890abcdef1234567890abcdef12345678"
            .parse()
            .unwrap();
        let (exit_identity, private_key) = random_exit_identity_with_private_key();
        let created = SystemTime::now();

        let num_extra_identities: u8 = thread_rng().gen();
        let mut exit_identities = vec![exit_identity];
        for _ in 0..num_extra_identities {
            exit_identities.push(random_exit_identity_with_private_key().0);
        }

        let exit_server_list = ExitServerList {
            contract,
            exit_list: exit_identities,
            created,
        };

        let mut signed_exit_server_list = exit_server_list.sign(private_key);

        assert!(signed_exit_server_list.verify(private_key.to_address()));

        // now we will tamper with the data and ensure that the signature fails
        signed_exit_server_list.data.created += std::time::Duration::from_secs(500);

        assert!(!signed_exit_server_list.verify(private_key.to_address()));
    }
}
