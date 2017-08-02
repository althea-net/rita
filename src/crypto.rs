use types::{Bytes32, Address, PrivateKey, Uint256, Signature};
use std::collections::HashMap;

pub struct Crypto {
    keystore: HashMap<Address, PrivateKey>,
}


impl Crypto {
    pub fn new() -> Crypto {
        Crypto { keystore: HashMap::new() }
    }
    pub fn sign(&self, address: &Address, hash: &Bytes32) -> Result<Signature, String> {
        match self.keystore.get(address) {
            None => Err(String::from("Address not found in keystore.")),
            Some(pk) => Ok([0; 65]),
        }
    }
    pub fn hash(input: Vec<Bytes32>) -> Bytes32 {
        [0; 32]
    }
    pub fn verify(fingerprint: &Bytes32, signature: &Signature, address: Address) -> bool {
        true
    }
}
