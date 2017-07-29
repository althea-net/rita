use types::{Bytes32, Address, PrivateKey, Uint256, Signature};
use std::collections::HashMap;

struct Crypto {
    keystore: HashMap<Address, PrivateKey>,
}


impl Crypto {
    pub fn sign(&self, address: &Address, hash: &Bytes32) -> Option<Bytes32> {
        match self.keystore.get(address) {
            None => None,
            Some(pk) => Some([0; 32]),
        }
    }
    pub fn hash(input: Vec<Bytes32>) -> Bytes32 {
        [0; 32]
    }
    pub fn verify(fingerprint: &Bytes32, signature: &Signature, address: Address) -> bool {
        true
    }
}
