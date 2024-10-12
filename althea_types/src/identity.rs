use crate::error::AltheaTypesError;
use crate::wg_key::WgKey;
use arrayvec::ArrayString;
use clarity::abi::encode_tokens;
use clarity::abi::AbiToken;
use clarity::Address;
use deep_space::Address as AltheaAddress;
use num256::Uint256;
use serde::Deserialize;
use serde::Serialize;
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::fmt::Display;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::net::Ipv6Addr;

/// The EVM integer size
pub const WORD_SIZE: usize = 32;

/// This function takes a flat byte vector `input` and divides it into chunks of a specified
/// word size (`WORD_SIZE`). Each chunk is then converted into a separate vector of bytes,
/// resulting in a vector of EVM words.
pub fn to_evm_words(input: Vec<u8>) -> Vec<Vec<u8>> {
    input.chunks(WORD_SIZE).map(|i| i.to_vec()).collect()
}

/// This is all the data we need to give a neighbor to open a wg connection
/// this is also known as a "hello" packet or message
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
pub struct LocalIdentity {
    pub wg_port: u16,
    pub have_tunnel: Option<bool>, // If we have an existing tunnel, None if we don't know
    pub global: Identity,
}

/// Unique identifier for an Althea node
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct Identity {
    pub mesh_ip: IpAddr,
    pub eth_address: Address,
    pub wg_public_key: WgKey,
    pub nickname: Option<ArrayString<32>>,
}

impl Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.nickname {
            Some(nick) => {
                write!(
                f,
                "nickname: {}, mesh_ip: {}, eth_address: {}, althea_address: {:?}, wg_pubkey {}",
                nick, self.mesh_ip, self.eth_address, self.get_althea_address(), self.wg_public_key
            )
            }
            None => write!(
                f,
                "mesh_ip: {}, eth_address: {}, althea_address: {:?}, wg_pubkey {}",
                self.mesh_ip,
                self.eth_address,
                self.get_althea_address(),
                self.wg_public_key
            ),
        }
    }
}

pub const ALTHEA_PREFIX: &str = "althea";

impl Identity {
    pub fn new(
        mesh_ip: IpAddr,
        eth_address: Address,
        wg_public_key: WgKey,
        nickname: Option<ArrayString<32>>,
    ) -> Identity {
        Identity {
            mesh_ip,
            eth_address,
            wg_public_key,
            nickname,
        }
    }

    /// Returns true if this identity is converged, meaning the Althea address is
    /// derived from and is interchangeable with the ETH address. If false we have
    /// to avoid assumptions avoid these being the same private key
    pub fn get_althea_address(&self) -> AltheaAddress {
        AltheaAddress::from_slice(self.eth_address.as_bytes(), ALTHEA_PREFIX).unwrap()
    }

    pub fn get_hash(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }

    pub fn get_hash_array(&self) -> [u8; 8] {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        let bits = hasher.finish();
        bits.to_be_bytes()
    }

    /// Returns the Identity in it's Ethereum ABI encoded form
    /// as used by the exit registration smart contract
    pub fn encode_to_eth_abi(&self) -> Vec<u8> {
        encode_tokens(&[self.encode_to_eth_abi_token()])
    }

    /// Returns the identity as an AbiToken type, this can be easily combined
    /// with other AbiToken types to create more complex structures or simply serialized
    /// using the encode_tokens function.
    pub fn encode_to_eth_abi_token(&self) -> AbiToken {
        let ip_bytes = match self.mesh_ip {
            IpAddr::V4(v4) => {
                let mut octets = [0; 16];
                octets[0..4].copy_from_slice(&v4.octets());
                octets
            }
            IpAddr::V6(v6) => v6.octets(),
        };
        AbiToken::Struct(vec![
            AbiToken::Uint(u128::from_be_bytes(ip_bytes).into()),
            AbiToken::Uint(self.wg_public_key.into()),
            AbiToken::Address(self.eth_address),
        ])
    }

    /// Returns an array of identities in their Ethereum ABI encoded form
    pub fn encode_array_to_eth_abi(identities: Vec<Identity>) -> Vec<u8> {
        let mut tokens = vec![];
        for id in identities {
            tokens.push(id.encode_to_eth_abi_token());
        }
        encode_tokens(&[AbiToken::Dynamic(tokens)])
    }

    /// Decodes an Identity from it's Ethereum ABI encoded form
    pub fn decode_from_eth_abi(input: Vec<u8>) -> Result<Self, AltheaTypesError> {
        let byte_chunks = to_evm_words(input);

        // A correct input should have only 3 lines for each entry of the id struct, anything else we return an error
        if byte_chunks.len() != 3 {
            return Err(AltheaTypesError::BadEthAbiInput(format!(
            "Received byte chunks: {byte_chunks:?}. Expected only 3 lines for meship, wgkey and ethaddress"
        )));
        }

        let mut index = 0;
        // 1st entry is the mes ip as a u128
        let mesh_ip: u128 = u128::from_be_bytes(match byte_chunks.get(index) {
            Some(a) => match a[16..32].try_into() {
                Ok(a) => a,
                Err(e) => {
                    return Err(AltheaTypesError::BadEthAbiInput(format!(
                        "Why cant we get [u8; 16]? {byte_chunks:?}. Error is {e}"
                    )))
                }
            },
            None => {
                return Err(AltheaTypesError::BadEthAbiInput(format!(
                    "Cant meship with byte chunks {byte_chunks:?}"
                )))
            }
        });

        if mesh_ip == 0 {
            return Err(AltheaTypesError::BadEthAbiInput(format!(
                "Recived a null output {byte_chunks:?}."
            )));
        }

        let mesh_ip = IpAddr::V6(Ipv6Addr::from(mesh_ip));

        // 2nd entry is the wg key as Uint256
        index += 1;
        let wg_public_key: WgKey = Uint256::from_be_bytes(match byte_chunks.get(index) {
            Some(a) => a,
            None => {
                return Err(AltheaTypesError::BadEthAbiInput(format!(
                    "Cant wg key with byte chunks {byte_chunks:?}"
                )))
            }
        })
        .into();

        // 3rd entry is the eth address
        index += 1;
        let eth_address: Address = match Address::from_slice(match byte_chunks.get(index) {
            Some(a) => {
                if a.len() < 32 {
                    return Err(AltheaTypesError::BadEthAbiInput(format!(
                        "Cant eth address with byte chunks {byte_chunks:?}"
                    )));
                }
                &a[12..]
            }
            None => {
                return Err(AltheaTypesError::BadEthAbiInput(format!(
                    "Cant eth address with byte chunks {byte_chunks:?}"
                )))
            }
        }) {
            Ok(a) => a,
            Err(e) => {
                return Err(AltheaTypesError::BadEthAbiInput(format!(
                    "Cant parse eth address with byte chunks {byte_chunks:?} with err {e}"
                )))
            }
        };

        Ok(Identity {
            mesh_ip,
            eth_address,
            wg_public_key,
            nickname: None,
        })
    }

    /// Decode an abi encoded array of identities
    pub fn decode_array_from_eth_abi(bytes: Vec<u8>) -> Result<Vec<Self>, AltheaTypesError> {
        const IDENTITY_SIZE: usize = 3 * WORD_SIZE;
        let mut ret = vec![];
        let byte_chunks = to_evm_words(bytes.clone());

        // An empty list, the first word has a type identifier, the second is empty
        if byte_chunks.len() == 2 {
            return Ok(vec![]);
        }

        // A valid array with 1 entry has 5 lines. An empty list has 2 lines
        if byte_chunks.len() < 5 {
            return Err(AltheaTypesError::BadEthAbiInput(format!(
                "Received byte chunks: {byte_chunks:?}"
            )));
        }

        let num_entries: usize =
            usize::from_be_bytes(match byte_chunks[1][24..WORD_SIZE].try_into() {
                Ok(a) => a,
                Err(e) => {
                    let msg = format!("Cannot parse array len with {}", e);
                    return Err(AltheaTypesError::BadEthAbiInput(msg));
                }
            });

        for i in 0..num_entries {
            let start_index = 2 * WORD_SIZE + i * IDENTITY_SIZE;
            if start_index + IDENTITY_SIZE > bytes.len() {
                return Err(AltheaTypesError::BadEthAbiInput(format!(
                    "Improper encoding, not enough bytes left to decode entry {}",
                    i,
                )));
            }
            // start index is computed from the front of the array, so one word is consumed by the
            // struct header, then another with the length of the array of offsets, then each offset
            // is a word representing the number of words to the start of the offset list to the struct!
            match Identity::decode_from_eth_abi(
                bytes[start_index..start_index + IDENTITY_SIZE].to_vec(),
            ) {
                Ok(a) => {
                    //println!("Finished decoding entry");
                    ret.push(a)
                }
                Err(e) => {
                    return Err(AltheaTypesError::BadEthAbiInput(format!(
                        "Failed to get entry with {}",
                        e
                    )));
                }
            }
        }

        Ok(ret)
    }
}

// Comparison ignoring nicknames to allow changing
// nicknames without breaking everything
impl PartialEq for Identity {
    fn eq(&self, other: &Identity) -> bool {
        self.mesh_ip == other.mesh_ip
            && self.eth_address == other.eth_address
            && self.wg_public_key == other.wg_public_key
    }
}

// I don't understand why we need this
// docs insist on it though https://doc.rust-lang.org/std/cmp/trait.Eq.html
impl Eq for Identity {}

// Custom hash implementation that also ignores nickname
impl Hash for Identity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.mesh_ip.hash(state);
        self.eth_address.hash(state);
        self.wg_public_key.hash(state);
    }
}

/// generates a random identity, never use in production
pub fn random_identity() -> Identity {
    use clarity::PrivateKey;

    let secret: [u8; 32] = rand::random();
    let not_secret: [u8; 32] = rand::random();
    let mut ip: [u8; 16] = [0; 16];
    ip.copy_from_slice(&secret[0..16]);

    // the starting location of the funds
    let eth_key = PrivateKey::from_bytes(secret).unwrap();
    let eth_address = eth_key.to_address();

    Identity {
        mesh_ip: ip.into(),
        eth_address,
        wg_public_key: not_secret.into(),
        nickname: None,
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use rand::{distributions::Uniform, prelude::Distribution, rngs::ThreadRng, thread_rng, Rng};
    use std::{
        net::Ipv6Addr,
        time::{Duration, Instant},
    };

    /// How long we fuzz the input
    pub const FUZZ_TIME: Duration = Duration::from_secs(30);

    pub fn get_fuzz_bytes(rng: &mut ThreadRng) -> Vec<u8> {
        let range = Uniform::from(1..200_000);
        let size: usize = range.sample(rng);
        let event_bytes: Vec<u8> = (0..size)
            .map(|_| {
                let val: u8 = rng.gen();
                val
            })
            .collect();
        event_bytes
    }

    /// In order to support eth abi serializing both ipv4 and ipv6 variants
    /// in identities we need to confirm how the serialization works
    #[test]
    fn test_ipv6_byte_encoding() {
        let ip: Ipv6Addr = "2001:0db8:85a3:0000:0000:8a2e:0370:7334".parse().unwrap();
        let num = u128::from(ip);
        let bytes = num.to_be_bytes();
        let num_from_bytes = u128::from_be_bytes(bytes);
        assert_eq!(num, num_from_bytes);
    }

    #[test]
    fn fuzz_pase_identity_abi_correct() {
        let start = Instant::now();
        while Instant::now() - start < FUZZ_TIME {
            let identity = random_identity();
            let bytes = identity.encode_to_eth_abi();
            let res = Identity::decode_from_eth_abi(bytes);
            match res {
                Ok(_) => {
                    assert_eq!(identity, res.unwrap());
                }
                Err(e) => panic!("Failed to decode eth abi with error {:?}", e),
            }
        }
    }

    #[test]
    fn fuzz_pase_identity_abi_incorrect() {
        let start = Instant::now();
        let mut rng = thread_rng();
        while Instant::now() - start < FUZZ_TIME {
            let bytes = get_fuzz_bytes(&mut rng);

            let res = Identity::decode_from_eth_abi(bytes);
            match res {
                Ok(_) => println!("Got valid output, this should happen very rarely!"),
                Err(_e) => {}
            }
        }
    }

    #[test]
    fn fuzz_pase_identity_array_abi_correct() {
        let start = Instant::now();
        while Instant::now() - start < FUZZ_TIME {
            let num_id: u8 = thread_rng().gen();
            let mut idents = Vec::new();
            for _ in 0..num_id {
                idents.push(random_identity());
            }
            let bytes = Identity::encode_array_to_eth_abi(idents.clone());
            let res = Identity::decode_array_from_eth_abi(bytes);
            match res {
                Ok(_) => {
                    assert_eq!(idents, res.unwrap());
                }
                Err(e) => panic!("Failed to decode eth abi {:?} with error {:?}", idents, e),
            }
        }
    }

    #[test]
    fn fuzz_pase_identity_array_abi_incorrect() {
        let start = Instant::now();
        let mut rng = thread_rng();
        while Instant::now() - start < FUZZ_TIME {
            let bytes = get_fuzz_bytes(&mut rng);

            let res = Identity::decode_array_from_eth_abi(bytes);
            match res {
                Ok(_) => println!("Got valid output, this should happen very rarely!"),
                Err(_e) => {}
            }
        }
    }

    #[test]
    fn test_parse_identity_abi() {
        use clarity::utils::hex_str_to_bytes;
        // test parsing an abi struct with various input types
        let id = Identity {
            mesh_ip: "e0b1:bf22:64ae:8e91:cc4e:5a1b:a0ef:8495".parse().unwrap(),
            eth_address: "0x090502B2fd4dE198554511C0a6fd4da5D41E7C49"
                .parse()
                .unwrap(),
            wg_public_key: "4LG/ImSujpHMTloboO+ElV7wgn2LRsUnZzoeZGMFO2Q="
                .parse()
                .unwrap(),
            nickname: None,
        };
        let bytes = "\
    00000000000000000000000000000000e0b1bf2264ae8e91cc4e5a1ba0ef8495\
    e0b1bf2264ae8e91cc4e5a1ba0ef84955ef0827d8b46c527673a1e6463053b64\
    000000000000000000000000090502b2fd4de198554511c0a6fd4da5d41e7c49";

        let bytes = hex_str_to_bytes(bytes).unwrap();
        assert_eq!(Identity::decode_from_eth_abi(bytes).unwrap(), id);

        // invalid input
        let bytes = "\
    00000000000000000000000000000000e0b1bf2264ae8e91cc4e5a1ba0ef8495\
    00000000000000000000000000000000e0b1bf2264ae8e91cc4e5a1ba0ef8495\
    e0b1bf2264ae8e91cc4e5a1ba0ef84955ef0827d8b46c527673a1e6463053b64\
    000000000000000000000000090502b2fd4de198554511c0a6fd4da5d41e7c49";

        let bytes = hex_str_to_bytes(bytes).unwrap();
        assert!(Identity::decode_from_eth_abi(bytes).is_err());

        // invalid input
        let bytes = "\
    0000000000000000000000000000000000000000000000000000000000000000\
    00000000000000000000000000000000e0b1bf2264ae8e91cc4e5a1ba0ef8495\
    e0b1bf2264ae8e91cc4e5a1ba0ef84955ef0827d8b46c527673a1e6463053b64";

        let bytes = hex_str_to_bytes(bytes).unwrap();
        assert!(Identity::decode_from_eth_abi(bytes).is_err());

        // invalid input
        let bytes = "\
    00000000000000000000000000000000e0b1bf2264ae8e91cc4e5a1ba0ef8495\
    e0b1bf2264ae8e91cc4e5a1ba0ef84955ef0827d8b46c527673a1e6463053b64";

        let bytes = hex_str_to_bytes(bytes).unwrap();
        assert!(Identity::decode_from_eth_abi(bytes).is_err());
    }

    #[test]
    fn test_parse_abi_array() {
        use clarity::utils::hex_str_to_bytes;
        // empty string
        let bytes = "";
        let bytes = hex_str_to_bytes(bytes).unwrap();
        assert!(Identity::decode_array_from_eth_abi(bytes).is_err());

        // valid entry
        let bytes = "\
    0000000000000000000000000000000000000000000000000000000000000020\
    0000000000000000000000000000000000000000000000000000000000000003\
    00000000000000000000000000000000e0b1bf2264ae8e91cc4e5a1ba0ef8495\
    e0b1bf2264ae8e91cc4e5a1ba0ef84955ef0827d8b46c527673a1e6463053b64\
    000000000000000000000000090502b2fd4de198554511c0a6fd4da5d41e7c49\
    00000000000000000000000000000000b1b3443a5b70425797fa4e7d4a4f78fd\
    b1b3443a5b70425797fa4e7d4a4f78fd432f982373bdd879bda9c1a3508bbd01\
    0000000000000000000000003a7090f876ae036cfedefb5359c078032b968458\
    000000000000000000000000000000003ef17d634ede32665e35816eda438a84\
    3ef17d634ede32665e35816eda438a84aeeccf32f53327538f66d6ce859b2d23\
    000000000000000000000000d9474fa480aca506f14c439a738e6362bb66f654";

        let bytes = hex_str_to_bytes(bytes).unwrap();
        assert!(Identity::decode_array_from_eth_abi(bytes.clone()).is_ok());
        assert!(Identity::decode_array_from_eth_abi(bytes).unwrap().len() == 3);

        // Second entry invalid
        let bytes = "\
    0000000000000000000000000000000000000000000000000000000000000020\
    0000000000000000000000000000000000000000000000000000000000000003\
    00000000000000000000000000000000e0b1bf2264ae8e91cc4e5a1ba0ef8495\
    e0b1bf2264ae8e91cc4e5a1ba0ef84955ef0827d8b46c527673a1e6463053b64\
    000000000000000000000000090502b2fd4de198554511c0a6fd4da5d41e7c49\
    0000000000000000000000000000000000000000000000000000000000000000\
    b1b3443a5b70425797fa4e7d4a4f78fd432f982373bdd879bda9c1a3508bbd01\
    0000000000000000000000003a7090f876ae036cfedefb5359c078032b968458\
    000000000000000000000000000000003ef17d634ede32665e35816eda438a84\
    3ef17d634ede32665e35816eda438a84aeeccf32f53327538f66d6ce859b2d23\
    000000000000000000000000d9474fa480aca506f14c439a738e6362bb66f654";

        let bytes = hex_str_to_bytes(bytes).unwrap();
        assert!(Identity::decode_array_from_eth_abi(bytes.clone()).is_err());

        // No valid entries
        let bytes = "\
    0000000000000000000000000000000000000000000000000000000000000020\
    0000000000000000000000000000000000000000000000000000000000000002\
    0000000000000000000000000000000000000000000000000000000000000000\
    ";
        let bytes = hex_str_to_bytes(bytes).unwrap();
        assert!(Identity::decode_array_from_eth_abi(bytes.clone()).is_err());
    }
}
