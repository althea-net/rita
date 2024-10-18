use crate::error::AltheaTypesError;
use crate::random_idenity_with_private_key;
use crate::regions::Regions;
use crate::to_evm_words;
use crate::wg_key::WgKey;
use crate::Identity;
use crate::SystemChain;
use crate::WORD_SIZE;
use clarity::abi::encode_tokens;
use clarity::abi::AbiToken;
use clarity::Address;
use clarity::PrivateKey;
use num256::Uint256;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;

/// This struct represents a single exit server. It contains all the details
/// needed to contact and register to the exit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitIdentity {
    /// This is the unique identity of the exit. Previously exit
    /// had a shared wg key and mesh ip, this struct needs to have unique
    /// meship, wgkey and ethaddress for each entry
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

impl ExitIdentity {
    pub fn new(
        mesh_ip: IpAddr,
        wg_key: WgKey,
        eth_addr: Address,
        registration_port: u16,
        wg_exit_listen_port: u16,
        allowed_regions: HashSet<Regions>,
        payment_types: HashSet<SystemChain>,
    ) -> Self {
        ExitIdentity {
            mesh_ip,
            wg_key,
            eth_addr,
            registration_port,
            wg_exit_listen_port,
            allowed_regions,
            payment_types,
        }
    }

    /// Returns the exit identity in it's Ethereum ABI encoded form
    /// as used by the exit registration smart contract
    pub fn encode_to_eth_abi(&self) -> Vec<u8> {
        encode_tokens(&[self.encode_to_eth_abi_token()])
    }

    /// Returns the exit identity as an AbiToken type, this can be easily combined
    /// with other AbiToken types to create more complex structures or simply serialized
    /// using the encode_tokens function.
    fn encode_to_eth_abi_token(&self) -> AbiToken {
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
            AbiToken::Uint(self.wg_key.into()),
            AbiToken::Address(self.eth_addr),
            AbiToken::Uint(self.registration_port.into()),
            AbiToken::Uint(self.wg_exit_listen_port.into()),
            allowed_regions_abi_array(self.allowed_regions.clone()).into(),
            payment_types_abi_array(self.payment_types.clone()).into(),
        ])
    }

    /// Returns an array of exit identities in their Ethereum ABI encoded form
    pub fn encode_array_to_eth_abi(input: Vec<ExitIdentity>) -> Vec<u8> {
        let mut ret = Vec::new();
        for id in input {
            ret.push(id.encode_to_eth_abi_token());
        }
        encode_tokens(&[AbiToken::Dynamic(ret)])
    }

    /// Returns an array of exit identities as an AbiToken type, this can be easily combined
    /// with other AbiToken types to create more complex structures or simply serialized
    pub fn encode_array_to_eth_abi_token(input: Vec<ExitIdentity>) -> AbiToken {
        let mut ret = Vec::new();
        for id in input {
            ret.push(id.encode_to_eth_abi_token());
        }
        AbiToken::Dynamic(ret)
    }

    pub fn decode_from_eth_abi(input: Vec<u8>) -> Result<Self, AltheaTypesError> {
        let mut byte_chunks = to_evm_words(input);

        // println!("Round");
        // for chunk in byte_chunks.iter() {
        //     println!("{}", bytes_to_hex_str(chunk));
        // }

        // The smallest entry has 7 lines, with two empty arrays
        if byte_chunks.len() < 9 {
            return Err(AltheaTypesError::BadEthAbiInput(format!(
                "Received byte chunks: {byte_chunks:?}"
            )));
        }

        // Remove the first entry which is the struct type header, only when it's present
        if Uint256::from_be_bytes(&byte_chunks[0]) == 32u8.into() {
            byte_chunks.remove(0);
        }

        // repeat size check now that we've dropped a word
        if byte_chunks.len() < 9 {
            return Err(AltheaTypesError::BadEthAbiInput(format!(
                "Received byte chunks: {byte_chunks:?}"
            )));
        }

        // index zero is the struct type header which we discard

        // Parse first 3 entries to get identity struct. Already validated length
        let exit_id = Identity::decode_from_eth_abi(byte_chunks[0..3].concat())?;

        let registration_port: Uint256 = Uint256::from_be_bytes(&byte_chunks[3]);
        let registration_port: u16 = u16::from_be_bytes(
            match registration_port.to_be_bytes()[30..WORD_SIZE].try_into() {
                Ok(a) => a,
                Err(e) => {
                    return Err(AltheaTypesError::BadEthAbiInput(format!(
                        "Cannot get registration port with {}",
                        e
                    )));
                }
            },
        );

        let wg_exit_listen_port: Uint256 = Uint256::from_be_bytes(&byte_chunks[4]);
        let wg_exit_listen_port: u16 = u16::from_be_bytes(
            match wg_exit_listen_port.to_be_bytes()[30..WORD_SIZE].try_into() {
                Ok(a) => a,
                Err(e) => {
                    return Err(AltheaTypesError::BadEthAbiInput(format!(
                        "Cannot get wg_exit port with {}",
                        e
                    )));
                }
            },
        );

        let regions_start: Uint256 = Uint256::from_be_bytes(&byte_chunks[5]) / WORD_SIZE.into();
        let regions_start: usize = usize::from_be_bytes(
            match regions_start.to_be_bytes()[24..WORD_SIZE].try_into() {
                Ok(a) => a,
                Err(e) => {
                    return Err(AltheaTypesError::BadEthAbiInput(format!(
                        "Cannot get region array start with {}",
                        e
                    )));
                }
            },
        );

        let payment_start: Uint256 = Uint256::from_be_bytes(&byte_chunks[6]) / WORD_SIZE.into();
        let payment_start: usize = usize::from_be_bytes(
            match payment_start.to_be_bytes()[24..WORD_SIZE].try_into() {
                Ok(a) => a,
                Err(e) => {
                    return Err(AltheaTypesError::BadEthAbiInput(format!(
                        "Cannot get region array start with {}",
                        e
                    )));
                }
            },
        );

        let regions_arr_len: usize = usize::from_be_bytes(match byte_chunks.get(regions_start) {
            Some(a) => match a[24..WORD_SIZE].try_into() {
                Ok(res) => res,
                Err(e) => {
                    return Err(AltheaTypesError::BadEthAbiInput(format!(
                        "Cannot get region array slice {}",
                        e
                    )));
                }
            },
            None => {
                return Err(AltheaTypesError::BadEthAbiInput(format!(
                    "Why cant we get region array len from slice {byte_chunks:?}"
                )))
            }
        });

        let payment_arr_len: usize = usize::from_be_bytes(match byte_chunks.get(payment_start) {
            Some(a) => match a[24..WORD_SIZE].try_into() {
                Ok(res) => res,
                Err(e) => {
                    return Err(AltheaTypesError::BadEthAbiInput(format!(
                        "Cannot get payment array slice {}",
                        e
                    )));
                }
            },
            None => {
                return Err(AltheaTypesError::BadEthAbiInput(format!(
                    "Why cant we get payment array len from slice {byte_chunks:?}"
                )))
            }
        });

        // Validate length here to avoid tedious error handling later
        // Total len should be: 3 (3 id struct entries) + 2 (struct len localtion pointers) + 2 (len value of each array) +2(ports)
        // + len of region array + len of payment array

        if byte_chunks.len() < 9 + regions_arr_len + payment_arr_len {
            let msg = format!(
                "Length validation failed, parsed incorrectly, expected length {}, got length {}",
                7 + regions_arr_len + payment_arr_len,
                byte_chunks.len()
            );
            return Err(AltheaTypesError::BadEthAbiInput(msg));
        }

        let mut reg_arr: HashSet<Regions> = HashSet::new();
        for region in byte_chunks
            .iter()
            .take(regions_arr_len + regions_start + 1)
            .skip(regions_start + 1)
        {
            let region_code = region[WORD_SIZE - 1];
            reg_arr.insert(region_code.into());
        }

        let mut payment_arr: HashSet<SystemChain> = HashSet::new();
        for code in byte_chunks
            .iter()
            .take(payment_arr_len + payment_start + 1)
            .skip(payment_start + 1)
        {
            let system_chain_code = code[WORD_SIZE - 1];
            payment_arr.insert(system_chain_code.into());
        }
        Ok(ExitIdentity {
            mesh_ip: exit_id.mesh_ip,
            wg_key: exit_id.wg_public_key,
            eth_addr: exit_id.eth_address,
            registration_port,
            wg_exit_listen_port,
            allowed_regions: reg_arr,
            payment_types: payment_arr,
        })
    }

    /// Decode an abi encoded array of exit identities
    pub fn decode_array_from_eth_abi(bytes: Vec<u8>) -> Result<Vec<Self>, AltheaTypesError> {
        let byte_chunks = to_evm_words(bytes.clone());
        // for chunk in byte_chunks.iter() {
        //     println!("{}", bytes_to_hex_str(chunk));
        // }

        // An empty list, the first word has a type identifier, the second is empty
        if byte_chunks.len() == 2 {
            return Ok(vec![]);
        }

        // A valid array with 1 entry will have atleast 11 lines
        if byte_chunks.len() < 11 {
            return Err(AltheaTypesError::BadEthAbiInput(format!(
                "Empty or invalid array: {byte_chunks:?}"
            )));
        }

        // Get number of entries in the array, below this is a list of offsets to each entry
        let num_entries: usize =
            usize::from_be_bytes(match byte_chunks[1][24..WORD_SIZE].try_into() {
                Ok(a) => a,
                Err(e) => {
                    let msg = format!("Cannot parse array len with {}", e);
                    return Err(AltheaTypesError::BadEthAbiInput(msg));
                }
            });

        //println!("Got {} entries", num_entries);

        let mut ret = Vec::new();
        // pass in each entry byte chunk to individual entry parser
        for i in 0..num_entries {
            // offset for this entry
            let offset = &byte_chunks[2 + i];
            let offset: usize = usize::from_be_bytes(match offset[24..WORD_SIZE].try_into() {
                Ok(a) => a,
                Err(e) => {
                    return Err(AltheaTypesError::BadEthAbiInput(format!(
                        "Cannot get entry offset with {}",
                        e
                    )));
                }
            });
            if offset >= bytes.len() {
                let msg = "Encoded array length longer than data".to_string();
                return Err(AltheaTypesError::BadEthAbiInput(msg));
            }
            // start index is computed from the front of the array, so one word is consumed by the
            // struct header, then another with the length of the array of offsets, then each offset
            // is a word representing the number of words to the start of the offset list to the struct!
            let start_index = (2 * WORD_SIZE) + offset;
            match ExitIdentity::decode_from_eth_abi(bytes[start_index..].to_vec()) {
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

fn allowed_regions_abi_array(allowed_regions: HashSet<Regions>) -> Vec<AbiToken> {
    let mut allowed_regions: Vec<Regions> = allowed_regions.into_iter().collect();
    allowed_regions.sort();
    let mut ret = vec![];
    for reg in allowed_regions.iter() {
        let reg_int: u8 = (*reg).into();
        ret.push(AbiToken::Uint(reg_int.into()));
    }
    ret
}

fn payment_types_abi_array(payment_types: HashSet<SystemChain>) -> Vec<AbiToken> {
    let mut payment_types: Vec<SystemChain> = payment_types.into_iter().collect();
    payment_types.sort();
    let mut ret = vec![];
    for payment_type in payment_types.iter() {
        let pay_int: u8 = (*payment_type).into();
        ret.push(AbiToken::Uint(pay_int.into()));
    }
    ret
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

impl From<ExitIdentity> for Identity {
    fn from(exit_id: ExitIdentity) -> Identity {
        Identity {
            mesh_ip: exit_id.mesh_ip,
            eth_address: exit_id.eth_addr,
            wg_public_key: exit_id.wg_key,
            nickname: None,
        }
    }
}

impl From<&ExitIdentity> for Identity {
    fn from(exit_id: &ExitIdentity) -> Identity {
        Identity {
            mesh_ip: exit_id.mesh_ip,
            eth_address: exit_id.eth_addr,
            wg_public_key: exit_id.wg_key,
            nickname: None,
        }
    }
}

pub fn exit_identity_to_id(exit_id: ExitIdentity) -> Identity {
    exit_id.into()
}

/// Returns a random exit identity, never use in production, your money will be stolen
/// Also returns the private key for testing purposes
pub fn random_exit_identity_with_private_key() -> (ExitIdentity, PrivateKey) {
    let (base_id, key) = random_idenity_with_private_key();

    let mut payment_types = HashSet::new();
    let num_payment_types = rand::random::<u8>().max(4);
    for _ in 0..num_payment_types {
        let pay_type: u8 = rand::random();
        let pay_type: SystemChain = pay_type.into();
        payment_types.insert(pay_type);
    }
    let mut allowed_regions = HashSet::new();
    let num_regions = rand::random::<u8>();
    for _ in 0..num_regions {
        let region: u8 = rand::random();
        let region: Regions = region.into();
        allowed_regions.insert(region);
    }

    (
        ExitIdentity {
            mesh_ip: base_id.mesh_ip,
            eth_addr: base_id.eth_address,
            wg_key: base_id.wg_public_key,
            registration_port: rand::random(),
            wg_exit_listen_port: rand::random(),
            allowed_regions,
            payment_types,
        },
        key,
    )
}

/// generates a random identity, never use in production
pub fn random_exit_identity() -> ExitIdentity {
    random_exit_identity_with_private_key().0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::tests::get_fuzz_bytes;
    use crate::identity::tests::FUZZ_TIME;
    use rand::thread_rng;
    use rand::Rng;
    use std::time::Instant;

    #[test]
    fn fuzz_pase_identity_abi_correct() {
        let start = Instant::now();
        while Instant::now() - start < FUZZ_TIME {
            let identity = random_exit_identity();
            let bytes = identity.encode_to_eth_abi();
            let res = ExitIdentity::decode_from_eth_abi(bytes);
            match res {
                Ok(_) => {
                    assert_eq!(identity, res.unwrap());
                }
                Err(e) => panic!("Failed to decode eth abi {:?} with error {:?}", identity, e),
            }
        }
    }

    #[test]
    fn fuzz_pase_identity_abi_incorrect() {
        let start = Instant::now();
        let mut rng = thread_rng();
        while Instant::now() - start < FUZZ_TIME {
            let bytes = get_fuzz_bytes(&mut rng);

            let res = ExitIdentity::decode_from_eth_abi(bytes);
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
                idents.push(random_exit_identity());
            }
            let bytes = ExitIdentity::encode_array_to_eth_abi(idents.clone());
            let res = ExitIdentity::decode_array_from_eth_abi(bytes);
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

            let res = ExitIdentity::decode_array_from_eth_abi(bytes);
            match res {
                Ok(_) => println!("Got valid output, this should happen very rarely!"),
                Err(_e) => {}
            }
        }
    }

    #[test]
    fn test_parse_exit_id_abi() {
        use clarity::utils::hex_str_to_bytes;

        let bytes = "\
    000000000000000000000000000000007bbab1ac348ee5be29ac57e2c3e052a1\
    7bbab1ac348ee5be29ac57e2c3e052a164bc756beb5063743399fd08fdb6c5bb\
    000000000000000000000000a970fab4bff2530005fdb65eeb4fe88d228aa9f8\
    000000000000000000000000000000000000000000000000000000000000130b\
    000000000000000000000000000000000000000000000000000000000000ea5e\
    00000000000000000000000000000000000000000000000000000000000000e0\
    0000000000000000000000000000000000000000000000000000000000000120\
    0000000000000000000000000000000000000000000000000000000000000001\
    0000000000000000000000000000000000000000000000000000000000000006\
    0000000000000000000000000000000000000000000000000000000000000001\
    0000000000000000000000000000000000000000000000000000000000000003";
        let bytes = hex_str_to_bytes(bytes).unwrap();

        let res = ExitIdentity::decode_from_eth_abi(bytes).unwrap();
        assert!(res.allowed_regions.contains(&Regions::Colombia));
        assert!(res.payment_types.contains(&SystemChain::Sepolia));
        assert_eq!(res.allowed_regions.len(), 1);
        assert_eq!(res.payment_types.len(), 1);

        let bytes = "\
    00000000000000000000000000000000d5ce8b4de8234789da53bddd707db3d5\
    d5ce8b4de8234789da53bddd707db3d589e00b5fce9d9b5f68cc7f3550d8944f\
    000000000000000000000000351634dbb20142a7f5ab996b96f71795e35e93f3\
    000000000000000000000000000000000000000000000000000000000000130b\
    000000000000000000000000000000000000000000000000000000000000ea5e\
    00000000000000000000000000000000000000000000000000000000000000e0\
    0000000000000000000000000000000000000000000000000000000000000140\
    0000000000000000000000000000000000000000000000000000000000000002\
    0000000000000000000000000000000000000000000000000000000000000005\
    0000000000000000000000000000000000000000000000000000000000000006\
    0000000000000000000000000000000000000000000000000000000000000003\
    0000000000000000000000000000000000000000000000000000000000000001\
    0000000000000000000000000000000000000000000000000000000000000002\
    0000000000000000000000000000000000000000000000000000000000000004";
        let bytes = hex_str_to_bytes(bytes).unwrap();

        let res = ExitIdentity::decode_from_eth_abi(bytes).unwrap();
        assert_eq!(res.allowed_regions.len(), 2);
        assert_eq!(res.payment_types.len(), 3);

        // Valid input with a bunch of cruft at the end
        let bytes = "\
    00000000000000000000000000000000d5ce8b4de8234789da53bddd707db3d5\
    d5ce8b4de8234789da53bddd707db3d589e00b5fce9d9b5f68cc7f3550d8944f\
    000000000000000000000000351634dbb20142a7f5ab996b96f71795e35e93f3\
    000000000000000000000000000000000000000000000000000000000000130b\
    000000000000000000000000000000000000000000000000000000000000ea5e\
    00000000000000000000000000000000000000000000000000000000000000e0\
    0000000000000000000000000000000000000000000000000000000000000140\
    0000000000000000000000000000000000000000000000000000000000000002\
    0000000000000000000000000000000000000000000000000000000000000003\
    0000000000000000000000000000000000000000000000000000000000000004\
    0000000000000000000000000000000000000000000000000000000000000003\
    0000000000000000000000000000000000000000000000000000000000000001\
    0000000000000000000000000000000000000000000000000000000000000002\
    0000000000000000000000000000000000000000000000000000000000000004\
    0000000000000000000000000000000000000000000000000000000000000002\
    0000000000000000000000000000000000000000000000000000000000000002\
    0000000000000000000000000000000000000000000000000000000000000002";
        let bytes = hex_str_to_bytes(bytes).unwrap();

        let res = ExitIdentity::decode_from_eth_abi(bytes).unwrap();
        print!("{:?}", res);
    }
}
