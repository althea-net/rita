extern crate base64;
extern crate ethereum_types;
extern crate eui48;
extern crate hex;
extern crate num256;
extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate serde_derive;

#[cfg(feature = "actix")]
extern crate actix;

pub mod interop;
pub mod rtt;

use ethereum_types::{Address, Public, Secret, Signature, U256};

pub use interop::*;
pub use rtt::RTTimestamps;

pub type Bytes32 = U256;
pub type EthAddress = Address;
pub type EthPubKey = Public;
pub type EthPrivateKey = Secret;
pub type EthSignature = Signature;

#[cfg(test)]
mod tests {
    extern crate serde_json;

    use num256::Uint256;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::net::IpAddr;
    use std::net::Ipv6Addr;

    use super::*;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Hash)]
    struct MyStruct {
        addr: EthAddress,
        sig: EthSignature,
        key: EthPrivateKey,
        payment: PaymentTx,
        identity: Identity,
    }

    fn new_addr(x: u64) -> EthAddress {
        x.into()
    }

    fn new_sig(x: u64) -> EthSignature {
        x.into()
    }

    fn new_key(x: u64) -> EthPrivateKey {
        x.into()
    }

    fn new_payment(x: u64) -> PaymentTx {
        PaymentTx {
            to: new_identity(x),
            from: new_identity(x),
            amount: Uint256::from(x),
        }
    }

    fn new_identity(x: u64) -> Identity {
        let y = x as u16;
        Identity {
            mesh_ip: IpAddr::V6(Ipv6Addr::new(y, y, y, y, y, y, y, y)),
            wg_public_key: String::from("AAAAAAAAAAAAAAAAAAAA"),
            eth_address: new_addr(x),
        }
    }

    fn new_struct(x: u64) -> MyStruct {
        MyStruct {
            addr: new_addr(x),
            sig: new_sig(x),
            key: new_key(x),
            identity: new_identity(x),
            payment: new_payment(x),
        }
    }

    macro_rules! test_eq {
        ($func_name:ident, $test_name:ident) => {
            #[test]
            fn $test_name() {
                let a = $func_name(1);
                let b = $func_name(1);

                assert_eq!(a, b);

                let a = $func_name(1);
                let b = $func_name(2);

                assert_ne!(a, b);
            }
        };
    }

    macro_rules! test_hash {
        ($func_name:ident, $test_name:ident) => {
            #[test]
            fn $test_name() {
                let a = $func_name(1);
                let b = $func_name(1);

                assert_eq!(calculate_hash(&a), calculate_hash(&b));

                let a = $func_name(1);
                let b = $func_name(2);

                assert_ne!(calculate_hash(&a), calculate_hash(&b));
            }
        };
    }

    macro_rules! test_serde {
        ($func_name:ident, $test_name:ident) => {
            #[test]
            fn $test_name() {
                let a = $func_name(1);

                let s = serde_json::to_string(&a).unwrap();

                let b = serde_json::from_str(&s).unwrap();

                assert_eq!(a, b)
            }
        };
    }

    test_eq!(new_addr, check_addr_eq);
    test_eq!(new_sig, check_sig_eq);
    test_eq!(new_key, check_key_eq);
    test_eq!(new_payment, check_payment_eq);
    test_eq!(new_identity, check_identity_eq);

    test_hash!(new_addr, check_addr_hash);
    test_hash!(new_sig, check_sig_hash);
    test_hash!(new_key, check_key_hash);
    test_hash!(new_payment, check_payment_hash);
    test_hash!(new_identity, check_identity_hash);

    test_serde!(new_addr, check_addr_serde);
    test_serde!(new_sig, check_sig_serde);
    test_serde!(new_key, check_key_serde);
    test_serde!(new_payment, check_payment_serde);
    test_serde!(new_identity, check_identity_serde);

    #[test]
    fn check_struct_serialize() {
        // Some data structure.
        let my_struct = new_struct(1);

        // Serialize it to a JSON string.
        let j = serde_json::to_string(&my_struct).unwrap();
        let s = "{\"addr\":\"0x0000000000000000000000000000000000000001\",\"sig\":\"0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001\",\"key\":\"0x0000000000000000000000000000000000000000000000000000000000000001\",\"payment\":{\"to\":{\"mesh_ip\":\"1:1:1:1:1:1:1:1\",\"eth_address\":\"0x0000000000000000000000000000000000000001\",\"wg_public_key\":\"AAAAAAAAAAAAAAAAAAAA\"},\"from\":{\"mesh_ip\":\"1:1:1:1:1:1:1:1\",\"eth_address\":\"0x0000000000000000000000000000000000000001\",\"wg_public_key\":\"AAAAAAAAAAAAAAAAAAAA\"},\"amount\":\"0x1\"},\"identity\":{\"mesh_ip\":\"1:1:1:1:1:1:1:1\",\"eth_address\":\"0x0000000000000000000000000000000000000001\",\"wg_public_key\":\"AAAAAAAAAAAAAAAAAAAA\"}}";
        // Print, write to a file, or send to an HTTP server.
        assert_eq!(s, j);

        assert_eq!(serde_json::from_str::<MyStruct>(s).unwrap(), my_struct);
    }

    #[test]
    fn check_struct_eq() {
        // Some data structure.
        let my_struct = new_struct(1);

        assert_eq!(my_struct, my_struct);
    }

    #[test]
    fn check_struct_ne() {
        // Some data structure.
        let my_struct = new_struct(1);

        let my_struct1 = new_struct(2);

        assert_ne!(my_struct, my_struct1);
    }

    fn calculate_hash<T: Hash>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }

    #[test]
    fn check_struct_hash_eq() {
        // Some data structure.
        let my_struct = new_struct(1);

        assert_eq!(calculate_hash(&my_struct), calculate_hash(&my_struct));
    }

    #[test]
    fn check_struct_hash_ne() {
        let my_struct = new_struct(1);

        let my_struct1 = new_struct(2);

        assert_ne!(calculate_hash(&my_struct), calculate_hash(&my_struct1));
    }
}
