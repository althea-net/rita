extern crate serde;
extern crate serde_json;
extern crate base64;
extern crate hex;

#[macro_use]
extern crate serde_derive;

pub mod bytes_32;
pub mod eth_address;
pub mod eth_private_key;
pub mod eth_signature;

pub use bytes_32::Bytes32;
pub use eth_address::EthAddress;
pub use eth_private_key::EthPrivateKey;
pub use eth_signature::EthSignature;

#[cfg(test)]
mod tests {
    extern crate serde_json;
    use super::{EthSignature, EthPrivateKey, EthAddress};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct MyStruct {
        addr: EthAddress,
        sig: EthSignature,
        key: EthPrivateKey
    }

    #[test]
    fn serialize() {
        // Some data structure.
        let my_struct = MyStruct {
            addr: "0x0707070707070707070707070707070707070707".parse().unwrap(),
            sig: EthSignature([8; 65]),
            key: EthPrivateKey([7; 64])
        };

        // Serialize it to a JSON string.
        let j = serde_json::to_string(&my_struct).unwrap();

        let s = "{\"addr\":\"0x0707070707070707070707070707070707070707\",\"sig\":\"0x0808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808\",\"key\":\"0x07070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707\"}";

        // Print, write to a file, or send to an HTTP server.
        assert_eq!(s, j);

        assert_eq!(serde_json::from_str::<MyStruct>(s).unwrap(), my_struct);
    }
}
