extern crate serde;
extern crate base64;
use std::ops::Deref;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate array_serialization_derive;
use serde::{Deserialize, Deserializer, Serialize, Serializer};



#[derive(ArrayTupleDeref, ArrayTupleBase64)]
pub struct Bytes32([u8; 32]);

#[derive(ArrayTupleDeref, ArrayTupleBase64, Debug, Copy, Clone, Hash, Eq, PartialEq)]
pub struct EthAddress([u8; 20]);

#[derive(ArrayTupleDeref, ArrayTupleBase64)]
pub struct EthSignature([u8; 65]);

#[derive(ArrayTupleDeref, ArrayTupleBase64)]
pub struct EthPrivateKey([u8; 64]);

#[cfg(test)]
mod tests {
    extern crate serde_json;
    use super::{EthSignature, EthPrivateKey, EthAddress};

    #[derive(Serialize, Deserialize)]
    struct MyStruct {
        addr: EthAddress,
        sig: EthSignature,
        key: EthPrivateKey
    }

    #[test]
    fn serialize() {
        // Some data structure.
        let my_struct = MyStruct {
            addr: EthAddress([9; 20]),
            sig: EthSignature([8; 65]),
            key: EthPrivateKey([7; 64])
        };

        // Serialize it to a JSON string.
        let j = serde_json::to_string(&my_struct).unwrap();

        // Print, write to a file, or send to an HTTP server.
        assert_eq!("{\"addr\":\"CQkJCQkJCQkJCQkJCQkJCQkJCQk=\",\"sig\":\"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg=\",\"key\":\"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBw==\"}", j);
    }
}
