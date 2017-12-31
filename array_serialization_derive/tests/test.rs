#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate array_serialization_derive;

use std::ops::Deref;
extern crate base64;
extern crate hex;
extern crate serde;
extern crate serde_json;

use self::serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(ArrayTupleDeref, ArrayTupleHex)]
pub struct Signature([u8; 65]);

#[derive(ArrayTupleDeref, ArrayTupleBase64)]
pub struct PrivateKey([u8; 64]);


#[test]
fn deref() {
  let sig = Signature([7; 65]);
  let pk = PrivateKey([9; 64]);
  assert_eq!(sig[0], 7);
  assert_eq!(pk[0], 9);
}

  #[derive(Serialize, Deserialize)]
  struct MyStruct {
    sig: Signature,
    pk: PrivateKey
  }

  #[test]
  fn serialize() {

    let my_bytes = MyStruct {
      sig: Signature([7; 65]),
      pk: PrivateKey([9; 64])
    };

    let expected = "{\"sig\":\"0707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707\",\"pk\":\"CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQ==\"}";

    let j = serde_json::to_string(&my_bytes).unwrap();

    assert_eq!(expected, j);

    let m: MyStruct = serde_json::from_str(expected).unwrap();

    assert_eq!(7, m.sig[0]);
  }

