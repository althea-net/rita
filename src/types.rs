extern crate base64;
extern crate bigint;
extern crate serde;
extern crate serde_bytes;
extern crate serde_json;

use self::serde::ser::{self, Serialize};
use self::serde::{Deserialize, Deserializer, Serializer};

// use serde::Serialize;

pub type Bytes32 = [u8; 32];
pub type Address = [u8; 20];
pub type Uint256 = u64;
pub type Int256 = i64;
pub type Signature = [u8; 65];
pub type PrivateKey = [u8; 64];

// impl Serialize for Signature {
//   fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//   where
//     S: Serializer,
//   {
//     serializer.serialize_i32(*self)
//   }
// }

#[derive(Copy, Clone)]
pub enum Participant {
  Zero = 0,
  One = 1,
}

impl Participant {
  pub fn get_me(&self) -> usize {
    match self {
      Zero => 0,
      One => 1,
    }
  }
  pub fn get_them(&self) -> usize {
    match self {
      One => 0,
      Zero => 1,
    }
  }
}

pub struct Channel {
  pub channel_id: Bytes32,
  pub addresses: [Address; 2],
  pub ended: bool,
  pub closed: bool,
  pub balances: [Uint256; 2],
  pub total_balance: Uint256,
  pub hashlocks: Vec<Hashlock>,
  pub sequence_number: Uint256,
  pub participant: Participant,
}

impl Channel {
  pub fn new(
    channel_id: Bytes32,
    addresses: [Address; 2],
    balances: [Uint256; 2],
    participant: Participant,
  ) -> Channel {
    Channel {
      channel_id,
      addresses,
      balances,
      participant,
      total_balance: balances[0] + balances[1],

      sequence_number: 0,
      closed: false,
      ended: false,
      hashlocks: Vec::new(),
    }
  }

  pub fn get_my_address(&self) -> Address {
    self.addresses[self.participant.get_me()]
  }
  pub fn get_their_address(&self) -> Address {
    self.addresses[self.participant.get_them()]
  }
  pub fn get_my_balance(&self) -> Uint256 {
    self.balances[self.participant.get_me()]
  }
  pub fn get_their_balance(&self) -> Uint256 {
    self.balances[self.participant.get_them()]
  }
}

pub struct Hashlock {
  pub hash: Bytes32,
  pub amount: Int256,
}

#[derive(Serialize, Deserialize)]
pub struct NewChannelTx {
  #[serde(serialize_with = "as_base64")] pub channel_id: Bytes32,
  pub settling_period: Uint256,
  #[serde(serialize_with = "as_base64")] pub address0: Address,
  #[serde(serialize_with = "as_base64")] pub address1: Address,
  pub balance0: Uint256,
  pub balance1: Uint256,
  // pub signatures: [Option<Signature>; 2],
}

impl NewChannelTx {
  pub fn get_fingerprint(&self) -> Bytes32 {
    [0; 32]
  }
}

pub struct Account {
  pub address: Address,
  pub private_key: PrivateKey,
  pub balance: Uint256,
}

pub struct Counterparty {
  pub address: Address,
  pub url: String,
}

impl Counterparty {}

pub struct Fullnode {
  pub address: Address,
  pub url: String,
}

fn as_base64<'a, T, S>(key: &T, serializer: S) -> Result<S::Ok, S::Error>
where
  T: AsRef<[u8]>,
  S: Serializer,
{
  serializer.serialize_str(&base64::encode(key.as_ref()))
}


#[cfg(test)]
mod tests {
  use types;
  #[test]
  fn serialize() {
    // Some data structure.
    let new_channel_tx = types::NewChannelTx {
      address0: [0; 20],
      address1: [0; 20],
      balance0: 23,
      balance1: 23,
      channel_id: [0; 32],
      settling_period: 45,
    };

    // Serialize it to a JSON string.
    let j = types::serde_json::to_string(&new_channel_tx).unwrap();

    // Print, write to a file, or send to an HTTP server.
    assert_eq!("{\"channel_id\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"settling_period\":45,\"address0\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"address1\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"balance0\":23,\"balance1\":23}", j);
  }
}
