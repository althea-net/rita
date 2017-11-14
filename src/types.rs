use std::ops::Deref;
use serde;
use serde::ser::{Serialize};
use serde::{Deserialize, Deserializer, Serializer};
use base64;

// use serde::Serialize;
#[derive(ArrayTupleDeref, ArrayTupleBase64)]
pub struct Bytes32([u8; 32]);

#[derive(ArrayTupleDeref, ArrayTupleBase64)]
pub struct Address([u8; 20]);

pub type Uint256 = u64;
pub type Int256 = i64;

#[derive(ArrayTupleDeref, ArrayTupleBase64)]
pub struct Signature([u8; 65]);

#[derive(ArrayTupleDeref, ArrayTupleBase64)]
pub struct PrivateKey([u8; 64]);


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

  // pub fn get_my_address(&self) -> Address {
  //   self.addresses[self.participant.get_me()]
  // }
  // pub fn get_their_address(&self) -> Address {
  //   self.addresses[self.participant.get_them()]
  // }
  // pub fn get_my_balance(&self) -> Uint256 {
  //   self.balances[self.participant.get_me()]
  // }
  // pub fn get_their_balance(&self) -> Uint256 {
  //   self.balances[self.participant.get_them()]
  // }
}

pub struct Hashlock {
  pub hash: Bytes32,
  pub amount: Int256,
}

#[derive(Serialize, Deserialize)]
pub struct NewChannelTx {
  pub channel_id: Bytes32,
  pub settling_period: Uint256,
  pub address0: Address,
  pub address1: Address,
  pub balance0: Uint256,
  pub balance1: Uint256,
  pub signature0: Option<Signature>,
  pub signature1: Option<Signature>,
}

impl NewChannelTx {
  pub fn get_fingerprint(&self) -> Bytes32 {
    Bytes32([0; 32])
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

#[cfg(test)]
mod tests {
  use types;
  use serde_json;
  #[test]
  fn serialize() {
    // Some data structure.
    let new_channel_tx = types::NewChannelTx {
      address0: types::Address([7; 20]),
      address1: types::Address([9; 20]),
      balance0: 23,
      balance1: 23,
      channel_id: types::Bytes32([11; 32]),
      settling_period: 45,
      signature0: None,
      signature1: None
    };

    // Serialize it to a JSON string.
    let j = serde_json::to_string(&new_channel_tx).unwrap();

    // Print, write to a file, or send to an HTTP server.
    assert_eq!("{\"channel_id\":\"CwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCws=\",\"settling_period\":45,\"address0\":\"BwcHBwcHBwcHBwcHBwcHBwcHBwc=\",\"address1\":\"CQkJCQkJCQkJCQkJCQkJCQkJCQk=\",\"balance0\":23,\"balance1\":23,\"signature0\":null,\"signature1\":null}", j);
  }
}
