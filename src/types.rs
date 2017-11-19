use std::ops::Deref;
use serde;
use serde::ser::{Serialize};
use serde::{Deserialize, Deserializer, Serializer};
use base64;
use storage::Storable;
use tiny_keccak::Keccak;
use num::bigint::{BigUint, BigInt};

const biggest_uint256: BigUint = (BigUint::new(vec![2, 0, 0]) ^ BigUint::new(vec![256, 0, 0])) - BigUint::new(vec![1, 0, 0]);

// fn biggest_uint256 () -> BigUint {
//   (BigUint::new(vec![2, 0, 0]) ^ BigUint::new(vec![256, 0, 0])) - BigUint::new(vec![1, 0, 0])
// }

#[derive(Copy, Clone, Debug)]
pub enum Buckets {
    Channels,
    Counterparties,
}

#[derive(ArrayTupleDeref, ArrayTupleBase64)]
pub struct Bytes32([u8; 32]);

#[derive(ArrayTupleDeref, ArrayTupleBase64, Copy, Clone)]
pub struct Address([u8; 20]);

pub struct Uint256(BigUint);

impl Deref for Uint256 {
  type Target = BigUint;

  fn deref(&self) -> &BigUint {
    &self.0
  }
}

impl Uint256 {
    fn checked_add(&self, v: &Uint256) -> Option<Uint256> {
        let num = **self + **v;
        if num > biggest_uint256 {
          return None;
        }
        Some(Uint256(num))
    }
}

pub struct Int256(BigInt);

#[derive(ArrayTupleDeref, ArrayTupleBase64)]
pub struct Signature([u8; 65]);

#[derive(ArrayTupleDeref, ArrayTupleBase64)]
pub struct PrivateKey([u8; 64]);


#[derive(Copy, Clone, Serialize, Deserialize)]
pub enum Participant {
  Zero = 0,
  One = 1,
}

#[derive(Serialize, Deserialize)]
pub struct Channel {
  pub channel_id: Bytes32,
  pub address0: Address,
  pub address1: Address,
  pub ended: bool,
  pub closed: bool,
  pub balance0: Uint256,
  pub balance1: Uint256,
  pub total_balance: Uint256,
  pub hashlocks: Vec<Hashlock>,
  pub sequence_number: Uint256,
  pub participant: Participant,
}

impl Storable for Channel {
  fn my_bucket() -> u8 {
    Buckets::Channels as u8
  }
  fn my_id(&self) -> &[u8] {
    &*self.channel_id
  }
}

impl Channel {
  pub fn new(
    channel_id: Bytes32,
    address0: Address,
    address1: Address,
    balance0: Uint256,
    balance1: Uint256,
    participant: Participant,
  ) -> Channel {
    Channel {
      channel_id,
      address0,
      address1,
      balance0,
      balance1,
      participant,
      total_balance: balance0.checked_add(balance1),

      sequence_number: 0,
      closed: false,
      ended: false,
      hashlocks: Vec::new(),
    }
  }

  pub fn get_my_address(&self) -> Address {
    match self.participant {
      Participant::Zero => self.address0,
      Participant::One => self.address1,
    }
  }
  pub fn get_their_address(&self) -> Address {
    match self.participant {
      Participant::Zero => self.address1,
      Participant::One => self.address0
    }
  }
  pub fn get_my_balance(&self) -> Uint256 {
    match self.participant {
      Participant::Zero => self.balance0,
      Participant::One => self.balance1,
    }
  }
  pub fn get_their_balance(&self) -> Uint256 {
    match self.participant {
      Participant::Zero => self.balance1,
      Participant::One => self.balance0,
    }
  }
}

#[derive(Serialize, Deserialize)]
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
		let mut keccak = Keccak::new_keccak256();
		let mut result = [0u8; 32];
		keccak.update(self.channel_id.as_ref());
    keccak.update(self.settling_period.to_bytes_le());
    keccak.update(self.address0.as_ref());
    keccak.update(self.address1.as_ref());
    keccak.update(self.balance0);
    keccak.update(self.balance1);
		keccak.finalize(&mut result);
		Bytes32(result)
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
