// extern crate num_bigint;
extern crate num;

use self::num::bigint::{BigUint, BigInt};
use self::num::Bounded;

impl Bounded for Uint256 {
  fn min_value() -> Self {
    0
  };
  fn max_value() -> Self {
    2^256
  };
}

impl Bounded for Int256 {
  fn min_value() -> Self {
    (2^256) * -1
  };
  fn max_value() -> Self {
    2^256
  };
}

pub type Bytes32 = [u8; 32];
pub type Address = [u8; 20];
pub type Uint256 = BigUint;
pub type Int256 = BigInt;
pub type Signature = [u8; 65];
pub type PrivateKey = [u8; 64];

#[derive(Copy, Clone)]
pub enum Participant {
  Zero = 0,
  One = 1
}

pub struct Channel {
  channelId: Bytes32,
  addresses: [Address; 2],
  ended: bool,
  closed: bool,
  balances: [Uint256; 2],
  totalBalance: Uint256,
  hashlocks: Vec<Hashlock>,
  sequenceNumber: Uint256,
  me: Participant
}

struct Hashlock {
  hash: Bytes32,
  amount: Int256
}