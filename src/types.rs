// extern crate num_bigint;
extern crate num;

use self::num::bigint::{BigUint, BigInt};
// use self::num::Bounded;

pub type Bytes32 = [u8; 32];
pub type Address = [u8; 20];
pub type Uint256 = BigUint;
pub type Int256 = BigInt;
pub type Signature = [u8; 65];
pub type PrivateKey = [u8; 64];

pub struct Channel {
  channelId: Bytes32,
  address0: Address,
  address1: Address,
  ended: bool,
  closed: bool,
  balance0: Uint256,
  balance1: Uint256,
  totalBalance: Uint256,
  hashlocks: Vec<Hashlock>,
  sequenceNumber: Uint256
}

struct Hashlock {
  hash: Bytes32,
  amount: Int256
}