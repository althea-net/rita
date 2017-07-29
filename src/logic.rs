use types::{Bytes32, Address, Uint256, Channel};
use storage::Storage;
use crypto;

struct Logic {
    storage: Storage
}

impl Logic {
  pub fn proposeChannel (
    channelId: Bytes32,
    counterPartyURL: String,
    myAddress: Address,
    theirAddress: Address,
    myBalance: Uint256,
    theirBalance: Uint256,
    settlingPeriod: Uint256
  ) {
    
  }
}