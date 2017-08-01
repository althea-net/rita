use types::{Bytes32, Address, Uint256, Channel, Participant};
use storage::Storage;
use crypto;

struct Logic {
    storage: Storage
}

impl Logic {
  pub fn propose_channel (
    &mut self,
    channel_id: Bytes32,
    my_address: Address,
    their_address: Address,
    my_balance: Uint256,
    their_balance: Uint256,
    settlingPeriod: Uint256
  ) -> Result<(), String> {
    let chan = Channel::new(
      channel_id,
      [my_address, their_address],
      [my_balance, their_balance],
      Participant::Zero,
    ); 

    try!(self.storage.new_channel(chan));

    Ok(())
  }
}