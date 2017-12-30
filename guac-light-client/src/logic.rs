extern crate rand;

use types::{Address, Bytes32, Channel, NewChannelTx, Participant, Uint256};
use storage::Storage;
use crypto::Crypto;
use network_client::CounterpartyAPI;


pub struct Logic<CP: CounterpartyAPI, ST: Storage> {
  pub crypto: Crypto,
  pub counterpartyAPI: CP,
  pub storage: ST,
}

impl<CP: CounterpartyAPI, ST: Storage> Logic<CP, ST> {
  pub fn propose_channel(
    self,
    channel_id: Bytes32,
    my_address: Address,
    their_address: Address,
    my_balance: Uint256,
    their_balance: Uint256,
    settling_period: Uint256,
  ) -> Result<(), String> {
    let channel = Channel::new(
      channel_id,
      [my_address, their_address],
      [my_balance, their_balance],
      Participant::Zero,
    );

    try!(self.storage.new_channel(channel));

    let mut tx = NewChannelTx {
      channel_id: rand::random::<Bytes32>(),
      address0: my_address,
      address1: their_address,
      balance0: my_balance,
      balance1: their_balance,
      settling_period,
      signature0: None,
      signature1: None,
    };

    tx.signature0 = Some(try!(self.crypto.sign(&my_address, &tx.get_fingerprint())));

    let counterparty = match try!(self.storage.get_counterparty(&their_address)) {
      Some(counterparty) => counterparty,
      None => return Err(String::from("Could not find counterparty")),
    };

    try!(
      self
        .counterpartyAPI
        .add_proposed_channel(counterparty.url, tx)
    );

    Ok(())
  }
}
