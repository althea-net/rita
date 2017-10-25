extern crate rand;


use types::{Address, Bytes32, Channel, NewChannelTx, Participant, Uint256};
use storage::Storage;
use crypto::Crypto;

pub trait CounterpartyApi {
  fn add_new_channel(&mut self, NewChannelTx) -> Result<(), String>;
}

pub struct Logic<T: CounterpartyApi> {
  pub storage: Storage,
  pub crypto: Crypto,
  pub counterparty: T,
}

pub struct Network {}

impl CounterpartyApi for Network {
  fn add_new_channel(&mut self, tx: NewChannelTx) -> Result<(), String> {
    Ok(())
  }
}

impl<T: CounterpartyApi> Logic<T> {
  pub fn propose_channel(
    &mut self,
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
      addresses: [my_address, their_address],
      balances: [my_balance, their_balance],
      settling_period,
      signatures: [None, None],
    };

    tx.signatures[1] = Some(try!(self.crypto.sign(&my_address, &tx.get_fingerprint())));

    let counterparty = match self.storage.get_counterparty(&their_address) {
      Some(counterparty) => counterparty,
      None => return Err(String::from("Could not find counterparty")),
    };

    Ok(())
  }
}
