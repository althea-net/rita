use std::net::IpAddr;
use types::NewChannelTx;

pub trait CounterpartyAPI {
  fn send(self, url: String, payload: &[u8]) -> Result<Vec<u8>, String>;
  fn add_proposed_channel(self, url: String, tx: NewChannelTx) -> Result<(), String>;
}

// Test stub struct implementing fake network client
struct FakeClient;

// Implementation of non NetworkApi methods
impl FakeClient {
  fn new() -> FakeClient {
    FakeClient {}
  }
}

impl CounterpartyAPI for FakeClient {
  fn send(self, url: String, payload: &[u8]) -> Result<Vec<u8>, String> {
    let vec = vec![2, 2];
    Ok(vec)
  }
  fn add_proposed_channel(self, url: String, tx: NewChannelTx) -> Result<(), String> {
    Ok(())
  }
}
