use std::net::IpAddr;
use types::NewChannelTx;


pub trait NetworkClient {
  fn send(self, address: IpAddr, payload: &[u8]) -> Result<&[u8], String>;
  fn add_proposed_channel(self, tx: NewChannelTx) -> Result<(), String>;
}

// Test stub struct implementing fake network client
struct FakeClient;

// Implementation of non NetworkApi methods
impl FakeClient {
  fn new() -> FakeClient {
    FakeClient {}
  }
}

impl NetworkClient for FakeClient {
  fn send(self, address: IpAddr, payload: &[u8]) -> Result<&[u8], String> {
    let vec = vec![2, 2];
    Ok(&vec)
  }
  fn add_proposed_channel(self, tx: NewChannelTx) -> Result<(), String> {
    Ok(())
  }
}
