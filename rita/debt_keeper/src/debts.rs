use stash::Stash;
use num256::Int256;
use std::collections::HashMap;
use althea_types::EthAddress;
use std::net::IpAddr;
use std::hash::Hash;
use std::cmp::Eq;

pub struct Debts {
  stash: Stash<Debt>,
  eth_index: HashMap<EthAddress, usize>,
  ip_index: HashMap<IpAddr, usize>,
}

#[derive(Clone)]
pub struct Debt {
  pub eth_addr: EthAddress,
  pub ip_addr: IpAddr,
  pub amount: Int256,
}

#[derive(Debug, Clone)]
pub enum Key {
  EthAddress(EthAddress),
  IpAddr(IpAddr),
}

impl Debts {
  pub fn insert(&mut self, item: Debt) {
    let key = self.stash.put(item.clone());
    self.eth_index.insert(item.eth_addr, key);
    self.ip_index.insert(item.ip_addr, key);
  }
  pub fn get(&self, key: &Key) -> Option<Debt> {
    let k = match *key {
      Key::EthAddress(k) => self.eth_index.get(&k),
      Key::IpAddr(k) => self.ip_index.get(&k),
    };
    match k {
      Some(k) => self.stash.get(*k).cloned(),
      None => None,
    }
  }
}

#[cfg(test)]
mod tests {
  #[test]
  fn it_works() {
    assert_eq!(2 + 2, 4);
  }
}
