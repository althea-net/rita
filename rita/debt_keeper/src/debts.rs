use stash::Stash;
use num256::Int256;
use std::collections::HashMap;
use althea_types::EthAddress;
use std::net::IpAddr;
use std::hash::Hash;
use std::cmp::Eq;

#[derive(Debug, Error)]
pub enum Error {
  #[error(msg_embedded, no_from, non_std)] DebtsError(String),
}


pub struct Debts {
  stash: Stash<Debt>,
  eth_index: HashMap<EthAddress, usize>,
  ip_index: HashMap<IpAddr, usize>,
}

#[derive(Clone)]
pub struct Debt {
  eth_addr: EthAddress,
  ip_addr: IpAddr,
  debt: Int256,
}

pub enum Key {
  EthAddress(EthAddress),
  IpAddr(IpAddr),
}

impl Debts {
  pub fn insert(&mut self, item: Debt) -> Result<(), Error> {
    let key = self.stash.put(item.clone());
    self.eth_index.insert(item.eth_addr, key);
    self.ip_index.insert(item.ip_addr, key);
    Ok(())
  }
  pub fn get(&self, key: Key) -> Result<Option<Debt>, Error> {
    let k = match key {
      Key::EthAddress(k) => self.eth_index.get(&k),
      Key::IpAddr(k) => self.ip_index.get(&k),
    };
    match k {
      Some(k) => Ok(self.stash.get(*k).cloned()),
      None => Ok(None),
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
