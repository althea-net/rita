#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate derive_error;

use std::net::IpAddr;
use std::collections::HashMap;
use std::ops::Add;

extern crate serde;

extern crate althea_types;
use althea_types::EthAddress;

extern crate num256;
use num256::Uint256;

extern crate eui48;
use eui48::MacAddress;

extern crate stash;
use num256::Int256;

mod debts;
use debts::{Debts, Neighbor};
pub use debts::Key;

#[derive(Debug, Error)]
pub enum Error {
    #[error(msg_embedded, no_from, non_std)] DebtKeeperError(String),
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
pub struct Identity {
    pub ip_address: IpAddr,
    pub eth_address: EthAddress,
    pub mac_address: MacAddress,
}

pub struct DebtKeeper {
    debts: HashMap<Identity, Int256>,
    pay_threshold: Int256,
    close_threshold: Int256,
}

pub enum DebtAction {
    SuspendTunnel,
    MakePayment(Uint256),
}

pub struct DebtAdjustment {
    pub ident: Identity,
    pub amount: Int256,
}

impl DebtKeeper {
    pub fn new(pay_threshold: Int256, close_threshold: Int256) -> Self {
        DebtKeeper {
            debts: HashMap::new(),
            pay_threshold,
            close_threshold,
        }
    }

    pub fn apply_debt(&mut self, ident: Identity, debt: Int256) -> Option<DebtAction> {
        let stored_debt = self.debts.entry(ident).or_insert(Int256::from(0));
        *stored_debt = stored_debt.clone().add(debt.clone());

        if debt < self.close_threshold {
            Some(DebtAction::SuspendTunnel)
        } else if debt > self.pay_threshold {
            Some(DebtAction::MakePayment(Uint256::from(debt)))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        let eth_addr = "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
            .parse()
            .unwrap();
        let ip_addr = "2001::3".parse().unwrap();
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(10));

        d.add_neighbor(ip_addr, eth_addr);

        assert_eq!(
            d.apply_debt(Key::EthAddress(eth_addr), Int256::from(7))
                .unwrap(),
            (true, Int256::from(7))
        );
    }
}
