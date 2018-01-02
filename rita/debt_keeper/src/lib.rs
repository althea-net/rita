#[macro_use]
extern crate derive_error;
use std::net::IpAddr;


extern crate althea_types;
use althea_types::EthAddress;

extern crate num256;
use num256::Uint256;

extern crate stash;

extern crate rita_types;
use rita_types::DebtAction;

mod debts;


#[derive(Debug, Error)]
pub enum Error {
    #[error(msg_embedded, no_from, non_std)] DebtKeeperError(String),
}

use debts::{Debts, Neighbor};
pub use debts::Key;
use num256::Int256;

pub struct DebtKeeper {
    debts: Debts,
    pay_threshold: Int256,
    close_threshold: Int256,
}

impl DebtKeeper {
    pub fn new(pay_threshold: Int256, close_threshold: Int256) -> Self {
        DebtKeeper {
            debts: Debts::new(),
            pay_threshold,
            close_threshold,
        }
    }

    pub fn add_neighbor(&mut self, ip_addr: IpAddr, eth_addr: EthAddress) {
        self.debts.insert(Neighbor {
            ip_addr,
            eth_addr,
            debt: Int256::from(0),
        })
    }

    pub fn apply_debt(&mut self, key: Key, debt: Int256) -> Result<Option<DebtAction>, Error> {
        match self.debts.get(&key) {
            Some(mut neigh) => {
                neigh.debt = neigh.debt + debt;
                let new_debt = neigh.debt.clone();

                self.debts.insert(neigh);
                Ok(self.check_thresholds(new_debt))
            }
            None => Err(Error::DebtKeeperError(format!("No entry for {:?}", key))),
        }
    }

    pub fn check_thresholds(&self, debt: Int256) -> Option<DebtAction> {
        if debt < self.close_threshold {
            Some(DebtAction::CloseTunnel)
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
