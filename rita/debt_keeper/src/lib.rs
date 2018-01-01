#[macro_use]
extern crate derive_error;

extern crate althea_types;
extern crate num256;
extern crate stash;

mod debts;

use althea_types::EthAddress;
use std::net::IpAddr;

#[derive(Debug, Error)]
pub enum Error {
    #[error(msg_embedded, no_from, non_std)] DebtKeeperError(String),
}

use debts::{Debts, Key, Neighbor};
use num256::Int256;

pub struct DebtKeeper {
    debts: Debts,
    pay_threshold: Int256,
    close_threshold: Int256,
}

impl DebtKeeper {
    fn new(pay_threshold: Int256, close_threshold: Int256) -> Self {
        DebtKeeper {
            debts: Debts::new(),
            pay_threshold,
            close_threshold,
        }
    }

    fn add_neighbor(&mut self, ip_addr: IpAddr, eth_addr: EthAddress) {
        self.debts.insert(Neighbor {
            ip_addr,
            eth_addr,
            debt: Int256::from(0),
        })
    }

    fn apply_debt(&mut self, key: Key, debt: Int256) -> Result<(bool, Int256), Error> {
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

    fn check_thresholds(&self, debt: Int256) -> (bool, Int256) {
        let close = debt < self.close_threshold;

        let payment = if debt > self.pay_threshold {
            debt
        } else {
            Int256::from(0)
        };

        (close, payment)
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
