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

#[derive(Debug, Error)]
pub enum Error {
    #[error(msg_embedded, no_from, non_std)] DebtKeeperError(String),
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
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

#[derive(Debug, PartialEq)]
pub enum DebtAction {
    SuspendTunnel,
    MakePayment(Uint256),
}

#[derive(Debug, PartialEq)]
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

        return Some(DebtAction::MakePayment(Uint256::from(debt)));

        // TODO: put this back in when done testing

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
    #[test]
    fn it_works() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(10));

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            ip_address: "2001::3".parse().unwrap(),
            mac_address: MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
        };

        assert_eq!(
            d.apply_debt(ident, Int256::from(7)).unwrap(),
            DebtAction::SuspendTunnel
        );
    }
}
