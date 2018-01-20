#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate derive_error;

use std::net::IpAddr;
use std::collections::HashMap;
use std::ops::{Add, Sub};

extern crate serde;

extern crate althea_types;
use althea_types::{EthAddress, Identity};

extern crate num256;
use num256::{Uint256, Int256};

extern crate eui48;
use eui48::MacAddress;

extern crate stash;

#[derive(Debug, Error)]
pub enum Error {
    #[error(msg_embedded, no_from, non_std)] DebtKeeperError(String),
}

pub struct DebtKeeper {
    debts: HashMap<Identity, Int256>,
    pay_threshold: Int256,
    close_threshold: Int256,
}

#[derive(Debug, PartialEq)]
pub enum DebtAction {
    SuspendTunnel,
    OpenTunnel,
    MakePayment(Uint256),
}

#[derive(Debug, PartialEq)]
pub struct DebtAdjustment {
    pub ident: Identity,
    pub amount: Int256,
}

impl DebtKeeper {
    pub fn new(pay_threshold: Int256, close_threshold: Int256) -> Self {
        assert!(pay_threshold > Int256::from(0));
        assert!(close_threshold < Int256::from(0));
        DebtKeeper {
            debts: HashMap::new(),
            pay_threshold,
            close_threshold,
        }
    }

    pub fn apply_debt(&mut self, ident: Identity, debt: Int256) -> Option<DebtAction> {
        let stored_debt = self.debts.entry(ident).or_insert(Int256::from(0));
        let old_debt = stored_debt.clone();

        *stored_debt = stored_debt.clone().add(debt.clone());

        if *stored_debt < self.close_threshold {
            Some(DebtAction::SuspendTunnel)
        } else if (self.close_threshold < *stored_debt) && (old_debt < self.close_threshold) {
            Some(DebtAction::OpenTunnel)
        } else if *stored_debt > self.pay_threshold {
            Some(DebtAction::MakePayment(Uint256::from(stored_debt.clone())))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_suspend() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10));

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            ip_address: "2001::3".parse().unwrap(),
            mac_address: MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
        };

        assert_eq!(
            d.apply_debt(ident, Int256::from(-100)).unwrap(),
            DebtAction::SuspendTunnel
        );
    }

    #[test]
    fn test_single_pay() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10));

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            ip_address: "2001::3".parse().unwrap(),
            mac_address: MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
        };

        assert_eq!(
            d.apply_debt(ident, Int256::from(100)).unwrap(),
            DebtAction::MakePayment(Uint256::from(100u32))
        );
    }

    #[test]
    fn test_single_reopen() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10));

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            ip_address: "2001::3".parse().unwrap(),
            mac_address: MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
        };

        assert_eq!(
            d.apply_debt(ident, Int256::from(-100)).unwrap(),
            DebtAction::SuspendTunnel
        );

        assert_eq!(
            d.apply_debt(ident, Int256::from(110)).unwrap(),
            DebtAction::OpenTunnel
        );
    }

    #[test]
    fn test_multi_pay() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10));

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            ip_address: "2001::3".parse().unwrap(),
            mac_address: MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
        };

        // send lots of payments
        for i in 0..100 {
            assert_eq!(
                d.apply_debt(ident, Int256::from(100)).unwrap(),
                DebtAction::MakePayment(Uint256::from(100u32 * (i + 1)))
            );
        }
    }

    #[test]
    fn test_multi_fail() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10));

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            ip_address: "2001::3".parse().unwrap(),
            mac_address: MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
        };

        // send lots of payments
        for i in 0..100 {
            assert_eq!(
                d.apply_debt(ident, Int256::from(100)).unwrap(),
                DebtAction::MakePayment(Uint256::from(100u32 * (i + 1)))
            );
        }

        // rack up lots of debt
        for i in 0..99 {
            assert_eq!(
                d.apply_debt(ident, Int256::from(-100)).unwrap(),
                DebtAction::MakePayment(Uint256::from(100u32 * (99 - i)))
            );
        }

        // should have +100 credit
        assert_eq!(
            d.apply_debt(ident, Int256::from(-200)).unwrap(),
            DebtAction::SuspendTunnel
        );
    }

    #[test]
    fn test_multi_reopen() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10));

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            ip_address: "2001::3".parse().unwrap(),
            mac_address: MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
        };

        // send lots of payments
        for i in 0..100 {
            assert_eq!(
                d.apply_debt(ident, Int256::from(100)).unwrap(),
                DebtAction::MakePayment(Uint256::from(100u32 * (i + 1)))
            );
        }

        // rack up lots of debt
        for i in 0..99 {
            assert_eq!(
                d.apply_debt(ident, Int256::from(-100)).unwrap(),
                DebtAction::MakePayment(Uint256::from(100u32 * (99 - i)))
            );
        }

        // should have +100 credit
        assert_eq!(
            d.apply_debt(ident, Int256::from(-200)).unwrap(),
            DebtAction::SuspendTunnel
        );

        // should have -100 credit

        assert_eq!(
            d.apply_debt(ident, Int256::from(200)).unwrap(),
            DebtAction::OpenTunnel
        );
    }
}
