#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate derive_error;

#[macro_use] extern crate log;

use std::net::IpAddr;
use std::collections::HashMap;
use std::ops::{Add, Sub};
use std::thread;
use std::sync::mpsc::{Sender, Receiver, channel};

extern crate serde;

extern crate althea_types;
use althea_types::{EthAddress, Identity};

extern crate num256;
use num256::{Uint256, Int256};

extern crate num_traits;
use num_traits::sign::Signed;

extern crate eui48;
use eui48::MacAddress;

extern crate stash;

#[derive(Debug, Error)]
pub enum Error {
    #[error(msg_embedded, no_from, non_std)] DebtKeeperError(String),
}

pub struct DebtKeeper {
    incoming_payments: HashMap<Identity, Uint256>,
    debts: HashMap<Identity, Int256>,
    pay_threshold: Int256,
    close_threshold: Int256,
}

/// The actions that a `DebtKeeper` can take. 
pub enum DebtKeeperMsg {
    Payment { from: Identity, amount: Uint256 },
    Traffic { from: Identity, amount: Int256 },
    StopThread
}

/// Actions to be taken upon a neighbor's debt reaching either a negative or positive
/// threshold. 
#[derive(Debug, PartialEq)]
pub enum DebtAction {
    SuspendTunnel,
    OpenTunnel,
    MakePayment {to: Identity, amount: Uint256},
}


impl DebtKeeper {
    pub fn start(pay_threshold: Int256, close_threshold: Int256) ->
        (Sender<DebtKeeperMsg>, Receiver<Option<DebtAction>>)
    {
        let mut keeper = DebtKeeper::new(pay_threshold, close_threshold);
        let (input_tx, input_rx) = channel();
        let (output_tx, output_rx) = channel();

        thread::spawn(move || {
            for msg in input_rx {
                match msg {
                    DebtKeeperMsg::Payment { from, amount } => keeper.apply_payment(from, amount),
                    DebtKeeperMsg::Traffic { from, amount } => output_tx.send(
                        keeper.apply_traffic(from, amount)
                    ).unwrap(),
                    DebtKeeperMsg::StopThread => return
                };
            }
        });
        (input_tx, output_rx)
    }

    pub fn new(pay_threshold: Int256, close_threshold: Int256) -> Self {
        assert!(pay_threshold > Int256::from(0));
        assert!(close_threshold < Int256::from(0));
        DebtKeeper {
            incoming_payments: HashMap::new(),
            debts: HashMap::new(),
            pay_threshold,
            close_threshold,
        }
    }

    fn apply_payment(&mut self, ident: Identity, amount: Uint256) {
        let stored_balance = self.incoming_payments.entry(ident).or_insert(Uint256::from(0 as u32));
        let old_balance = stored_balance.clone();

        trace!("apply_payment: old balance for {:?}: {:?}", ident.ip_address, old_balance);

        *stored_balance = stored_balance.clone().add(amount.clone());

        trace!("new balance for {:?}: {:?}", ident.ip_address, *stored_balance);
    }

    /// This updates a neighbor's debt and outputs a DebtAction if one is necessary.
    fn apply_traffic(&mut self, ident: Identity, traffic: Int256) -> Option<DebtAction> {
        let debt_ref = self.debts.entry(ident).or_insert(Int256::from(0));
        let debt = debt_ref.clone();

        let payment_balance_ref = self.incoming_payments.entry(ident).or_insert(Uint256::from(0 as u32));
        let payment_balance = payment_balance_ref.clone();

        trace!(
            "apply_traffic for {:?}: debt: {:?}, traffic: {:?}, payment balance: {:?}",
            ident.ip_address,
            debt,
            traffic,
            payment_balance
        );

        *payment_balance_ref = Uint256::from(0 as u32);
        *debt_ref = debt.clone().add(traffic).add(Int256::from(payment_balance));

        trace!("new debt for {:?}: {:?}", ident.ip_address, *debt_ref);

        if *debt_ref < self.close_threshold {
            trace!("debt is below close threshold. suspending forwarding");
            Some(DebtAction::SuspendTunnel)
        } else if (self.close_threshold < *debt_ref) && (debt < self.close_threshold) {
            trace!("debt is above close threshold. resuming forwarding");
            Some(DebtAction::OpenTunnel)
        } else if *debt_ref > self.pay_threshold {
            trace!("debt is above payment threshold. making payment");
            let d = debt_ref.clone();
            *debt_ref = Int256::from(0);
            Some(DebtAction::MakePayment{to: ident, amount: Uint256::from(d)})
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
            d.apply_traffic(ident, Int256::from(-100)).unwrap(),
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
            d.apply_traffic(ident, Int256::from(100)).unwrap(),
            DebtAction::MakePayment{amount: Uint256::from(100u32), to: ident}
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
            d.apply_traffic(ident, Int256::from(-100)).unwrap(),
            DebtAction::SuspendTunnel
        );

        assert_eq!(
            d.apply_traffic(ident, Int256::from(110)).unwrap(),
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
            d.apply_payment(ident, Uint256::from(100u32))
        }

        assert_eq!(
            d.apply_traffic(ident, Int256::from(0)).unwrap(),
            DebtAction::MakePayment{amount: Uint256::from(10000u32), to: ident}
        );
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
            d.apply_payment(ident, Uint256::from(100u32))
        }

        assert_eq!(
            d.apply_traffic(ident, Int256::from(-10100)).unwrap(),
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

        for i in 0..100 {
            d.apply_payment(ident, Uint256::from(100u32))
        }

        assert_eq!(
            d.apply_traffic(ident, Int256::from(-10100)).unwrap(),
            DebtAction::SuspendTunnel
        );

        d.apply_payment(ident, Uint256::from(200u32));

        assert_eq!(
            d.apply_traffic(ident, Int256::from(0)).unwrap(),
            DebtAction::OpenTunnel
        );
    }
}
