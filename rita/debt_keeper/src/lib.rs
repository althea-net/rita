#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate derive_error;

#[macro_use] extern crate log;

use std::net::IpAddr;
use std::collections::HashMap;
use std::ops::{Add, Sub, Div};
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

struct NodeDebtData {
    temp_balance: Int256,
    total_payment: Uint256,
    debt: Int256,
}

impl NodeDebtData {
    fn new() -> NodeDebtData {
        NodeDebtData{
            temp_balance: Int256::from(0),
            total_payment: Uint256::from(0u32),
            debt: Int256::from(0),
        }
    }
}

pub struct DebtKeeper {
    debt_data: HashMap<Identity, NodeDebtData>,
    pay_threshold: Int256,
    close_fraction: Int256,
    close_threshold: Int256, // Connection is closed when debt < close_fraction * total_payment + close_threshold
}

/// The actions that a `DebtKeeper` can take.
#[derive(Debug, PartialEq)]
pub enum DebtKeeperMsg {
    UpdateBalance { from: Identity, amount: Int256 },
    SendUpdate { from: Identity},
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
    pub fn start(pay_threshold: Int256, close_threshold: Int256, close_fraction: Int256) ->
        (Sender<DebtKeeperMsg>, Receiver<Option<DebtAction>>)
    {
        let mut keeper = DebtKeeper::new(pay_threshold, close_threshold, close_fraction);
        let (input_tx, input_rx) = channel();
        let (output_tx, output_rx) = channel();

        thread::spawn(move || {
            for msg in input_rx {
                match msg {
                    DebtKeeperMsg::UpdateBalance { from, amount } => keeper.update_balance(from, amount),
                    DebtKeeperMsg::SendUpdate { from } => output_tx.send(
                        keeper.send_update(from)
                    ).unwrap(),
                    DebtKeeperMsg::StopThread => return
                };
            }
        });
        (input_tx, output_rx)
    }

    pub fn new(pay_threshold: Int256, close_threshold: Int256, close_fraction: Int256) -> Self {
        assert!(pay_threshold >= Int256::from(0));
        assert!(close_fraction > Int256::from(0));
        DebtKeeper {
            debt_data: HashMap::new(),
            pay_threshold,
            close_fraction,
            close_threshold,
        }
    }

    fn update_balance(&mut self, ident: Identity, amount: Int256) {
        let debt_data = self.debt_data.entry(ident).or_insert(NodeDebtData::new());
        let old_balance = debt_data.temp_balance.clone();

        trace!("apply_payment: old balance for {:?}: {:?}", ident.ip_address, old_balance);

        debt_data.temp_balance = old_balance.clone().add(amount.clone());
        debt_data.total_payment = debt_data.total_payment.clone().add(Uint256::from(amount.clone()));
        trace!("new balance for {:?}: {:?}", ident.ip_address, debt_data.temp_balance);
    }

    /// This updates a neighbor's debt and outputs a DebtAction if one is necessary.
    fn send_update(&mut self, ident: Identity) -> Option<DebtAction> {
        let debt_data = self.debt_data.entry(ident).or_insert(NodeDebtData::new());
        let debt = debt_data.debt.clone();

        let payment_balance = debt_data.temp_balance.clone();

        trace!(
            "apply_traffic for {:?}: debt: {:?}, payment balance: {:?}",
            ident.ip_address,
            debt,
            payment_balance
        );

        debt_data.temp_balance = Int256::from(0);
        debt_data.debt = debt.clone().add(Int256::from(payment_balance));

        let close_threshold = self.close_threshold.clone() - Int256::from(debt_data.total_payment.clone()).div(self.close_fraction.clone());

        if debt_data.debt < close_threshold {
            trace!("debt is below close threshold. suspending forwarding");
            Some(DebtAction::SuspendTunnel)
        } else if (close_threshold < debt_data.debt) && (debt < close_threshold) {
            trace!("debt is above close threshold. resuming forwarding");
            Some(DebtAction::OpenTunnel)
        } else if debt_data.debt > self.pay_threshold {
            trace!("debt is above payment threshold. making payment");
            let d = debt_data.debt.clone();
            debt_data.debt = Int256::from(0);
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
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10), Int256::from(100));

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            ip_address: "2001::3".parse().unwrap(),
            mac_address: MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
        };

        d.update_balance(ident, Int256::from(-100));

        assert_eq!(
            d.send_update(ident).unwrap(),
            DebtAction::SuspendTunnel
        );
    }

    #[test]
    fn test_single_pay() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10), Int256::from(100));

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            ip_address: "2001::3".parse().unwrap(),
            mac_address: MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
        };

        d.update_balance(ident, Int256::from(100));

        assert_eq!(
            d.send_update(ident).unwrap(),
            DebtAction::MakePayment{amount: Uint256::from(100u32), to: ident}
        );
    }

    #[test]
    fn test_fudge() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-1), Int256::from(100));

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            ip_address: "2001::3".parse().unwrap(),
            mac_address: MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
        };

        d.update_balance(ident, Int256::from(100000));
        d.update_balance(ident, Int256::from(-100100));

        assert_eq!(
            d.send_update(ident),
            None
        );
    }

    #[test]
    fn test_single_reopen() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10), Int256::from(100));

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            ip_address: "2001::3".parse().unwrap(),
            mac_address: MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
        };

        d.update_balance(ident, Int256::from(-100));

        assert_eq!(
            d.send_update(ident).unwrap(),
            DebtAction::SuspendTunnel
        );

        d.update_balance(ident, Int256::from(110));

        assert_eq!(
            d.send_update(ident).unwrap(),
            DebtAction::OpenTunnel
        );
    }

    #[test]
    fn test_multi_pay() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10), Int256::from(100));

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            ip_address: "2001::3".parse().unwrap(),
            mac_address: MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
        };

        // send lots of payments
        for i in 0..100 {
            d.update_balance(ident, Int256::from(100))
        }

        assert_eq!(
            d.send_update(ident).unwrap(),
            DebtAction::MakePayment{amount: Uint256::from(10000u32), to: ident}
        );
    }

    #[test]
    fn test_multi_fail() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10), Int256::from(100000));

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            ip_address: "2001::3".parse().unwrap(),
            mac_address: MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
        };

        // send lots of payments
        for i in 0..100 {
            d.update_balance(ident, Int256::from(100))
        }

        d.update_balance(ident, Int256::from(-10100));

        assert_eq!(
            d.send_update(ident).unwrap(),
            DebtAction::SuspendTunnel
        );
    }

    #[test]
    fn test_multi_reopen() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10), Int256::from(1000000000));

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            ip_address: "2001::3".parse().unwrap(),
            mac_address: MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
        };

        for i in 0..100 {
            d.update_balance(ident, Int256::from(100))
        }

        d.update_balance(ident, Int256::from(-10100));

        assert_eq!(
            d.send_update(ident).unwrap(),
            DebtAction::SuspendTunnel
        );

        d.update_balance(ident, Int256::from(200));

        assert_eq!(
            d.send_update(ident).unwrap(),
            DebtAction::OpenTunnel
        );
    }
}
