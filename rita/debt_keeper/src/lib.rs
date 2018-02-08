#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate derive_error;

#[macro_use] extern crate log;

use std::net::IpAddr;
use std::collections::{HashMap, VecDeque};
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

#[derive(Clone, Debug)]
struct NodeDebtData {
    total_payment: Uint256,
    debt: Int256,
    incoming_payments: Int256,
    /// Front = older
    /// Only pop from front
    /// Only push to back
    debt_buffer: VecDeque<Int256>,
}

impl NodeDebtData {
    fn new(buffer_period: u32) -> NodeDebtData {
        NodeDebtData{
            total_payment: Uint256::from(0u32),
            debt: Int256::from(0),
            incoming_payments: Int256::from(0),
            debt_buffer: {
                let mut buf = VecDeque::new();
                for i in 0..buffer_period {
                    buf.push_back(Int256::from(0));
                }
                buf
            },
        }
    }
}

pub struct DebtKeeper {
    buffer_period: u32,
    debt_data: HashMap<IpAddr, NodeDebtData>,
    pay_threshold: Int256,
    close_fraction: Int256,
    close_threshold: Int256, // Connection is closed when debt < total_payment/close_fraction + close_threshold
}

/// The actions that a `DebtKeeper` can take.
#[derive(Debug, PartialEq)]
pub enum DebtKeeperMsg {
    PaymentReceived { from: Identity, amount: Uint256 },
    TrafficUpdate { from: Identity, amount: Int256 },
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
    pub fn start(pay_threshold: Int256, close_threshold: Int256, close_fraction: Int256, buffer_period: u32) ->
        (Sender<DebtKeeperMsg>, Receiver<Option<DebtAction>>)
    {
        let mut keeper = DebtKeeper::new(pay_threshold, close_threshold, close_fraction, buffer_period);
        let (input_tx, input_rx) = channel();
        let (output_tx, output_rx) = channel();

        thread::spawn(move || {
            for msg in input_rx {
                match msg {
                    DebtKeeperMsg::PaymentReceived { from, amount } => keeper.payment_recieved(from, amount),
                    DebtKeeperMsg::TrafficUpdate { from, amount } => keeper.traffic_update(from, amount),
                    DebtKeeperMsg::SendUpdate { from } => output_tx.send(
                        keeper.send_update(from)
                    ).unwrap(),
                    DebtKeeperMsg::StopThread => return
                };
            }
        });
        (input_tx, output_rx)
    }

    pub fn new(pay_threshold: Int256, close_threshold: Int256, close_fraction: Int256, buffer_period: u32) -> Self {
        assert!(pay_threshold >= Int256::from(0));
        assert!(close_fraction > Int256::from(0));
        DebtKeeper {
            debt_data: HashMap::new(),
            pay_threshold,
            close_fraction,
            close_threshold,
            buffer_period
        }
    }

    fn payment_recieved(&mut self, ident: Identity, amount: Uint256) {
        trace!("debt data: {:#?}", self.debt_data);
        let debt_data = self.debt_data.entry(ident.ip_address).or_insert(NodeDebtData::new(self.buffer_period));

        let old_balance = debt_data.incoming_payments.clone();
        trace!("payment_recieved: old balance for {:?}: {:?}", ident.ip_address, old_balance);
        debt_data.incoming_payments += amount.clone();
        debt_data.total_payment += amount.clone();

        trace!("new balance for {:?}: {:?}", ident.ip_address, debt_data.incoming_payments);
    }

    fn traffic_update(&mut self, ident: Identity, amount: Int256) {
        {
            let debt_data = self.debt_data.entry(ident.ip_address).or_insert(NodeDebtData::new(self.buffer_period));

            if amount < Int256::from(0) {
                // Buffer debt in the back of the debt buffer
                debt_data.debt_buffer[(self.buffer_period - 1) as usize] += amount;
            } else {
                // Immediately apply credit
                debt_data.debt += amount;
            }
        } // borrowck

        let mut imbalance = Uint256::from(0u32);
        for (k, v) in self.debt_data.clone() {
            imbalance = imbalance.clone() + v.debt.abs();
        }
        trace!("total debt imbalance: {}", imbalance);
    }

    /// This updates a neighbor's debt and outputs a DebtAction if one is necessary.
    fn send_update(&mut self, ident: Identity) -> Option<DebtAction> {
        trace!("debt data: {:#?}", self.debt_data);
        let debt_data = self.debt_data.entry(ident.ip_address).or_insert(NodeDebtData::new(self.buffer_period));
        let debt = debt_data.debt.clone();

        let traffic = debt_data.debt_buffer.pop_front().unwrap();
        debt_data.debt_buffer.push_back(Int256::from(0));

        trace!(
            "send_update for {:?}: debt: {:?}, payment balance: {:?}, traffic: {:?}",
            ident.ip_address,
            debt,
            debt_data.incoming_payments,
            traffic
        );

        if debt_data.incoming_payments > -traffic.clone() {
            // we have enough to pay off the traffic from just the payment balance
            debt_data.incoming_payments += traffic.clone();

            // pay off some debt if we have extra
            if debt_data.debt > Int256::from(0) {
                // no need to pay off
            } else if debt_data.debt < -debt_data.incoming_payments.clone() {
                // not enough to pay off fully
                debt_data.debt += debt_data.incoming_payments.clone();
                debt_data.incoming_payments = Int256::from(0);
            } else {
                // pay off debt fully
                debt_data.incoming_payments += debt_data.debt.clone();
                debt_data.debt = Int256::from(0);
            }
        } else {
            // rack up debt
            debt_data.debt += debt_data.incoming_payments.clone() + traffic;
            debt_data.incoming_payments = Int256::from(0);
        }

        let close_threshold = self.close_threshold.clone() - debt_data.total_payment.clone()/self.close_fraction.clone();

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
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10), Int256::from(100), 1u32);

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            ip_address: "2001::3".parse().unwrap(),
            mac_address: MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
        };

        d.traffic_update(ident, Int256::from(-100));

        assert_eq!(
            d.send_update(ident).unwrap(),
            DebtAction::SuspendTunnel
        );
    }

    #[test]
    fn test_single_overpay() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10), Int256::from(100), 1u32);

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            ip_address: "2001::3".parse().unwrap(),
            mac_address: MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
        };

        d.traffic_update(ident, Int256::from(-100));
        d.payment_recieved(ident, Uint256::from(1000));

        assert_eq!(
            d.send_update(ident),
            None
        );
    }

    #[test]
    fn test_buffer_suspend() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10), Int256::from(100), 2u32);

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            ip_address: "2001::3".parse().unwrap(),
            mac_address: MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
        };

        d.traffic_update(ident, Int256::from(-100));

        assert_eq!(
            d.send_update(ident),
            None
        );

        assert_eq!(
            d.send_update(ident).unwrap(),
            DebtAction::SuspendTunnel
        );
    }

    #[test]
    fn test_buffer_average() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10), Int256::from(100), 2u32);

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            ip_address: "2001::3".parse().unwrap(),
            mac_address: MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
        };

        d.traffic_update(ident, Int256::from(-100));

        assert_eq!(
            d.send_update(ident),
            None
        );

        d.traffic_update(ident, Int256::from(100));

        assert_eq!(
            d.send_update(ident),
            None
        );
    }

    #[test]
    fn test_buffer_repay() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10), Int256::from(100), 2u32);

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            ip_address: "2001::3".parse().unwrap(),
            mac_address: MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
        };

        d.traffic_update(ident, Int256::from(-100));

        assert_eq!(
            d.send_update(ident),
            None
        );

        d.payment_recieved(ident, Uint256::from(100));

        assert_eq!(
            d.send_update(ident),
            None
        );
    }

    #[test]
    fn test_buffer_overpay() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10), Int256::from(100), 2u32);

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            ip_address: "2001::3".parse().unwrap(),
            mac_address: MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
        };

        d.traffic_update(ident, Int256::from(-100));

        assert_eq!(
            d.send_update(ident),
            None
        );

        d.traffic_update(ident, Int256::from(-100));
        d.payment_recieved(ident, Uint256::from(1000));

        assert_eq!(
            d.send_update(ident),
            None
        );
    }

    #[test]
    fn test_buffer_debt() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-100), Int256::from(100), 2u32);

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            ip_address: "2001::3".parse().unwrap(),
            mac_address: MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
        };

        d.traffic_update(ident, Int256::from(-50));

        assert_eq!(
            d.send_update(ident),
            None
        );

        assert_eq!(
            d.send_update(ident),
            None
        );

        // our debt should be -50

        d.traffic_update(ident, Int256::from(100));

        assert_eq!(
            d.send_update(ident).unwrap(),
            DebtAction::MakePayment{amount: Uint256::from(50u32), to: ident}
        );
    }

    #[test]
    fn test_single_pay() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10), Int256::from(100), 1u32);

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            ip_address: "2001::3".parse().unwrap(),
            mac_address: MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
        };

        d.traffic_update(ident, Int256::from(100));

        assert_eq!(
            d.send_update(ident).unwrap(),
            DebtAction::MakePayment{amount: Uint256::from(100u32), to: ident}
        );
    }

    #[test]
    fn test_fudge() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-1), Int256::from(100), 1u32);

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            ip_address: "2001::3".parse().unwrap(),
            mac_address: MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
        };

        d.payment_recieved(ident, Uint256::from(100000));
        d.traffic_update(ident, Int256::from(-100100));

        assert_eq!(
            d.send_update(ident),
            None
        );
    }

    #[test]
    fn test_single_reopen() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10), Int256::from(100), 1u32);

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            ip_address: "2001::3".parse().unwrap(),
            mac_address: MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
        };

        d.traffic_update(ident, Int256::from(-100));

        assert_eq!(
            d.send_update(ident).unwrap(),
            DebtAction::SuspendTunnel
        );

        d.payment_recieved(ident, Uint256::from(110));

        assert_eq!(
            d.send_update(ident).unwrap(),
            DebtAction::OpenTunnel
        );
    }

    #[test]
    fn test_multi_pay() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10), Int256::from(100), 1u32);

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            ip_address: "2001::3".parse().unwrap(),
            mac_address: MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
        };

        // send lots of payments
        for i in 0..100 {
            d.traffic_update(ident, Int256::from(100))
        }

        assert_eq!(
            d.send_update(ident).unwrap(),
            DebtAction::MakePayment{amount: Uint256::from(10000u32), to: ident}
        );
    }

    #[test]
    fn test_multi_fail() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10), Int256::from(100000), 1);

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            ip_address: "2001::3".parse().unwrap(),
            mac_address: MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
        };

        // send lots of payments
        for i in 0..100 {
            d.payment_recieved(ident, Uint256::from(100))
        }

        d.traffic_update(ident, Int256::from(-10100));

        assert_eq!(
            d.send_update(ident),
            Some(DebtAction::SuspendTunnel)
        );
    }

    #[test]
    fn test_multi_reopen() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10), Int256::from(1000000000), 1u32);

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            ip_address: "2001::3".parse().unwrap(),
            mac_address: MacAddress::parse_str("00:00:00:aa:00:02").unwrap(),
        };

        for i in 0..100 {
            d.payment_recieved(ident, Uint256::from(100))
        }

        d.traffic_update(ident, Int256::from(-10100));

        assert_eq!(
            d.send_update(ident).unwrap(),
            DebtAction::SuspendTunnel
        );

        d.payment_recieved(ident, Uint256::from(200));

        assert_eq!(
            d.send_update(ident).unwrap(),
            DebtAction::OpenTunnel
        );
    }
}
