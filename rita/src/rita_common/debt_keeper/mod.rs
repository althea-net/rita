use actix::prelude::*;

use std::collections::{HashMap, VecDeque};

use althea_types::{Identity, PaymentTx};

use num256::{Int256, Uint256};

use SETTING;

use rita_common::payment_controller;
use rita_common::payment_controller::PaymentController;

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
        NodeDebtData {
            total_payment: Uint256::from(0u32),
            debt: Int256::from(0),
            incoming_payments: Int256::from(0),
            debt_buffer: {
                let mut buf = VecDeque::new();
                for _ in 0..buffer_period {
                    buf.push_back(Int256::from(0));
                }
                buf
            },
        }
    }
}

pub struct DebtKeeper {
    buffer_period: u32,
    debt_data: HashMap<Identity, NodeDebtData>,
    pay_threshold: Int256,
    close_fraction: Int256,
    close_threshold: Int256, // Connection is closed when debt < total_payment/close_fraction + close_threshold
}

impl Actor for DebtKeeper {
    type Context = Context<Self>;
}

impl Supervised for DebtKeeper {}
impl SystemService for DebtKeeper {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("Debt Keeper started");
    }
}

pub struct Dump;

impl Message for Dump {
    type Result = Result<HashMap<Identity, NodeDebtData>, ()>;
}

impl Handler<Dump> for DebtKeeper {
    type Result = Result<HashMap<Identity, NodeDebtData>, ()>;
    fn handle(&mut self, _msg: Dump, _: &mut Context<Self>) -> Self::Result {
        Ok(self.debt_data.clone())
    }
}

#[derive(Message, PartialEq, Eq, Debug)]
pub struct PaymentReceived {
    pub from: Identity,
    pub amount: Uint256,
}

#[derive(Message)]
pub struct TrafficUpdate {
    pub from: Identity,
    pub amount: Int256,
}

#[derive(Message)]
pub struct SendUpdate;

pub struct GetDebt {
    pub from: Identity,
}
impl Message for GetDebt {
    type Result = Result<Uint256, ()>;
}

impl Supervised for DebtKeeper {}
impl SystemService for DebtKeeper {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("Debt Keeper started");
    }
}

/// Actions to be taken upon a neighbor's debt reaching either a negative or positive
/// threshold.
#[derive(Debug, PartialEq)]
pub enum DebtAction {
    SuspendTunnel,
    OpenTunnel,
    MakePayment { to: Identity, amount: Uint256 },
    None,
}

impl Handler<PaymentReceived> for DebtKeeper {
    type Result = ();

    fn handle(&mut self, msg: PaymentReceived, _: &mut Context<Self>) -> Self::Result {
        self.payment_received(&msg.from, msg.amount)
    }
}

impl Handler<TrafficUpdate> for DebtKeeper {
    type Result = ();

    fn handle(&mut self, msg: TrafficUpdate, _: &mut Context<Self>) -> Self::Result {
        self.traffic_update(&msg.from, msg.amount)
    }
}

impl Handler<SendUpdate> for DebtKeeper {
    type Result = ();

    fn handle(&mut self, _msg: SendUpdate, _ctx: &mut Context<Self>) -> Self::Result {
        info!("sending debt keeper update");
        trace!("total debt data: {:?}", self.debt_data);
        for (k, _) in self.debt_data.clone() {
            trace!("sending update for {:?}", k);
            match self.send_update(&k) {
                DebtAction::SuspendTunnel => {}
                DebtAction::OpenTunnel => {}
                DebtAction::MakePayment { to, amount } => PaymentController::from_registry()
                    .do_send(payment_controller::MakePayment(PaymentTx {
                        to,
                        from: SETTING.read().unwrap().get_identity(),
                        amount,
                    })),
                DebtAction::None => {}
            }
        }
    }
}

impl Default for DebtKeeper {
    fn default() -> DebtKeeper {
        Self::new(
            SETTING.read().unwrap().payment.pay_threshold.clone(),
            SETTING.read().unwrap().payment.close_threshold.clone(),
            SETTING.read().unwrap().payment.close_fraction.clone(),
            SETTING.read().unwrap().payment.buffer_period.clone(),
        )
    }
}

impl DebtKeeper {
    pub fn new(
        pay_threshold: Int256,
        close_threshold: Int256,
        close_fraction: Int256,
        buffer_period: u32,
    ) -> Self {
        assert!(pay_threshold >= Int256::from(0));
        assert!(close_fraction > Int256::from(0));

        DebtKeeper {
            debt_data: HashMap::new(),
            pay_threshold,
            close_fraction,
            close_threshold,
            buffer_period,
        }
    }

    fn payment_received(&mut self, ident: &Identity, amount: Uint256) {
        let buffer = self.buffer_period;
        let debt_data = self.debt_data
            .entry(ident.clone())
            .or_insert_with(|| NodeDebtData::new(buffer));

        let old_balance = debt_data.incoming_payments.clone();
        trace!(
            "payment received: old balance for {:?}: {:?}",
            ident.mesh_ip,
            old_balance
        );
        debt_data.incoming_payments += amount.clone();
        debt_data.total_payment += amount.clone();

        trace!(
            "new balance for {:?}: {:?}",
            ident.mesh_ip,
            debt_data.incoming_payments
        );
    }

    fn traffic_update(&mut self, ident: &Identity, mut amount: Int256) {
        {
            trace!("traffic update for {} is {}", ident.mesh_ip, amount);
            let buffer = self.buffer_period;
            let debt_data = self.debt_data
                .entry(ident.clone())
                .or_insert_with(|| NodeDebtData::new(buffer));

            if amount < Int256::from(0) {
                if debt_data.incoming_payments > -amount.clone() {
                    // can pay off debt fully
                    debt_data.incoming_payments += amount;
                    amount = Int256::from(0);
                } else {
                    // pay off part of it
                    amount += debt_data.incoming_payments.clone();
                    debt_data.incoming_payments = Int256::from(0);

                    // Buffer debt in the back of the debt buffer
                    debt_data.debt_buffer[(self.buffer_period - 1) as usize] += amount;
                }
            } else {
                // Immediately apply credit
                debt_data.debt += amount;
            }
            trace!("debt data for {} is {:?}", ident.mesh_ip, debt_data);
        } // borrowck

        let mut imbalance = Uint256::from(0u32);
        for (_, v) in self.debt_data.clone() {
            imbalance = imbalance.clone() + v.debt.abs();
        }
        trace!("total debt imbalance: {}", imbalance);
    }

    /// This updates a neighbor's debt and outputs a DebtAction if one is necessary.
    fn send_update(&mut self, ident: &Identity) -> DebtAction {
        trace!("debt data: {:?}", self.debt_data);
        let buffer = self.buffer_period;
        let debt_data = self.debt_data
            .entry(ident.clone())
            .or_insert_with(|| NodeDebtData::new(buffer));
        let debt = debt_data.debt.clone();

        let traffic = debt_data.debt_buffer.pop_front().unwrap();
        debt_data.debt_buffer.push_back(Int256::from(0));

        trace!(
            "send_update for {:?}: debt: {:?}, payment balance: {:?}, traffic: {:?}",
            ident.mesh_ip,
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

        let close_threshold = self.close_threshold.clone()
            - debt_data.total_payment.clone() / self.close_fraction.clone();

        if debt_data.debt < close_threshold {
            trace!(
                "debt is below close threshold for {}. suspending forwarding",
                ident.mesh_ip
            );
            DebtAction::SuspendTunnel
        } else if (close_threshold < debt_data.debt) && (debt < close_threshold) {
            trace!("debt is above close threshold. resuming forwarding");
            DebtAction::OpenTunnel
        } else if debt_data.debt > self.pay_threshold {
            let d = debt_data.debt.clone();
            trace!(
                "debt is above payment threshold for {}. making payment of {}",
                ident.mesh_ip,
                d
            );
            debt_data.debt = Int256::from(0);
            DebtAction::MakePayment {
                to: ident.clone(),
                amount: Uint256::from(d),
            }
        } else {
            DebtAction::None
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
            mesh_ip: "2001::3".parse().unwrap(),
            wg_public_key: String::from("AAAAAAAAAAA"),
        };

        d.traffic_update(&ident, Int256::from(-100));

        assert_eq!(d.send_update(&ident), DebtAction::SuspendTunnel);
    }

    #[test]
    fn test_single_overpay() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10), Int256::from(100), 1u32);

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            mesh_ip: "2001::3".parse().unwrap(),
            wg_public_key: String::from("AAAAAAAAAAA"),
        };

        d.traffic_update(&ident, Int256::from(-100));
        d.payment_received(&ident, Uint256::from(1000));

        assert_eq!(d.send_update(&ident), DebtAction::None,);
    }

    #[test]
    fn test_buffer_suspend() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10), Int256::from(100), 2u32);

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            mesh_ip: "2001::3".parse().unwrap(),
            wg_public_key: String::from("AAAAAAAAAAA"),
        };

        d.traffic_update(&ident, Int256::from(-100));

        assert_eq!(d.send_update(&ident), DebtAction::None,);

        assert_eq!(d.send_update(&ident), DebtAction::SuspendTunnel);
    }

    #[test]
    fn test_buffer_average() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10), Int256::from(100), 2u32);

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            mesh_ip: "2001::3".parse().unwrap(),
            wg_public_key: String::from("AAAAAAAAAAA"),
        };

        d.traffic_update(&ident, Int256::from(-100));

        assert_eq!(d.send_update(&ident), DebtAction::None,);

        d.traffic_update(&ident, Int256::from(100));

        assert_eq!(d.send_update(&ident), DebtAction::None,);
    }

    #[test]
    fn test_buffer_repay() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10), Int256::from(100), 2u32);

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            mesh_ip: "2001::3".parse().unwrap(),
            wg_public_key: String::from("AAAAAAAAAAA"),
        };

        d.traffic_update(&ident, Int256::from(-100));

        assert_eq!(d.send_update(&ident), DebtAction::None,);

        d.payment_received(&ident, Uint256::from(100));

        assert_eq!(d.send_update(&ident), DebtAction::None,);
    }

    #[test]
    fn test_buffer_overpay() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10), Int256::from(100), 2u32);

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            mesh_ip: "2001::3".parse().unwrap(),
            wg_public_key: String::from("AAAAAAAAAAA"),
        };

        d.traffic_update(&ident, Int256::from(-100));

        assert_eq!(d.send_update(&ident), DebtAction::None,);

        d.traffic_update(&ident, Int256::from(-100));
        d.payment_received(&ident, Uint256::from(1000));

        assert_eq!(d.send_update(&ident), DebtAction::None,);
    }

    #[test]
    fn test_buffer_debt() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-100), Int256::from(100), 2u32);

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            mesh_ip: "2001::3".parse().unwrap(),
            wg_public_key: String::from("AAAAAAAAAAA"),
        };

        d.traffic_update(&ident.clone(), Int256::from(-50));

        assert_eq!(d.send_update(&ident), DebtAction::None,);

        assert_eq!(d.send_update(&ident), DebtAction::None,);

        // our debt should be -50

        d.traffic_update(&ident, Int256::from(100));

        assert_eq!(
            d.send_update(&ident),
            DebtAction::MakePayment {
                amount: Uint256::from(50u32),
                to: ident,
            }
        );
    }

    #[test]
    fn test_single_pay() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10), Int256::from(100), 1u32);

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            mesh_ip: "2001::3".parse().unwrap(),
            wg_public_key: String::from("AAAAAAAAAAA"),
        };

        d.traffic_update(&ident, Int256::from(100));

        assert_eq!(
            d.send_update(&ident),
            DebtAction::MakePayment {
                amount: Uint256::from(100u32),
                to: ident,
            }
        );
    }

    #[test]
    fn test_fudge() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-1), Int256::from(100), 1u32);

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            mesh_ip: "2001::3".parse().unwrap(),
            wg_public_key: String::from("AAAAAAAAAAA"),
        };

        d.payment_received(&ident, Uint256::from(100000));
        d.traffic_update(&ident, Int256::from(-100100));

        assert_eq!(d.send_update(&ident), DebtAction::None,);
    }

    #[test]
    fn test_single_reopen() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10), Int256::from(100), 1u32);

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            mesh_ip: "2001::3".parse().unwrap(),
            wg_public_key: String::from("AAAAAAAAAAA"),
        };

        d.traffic_update(&ident, Int256::from(-100));

        assert_eq!(d.send_update(&ident), DebtAction::SuspendTunnel);

        d.payment_received(&ident, Uint256::from(110));

        assert_eq!(d.send_update(&ident), DebtAction::OpenTunnel);
    }

    #[test]
    fn test_multi_pay() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10), Int256::from(100), 1u32);

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            mesh_ip: "2001::3".parse().unwrap(),
            wg_public_key: String::from("AAAAAAAAAAA"),
        };

        // send lots of payments
        for i in 0..100 {
            d.traffic_update(&ident, Int256::from(100))
        }

        assert_eq!(
            d.send_update(&ident),
            DebtAction::MakePayment {
                amount: Uint256::from(10000u32),
                to: ident,
            }
        );
    }

    #[test]
    fn test_multi_fail() {
        let mut d = DebtKeeper::new(Int256::from(5), Int256::from(-10), Int256::from(100000), 1);

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            mesh_ip: "2001::3".parse().unwrap(),
            wg_public_key: String::from("AAAAAAAAAAA"),
        };

        // send lots of payments
        for i in 0..100 {
            d.payment_received(&ident, Uint256::from(100))
        }

        d.traffic_update(&ident, Int256::from(-10100));

        assert_eq!(d.send_update(&ident), DebtAction::SuspendTunnel);
    }

    #[test]
    fn test_multi_reopen() {
        let mut d = DebtKeeper::new(
            Int256::from(5),
            Int256::from(-10),
            Int256::from(1000000000),
            1u32,
        );

        let ident = Identity {
            eth_address: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
                .parse()
                .unwrap(),
            mesh_ip: "2001::3".parse().unwrap(),
            wg_public_key: String::from("AAAAAAAAAAA"),
        };

        for i in 0..100 {
            d.payment_received(&ident, Uint256::from(100))
        }

        d.traffic_update(&ident, Int256::from(-10100));

        assert_eq!(d.send_update(&ident), DebtAction::SuspendTunnel);

        d.payment_received(&ident, Uint256::from(200));

        assert_eq!(d.send_update(&ident), DebtAction::OpenTunnel);
    }
}
