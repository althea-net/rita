//! While traffic watcher keeps an eye on how much traffic flows and what that is worth debtkeeper
//! maintains the long term memory of who owes whow what so that it may later be quiered and paid
//! by payment manager in the current implementation or guac in the more final one

use actix::prelude::*;

use std::collections::{HashMap, VecDeque};

use althea_types::{Identity, PaymentTx};

use num256::{Int256, Uint256};

use settings::RitaCommonSettings;
use SETTING;

use rita_common::payment_controller;
use rita_common::payment_controller::PaymentController;

use failure::Error;

use std::ops::Add;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeDebtData {
    pub total_payment_received: Uint256,
    pub total_payment_sent: Uint256,
    pub debt: Int256,
    pub incoming_payments: Int256,
    /// Front = older
    /// Only pop from front
    /// Only push to back
    #[serde(skip_serializing)]
    pub debt_buffer: VecDeque<Int256>,
}

impl NodeDebtData {
    fn new(buffer_period: u32) -> NodeDebtData {
        NodeDebtData {
            total_payment_received: Uint256::from(0u32),
            total_payment_sent: Uint256::from(0u32),
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

pub type DebtData = HashMap<Identity, NodeDebtData>;

pub struct DebtKeeper {
    debt_data: DebtData,
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
    type Result = Result<DebtData, Error>;
}

impl Handler<Dump> for DebtKeeper {
    type Result = Result<DebtData, Error>;
    fn handle(&mut self, _msg: Dump, _: &mut Context<Self>) -> Self::Result {
        Ok(self.get_debts())
    }
}

#[derive(Message, PartialEq, Eq, Debug)]
pub struct PaymentReceived {
    pub from: Identity,
    pub amount: Uint256,
}

impl Handler<PaymentReceived> for DebtKeeper {
    type Result = ();

    fn handle(&mut self, msg: PaymentReceived, _: &mut Context<Self>) -> Self::Result {
        self.payment_received(&msg.from, msg.amount)
    }
}

#[derive(Message)]
pub struct TrafficUpdate {
    pub from: Identity,
    pub amount: Int256,
}

impl Handler<TrafficUpdate> for DebtKeeper {
    type Result = ();

    fn handle(&mut self, msg: TrafficUpdate, _: &mut Context<Self>) -> Self::Result {
        self.traffic_update(&msg.from, msg.amount)
    }
}

pub struct SendUpdate;

impl Message for SendUpdate {
    type Result = Result<(), Error>;
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

impl Handler<SendUpdate> for DebtKeeper {
    type Result = Result<(), Error>;

    fn handle(&mut self, _msg: SendUpdate, _ctx: &mut Context<Self>) -> Self::Result {
        trace!("sending debt keeper update");
        trace!("total debt data: {:?}", self.debt_data);
        for (k, _) in self.debt_data.clone() {
            trace!("sending update for {:?}", k);
            match self.send_update(&k) {
                DebtAction::SuspendTunnel => {}
                DebtAction::OpenTunnel => {}
                DebtAction::MakePayment { to, amount } => PaymentController::from_registry()
                    .do_send(payment_controller::MakePayment(PaymentTx {
                        to,
                        from: match SETTING.get_identity() {
                            Some(id) => id,
                            None => bail!("Identity has no mesh IP ready yet"),
                        },
                        amount,
                    })),
                DebtAction::None => {}
            }
        }
        Ok(())
    }
}

impl Default for DebtKeeper {
    fn default() -> DebtKeeper {
        Self::new()
    }
}

impl DebtKeeper {
    pub fn new() -> Self {
        assert!(SETTING.get_payment().pay_threshold >= Int256::from(0));
        assert!(SETTING.get_payment().close_fraction > Int256::from(0));

        DebtKeeper {
            debt_data: DebtData::new(),
        }
    }

    fn get_debts(&self) -> DebtData {
        self.debt_data.clone()
    }

    fn get_debt_data(&mut self, ident: &Identity) -> &mut NodeDebtData {
        let buffer = SETTING.get_payment().buffer_period;
        self.debt_data
            .entry(ident.clone())
            .or_insert_with(|| NodeDebtData::new(buffer))
    }

    fn payment_received(&mut self, ident: &Identity, amount: Uint256) {
        let debt_data = self.get_debt_data(ident);

        let old_balance = debt_data.incoming_payments.clone();
        trace!(
            "payment received: old balance for {:?}: {:?}",
            ident.mesh_ip,
            old_balance
        );
        // TODO: Refactor with BigInt/BigUint
        debt_data.incoming_payments = old_balance.clone().add(amount.clone());
        debt_data.total_payment_received = debt_data
            .total_payment_received
            .clone()
            .add(Uint256::from(amount.clone()));

        trace!(
            "new balance for {:?}: {:?}",
            ident.mesh_ip,
            debt_data.incoming_payments
        );
    }

    fn traffic_update(&mut self, ident: &Identity, mut amount: Int256) {
        {
            trace!("traffic update for {} is {}", ident.mesh_ip, amount);
            let debt_data = self.get_debt_data(ident);

            if amount < Int256::from(0) {
                if debt_data.incoming_payments > -amount.clone() {
                    // can pay off debt fully
                    debt_data.incoming_payments += amount;
                } else {
                    // pay off part of it
                    amount += debt_data.incoming_payments.clone();
                    debt_data.incoming_payments = Int256::from(0);

                    // Buffer debt in the back of the debt buffer
                    debt_data.debt_buffer[(SETTING.get_payment().buffer_period - 1) as usize] +=
                        amount;
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
        let debt_data = self.get_debt_data(ident);
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

        let close_threshold = SETTING.get_payment().close_threshold.clone()
            - debt_data.total_payment_received.clone()
                / SETTING.get_payment().close_fraction.clone();

        if debt_data.debt < close_threshold {
            trace!(
                "debt is below close threshold for {}. suspending forwarding",
                ident.mesh_ip
            );
            DebtAction::SuspendTunnel
        } else if (close_threshold < debt_data.debt) && (debt < close_threshold) {
            trace!("debt is above close threshold. resuming forwarding");
            DebtAction::OpenTunnel
        } else if debt_data.debt > SETTING.get_payment().pay_threshold {
            let d = debt_data.debt.clone();
            trace!(
                "debt is above payment threshold for {}. making payment of {}",
                ident.mesh_ip,
                d
            );
            debt_data.total_payment_sent = debt_data.total_payment_sent.clone().add(d.clone());
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

pub struct GetDebtsList;

impl Message for GetDebtsList {
    type Result = Result<Vec<GetDebtsResult>, Error>;
}

#[derive(Serialize)]
pub struct GetDebtsResult {
    identity: Identity,
    payment_details: NodeDebtData,
}

impl GetDebtsResult {
    pub fn new(identity: &Identity, payment_details: &NodeDebtData) -> GetDebtsResult {
        GetDebtsResult {
            identity: identity.clone(),
            payment_details: payment_details.clone(),
        }
    }
}

impl Handler<GetDebtsList> for DebtKeeper {
    type Result = Result<Vec<GetDebtsResult>, Error>;

    fn handle(&mut self, _msg: GetDebtsList, _ctx: &mut Context<Self>) -> Self::Result {
        let debts: Vec<GetDebtsResult> = self
            .debt_data
            .iter()
            .map(|(key, value)| GetDebtsResult::new(&key, &value))
            .collect();
        trace!("Debts: {}", debts.len());
        Ok(debts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_suspend() {
        SETTING.get_payment_mut().pay_threshold = Int256::from(5);
        SETTING.get_payment_mut().close_threshold = Int256::from(-10);
        SETTING.get_payment_mut().close_fraction = Int256::from(100);
        SETTING.get_payment_mut().buffer_period = 1;

        let mut d = DebtKeeper::new();

        let ident = Identity {
            eth_address: 1.into(),
            mesh_ip: "2001::3".parse().unwrap(),
            wg_public_key: "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk="
                .parse()
                .unwrap(),
        };

        d.traffic_update(&ident, Int256::from(-100));

        assert_eq!(d.send_update(&ident), DebtAction::SuspendTunnel);
    }

    #[test]
    fn test_single_overpay() {
        SETTING.get_payment_mut().pay_threshold = Int256::from(5);
        SETTING.get_payment_mut().close_threshold = Int256::from(-10);
        SETTING.get_payment_mut().close_fraction = Int256::from(100);
        SETTING.get_payment_mut().buffer_period = 1;

        let mut d = DebtKeeper::new();

        let ident = Identity {
            eth_address: 1.into(),
            mesh_ip: "2001::3".parse().unwrap(),
            wg_public_key: "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk="
                .parse()
                .unwrap(),
        };

        d.traffic_update(&ident, Int256::from(-100));
        d.payment_received(&ident, Uint256::from(1000));

        assert_eq!(d.send_update(&ident), DebtAction::None,);
    }

    #[test]
    fn test_buffer_suspend() {
        SETTING.get_payment_mut().pay_threshold = Int256::from(5);
        SETTING.get_payment_mut().close_threshold = Int256::from(-10);
        SETTING.get_payment_mut().close_fraction = Int256::from(100);
        SETTING.get_payment_mut().buffer_period = 2;

        let mut d = DebtKeeper::new();

        let ident = Identity {
            eth_address: 1.into(),
            mesh_ip: "2001::3".parse().unwrap(),
            wg_public_key: "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk="
                .parse()
                .unwrap(),
        };

        d.traffic_update(&ident, Int256::from(-100));

        assert_eq!(d.send_update(&ident), DebtAction::None,);

        assert_eq!(d.send_update(&ident), DebtAction::SuspendTunnel);
    }

    #[test]
    fn test_buffer_average() {
        SETTING.get_payment_mut().pay_threshold = Int256::from(5);
        SETTING.get_payment_mut().close_threshold = Int256::from(-10);
        SETTING.get_payment_mut().close_fraction = Int256::from(100);
        SETTING.get_payment_mut().buffer_period = 2;

        let mut d = DebtKeeper::new();

        let ident = Identity {
            eth_address: 1.into(),
            mesh_ip: "2001::3".parse().unwrap(),
            wg_public_key: "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk="
                .parse()
                .unwrap(),
        };

        d.traffic_update(&ident, Int256::from(-100));

        assert_eq!(d.send_update(&ident), DebtAction::None,);

        d.traffic_update(&ident, Int256::from(100));

        assert_eq!(d.send_update(&ident), DebtAction::None,);
    }

    #[test]
    fn test_buffer_repay() {
        SETTING.get_payment_mut().pay_threshold = Int256::from(5);
        SETTING.get_payment_mut().close_threshold = Int256::from(-10);
        SETTING.get_payment_mut().close_fraction = Int256::from(100);
        SETTING.get_payment_mut().buffer_period = 2;

        let mut d = DebtKeeper::new();

        let ident = Identity {
            eth_address: 1.into(),
            mesh_ip: "2001::3".parse().unwrap(),
            wg_public_key: "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk="
                .parse()
                .unwrap(),
        };

        d.traffic_update(&ident, Int256::from(-100));

        assert_eq!(d.send_update(&ident), DebtAction::None,);

        d.payment_received(&ident, Uint256::from(100));

        assert_eq!(d.send_update(&ident), DebtAction::None,);
    }

    #[test]
    fn test_buffer_overpay() {
        SETTING.get_payment_mut().pay_threshold = Int256::from(5);
        SETTING.get_payment_mut().close_threshold = Int256::from(-10);
        SETTING.get_payment_mut().close_fraction = Int256::from(100);
        SETTING.get_payment_mut().buffer_period = 2;

        let mut d = DebtKeeper::new();

        let ident = Identity {
            eth_address: 1.into(),
            mesh_ip: "2001::3".parse().unwrap(),
            wg_public_key: "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk="
                .parse()
                .unwrap(),
        };

        d.traffic_update(&ident, Int256::from(-100));

        assert_eq!(d.send_update(&ident), DebtAction::None,);

        d.traffic_update(&ident, Int256::from(-100));
        d.payment_received(&ident, Uint256::from(1000));

        assert_eq!(d.send_update(&ident), DebtAction::None,);
    }

    #[test]
    fn test_buffer_debt() {
        SETTING.get_payment_mut().pay_threshold = Int256::from(5);
        SETTING.get_payment_mut().close_threshold = Int256::from(-100);
        SETTING.get_payment_mut().close_fraction = Int256::from(100);
        SETTING.get_payment_mut().buffer_period = 2;

        let mut d = DebtKeeper::new();

        let ident = Identity {
            eth_address: 1.into(),
            mesh_ip: "2001::3".parse().unwrap(),
            wg_public_key: "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk="
                .parse()
                .unwrap(),
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
        SETTING.get_payment_mut().pay_threshold = Int256::from(5);
        SETTING.get_payment_mut().close_threshold = Int256::from(-10);
        SETTING.get_payment_mut().close_fraction = Int256::from(100);
        SETTING.get_payment_mut().buffer_period = 2;

        let mut d = DebtKeeper::new();

        let ident = Identity {
            eth_address: 1.into(),
            mesh_ip: "2001::3".parse().unwrap(),
            wg_public_key: "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk="
                .parse()
                .unwrap(),
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
        SETTING.get_payment_mut().pay_threshold = Int256::from(5);
        SETTING.get_payment_mut().close_threshold = Int256::from(-10);
        SETTING.get_payment_mut().close_fraction = Int256::from(100);
        SETTING.get_payment_mut().buffer_period = 1;

        let mut d = DebtKeeper::new();

        let ident = Identity {
            eth_address: 1.into(),
            mesh_ip: "2001::3".parse().unwrap(),
            wg_public_key: "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk="
                .parse()
                .unwrap(),
        };

        d.payment_received(&ident, Uint256::from(100000));
        d.traffic_update(&ident, Int256::from(-100100));

        assert_eq!(d.send_update(&ident), DebtAction::None,);
    }

    #[test]
    fn test_single_reopen() {
        SETTING.get_payment_mut().pay_threshold = Int256::from(5);
        SETTING.get_payment_mut().close_threshold = Int256::from(-10);
        SETTING.get_payment_mut().close_fraction = Int256::from(100);
        SETTING.get_payment_mut().buffer_period = 1;

        let mut d = DebtKeeper::new();

        let ident = Identity {
            eth_address: 1.into(),
            mesh_ip: "2001::3".parse().unwrap(),
            wg_public_key: "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk="
                .parse()
                .unwrap(),
        };

        d.traffic_update(&ident, Int256::from(-100));

        assert_eq!(d.send_update(&ident), DebtAction::SuspendTunnel);

        d.payment_received(&ident, Uint256::from(110));

        assert_eq!(d.send_update(&ident), DebtAction::OpenTunnel);
    }

    #[test]
    fn test_multi_pay() {
        SETTING.get_payment_mut().pay_threshold = Int256::from(5);
        SETTING.get_payment_mut().close_threshold = Int256::from(-10);
        SETTING.get_payment_mut().close_fraction = Int256::from(100);
        SETTING.get_payment_mut().buffer_period = 1;

        let mut d = DebtKeeper::new();

        let ident = Identity {
            eth_address: 1.into(),
            mesh_ip: "2001::3".parse().unwrap(),
            wg_public_key: "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk="
                .parse()
                .unwrap(),
        };

        // send lots of payments
        for _ in 0..100 {
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
        SETTING.get_payment_mut().pay_threshold = Int256::from(5);
        SETTING.get_payment_mut().close_threshold = Int256::from(-10);
        SETTING.get_payment_mut().close_fraction = Int256::from(100000);
        SETTING.get_payment_mut().buffer_period = 1;

        let mut d = DebtKeeper::new();

        let ident = Identity {
            eth_address: 1.into(),
            mesh_ip: "2001::3".parse().unwrap(),
            wg_public_key: "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk="
                .parse()
                .unwrap(),
        };

        // send lots of payments
        for _ in 0..100 {
            d.payment_received(&ident, Uint256::from(100))
        }

        d.traffic_update(&ident, Int256::from(-10100));

        assert_eq!(d.send_update(&ident), DebtAction::SuspendTunnel);
    }

    #[test]
    fn test_multi_reopen() {
        SETTING.get_payment_mut().pay_threshold = Int256::from(5);
        SETTING.get_payment_mut().close_threshold = Int256::from(-10);
        SETTING.get_payment_mut().close_fraction = Int256::from(1000000000);
        SETTING.get_payment_mut().buffer_period = 1;

        let mut d = DebtKeeper::new();

        let ident = Identity {
            eth_address: 1.into(),
            mesh_ip: "2001::3".parse().unwrap(),
            wg_public_key: "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk="
                .parse()
                .unwrap(),
        };

        for _ in 0..100 {
            d.payment_received(&ident, Uint256::from(100))
        }

        d.traffic_update(&ident, Int256::from(-10100));

        assert_eq!(d.send_update(&ident), DebtAction::SuspendTunnel);

        d.payment_received(&ident, Uint256::from(200));

        assert_eq!(d.send_update(&ident), DebtAction::OpenTunnel);
    }
}
