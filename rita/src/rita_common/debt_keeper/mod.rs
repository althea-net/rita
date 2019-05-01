//! While traffic watcher keeps an eye on how much traffic flows and what that is worth debtkeeper
//! maintains the long term memory of who owes who what so that it may later be quiered and paid
//! by payment manager in the current implementation or guac in the more final one
//!
//! You may be wondering what's up with incoming payments, why can't we just have debt?
//! Well this whole module is only slightly more complicated than it needs to be.
//! Lets say for example that we owe Bob some money, but for reasons unknown Bob pays us, do we
//! increase the amount we owe Bob? That's probably a vulnerability rabbit hole at the very least.
//! Hence we need an incoming paymetns parameter to take money out of. This of course implies half
//! of the excess complexity you see, managing an incoming payments pool versus a incoming debts pool

use crate::rita_common::payment_controller;
use crate::rita_common::payment_controller::PaymentController;
use crate::rita_common::tunnel_manager::TunnelAction;
use crate::rita_common::tunnel_manager::TunnelManager;
use crate::rita_common::tunnel_manager::TunnelStateChange;
use crate::SETTING;
use ::actix::prelude::{Actor, Context, Handler, Message, Supervised, SystemService};
use althea_types::{Identity, PaymentTx};
use failure::Error;
use num256::{Int256, Uint256};
use num_traits::{CheckedSub, Signed};
use settings::RitaCommonSettings;
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeDebtData {
    pub total_payment_received: Uint256,
    pub total_payment_sent: Uint256,
    pub debt: Int256,
    pub incoming_payments: Int256,
    pub action: DebtAction,
}

impl NodeDebtData {
    pub fn new() -> NodeDebtData {
        NodeDebtData {
            total_payment_received: Uint256::from(0u32),
            total_payment_sent: Uint256::from(0u32),
            debt: Int256::from(0),
            incoming_payments: Int256::from(0),
            action: DebtAction::OpenTunnel,
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
#[rtype(result = "Result<(), Error>")]
pub struct PaymentReceived {
    pub from: Identity,
    pub amount: Uint256,
}

impl Handler<PaymentReceived> for DebtKeeper {
    type Result = Result<(), Error>;

    fn handle(&mut self, msg: PaymentReceived, _: &mut Context<Self>) -> Self::Result {
        self.payment_received(&msg.from, msg.amount)
    }
}

#[derive(Message, PartialEq, Eq, Debug)]
#[rtype(result = "Result<(), Error>")]
/// This is called when a payment fails and needs to be retried, the debt
/// state is restored with the failed debt as it's top priority to immediately
/// be retried
pub struct PaymentFailed {
    pub to: Identity,
    pub amount: Uint256,
}

impl Handler<PaymentFailed> for DebtKeeper {
    type Result = Result<(), Error>;

    fn handle(&mut self, msg: PaymentFailed, _: &mut Context<Self>) -> Self::Result {
        match msg.amount.to_int256() {
            Some(amount_int) => match self.debt_data.get_mut(&msg.to) {
                Some(entry) => {
                    // no need to check for negative amount_int because we're converting
                    // from a uint256
                    entry.debt += amount_int.clone();
                    entry.total_payment_sent = entry
                        .total_payment_sent
                        .checked_sub(&msg.amount)
                        .ok_or_else(|| {
                            format_err!("Unable to subtract amount from total payments sent")
                        })?;
                    Ok(())
                }
                None => bail!("Payment failed but no debt! Somthing Must have gone wrong!"),
            },
            None => bail!("Unsable to convert amount to integer256 bit"),
        }
    }
}

pub struct Traffic {
    pub from: Identity,
    pub amount: Int256,
}

#[derive(Message)]
pub struct TrafficUpdate {
    pub traffic: Vec<Traffic>,
}

impl Handler<TrafficUpdate> for DebtKeeper {
    type Result = ();

    fn handle(&mut self, msg: TrafficUpdate, _: &mut Context<Self>) -> Self::Result {
        for t in msg.traffic.iter() {
            self.traffic_update(&t.from, t.amount.clone());
        }
    }
}

pub struct SendUpdate;

impl Message for SendUpdate {
    type Result = Result<(), Error>;
}

/// Actions to be taken upon a neighbor's debt reaching either a negative or positive
/// threshold.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum DebtAction {
    SuspendTunnel,
    OpenTunnel,
    MakePayment { to: Identity, amount: Uint256 },
}

impl Handler<SendUpdate> for DebtKeeper {
    type Result = Result<(), Error>;

    fn handle(&mut self, _msg: SendUpdate, _ctx: &mut Context<Self>) -> Self::Result {
        trace!("sending debt keeper update");
        for (k, _) in self.debt_data.clone() {
            match self.send_update(&k)? {
                DebtAction::SuspendTunnel => {
                    TunnelManager::from_registry().do_send(TunnelStateChange {
                        identity: k,
                        action: TunnelAction::PaymentOverdue,
                    });
                }
                DebtAction::OpenTunnel => {
                    TunnelManager::from_registry().do_send(TunnelStateChange {
                        identity: k,
                        action: TunnelAction::PaidOnTime,
                    });
                }
                DebtAction::MakePayment { to, amount } => PaymentController::from_registry()
                    .do_send(payment_controller::MakePayment(PaymentTx {
                        to,
                        from: match SETTING.get_identity() {
                            Some(id) => id,
                            None => bail!("Identity has no mesh IP ready yet"),
                        },
                        amount,
                        txid: None, // not yet published
                    })),
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
        assert!(SETTING.get_payment().close_threshold <= Int256::from(0));

        DebtKeeper {
            debt_data: DebtData::new(),
        }
    }

    fn get_debts(&self) -> DebtData {
        self.debt_data.clone()
    }

    fn get_debt_data_mut(&mut self, ident: &Identity) -> &mut NodeDebtData {
        self.debt_data
            .entry(ident.clone())
            .or_insert_with(NodeDebtData::new)
    }

    fn payment_received(&mut self, ident: &Identity, amount: Uint256) -> Result<(), Error> {
        let zero = Int256::from(0);
        let incoming_amount = amount
            .to_int256()
            .ok_or_else(|| format_err!("Unable to convert amount to 256 bit signed integer"))?;
        let debt_data = self.get_debt_data_mut(ident);
        trace!(
            "payment received: old incoming payments for {:?}: {:?}",
            ident.mesh_ip,
            debt_data.incoming_payments
        );

        // just a counter, no convergence importance
        debt_data.total_payment_received += amount.clone();
        // add in the latest amount to the pile before processing
        debt_data.incoming_payments += incoming_amount;

        let they_owe_us = debt_data.debt < Int256::from(0);
        let incoming_greater_than_debt = debt_data.incoming_payments > debt_data.debt.abs();

        // somewhat more complicated, we apply incoming to the balance, but don't allow
        // the balance to go positive (we owe them) we don't want to get into paying them
        // because they overpaid us.
        match (they_owe_us, incoming_greater_than_debt) {
            (true, true) => {
                debt_data.incoming_payments -= debt_data.debt.abs();
                debt_data.debt = zero;
            }
            (true, false) => {
                debt_data.debt += debt_data.incoming_payments.clone();
                debt_data.incoming_payments = zero;
            }
            (false, _) => {}
        }

        trace!(
            "new incoming payments for {:?}: {:?}",
            ident.mesh_ip,
            debt_data.incoming_payments
        );
        Ok(())
    }

    fn traffic_update(&mut self, ident: &Identity, amount: Int256) {
        trace!("traffic update for {} is {}", ident.mesh_ip, amount);
        let debt_data = self.get_debt_data_mut(ident);
        assert!(debt_data.incoming_payments >= Int256::from(0));

        // we handle the incoming debit or credit versus our existing debit or credit
        // very simple
        debt_data.debt += amount;

        trace!("debt data for {} is {:?}", ident.mesh_ip, debt_data);
    }

    /// This updates a neighbor's debt and outputs a DebtAction if one is necessary.
    fn send_update(&mut self, ident: &Identity) -> Result<DebtAction, Error> {
        trace!("debt data: {:?}", self.debt_data);
        let debt_data = self.get_debt_data_mut(ident);
        // the debt we started this round with

        trace!(
            "send_update for {:?}: debt: {:?}, payment balance: {:?}",
            ident.mesh_ip,
            debt_data.debt,
            debt_data.incoming_payments,
        );

        // reduce debt if it's negative to try and trend to zero
        // the edge case this is supposed to handle is if a node ran out of money and then
        // crashed so it doesn't know what it owes the exit and it may come back hours later
        // the other side of this coin is that we're causing a node running on the free tier
        // to bounce in and out of it, this value is hand tuned to take the average round overrun
        // and bring it below the close treshold once every 3 hours. If the client router has been
        // refilled it should return to full function then
        // TODO replace with explcit timer system
        // if debt_data.debt < Int256::from(0) {
        //     debt_data.debt += 300_000_000u64.into();
        // }

        let close_threshold = SETTING.get_payment().close_threshold.clone();

        trace!(
            "Debt is {} and close is {}",
            debt_data.debt,
            close_threshold
        );
        // negative debt means they owe us so when the debt is more negative than
        // the close treshold we should enforce.

        let should_close = debt_data.debt < close_threshold;
        let should_pay = debt_data.debt > SETTING.get_payment().pay_threshold;
        match (should_close, should_pay) {
            (true, true) => panic!("Close threshold is less than pay threshold!"),
            (true, false) => {
                info!(
                    "debt is below close threshold for {}. suspending forwarding",
                    ident.mesh_ip
                );
                debt_data.action = DebtAction::SuspendTunnel;
                Ok(DebtAction::SuspendTunnel)
            }
            (false, true) => {
                let d: Uint256 = debt_data.debt.to_uint256().ok_or_else(|| {
                    format_err!("Unable to convert debt data into unsigned 256 bit integer")
                })?;
                debt_data.total_payment_sent += d.clone();
                debt_data.debt = Int256::from(0);

                debt_data.action = DebtAction::MakePayment {
                    to: *ident,
                    amount: d.clone(),
                };

                Ok(DebtAction::MakePayment {
                    to: *ident,
                    amount: d,
                })
            }
            (false, false) => {
                debt_data.action = DebtAction::OpenTunnel;
                Ok(DebtAction::OpenTunnel)
            }
        }
    }
}

pub struct GetDebtsList;

impl Message for GetDebtsList {
    type Result = Result<Vec<GetDebtsResult>, Error>;
}

#[derive(Serialize)]
pub struct GetDebtsResult {
    pub identity: Identity,
    pub payment_details: NodeDebtData,
}

impl GetDebtsResult {
    pub fn new(identity: &Identity, payment_details: &NodeDebtData) -> GetDebtsResult {
        GetDebtsResult {
            identity: *identity,
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

    fn get_test_identity() -> Identity {
        Identity::new(
            "2001::3".parse().unwrap(),
            "0x0000000000000000000000000000000000000001"
                .parse()
                .unwrap(),
            "8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk="
                .parse()
                .unwrap(),
            None,
        )
    }

    #[test]
    fn test_single_suspend() {
        SETTING.get_payment_mut().pay_threshold = Int256::from(5);
        SETTING.get_payment_mut().close_threshold = Int256::from(-10);

        let mut d = DebtKeeper::new();

        let ident = get_test_identity();

        d.traffic_update(&ident, Int256::from(-100i64));

        assert_eq!(d.send_update(&ident).unwrap(), DebtAction::SuspendTunnel);
    }

    #[test]
    fn test_single_overpay() {
        SETTING.get_payment_mut().pay_threshold = Int256::from(5);
        SETTING.get_payment_mut().close_threshold = Int256::from(-10);

        let mut d = DebtKeeper::new();

        let ident = get_test_identity();

        d.traffic_update(&ident, Int256::from(-100i64));
        let _ = d.payment_received(&ident, Uint256::from(1000u64));

        assert_eq!(d.send_update(&ident).unwrap(), DebtAction::OpenTunnel);
    }

    #[test]
    fn test_single_pay() {
        SETTING.get_payment_mut().pay_threshold = Int256::from(5);
        SETTING.get_payment_mut().close_threshold = Int256::from(-10);

        let mut d = DebtKeeper::new();
        let ident = get_test_identity();

        d.traffic_update(&ident, Int256::from(100));

        assert_eq!(
            d.send_update(&ident).unwrap(),
            DebtAction::MakePayment {
                amount: Uint256::from(100u32),
                to: ident,
            }
        );
    }

    #[test]
    fn test_single_reopen() {
        SETTING.get_payment_mut().pay_threshold = Int256::from(5);
        SETTING.get_payment_mut().close_threshold = Int256::from(-10);

        let mut d = DebtKeeper::new();
        let ident = get_test_identity();

        d.traffic_update(&ident, Int256::from(-100i64));

        assert_eq!(d.send_update(&ident).unwrap(), DebtAction::SuspendTunnel);

        d.payment_received(&ident, Uint256::from(110u64)).unwrap();

        assert_eq!(d.send_update(&ident).unwrap(), DebtAction::OpenTunnel);
    }

    #[test]
    fn test_multi_pay() {
        SETTING.get_payment_mut().pay_threshold = Int256::from(5);
        SETTING.get_payment_mut().close_threshold = Int256::from(-10);

        let mut d = DebtKeeper::new();
        let ident = get_test_identity();

        // send lots of payments
        for _ in 0..100 {
            d.traffic_update(&ident, Int256::from(100))
        }

        assert_eq!(
            d.send_update(&ident).unwrap(),
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

        let mut d = DebtKeeper::new();
        let ident = get_test_identity();

        // send lots of payments
        for _ in 0..100 {
            d.payment_received(&ident, Uint256::from(100u64)).unwrap();
        }

        d.traffic_update(&ident, Int256::from(-10100i64));

        assert_eq!(d.send_update(&ident).unwrap(), DebtAction::SuspendTunnel);
    }

    #[test]
    fn test_multi_reopen() {
        SETTING.get_payment_mut().pay_threshold = Int256::from(5);
        SETTING.get_payment_mut().close_threshold = Int256::from(-10);

        let mut d = DebtKeeper::new();
        let ident = get_test_identity();

        for _ in 0..100 {
            d.payment_received(&ident, Uint256::from(100u64)).unwrap();
        }

        d.traffic_update(&ident, Int256::from(-10100i64));

        assert_eq!(d.send_update(&ident).unwrap(), DebtAction::SuspendTunnel);

        d.payment_received(&ident, Uint256::from(200u64)).unwrap();

        assert_eq!(d.send_update(&ident).unwrap(), DebtAction::OpenTunnel);
    }
}
