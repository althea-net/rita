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
use num_traits::Signed;
use settings::RitaCommonSettings;
use std::collections::HashMap;
use std::time::Duration;
use std::time::Instant;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeDebtData {
    pub total_payment_received: Uint256,
    pub total_payment_sent: Uint256,
    pub debt: Int256,
    pub incoming_payments: Uint256,
    pub action: DebtAction,
    pub payment_in_flight: bool,
    #[serde(skip_serializing, skip_deserializing)]
    pub payment_in_flight_start: Option<Instant>,
}

impl NodeDebtData {
    pub fn new() -> NodeDebtData {
        NodeDebtData {
            total_payment_received: Uint256::from(0u32),
            total_payment_sent: Uint256::from(0u32),
            debt: Int256::from(0),
            incoming_payments: Uint256::from(0u32),
            action: DebtAction::OpenTunnel,
            payment_in_flight: false,
            payment_in_flight_start: None,
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

#[derive(PartialEq, Eq, Debug)]
pub struct PaymentReceived {
    pub from: Identity,
    pub amount: Uint256,
}

impl Message for PaymentReceived {
    type Result = Result<(), Error>;
}

impl Handler<PaymentReceived> for DebtKeeper {
    type Result = Result<(), Error>;

    fn handle(&mut self, msg: PaymentReceived, _: &mut Context<Self>) -> Self::Result {
        self.payment_received(&msg.from, msg.amount)
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct PaymentFailed {
    pub to: Identity,
}

impl Message for PaymentFailed {
    type Result = Result<(), Error>;
}

impl Handler<PaymentFailed> for DebtKeeper {
    type Result = Result<(), Error>;

    fn handle(&mut self, msg: PaymentFailed, _: &mut Context<Self>) -> Self::Result {
        self.payment_failed(&msg.to)
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct PaymentSucceeded {
    pub to: Identity,
    pub amount: Uint256,
}

impl Message for PaymentSucceeded {
    type Result = Result<(), Error>;
}

impl Handler<PaymentSucceeded> for DebtKeeper {
    type Result = Result<(), Error>;

    fn handle(&mut self, msg: PaymentSucceeded, _: &mut Context<Self>) -> Self::Result {
        self.payment_succeeded(&msg.to, msg.amount)
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

    fn payment_failed(&mut self, to: &Identity) -> Result<(), Error> {
        let peer = self.get_debt_data_mut(to);
        peer.payment_in_flight = false;
        peer.payment_in_flight_start = None;
        Ok(())
    }

    fn payment_succeeded(&mut self, to: &Identity, amount: Uint256) -> Result<(), Error> {
        let peer = self.get_debt_data_mut(to);
        peer.payment_in_flight = false;
        peer.payment_in_flight_start = None;

        peer.total_payment_sent += amount.clone();
        peer.debt -= match amount.to_int256() {
            Some(val) => val,
            None => bail!("Failed to convert amount paid to Int256!"),
        };
        Ok(())
    }

    fn payment_received(&mut self, ident: &Identity, amount: Uint256) -> Result<(), Error> {
        let signed_zero = Int256::from(0);
        let unsigned_zero = Uint256::from(0u32);

        let debt_data = self.get_debt_data_mut(ident);
        info!(
            "payment received: old incoming payments for {:?}: {:?}",
            ident.mesh_ip, debt_data.incoming_payments
        );

        // just a counter, no convergence importance
        debt_data.total_payment_received += amount.clone();
        // add in the latest amount to the pile before processing
        debt_data.incoming_payments += amount;

        let they_owe_us = debt_data.debt < Int256::from(0);
        // unwrap is safe because the abs of a signed 256 bit int can't overflow a unsigned 256 bit int or be negative
        let incoming_greater_than_debt =
            debt_data.incoming_payments > debt_data.debt.abs().to_uint256().unwrap();

        // somewhat more complicated, we apply incoming to the balance, but don't allow
        // the balance to go positive (we owe them) we don't want to get into paying them
        // because they overpaid us.
        match (they_owe_us, incoming_greater_than_debt) {
            (true, true) => {
                debt_data.incoming_payments -= debt_data.debt.abs().to_uint256().unwrap();
                debt_data.debt = signed_zero;
            }
            (true, false) => {
                // we validate payments before they get here, so in theory if someone pays you a few trillion coins and it
                // gets into a block this could overflow
                let signed_incoming = match debt_data.incoming_payments.to_int256() {
                    Some(val) => val,
                    None => bail!("Unsigned payment int too big! You're super rich now"),
                };
                debt_data.debt += signed_incoming;
                debt_data.incoming_payments = unsigned_zero;
            }
            (false, _) => {
                error!("Why did we get a payment when they don't owe us anything?");
            }
        }

        info!(
            "new incoming payments for {:?}: {:?}",
            ident.mesh_ip, debt_data.incoming_payments
        );
        Ok(())
    }

    fn traffic_update(&mut self, ident: &Identity, amount: Int256) {
        trace!("traffic update for {} is {}", ident.mesh_ip, amount);
        let debt_data = self.get_debt_data_mut(ident);

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
        let payment_in_flight = debt_data.payment_in_flight;
        match (should_close, should_pay, payment_in_flight) {
            (true, true, _) => panic!("Close threshold is less than pay threshold!"),
            (true, false, _) => {
                info!(
                    "debt is below close threshold for {}. suspending forwarding",
                    ident.mesh_ip
                );
                debt_data.action = DebtAction::SuspendTunnel;
                Ok(DebtAction::SuspendTunnel)
            }
            (false, true, false) => {
                let d: Uint256 = debt_data.debt.to_uint256().ok_or_else(|| {
                    format_err!("Unable to convert debt data into unsigned 256 bit integer")
                })?;

                debt_data.payment_in_flight = true;
                debt_data.payment_in_flight_start = Some(Instant::now());

                debt_data.action = DebtAction::MakePayment {
                    to: *ident,
                    amount: d.clone(),
                };

                Ok(DebtAction::MakePayment {
                    to: *ident,
                    amount: d,
                })
            }
            (false, false, _) => {
                debt_data.action = DebtAction::OpenTunnel;
                Ok(DebtAction::OpenTunnel)
            }
            (false, true, true) => {
                // In theory it's possible for the payment_failed or payment_succeeded actor calls to fail for
                // various reasons. In practice this only happens with the system is in a nearly inoperable state.
                // But for the sake of parinoia we provide a handler here which will time out in such a situation
                match debt_data.payment_in_flight_start {
                    Some(start_time) => {
                        if Instant::now() - start_time > Duration::from_secs(600) {
                            error!("Payment in flight for more than 10 minutes! Resetting!");
                            debt_data.payment_in_flight = false;
                            debt_data.payment_in_flight_start = None;
                        }
                    }
                    None => {
                        error!("No start time but payment in flight?");
                        debt_data.payment_in_flight = false;
                    }
                }
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

    #[test]
    fn test_payment_fail() {
        SETTING.get_payment_mut().pay_threshold = Int256::from(5);
        SETTING.get_payment_mut().close_threshold = Int256::from(-10);

        let mut d = DebtKeeper::new();
        let ident = get_test_identity();

        // generate a bunch of traffic
        for _ in 0..100 {
            d.traffic_update(&ident, Int256::from(100))
        }
        // make sure that the update response is to pay
        assert_eq!(
            d.send_update(&ident).unwrap(),
            DebtAction::MakePayment {
                amount: Uint256::from(10000u32),
                to: ident,
            }
        );
        // simulate a payment failure
        d.payment_failed(&ident).unwrap();

        // make sure we haven't marked any payments as sent (because the payment failed)
        assert_eq!(
            d.get_debts()[&ident].total_payment_sent,
            Uint256::from(0u32)
        );

        // mark the payment as a success
        d.payment_succeeded(&ident, Uint256::from(10000u32))
            .unwrap();
        // make sure the payment sent value is updated
        assert_eq!(
            d.get_debts()[&ident].total_payment_sent,
            Uint256::from(10000u32)
        );

        // more traffic
        for _ in 0..100 {
            d.traffic_update(&ident, Int256::from(100))
        }
        // another payment, to make sure the state was all set right after
        // the failure then success
        assert_eq!(
            d.send_update(&ident).unwrap(),
            DebtAction::MakePayment {
                amount: Uint256::from(10000u32),
                to: ident,
            }
        );
        d.payment_succeeded(&ident, Uint256::from(10000u32))
            .unwrap();
        assert_eq!(
            d.get_debts()[&ident].total_payment_sent,
            Uint256::from(20000u32)
        );

        // finally lets make sure we don't send any payments while
        // a payment is in flight
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
        assert_eq!(d.send_update(&ident).unwrap(), DebtAction::OpenTunnel);
        assert_eq!(d.send_update(&ident).unwrap(), DebtAction::OpenTunnel);
        assert_eq!(d.send_update(&ident).unwrap(), DebtAction::OpenTunnel);
    }
}
