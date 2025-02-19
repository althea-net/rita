//! While traffic watcher keeps an eye on how much traffic flows and what that is worth debtkeeper
//! maintains the long term memory of who owes who what so that it may later be queried and paid
//! by payment_controller
//!
//! You may be wondering what's up with incoming payments, why can't we just have debt?
//! Well this whole module is only slightly more complicated than it needs to be.
//! Lets say for example that we owe Bob some money, but for reasons unknown Bob pays us, do we
//! increase the amount we owe Bob? That's probably a vulnerability rabbit hole at the very least.
//! Hence we need an incoming payments parameter to take money out of. This of course implies half
//! of the excess complexity you see, managing an incoming payments pool versus a incoming debts pool
use crate::blockchain_oracle::calculate_close_thresh;
use crate::blockchain_oracle::get_pay_thresh;
use crate::simulated_txfee_manager::add_tx_to_total;
use crate::tunnel_manager::tm_tunnel_state_change;
use crate::tunnel_manager::TunnelAction;
use crate::tunnel_manager::TunnelChange;
use crate::RitaCommonError;
use althea_kernel_interface::netns::check_integration_test_netns;
use althea_types::Denom;
use althea_types::Identity;
use althea_types::UnpublishedPaymentTx;
use num256::{Int256, Uint256};
use num_traits::identities::Zero;
use num_traits::CheckedMul;
use num_traits::Signed;
use settings::DEBT_KEEPER_DENOM;
use settings::DEBT_KEEPER_DENOM_DECIMAL;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::Error as IOError;
use std::io::Read;
use std::io::Write;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::time::Instant;

lazy_static! {
    /// A locked global ref containing the state for this module. Note that the default implementation
    /// loads saved data from the disk if it exists.
    static ref DEBT_DATA: Arc<RwLock<HashMap<u32,DebtKeeper>>> = Arc::new(RwLock::new(HashMap::new()));
}

/// Resets the debt keeper, this is used in tests to ensure that the debt keeper is in a known state
#[cfg(test)]
pub fn reset_debt_keeper() {
    let mut dk = DEBT_DATA.write().unwrap();
    *dk = HashMap::new();
}

/// Returns the default denomination for the debt keeper
/// this is used for all internal bandwidth accounting becuase it provides the highest
/// level of precision which is importnat when communicating prices through babel
pub fn wei_denom() -> Denom {
    Denom {
        denom: DEBT_KEEPER_DENOM.to_string(),
        decimal: DEBT_KEEPER_DENOM_DECIMAL,
    }
}

/// Gets DebtKeeper copy from the static ref, or default if no value has been set
pub fn get_debt_keeper() -> DebtKeeper {
    let netns = check_integration_test_netns();
    DEBT_DATA
        .read()
        .unwrap()
        .clone()
        .get(&netns)
        .cloned()
        .unwrap_or_default()
}

/// Gets a write ref for the debt keeper lock, since this is a mutable reference
/// the lock will be held until you drop the return value, this lets the caller abstract the namespace handling
/// but still hold the lock in the local thread to prevent parallel modification
fn get_debt_keeper_write_ref(input: &mut HashMap<u32, DebtKeeper>) -> &mut DebtKeeper {
    let netns = check_integration_test_netns();
    input.entry(netns).or_default();
    input.get_mut(&netns).unwrap()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeDebtData {
    /// The amount this node has paid us, validated in payment_validator
    pub total_payment_received: Uint256,
    /// The amount we have sent another node, does not count until validated
    /// by payment_validator
    pub total_payment_sent: Uint256,
    /// The amount we owe the other node (positive) or they owe us (negative)
    pub debt: Int256,
    /// A storage pool for overpayment, if a node overpays us we don't go into debt to them
    /// the excess value is placed here to be applied in the future
    pub incoming_payments: Uint256,
    /// The last thing we did, this value is updated but does not actual affect controll flow
    /// do not use it to affect control flow!
    pub action: DebtAction,
    #[serde(skip_serializing, skip_deserializing)]
    /// If we have an outgoing payment to a node in flight
    pub payment_in_flight: bool,
    #[serde(skip_serializing, skip_deserializing)]
    /// The last time we successfully paid a node, this is used only in the exit payments
    /// case, where when we get payments from the exit there is a race condition where the
    /// exit may not update that we have paid it fast enough
    pub last_successful_payment: Option<Instant>,
}

impl Default for NodeDebtData {
    fn default() -> Self {
        NodeDebtData {
            total_payment_received: Uint256::from(0u32),
            total_payment_sent: Uint256::from(0u32),
            debt: Int256::from(0),
            incoming_payments: Uint256::from(0u32),
            action: DebtAction::OpenTunnel,
            payment_in_flight: false,
            last_successful_payment: None,
        }
    }
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
            last_successful_payment: None,
        }
    }
}

pub type DebtData = HashMap<Identity, NodeDebtData>;
/// a datatype used only for the serializing of DebtData since
/// serde does not support structs as keys in maps
type DebtDataSer = Vec<(Identity, NodeDebtData)>;

fn debt_data_to_ser(input: DebtData) -> DebtDataSer {
    let mut ret = DebtDataSer::new();
    for (i, d) in input {
        ret.push((i, d));
    }
    ret
}

fn ser_to_debt_data(input: DebtDataSer) -> DebtData {
    let mut ret = DebtData::new();
    for (i, mut d) in input {
        // Don't load negative debts, essentailly means that all debt will be
        // forgiven on reboot, but each node will still try and pay it's debts
        // in good faith. Although it's tempting to remove this and not let people
        // get away with unpaid bills service not working for arbitrary bad data reasons
        // is much worse
        //
        // In the case that the debt is negative and incoming payments is zero we can safely
        // discard the entry, in the case that they do have some incoming payments the user
        // deserves to have that credit applied in the future so we must retain the entry and
        // reset the debt
        if settings::get_rita_common().payment.forgive_on_reboot {
            if d.debt <= Int256::zero() && d.incoming_payments == Uint256::zero() {
                continue;
            } else if d.debt <= Int256::zero() {
                d.debt = Int256::from(0);
            }
        }
        ret.insert(i, d);
    }
    ret
}

/// used to prevent debts from growing higher than the enforcement limit in either direction
/// if the debt is more negative or more positive than the ABS of close_threshold we set it to
/// one more than that value
fn debt_limit(debt: Int256, close_threshold: Int256) -> Int256 {
    if debt < close_threshold {
        info!(
            "Forgiving {} wei to enforce debt limit",
            debt - close_threshold
        );
        close_threshold - 1u8.into()
    } else if debt > close_threshold.abs() {
        info!(
            "Not paying {} wei to enforce debt limit",
            debt - close_threshold
        );
        close_threshold.abs() + 1u8.into()
    } else {
        debt
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DebtKeeper {
    #[serde(skip_serializing, skip_deserializing)]
    last_save: Option<Instant>,
    debt_data: DebtData,
}

#[allow(dead_code)]
pub fn dump() -> DebtData {
    let dk = get_debt_keeper();
    dk.get_debts()
}

pub fn payment_received(
    from: Identity,
    amount: Uint256,
    denom: Denom,
) -> Result<(), RitaCommonError> {
    let dk_pin = &mut *DEBT_DATA.write().unwrap();
    let dk = get_debt_keeper_write_ref(dk_pin);

    // Debt keeper currently bookeeps in dai, we convert whatever amount we recive to the debt keeper using
    let amount = normalize_payment_amount(
        amount,
        denom,
        Denom {
            denom: DEBT_KEEPER_DENOM.to_string(),
            decimal: DEBT_KEEPER_DENOM_DECIMAL,
        },
    );
    dk.payment_received(&from, amount)
}

/// Currency conversion from_denom -> to_denom, this is required for any target chain or token with less than
/// 18 decimals of precision. Take for example USDC on Althea L1, it has 6 decimals of precision, but the way
/// we specify bandwidth prices in the babel protocol is smallest unit of payment / byte (smallest unit of billed data)
/// with a 6 decimal token that's a minimum bandwidth price of $1000/GB so totally unusable. We need to scale up the internal
/// accounting to deal with wei (18 decimals) only then scale it back down on payment out
pub fn normalize_payment_amount(amount: Uint256, from_denom: Denom, to_denom: Denom) -> Uint256 {
    let mut amount = amount;
    if from_denom.denom != to_denom.denom {
        let unit_factor = match amount.checked_mul(&to_denom.decimal.into()) {
            Some(a) => a,
            None => panic!(
                "We overflowed when multipling {} and {}",
                amount, to_denom.decimal
            ),
        };
        amount = unit_factor / from_denom.decimal.into();
    };
    amount
}

pub fn payment_failed(to: Identity) {
    let dk_pin = &mut *DEBT_DATA.write().unwrap();
    let dk = get_debt_keeper_write_ref(dk_pin);
    dk.payment_failed(&to)
}

pub fn payment_succeeded(
    to: Identity,
    amount: Uint256,
    denom: Denom,
) -> Result<(), RitaCommonError> {
    let dk_pin = &mut *DEBT_DATA.write().unwrap();
    let dk = get_debt_keeper_write_ref(dk_pin);
    // Debt keeper currently bookeeps in dai, we convert whatever amount we recive to the debt keeper using
    let amount = normalize_payment_amount(
        amount,
        denom,
        Denom {
            denom: DEBT_KEEPER_DENOM.to_string(),
            decimal: DEBT_KEEPER_DENOM_DECIMAL,
        },
    );
    add_tx_to_total(amount);
    dk.payment_succeeded(&to, amount)
}

pub struct Traffic {
    pub from: Identity,
    pub amount: Int256,
}

pub fn traffic_update(traffic: Vec<Traffic>) {
    let dk_pin = &mut *DEBT_DATA.write().unwrap();
    let dk = get_debt_keeper_write_ref(dk_pin);
    for t in traffic.iter() {
        dk.traffic_update(&t.from, t.amount);
    }
}

#[allow(dead_code)]
/// Special case traffic update for client gateway corner case, see rita client traffic watcher for more
/// details.
pub fn gateway_traffic_update(traffic: Traffic) {
    let dk_pin = &mut *DEBT_DATA.write().unwrap();
    let dk = get_debt_keeper_write_ref(dk_pin);
    let exit_id = traffic.from;
    for (id, _) in dk.debt_data.clone().iter() {
        if *id == exit_id {
            dk.traffic_update(id, traffic.amount);
            return;
        }
    }
    error!("Gateway billing has not found a target! Gateway billing incorrect!");
}

/// A variant of traffic update that replaces one debts entry wholesale
/// only used by the client to update it's own debt to the exit
pub fn traffic_replace(traffic: Traffic) {
    let dk_pin = &mut *DEBT_DATA.write().unwrap();
    let dk = get_debt_keeper_write_ref(dk_pin);
    dk.traffic_replace(&traffic.from, traffic.amount)
}

/// Actions to be taken upon a neighbor's debt reaching either a negative or positive
/// threshold.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Hash, Eq)]
pub enum DebtAction {
    SuspendTunnel,
    OpenTunnel,
    MakePayment { to: Box<Identity>, amount: Uint256 },
}

pub fn send_debt_update() -> Result<Vec<UnpublishedPaymentTx>, RitaCommonError> {
    let dk_pin = &mut *DEBT_DATA.write().unwrap();
    let dk = get_debt_keeper_write_ref(dk_pin);

    // in order to keep from overloading actix when we have thousands of debts to process
    // (mainly on exits) we batch tunnel change operations before sending them over
    let mut debts_message = Vec::new();
    let mut payments_to_send = Vec::new();

    for (k, _) in dk.debt_data.clone() {
        match dk.update_debt_keeper_state_machine(&k)? {
            DebtAction::SuspendTunnel => {
                debts_message.push(TunnelChange {
                    identity: k,
                    action: TunnelAction::PaymentOverdue,
                });
            }
            DebtAction::OpenTunnel => {
                debts_message.push(TunnelChange {
                    identity: k,
                    action: TunnelAction::PaidOnTime,
                });
            }
            DebtAction::MakePayment { to, amount } => {
                payments_to_send.push(UnpublishedPaymentTx {
                    to: *to,
                    from: match settings::get_rita_common().get_identity() {
                        Some(id) => id,
                        None => {
                            return Err(RitaCommonError::MiscStringError(
                                "Identity has no mesh IP ready yet".to_string(),
                            ))
                        }
                    },
                    amount,
                });
            }
        }
    }

    if let Err(e) = tm_tunnel_state_change(debts_message) {
        warn!("Error during tunnel state change: {}", e);
    }
    Ok(payments_to_send)
}

/// deserialize debt data from bincode format
fn deserialize_from_binary(file_path: String) -> Option<DebtDataSer> {
    let file = fs::read(file_path);
    match file {
        Ok(file) => {
            let deserialized_binary: DebtDataSer = match bincode::deserialize(&file) {
                Ok(value) => value,
                Err(val) => {
                    error!("Failed to deserialize debts file via bincode {:?}", val);
                    Vec::new()
                }
            };
            Some(deserialized_binary)
        }
        Err(e) => {
            error!("Failed to deserialize debts file via binary{:?}", e);
            None
        }
    }
}

/// deserialize debt data from json format
fn deserialize_from_json(file_path: String) -> Option<DebtDataSer> {
    let file = File::open(file_path);
    match file {
        Ok(mut file) => {
            let mut contents = String::new();
            match file.read_to_string(&mut contents) {
                Ok(_bytes_read) => {
                    let deserialized_json = match serde_json::from_str(&contents) {
                        Ok(value) => value,
                        Err(e) => {
                            error!("Failed to deserialize debts file via json{:?}", e);
                            Vec::new()
                        }
                    };
                    Some(deserialized_json)
                }
                Err(e) => {
                    error!("Failed to read debts file! {:?}", e);
                    None
                }
            }
        }
        Err(e) => {
            error!("Failed to open debts file! {:?}", e);
            None
        }
    }
}

impl Default for DebtKeeper {
    fn default() -> DebtKeeper {
        assert!(get_pay_thresh() >= Int256::zero());
        assert!(calculate_close_thresh() <= Int256::zero());
        // if the loading process goes wrong for any reason, we just start again
        let blank_debt_keeper = DebtKeeper {
            last_save: None,
            debt_data: HashMap::new(),
        };

        let deserialized_binary =
            deserialize_from_binary(settings::get_rita_common().payment.debts_file);
        let deserialized_json =
            deserialize_from_json(settings::get_rita_common().payment.debts_file);
        match (deserialized_binary, deserialized_json) {
            (None, None) => {
                error!("Unable to deserialize file from json and binary");
                blank_debt_keeper
            }
            (None, Some(val)) => DebtKeeper {
                last_save: None,
                debt_data: ser_to_debt_data(val),
            },
            (Some(val), None) => DebtKeeper {
                last_save: None,
                debt_data: ser_to_debt_data(val),
            },
            (Some(val), Some(_)) => {
                log::info!("File is both binary and json");
                DebtKeeper {
                    last_save: None,
                    debt_data: ser_to_debt_data(val),
                }
            }
        }
    }
}

impl DebtKeeper {
    #[cfg(test)]
    pub fn new() -> Self {
        assert!(get_pay_thresh() >= Int256::zero());
        assert!(calculate_close_thresh() <= Int256::zero());

        DebtKeeper {
            last_save: None,
            debt_data: DebtData::new(),
        }
    }

    pub fn save_if_needed(&mut self, save_frequency: Duration) {
        match self.last_save {
            Some(val) => {
                if Instant::now() - val > save_frequency {
                    if let Err(e) = self.save() {
                        error!("Failed to save debts {:?}", e);
                    } else {
                        self.last_save = Some(Instant::now());
                        info!("Writing to disk the save data");
                    }
                }
            }
            None => {
                if let Err(e) = self.save() {
                    error!("Failed to save debts {:?}", e);
                } else {
                    self.last_save = Some(Instant::now());
                }
            }
        }
    }

    fn save(&mut self) -> Result<(), IOError> {
        let mut new_settings = settings::get_rita_common();
        let mut file_path: String = new_settings.payment.debts_file.clone();
        // convert to the serializeable format and dump to the disk
        if file_path.ends_with("json") {
            file_path.drain(0..file_path.len() - 4);
            file_path.push_str("bincode");
        }
        new_settings.payment.debts_file.clone_from(&file_path);
        settings::set_rita_common(new_settings);

        let serialized = bincode::serialize(&debt_data_to_ser(self.debt_data.clone())).unwrap();
        let mut file = File::create(file_path)?;
        file.write_all(&serialized)
    }

    fn get_debts(&self) -> DebtData {
        self.debt_data.clone()
    }

    fn get_debt_data_mut(&mut self, ident: &Identity) -> &mut NodeDebtData {
        self.debt_data.entry(*ident).or_default()
    }

    fn payment_failed(&mut self, to: &Identity) {
        warn!("Payment to {} failed", to.eth_address);
        let peer = self.get_debt_data_mut(to);

        // this should be true! if it's not we have a bug
        if !peer.payment_in_flight {
            error!(
                "Payment to {} failed but no payment in flight!",
                to.eth_address
            );
        }
        // this should be true! if it's not we have a bug
        assert!(peer.payment_in_flight);

        peer.payment_in_flight = false;
    }

    fn payment_succeeded(&mut self, to: &Identity, amount: Uint256) -> Result<(), RitaCommonError> {
        let peer = self.get_debt_data_mut(to);
        info!("Payment to {} succeeded", to.eth_address);

        // this should be true! if it's not we have a bug
        if !peer.payment_in_flight {
            error!(
                "Payment to {} succeeded but no payment in flight!",
                to.eth_address
            );
        }
        assert!(peer.payment_in_flight);

        peer.payment_in_flight = false;

        peer.total_payment_sent += amount;
        peer.last_successful_payment = Some(Instant::now());
        peer.debt -= match amount.to_int256() {
            Some(val) => val,
            None => {
                return Err(RitaCommonError::ConversionError(
                    "Failed to convert amount paid to Int256!".to_string(),
                ))
            }
        };
        Ok(())
    }

    fn payment_received(
        &mut self,
        ident: &Identity,
        amount: Uint256,
    ) -> Result<(), RitaCommonError> {
        let signed_zero = Int256::zero();
        let unsigned_zero = Uint256::zero();

        let debt_data = self.get_debt_data_mut(ident);
        info!(
            "payment received: old incoming payments for {:?}: {:?}",
            ident.mesh_ip, debt_data.incoming_payments
        );

        // just a counter, no convergence importance
        debt_data.total_payment_received += amount;
        // add in the latest amount to the pile before processing
        debt_data.incoming_payments += amount;

        let they_owe_us = debt_data.debt < Int256::zero();
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
                    None => {
                        return Err(RitaCommonError::MiscStringError(
                            "Unsigned payment int too big! You're super rich now".to_string(),
                        ))
                    }
                };
                debt_data.debt += signed_incoming;
                debt_data.incoming_payments = unsigned_zero;
            }
            (false, _) => {
                if amount > Uint256::zero() {
                    error!("Why did we get a payment when they don't owe us anything?");
                }
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

    fn traffic_replace(&mut self, ident: &Identity, amount: Int256) {
        trace!("traffic replace for {} is {}", ident.mesh_ip, amount);
        let debt_data = self.get_debt_data_mut(ident);

        // if we have a payment in flight we shouldn't reset the debt as
        // we may end up double paying we also should wait 60 seconds after
        // our last successful payment to make sure that the exit has had time
        // to check the full node, then update it's own debt keeper
        match (
            debt_data.payment_in_flight,
            debt_data.last_successful_payment,
        ) {
            (true, _) => {}
            (false, Some(val)) => {
                if Instant::now() - val > Duration::from_secs(15) {
                    debt_data.debt = amount;
                }
            }
            (false, None) => debt_data.debt = amount,
        }

        trace!("debt data for {} is {:?}", ident.mesh_ip, debt_data);
    }

    /// This updates a neighbor's debt and outputs a DebtAction if one is necessary.
    fn update_debt_keeper_state_machine(
        &mut self,
        ident: &Identity,
    ) -> Result<DebtAction, RitaCommonError> {
        trace!("debt data: {:?}", self.debt_data);
        let debt_data = self.get_debt_data_mut(ident);
        // the debt we started this round with

        if debt_data.debt != Int256::zero() {
            trace!(
                "debt update for {}: debt: {}, payment balance: {}",
                ident.wg_public_key,
                debt_data.debt,
                debt_data.incoming_payments,
            );
        }

        let payment_settings = settings::get_rita_common().payment;
        let close_threshold = calculate_close_thresh();
        let pay_threshold = get_pay_thresh();
        let debt_limit_enabled = payment_settings.debt_limit_enabled;
        let apply_incoming_credit_immediately = payment_settings.apply_incoming_credit_immediately;
        let enable_enforcement = payment_settings.enable_enforcement;

        trace!(
            "Debt is {} and close is {}",
            debt_data.debt,
            close_threshold
        );
        // negative debt means they owe us so when the debt is more negative than
        // the close treshold we should enforce.
        let should_close = debt_data.debt < close_threshold;
        let should_pay = debt_data.debt > pay_threshold;
        let payment_in_flight = debt_data.payment_in_flight;

        if debt_limit_enabled {
            debt_data.debt = debt_limit(debt_data.debt, close_threshold);
        }

        match (should_close, should_pay, payment_in_flight) {
            (true, true, _) => panic!("Close threshold is less than pay threshold!"),
            (true, false, _) => {
                // before we suspend check if there is any unapplied credit
                // if there is send a zero payment to apply it.
                let zero = Uint256::zero();
                if debt_data.incoming_payments > zero {
                    debt_data.action = DebtAction::OpenTunnel;
                    self.payment_received(ident, zero)?;
                    return Ok(DebtAction::OpenTunnel);
                }

                if enable_enforcement {
                    info!(
                        "debt {} is below close threshold {} for {}. suspending forwarding",
                        debt_data.debt, close_threshold, ident.wg_public_key
                    );
                    debt_data.action = DebtAction::SuspendTunnel;
                    Ok(DebtAction::SuspendTunnel)
                } else {
                    debt_data.action = DebtAction::OpenTunnel;
                    Ok(DebtAction::OpenTunnel)
                }
            }
            (false, true, false) => {
                let to_pay: Uint256 = debt_data.debt.to_uint256().ok_or_else(|| {
                    RitaCommonError::ConversionError(
                        "Unable to convert debt data into unsigned 256 bit integer".to_string(),
                    )
                })?;

                debt_data.payment_in_flight = true;

                info!("Make payment to {} for {}", ident.wg_public_key, to_pay);

                debt_data.action = DebtAction::MakePayment {
                    to: Box::new(*ident),
                    amount: to_pay,
                };

                Ok(debt_data.action.clone())
            }
            (false, false, _) => {
                // Check if there is any unapplied credit
                // if there is send a zero payment to apply it.
                //
                // this only has a meaningful function on the exits and is only enabled there
                // On clients 'extra' payment is probably disagreement
                // for example client A sees it's traffic early and sends a payment
                // client B is running slower and slots that into overpayment, then sees
                // the new traffic, goes to enforce, and applies the credit.
                //
                // Exits on the other hand have clients ask for debt values, so if the client
                // overpays for whatever reason they will keep paying at the pay threshold and
                // never use their credit until they run totally out of money. In practice I've seen
                // routers where this unapplied credit is several dollars worth, so it's best to remit
                // that to the users by applying it here.
                let zero = Uint256::zero();
                if apply_incoming_credit_immediately && debt_data.incoming_payments > zero {
                    debt_data.action = DebtAction::OpenTunnel;
                    self.payment_received(ident, zero)?;
                    return Ok(DebtAction::OpenTunnel);
                }

                debt_data.action = DebtAction::OpenTunnel;
                Ok(DebtAction::OpenTunnel)
            }
            (false, true, true) => {
                // we have a payment outstanding, we wait for it to complete
                // if it fails payment_validator will call payment_failed so that
                // we can try again
                debt_data.action = DebtAction::OpenTunnel;
                Ok(DebtAction::OpenTunnel)
            }
        }
    }
}

/// Saves the debt keeper to disk
pub fn save_debt_to_disk(save_frequency: Duration) {
    let dk_pin = &mut *DEBT_DATA.write().unwrap();
    let dk = get_debt_keeper_write_ref(dk_pin);
    trace!("sending debt keeper update");
    dk.save_if_needed(save_frequency);
}

/// On an interupt (SIGTERM), saving debtkeeper before exiting, this will only
/// happen if a reboot command is sent or an update is sent. The most common
/// form of reboot (pulling the power) will not call this
pub fn save_debt_on_shutdown() {
    let dk_pin = &mut *DEBT_DATA.write().unwrap();
    let dk = get_debt_keeper_write_ref(dk_pin);

    if let Err(e) = dk.save() {
        error!("Failed to save debts {:?}", e);
    } else {
        info!("Shutdown: Saving debt data");
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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

pub fn get_debts_list() -> Vec<GetDebtsResult> {
    let dk = get_debt_keeper();
    let debts: Vec<GetDebtsResult> = dk
        .debt_data
        .iter()
        .map(|(key, value)| GetDebtsResult::new(key, value))
        .collect();
    trace!("Debts: {}", debts.len());
    debts
}

#[cfg(test)]
mod tests {
    use std::fs::remove_file;

    use super::*;
    use rand::Rng;
    use serial_test::serial;
    use settings::client::RitaClientSettings;

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

    fn get_random_test_identity() -> Identity {
        let mut rng = rand::thread_rng();
        let mut array: [u16; 8] = [0; 8];
        for i in array.iter_mut() {
            *i = rng.gen();
        }

        Identity::new(
            array.into(),
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
    #[serial]
    fn test_single_suspend() {
        settings::set_rita_client(RitaClientSettings::default());
        let mut client = settings::get_rita_client();
        client.payment.payment_threshold = 1.into();
        settings::set_rita_client(client);

        let mut d = DebtKeeper::new();

        let ident = get_test_identity();

        d.traffic_update(&ident, Int256::from(-100i64));

        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::SuspendTunnel
        );
    }

    #[test]
    #[serial]
    fn test_single_overpay() {
        settings::set_rita_client(RitaClientSettings::default());
        let mut client = settings::get_rita_client();
        client.payment.payment_threshold = 1.into();
        settings::set_rita_client(client);

        let mut d = DebtKeeper::new();

        let ident = get_test_identity();

        d.traffic_update(&ident, Int256::from(-100i64));
        let _ = d.payment_received(&ident, Uint256::from(1000u64));

        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::OpenTunnel
        );
    }

    #[test]
    #[serial]
    fn test_single_pay() {
        settings::set_rita_client(RitaClientSettings::default());
        let mut common = settings::get_rita_common();
        common.payment.payment_threshold = 1.into();

        common.payment.debt_limit_enabled = false;
        settings::set_rita_common(common);

        let mut d = DebtKeeper::new();
        let ident = get_test_identity();

        d.traffic_update(&ident, Int256::from(100));

        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::MakePayment {
                amount: Uint256::from(100u32),
                to: Box::new(ident),
            }
        );
        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::OpenTunnel
        );
    }

    #[test]
    #[serial]
    fn test_single_pay_limited() {
        settings::set_rita_client(RitaClientSettings::default());
        let mut common = settings::get_rita_common();
        common.payment.payment_threshold = 1.into();

        common.payment.debt_limit_enabled = true;
        settings::set_rita_common(common);

        let mut d = DebtKeeper::new();
        let ident = get_test_identity();

        d.traffic_update(&ident, Int256::from(100));

        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::MakePayment {
                amount: Uint256::from(11u32),
                to: Box::new(ident),
            }
        );
    }

    #[test]
    #[serial]
    fn test_single_reopen() {
        settings::set_rita_client(RitaClientSettings::default());
        let mut client = settings::get_rita_client();
        client.payment.payment_threshold = 1.into();
        settings::set_rita_client(client);

        let mut d = DebtKeeper::new();
        let ident = get_test_identity();

        d.traffic_update(&ident, Int256::from(-100i64));

        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::SuspendTunnel
        );

        d.payment_received(&ident, Uint256::from(110u64)).unwrap();

        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::OpenTunnel
        );
    }

    #[test]
    #[serial]
    fn test_multi_pay() {
        settings::set_rita_client(RitaClientSettings::default());
        let mut common = settings::get_rita_common();
        common.payment.payment_threshold = 1.into();

        common.payment.debt_limit_enabled = false;
        settings::set_rita_common(common);

        let mut d = DebtKeeper::new();
        let ident = get_test_identity();

        for _ in 0..100 {
            d.traffic_update(&ident, Int256::from(100))
        }

        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::MakePayment {
                amount: Uint256::from(10000u32),
                to: Box::new(ident),
            }
        );
    }

    #[test]
    #[serial]
    fn test_multi_pay_lmited() {
        settings::set_rita_client(RitaClientSettings::default());
        let mut common = settings::get_rita_common();
        common.payment.payment_threshold = 1.into();

        common.payment.debt_limit_enabled = true;
        settings::set_rita_common(common);

        let mut d = DebtKeeper::new();
        let ident = get_test_identity();

        for _ in 0..100 {
            d.traffic_update(&ident, Int256::from(100))
        }

        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::MakePayment {
                amount: Uint256::from(11u32),
                to: Box::new(ident),
            }
        );
    }

    #[test]
    #[serial]
    fn test_multi_fail() {
        settings::set_rita_client(RitaClientSettings::default());
        let mut client = settings::get_rita_client();
        client.payment.payment_threshold = 1.into();
        settings::set_rita_client(client);

        let mut d = DebtKeeper::new();
        let ident = get_test_identity();

        d.traffic_update(&ident, Int256::from(-10100i64));

        // send lots of payments
        for _ in 0..100 {
            d.payment_received(&ident, Uint256::from(100u64)).unwrap();
        }

        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::SuspendTunnel
        );
    }

    #[test]
    #[serial]
    fn test_multi_reopen() {
        settings::set_rita_client(RitaClientSettings::default());
        let mut client = settings::get_rita_client();
        client.payment.payment_threshold = 1.into();
        settings::set_rita_client(client);

        let mut d = DebtKeeper::new();
        let ident = get_test_identity();

        d.traffic_update(&ident, Int256::from(-10100i64));

        for _ in 0..100 {
            d.payment_received(&ident, Uint256::from(100u64)).unwrap();
        }

        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::SuspendTunnel
        );

        d.payment_received(&ident, Uint256::from(200u64)).unwrap();

        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::OpenTunnel
        );
    }

    #[test]
    #[serial]
    fn test_credit_reopen() {
        settings::set_rita_client(RitaClientSettings::default());
        let mut common = settings::get_rita_common();
        common.payment.payment_threshold = 1.into();

        common.payment.debt_limit_enabled = false;
        settings::set_rita_common(common);

        let mut d = DebtKeeper::new();
        let ident = get_test_identity();

        // user pays early
        for _ in 0..100 {
            d.payment_received(&ident, Uint256::from(100u64)).unwrap();
        }

        d.traffic_update(&ident, Int256::from(-10100i64));

        // one round of grace while we apply their old payments
        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::OpenTunnel
        );
        // then enforcement kicks in becuase they have in fact used more than their credit
        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::SuspendTunnel
        );

        d.payment_received(&ident, Uint256::from(200u64)).unwrap();

        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::OpenTunnel
        );
    }

    #[test]
    #[serial]
    fn test_credit_reopen_limited() {
        settings::set_rita_client(RitaClientSettings::default());
        let mut common = settings::get_rita_common();
        common.payment.payment_threshold = 10.into();

        common.payment.debt_limit_enabled = true;
        settings::set_rita_common(common);

        let mut d = DebtKeeper::new();
        let ident = get_test_identity();

        // when the debt limit is enabled these tests have to get a little more real
        // the values stop making sense once you eceed the close_threshold because that's
        // the desired behavior of a system with the debt limit on, so you can't add in
        // big numbers and expect conservation to make sense. Instead what we do here is
        // more realistic and reflects a slight underpayment until enforcement starts followed
        // by a smaller payment to reopen
        for _ in 0..100 {
            d.payment_received(&ident, Uint256::from(25u64)).unwrap();
            assert_eq!(
                d.update_debt_keeper_state_machine(&ident).unwrap(),
                DebtAction::OpenTunnel
            );
            d.traffic_update(&ident, Int256::from(-26i64));
        }
        // negative debt is now -105 so a payment of 100 shouldn't open unless limiting is working
        d.traffic_update(&ident, Int256::from(-5i64));
        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::SuspendTunnel
        );

        d.payment_received(&ident, Uint256::from(100u64)).unwrap();

        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::OpenTunnel
        );
    }

    #[test]
    #[serial]
    fn test_payment_fail() {
        settings::set_rita_client(RitaClientSettings::default());
        let mut common = settings::get_rita_common();
        common.payment.payment_threshold = 1.into();
        common.payment.debt_limit_enabled = false;
        settings::set_rita_common(common);

        let mut d = DebtKeeper::new();
        let ident = get_test_identity();

        // generate a bunch of traffic
        for _ in 0..100 {
            d.traffic_update(&ident, Int256::from(100))
        }
        // make sure that the update response is to pay
        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::MakePayment {
                amount: Uint256::from(10000u32),
                to: Box::new(ident),
            }
        );
        // simulate a payment failure
        d.payment_failed(&ident);

        // make sure we haven't marked any payments as sent (because the payment failed)
        assert_eq!(
            d.get_debts()[&ident].total_payment_sent,
            Uint256::from(0u32)
        );

        // update the state machine again, make sure it tires the payment again since the last one failed
        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::MakePayment {
                amount: Uint256::from(10000u32),
                to: Box::new(ident),
            }
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
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::MakePayment {
                amount: Uint256::from(10000u32),
                to: Box::new(ident),
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
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::MakePayment {
                amount: Uint256::from(10000u32),
                to: Box::new(ident),
            }
        );
        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::OpenTunnel
        );
        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::OpenTunnel
        );
        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::OpenTunnel
        );
    }

    #[test]
    #[serial]
    fn test_payment_fail_limited() {
        settings::set_rita_client(RitaClientSettings::default());

        let mut common = settings::get_rita_common();
        common.payment.payment_threshold = 1.into();
        common.payment.debt_limit_enabled = true;
        settings::set_rita_common(common);

        // same as above except debt is limited, so we will be paying much
        // smaller amounts than we are setup to 'owe'

        let mut d = DebtKeeper::new();
        let ident = get_test_identity();

        // generate a bunch of traffic
        for _ in 0..100 {
            d.traffic_update(&ident, Int256::from(100))
        }
        // make sure that the update response is to pay
        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::MakePayment {
                amount: Uint256::from(11u32),
                to: Box::new(ident),
            }
        );
        // simulate a payment failure
        d.payment_failed(&ident);

        // make sure we haven't marked any payments as sent (because the payment failed)
        assert_eq!(
            d.get_debts()[&ident].total_payment_sent,
            Uint256::from(0u32)
        );

        // try the payment again
        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::MakePayment {
                amount: Uint256::from(11u32),
                to: Box::new(ident),
            }
        );

        // mark the payment as a success
        d.payment_succeeded(&ident, Uint256::from(11u32)).unwrap();
        // make sure the payment sent value is updated
        assert_eq!(
            d.get_debts()[&ident].total_payment_sent,
            Uint256::from(11u32)
        );

        // more traffic
        for _ in 0..100 {
            d.traffic_update(&ident, Int256::from(100))
        }
        // another payment, to make sure the state was all set right after
        // the failure then success
        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::MakePayment {
                amount: Uint256::from(11u32),
                to: Box::new(ident),
            }
        );
        d.payment_succeeded(&ident, Uint256::from(11u32)).unwrap();
        assert_eq!(
            d.get_debts()[&ident].total_payment_sent,
            Uint256::from(22u32)
        );

        // finally lets make sure we don't send any payments while
        // a payment is in flight
        for _ in 0..100 {
            d.traffic_update(&ident, Int256::from(100))
        }
        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::MakePayment {
                amount: Uint256::from(11u32),
                to: Box::new(ident),
            }
        );
        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::OpenTunnel
        );
        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::OpenTunnel
        );
        assert_eq!(
            d.update_debt_keeper_state_machine(&ident).unwrap(),
            DebtAction::OpenTunnel
        );
    }

    #[test]
    #[serial]
    fn test_debts_saving() {
        settings::set_rita_client(RitaClientSettings::default());
        let mut test_they_owe = NodeDebtData::new();
        test_they_owe.debt = Int256::from(-500_000i64);
        let they_owe = (get_random_test_identity(), test_they_owe);

        let mut test_we_owe = NodeDebtData::new();
        test_we_owe.debt = Int256::from(500_000i64);
        let we_owe = (get_random_test_identity(), test_we_owe);

        let mut test_have_credit = NodeDebtData::new();
        test_have_credit.incoming_payments = Uint256::from(1000u64);
        let have_credit = (get_random_test_identity(), test_have_credit);

        let mut test_have_credit_and_we_owe = NodeDebtData::new();
        test_have_credit_and_we_owe.debt = Int256::from(500_000i64);
        test_have_credit_and_we_owe.incoming_payments = Uint256::from(1000u64);
        let have_credit_and_we_owe = (get_random_test_identity(), test_have_credit_and_we_owe);

        let mut test_have_credit_and_they_owe = NodeDebtData::new();
        test_have_credit_and_they_owe.debt = Int256::from(-500_000i64);
        test_have_credit_and_they_owe.incoming_payments = Uint256::from(1000u64);
        let have_credit_and_they_owe = (get_random_test_identity(), test_have_credit_and_they_owe);

        let input: DebtDataSer = vec![
            they_owe,
            we_owe,
            have_credit,
            have_credit_and_we_owe,
            have_credit_and_they_owe,
        ];

        let dd = ser_to_debt_data(input);
        let mut one_pos_debt = false;
        let mut one_pos_credit = false;
        for item in dd.iter() {
            assert!(item.1.debt >= Int256::zero());
            if item.1.debt > Int256::zero() {
                one_pos_debt = true;
            }
            if item.1.incoming_payments > Uint256::zero() {
                one_pos_credit = true;
            }
        }
        // we should discard the negative with no credit, keep the one with credit but zero it's entry
        assert!(dd.len() == 4);
        assert!(one_pos_credit);
        assert!(one_pos_debt);
    }

    #[test]
    #[serial]
    fn test_saving_debts_to_file() {
        let mut debt_data: DebtData = HashMap::new();
        let id = Identity {
            mesh_ip: "fd00::1447:1eff".parse().unwrap(),
            eth_address: "0x5AeE3Dff733F56cFe7E5390B9cC3A46a90cA1CfA"
                .parse()
                .unwrap(),
            wg_public_key: "zgAlhyOQy8crB0ewrsWt3ES9SvFguwx5mq9i2KiknmA="
                .parse()
                .unwrap(),
            nickname: None,
        };

        let node_debts = NodeDebtData {
            total_payment_received: Uint256::from(8u8),
            total_payment_sent: Uint256::from(35u8),
            debt: Int256::from(34634u64),
            incoming_payments: Uint256::from(0u8),
            action: DebtAction::OpenTunnel,
            payment_in_flight: false,
            last_successful_payment: None,
        };

        let id2 = Identity {
            mesh_ip: "fd00::1337:e2f".parse().unwrap(),
            eth_address: "0x5AeE3Dff733F56cFe7E5390B9cC3A46a90cA1CfA"
                .parse()
                .unwrap(),
            wg_public_key: "uNu3IMSgt3SY2+MvtEwjEpx45lOk7q/7sWC3ff80GXE="
                .parse()
                .unwrap(),
            nickname: None,
        };

        let node_debts2 = NodeDebtData {
            total_payment_received: Uint256::from(9u8),
            total_payment_sent: Uint256::from(5u8),
            debt: Int256::from(3460u64),
            incoming_payments: Uint256::from(0u8),
            action: DebtAction::OpenTunnel,
            payment_in_flight: false,
            last_successful_payment: None,
        };

        debt_data.insert(id, node_debts);
        debt_data.insert(id2, node_debts2);

        let file_path = "testing_debt_saving.bincode";

        let serialized = bincode::serialize(&debt_data_to_ser(debt_data.clone())).unwrap();
        let mut file = File::create(file_path).expect("Why fail");
        if let Err(e) = file.write_all(&serialized) {
            println!("{e:?}");
        }

        match deserialize_from_binary(file_path.to_string()) {
            Some(a) => println!("{a:?}"),
            None => print!("Unable to deserial"),
        }

        if let Err(e) = remove_file(file_path) {
            println!("Remove the file: {e:?}");
        }

        // TEST USING BufReader / BufWriter

        // use std::{
        //     io::{BufReader, BufWriter},
        //     net::IpAddr,
        // };

        // use bincode::{deserialize_from, serialize_into};

        // {
        //     let serialized = debt_data_to_ser(debt_data.clone());
        //     // let serialized = debt_data.clone();
        //     let mut f = BufWriter::new(File::create(file_path).unwrap());
        //     serialize_into(&mut f, &serialized).unwrap();
        // }

        // let file_path = "testing_debt_saving.bincode";
        // let reader = BufReader::new(File::open(file_path).unwrap());
        // let mut x: Vec<(Identity, NodeDebtData)> = deserialize_from(reader).unwrap();
        // println!("{:?}", x);
    }

    #[test]
    #[serial]
    fn test_normalize_payment_amount() {
        // this is $6 in a 6 decimal of precision token where 1 unit = $1
        let start_amount = Uint256::from(6_000_000u64);
        // this is $6 in a 18 decimal of precision token where 1 unit = $1
        let end_amount = Uint256::from(6_000_000_000_000_000_000u64);
        let usdc = Denom {
            denom: "uUSDC".to_string(),
            decimal: 1_000_000,
        };
        let res = normalize_payment_amount(start_amount, usdc.clone(), wei_denom());
        assert_eq!(res, end_amount);
        let res = normalize_payment_amount(end_amount, wei_denom(), usdc);
        assert_eq!(res, start_amount)
    }
}
