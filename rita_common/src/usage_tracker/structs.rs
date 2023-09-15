use althea_types::{Identity, IndexedUsageHour, PaymentTx, Usage};
use num256::Uint256;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;

/// A struct for tracking each hours of payments indexed in hours since unix epoch
/// used to send to the frontend
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaymentHour {
    pub index: u64,
    pub payments: Vec<FormattedPaymentTxOld>,
}

/// Old usage tracker struct used by versions up to Beta 20 rc29 and Beta 21 rc2
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsageTrackerStorageOld {
    pub last_save_hour: u64,
    // at least one of these will be left unused
    pub client_bandwidth: VecDeque<IndexedUsageHour>,
    pub relay_bandwidth: VecDeque<IndexedUsageHour>,
    pub exit_bandwidth: VecDeque<IndexedUsageHour>,
    /// A history of payments
    pub payments: VecDeque<PaymentHour>,
}

/// Usage tracker data storage, stores information about the data usage of this
/// Rita process
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct UsageTrackerStorage {
    /// The last time this struct was saved to the disk
    pub last_save_hour: u64,
    // at least one of these will be left unused
    /// client bandwidth usage per hour indexd by unix timestamp in hours
    pub client_bandwidth: HashMap<u64, Usage>,
    /// relay bandwidth usage per hour indexd by unix timestamp in hours
    pub relay_bandwidth: HashMap<u64, Usage>,
    /// exit bandwidth usage per hour indexd by unix timestamp in hours
    pub exit_bandwidth: HashMap<u64, Usage>,
    /// A history of payments
    pub payments: HashSet<UsageTrackerPayment>,
}

impl UsageTrackerStorage {
    pub fn get_txids(&self) -> HashSet<Uint256> {
        let mut set = HashSet::new();
        for p in &self.payments {
            set.insert(p.txid);
        }
        set
    }
}

/// In an effort to converge this module between the three possible bw tracking
/// use cases this enum is used to identify which sort of usage we are tracking
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum UsageType {
    Client,
    Relay,
    Exit,
}

/// A version of payment tx with a string txid so that the formatting is correct
/// for display to users.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct FormattedPaymentTxOld {
    pub to: Identity,
    pub from: Identity,
    pub amount: Uint256,
    pub txid: String,
}

impl From<PaymentTx> for FormattedPaymentTxOld {
    fn from(input: PaymentTx) -> Self {
        let txid = input.txid;
        FormattedPaymentTxOld {
            to: input.to,
            from: input.from,
            amount: input.amount,
            txid: format!("{txid:#066x}"),
        }
    }
}

impl From<UsageTrackerPayment> for FormattedPaymentTxOld {
    fn from(value: UsageTrackerPayment) -> Self {
        let txid = value.txid;
        FormattedPaymentTxOld {
            to: value.to,
            from: value.from,
            amount: value.amount,
            txid: format!("{txid:#066x}"),
        }
    }
}

/// A version of payment tx with a string txid so that the formatting is correct
/// for display to users.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct UsageTrackerPayment {
    pub to: Identity,
    pub from: Identity,
    pub amount: Uint256,
    pub txid: Uint256,
    /// the unix timestamp in hours of when this payment occured.
    pub index: u64,
}

impl Ord for UsageTrackerPayment {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.index.cmp(&other.index)
    }
}

impl PartialOrd for UsageTrackerPayment {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.index.partial_cmp(&other.index)
    }
}

impl Hash for UsageTrackerPayment {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // hash all values except the timestamp
        self.to.hash(state);
        self.from.hash(state);
        self.amount.hash(state);
        self.txid.hash(state);
    }
}

impl UsageTrackerPayment {
    pub fn from_payment_tx(input: PaymentTx, index: u64) -> UsageTrackerPayment {
        UsageTrackerPayment {
            to: input.to,
            from: input.from,
            amount: input.amount,
            txid: input.txid,
            index,
        }
    }
}

pub fn convert_payment_set_to_payment_hour(
    input: HashSet<UsageTrackerPayment>,
) -> VecDeque<PaymentHour> {
    let mut intermediate = HashMap::new();
    for ph in input {
        match intermediate.get_mut(&ph.index) {
            None => {
                intermediate.insert(ph.index, vec![ph]);
            }
            Some(val) => val.push(ph),
        }
    }
    let mut out = VecDeque::new();
    for (h, phs) in intermediate {
        out.push_back(PaymentHour {
            index: h,
            payments: phs.into_iter().map(|v| v.into()).collect(),
        })
    }
    out
}
