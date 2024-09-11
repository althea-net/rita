use crate::Identity;
use num256::Uint256;
use serde::Deserialize;
use serde::Serialize;
use std::hash::{Hash, Hasher};

#[derive(PartialEq, Eq, Hash, Clone, Debug, Serialize, Deserialize)]
pub struct Denom {
    /// String representation of token, ex, ualthea, wei, from athea chain will be some unpredictable ibc/<hash>
    pub denom: String,
    /// This value * 1 denom = 1 unit of token. For example for wei, decimal is 10^18. So 1 wei * 10^18 = 1 eth
    /// u64 supports upto a 10^19 decimal
    pub decimal: u64,
}

/// This represents a generic payment that may be to or from us
/// it contains a txid from a published transaction
/// that should be validated against the blockchain
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub struct PaymentTx {
    pub to: Identity,
    pub from: Identity,
    pub amount: Uint256,
    // txhash of the payment this could either be on Ethereum or Althea as both are 256 bit integers
    pub txid: Uint256,
}

// Ensure that duplicate txid are always treated as the same object
impl Hash for PaymentTx {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.txid.hash(state);
    }
}

/// This represents a generic payment that may be to or from us, it does not contain a txid meaning it is
/// unpublished
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct UnpublishedPaymentTx {
    pub to: Identity,
    pub from: Identity,
    pub amount: Uint256,
}

impl UnpublishedPaymentTx {
    pub fn publish(&self, txid: Uint256) -> PaymentTx {
        PaymentTx {
            to: self.to,
            from: self.from,
            amount: self.amount,
            txid,
        }
    }
}
