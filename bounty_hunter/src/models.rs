use clarity::Signature;
use failure::Error;
use num256::Uint256;
use num_traits::Zero;

use std::convert::{From, Into};

use schema::states;

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct ChannelState {
    pub channel_id: Uint256,
    pub nonce: Uint256,

    pub balance_a: Uint256,
    pub balance_b: Uint256,

    pub signature_a: Option<Signature>,
    pub signature_b: Option<Signature>,
}

/// A helper type that prepares a [ChannelState](ChannelState) for storage by turning the contents into types
/// easy to grasp for `diesel`.
#[derive(Queryable, Debug, Clone, PartialEq, Eq, Default)]
pub struct ChannelStateRecord {
    pub id: i64,
    pub channel_id: Vec<u8>,
    pub nonce: Vec<u8>,

    pub balance_a: Vec<u8>,
    pub balance_b: Vec<u8>,

    pub sig_a_v: Option<Vec<u8>>,
    pub sig_a_r: Option<Vec<u8>>,
    pub sig_a_s: Option<Vec<u8>>,

    pub sig_b_v: Option<Vec<u8>>,
    pub sig_b_r: Option<Vec<u8>>,
    pub sig_b_s: Option<Vec<u8>>,
}

#[derive(AsChangeset, Insertable, Clone, Debug, Eq, PartialEq)]
#[table_name = "states"]
pub struct NewChannelStateRecord {
    pub channel_id: Vec<u8>,
    pub nonce: Vec<u8>,

    pub balance_a: Vec<u8>,
    pub balance_b: Vec<u8>,

    pub sig_a_v: Option<Vec<u8>>,
    pub sig_a_r: Option<Vec<u8>>,
    pub sig_a_s: Option<Vec<u8>>,

    pub sig_b_v: Option<Vec<u8>>,
    pub sig_b_r: Option<Vec<u8>>,
    pub sig_b_s: Option<Vec<u8>>,
}

impl Default for ChannelState {
    fn default() -> Self {
        Self {
            channel_id: Uint256::zero(),
            nonce: Uint256::zero(),
            balance_a: Uint256::zero(),
            balance_b: Uint256::zero(),
            signature_a: None,
            signature_b: None,
        }
    }
}

impl From<ChannelStateRecord> for NewChannelStateRecord {
    fn from(record: ChannelStateRecord) -> Self {
        NewChannelStateRecord {
            channel_id: record.channel_id,
            nonce: record.nonce,

            balance_a: record.balance_a,
            balance_b: record.balance_b,

            sig_a_v: record.sig_a_v,
            sig_a_r: record.sig_a_r,
            sig_a_s: record.sig_a_s,

            sig_b_v: record.sig_b_v,
            sig_b_r: record.sig_b_r,
            sig_b_s: record.sig_b_s,
        }
    }
}

impl ChannelState {
    /// Verify the channel state against all available signatures
    pub fn verify(&self, _sig: &Signature) -> Result<(), Error> {
        Ok(())
    }
}

impl ChannelStateRecord {
    // TODO: Implement TryInto instead once it makes it to stable
    pub fn to_state(self) -> Result<ChannelState, Error> {
        let mut state = ChannelState {
            channel_id: Uint256::from_bytes_be(&self.channel_id),
            nonce: Uint256::from_bytes_be(&self.nonce),

            balance_a: Uint256::from_bytes_be(&self.balance_a),
            balance_b: Uint256::from_bytes_be(&self.balance_b),

            // We need to determine that the signature fields are sane first
            signature_a: None,
            signature_b: None,
        };

        // Check that all three sig vars are either all Some() or all None, nothing in between;
        // assign to state.
        state.signature_a = match (self.sig_a_v, self.sig_a_r, self.sig_a_s) {
            (Some(v), Some(r), Some(s)) => Some(Signature::new(
                Uint256::from_bytes_be(&v),
                Uint256::from_bytes_be(&r),
                Uint256::from_bytes_be(&s),
            )),
            (None, None, None) => None,
            (other_v, other_r, other_s) => bail!(
                "Signature A variable Options inconsistent: v: {:?}, r: {:?}, s: {:?}",
                other_v,
                other_r,
                other_s,
            ),
        };
        state.signature_b = match (self.sig_b_v, self.sig_b_r, self.sig_b_s) {
            (Some(v), Some(r), Some(s)) => Some(Signature::new(
                Uint256::from_bytes_be(&v),
                Uint256::from_bytes_be(&r),
                Uint256::from_bytes_be(&s),
            )),
            (None, None, None) => None,
            (other_v, other_r, other_s) => bail!(
                "Signature B variable Options inconsistent: v: {:?}, r: {:?}, s: {:?}",
                other_v,
                other_r,
                other_s,
            ),
        };

        Ok(state)
    }
}

impl NewChannelStateRecord {
    /// Convenience wrapper for `ChannelStateRecord::to_state()` for using `NewChannelStateRecord`;
    /// TODO: implement TryInto once it makes it to stable
    pub fn to_state(self) -> Result<ChannelState, Error> {
        (ChannelStateRecord {
            id: 0, // Dummy value; Meaningless and wrong for most use cases of ChannelStateRecord

            channel_id: self.channel_id,
            nonce: self.nonce,

            balance_a: self.balance_a,
            balance_b: self.balance_b,

            sig_a_v: self.sig_a_v,
            sig_a_r: self.sig_a_r,
            sig_a_s: self.sig_a_s,

            sig_b_v: self.sig_b_v,
            sig_b_r: self.sig_b_r,
            sig_b_s: self.sig_b_s,
        }).to_state()
    }
}

impl From<ChannelState> for NewChannelStateRecord {
    fn from(state: ChannelState) -> Self {
        /*
         * DO NOT "OPTIMIZE" `nonce_fixed` INTO A VEC. Fixed-length is critical for ordering to
         * work properly within the database (blob ordering in SQLite is analogous to string
         * ordering - string "9" goes BEFORE string "10", but fixed-size would make this comparison
         * more like "09" vs. "10" which checks out).
         *
         * SCREWED UP ORDERING FOR NONCE/SEQNO VARIABLES MEANS HIDEOUS ERRORS AND REPLAY ATTACK
         * VULNERABILITIES.
         */
        let nonce_fixed: [u8; 32] = state.nonce.into();
        let mut record = Self {
            channel_id: state.channel_id.to_bytes_be(),
            nonce: nonce_fixed.to_vec(),
            balance_a: state.balance_a.to_bytes_be(),
            balance_b: state.balance_b.to_bytes_be(),

            // Initially fill with Nones
            sig_a_v: None,
            sig_a_r: None,
            sig_a_s: None,
            sig_b_v: None,
            sig_b_r: None,
            sig_b_s: None,
        };

        // Assign sig vars in-bulk
        if let Some(sig_a) = state.signature_a {
            record.sig_a_v = Some(sig_a.v.to_bytes_be());
            record.sig_a_r = Some(sig_a.r.to_bytes_be());
            record.sig_a_s = Some(sig_a.s.to_bytes_be());
        }
        if let Some(sig_b) = state.signature_b {
            record.sig_b_v = Some(sig_b.v.to_bytes_be());
            record.sig_b_r = Some(sig_b.r.to_bytes_be());
            record.sig_b_s = Some(sig_b.s.to_bytes_be());
        }

        return record;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state2record() {
        let mut example_state = ChannelState::default();
        example_state.signature_a = Some(Signature::new(15000.into(), 200.into(), 35.into()));
        example_state.signature_b = Some(Signature::new(42.into(), 2001.into(), 1.into()));

        let expected_record = NewChannelStateRecord {
            channel_id: vec![0],
            nonce: vec![0u8; 32],

            balance_a: vec![0],
            balance_b: vec![0],

            sig_a_v: Some(vec![58, 152]),
            sig_a_r: Some(vec![200]),
            sig_a_s: Some(vec![35]),

            sig_b_v: Some(vec![42]),
            sig_b_r: Some(vec![7, 209]),
            sig_b_s: Some(vec![1]),
        };

        assert_eq!(NewChannelStateRecord::from(example_state), expected_record);
    }

    #[test]
    fn test_record2state() {
        let example_record = NewChannelStateRecord {
            channel_id: Vec::new(),
            nonce: Vec::new(),

            balance_a: Vec::new(),
            balance_b: Vec::new(),

            sig_a_v: Some(vec![0x3a, 0x98]),
            sig_a_r: Some(vec![0xc8]),
            sig_a_s: Some(vec![0x23]),

            sig_b_v: Some(vec![0x2a]),
            sig_b_r: Some(vec![0x07, 0xd1]),
            sig_b_s: Some(vec![0x1]),
        };

        let mut expected_state = ChannelState::default();
        expected_state.signature_a = Some(Signature::new(15000.into(), 200.into(), 35.into()));
        expected_state.signature_b = Some(Signature::new(42.into(), 2001.into(), 1.into()));

        assert_eq!(example_record.to_state().unwrap(), expected_state);
    }

    /// Constructing a signature with missing variables is impossible and ambiguous to handle
    /// programatically
    #[test]
    #[should_panic]
    fn test_inconsistent_record() {
        let inconsistent_record = NewChannelStateRecord {
            channel_id: vec![],
            nonce: vec![],

            balance_a: vec![],
            balance_b: vec![],

            sig_a_v: Some(vec![]),
            sig_a_r: None,
            sig_a_s: Some(vec![]),

            sig_b_v: Some(vec![]),
            sig_b_r: Some(vec![]),
            sig_b_s: None,
        };

        let _impossible_state = inconsistent_record.to_state().unwrap();
    }

    /// nonce 0x100 vs. 0xff edge case
    #[test]
    fn test_nonce_ordering_sanity() {
        let smaller_nonce = ChannelState {
            channel_id: 0.into(),
            nonce: 0xff.into(),
            balance_a: 0.into(),
            balance_b: 0.into(),

            signature_a: Some(Signature::new(0.into(), 0.into(), 0.into())),
            signature_b: Some(Signature::new(0.into(), 0.into(), 0.into())),
        };

        let mut bigger_nonce = smaller_nonce.clone();
        bigger_nonce.nonce = 0x100.into();

        let record_smaller = NewChannelStateRecord::from(smaller_nonce);
        let record_bigger = NewChannelStateRecord::from(bigger_nonce);

        assert!(
            record_bigger.nonce > record_smaller.nonce,
            "Congratulations, your bounty hunter may be horribly broken! bigger: {:?}, smaller: {:?}",
            record_bigger.nonce,
            record_smaller.nonce
            );
    }
}
