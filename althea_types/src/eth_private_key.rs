use std::ops::Deref;
use std::str::FromStr;
use std::fmt;
use hex;
use serde;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::hash::{Hash, Hasher};

use eth_macro;

impl_eth!(EthPrivateKey[u8; 64]);
