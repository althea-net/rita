use serde::Serialize;
use serde::{Deserialize, Deserializer, Serializer};
use std::fmt;
use std::fmt::Display;
use std::hash::Hash;
use std::str::FromStr;

#[derive(Default, Debug, Hash, Clone, Eq, PartialEq, Copy)]
pub enum SystemChain {
    Ethereum,
    Sepolia,
    #[default]
    Xdai,
    AltheaL1,
}

/// Interal mapping of a SystemChain to an integer, used to store data in the db
impl From<SystemChain> for u8 {
    fn from(value: SystemChain) -> Self {
        match value {
            SystemChain::AltheaL1 => 1,
            SystemChain::Ethereum => 2,
            SystemChain::Sepolia => 3,
            SystemChain::Xdai => 4,
        }
    }
}

impl From<u8> for SystemChain {
    fn from(value: u8) -> Self {
        match value {
            1 => SystemChain::AltheaL1,
            2 => SystemChain::Ethereum,
            3 => SystemChain::Sepolia,
            4 => SystemChain::Xdai,
            // Undefined, return Althea chain by default
            _ => SystemChain::AltheaL1,
        }
    }
}

impl Display for SystemChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SystemChain::Ethereum => write!(f, "Ethereum"),
            SystemChain::Sepolia => write!(f, "Sepolia"),
            SystemChain::Xdai => write!(f, "Xdai"),
            SystemChain::AltheaL1 => write!(f, "Althea"),
        }
    }
}

pub fn default_system_chain() -> SystemChain {
    SystemChain::default()
}

impl FromStr for SystemChain {
    type Err = String;
    fn from_str(s: &str) -> Result<SystemChain, String> {
        match s {
            "Ethereum" => Ok(SystemChain::Ethereum),
            "ethereum" => Ok(SystemChain::Ethereum),
            "eth" => Ok(SystemChain::Ethereum),
            "ETH" => Ok(SystemChain::Ethereum),
            "Rinkeby" => Ok(SystemChain::Sepolia),
            "rinkeby" => Ok(SystemChain::Sepolia),
            "Sepolia" => Ok(SystemChain::Sepolia),
            "sepolia" => Ok(SystemChain::Sepolia),
            "Testnet" => Ok(SystemChain::Sepolia),
            "Test" => Ok(SystemChain::Sepolia),
            "testnet" => Ok(SystemChain::Sepolia),
            "test" => Ok(SystemChain::Sepolia),
            "Xdai" => Ok(SystemChain::Xdai),
            "xDai" => Ok(SystemChain::Xdai),
            "xDAI" => Ok(SystemChain::Xdai),
            "xdai" => Ok(SystemChain::Xdai),
            "GnosisChain" => Ok(SystemChain::Xdai),
            "gnosischain" => Ok(SystemChain::Xdai),
            "Gnosis" => Ok(SystemChain::Xdai),
            "gnosis" => Ok(SystemChain::Xdai),
            "Althea" => Ok(SystemChain::AltheaL1),
            "AltheaL1" => Ok(SystemChain::AltheaL1),
            "altheal1" => Ok(SystemChain::AltheaL1),
            "altheaL1" => Ok(SystemChain::AltheaL1),
            _ => Err("Unknown SystemChain!".to_string()),
        }
    }
}

impl Serialize for SystemChain {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for SystemChain {
    fn deserialize<D>(deserializer: D) -> Result<SystemChain, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}
