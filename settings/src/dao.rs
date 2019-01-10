use config;

use toml;

use serde;
use serde_json;

use clarity::Address;

// in seconds
fn default_cache_timeout() -> u64 {
    600
}

fn default_dao_enforcement() -> bool {
    true
}

fn default_node_list() -> Vec<String> {
    vec!["https://eth.althea.org:443".to_string()]
}

fn default_dao_address() -> Vec<Address> {
    Vec::new()
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Default)]
pub struct SubnetDAOSettings {
    /// If we should take action based on DAO membership
    #[serde(default = "default_dao_enforcement")]
    pub dao_enforcement: bool,
    /// The amount of time an entry is used before refreshing the cache
    #[serde(default = "default_cache_timeout")]
    pub cache_timeout_seconds: u64,
    /// A list of nodes to query for blockchain data
    /// this is kept seperate from the version for payment settings node
    /// list in order to allow for the DAO and payments to exist on different
    /// chains, provided in name:port format
    #[serde(default = "default_node_list")]
    pub node_list: Vec<String>,
    /// List of subnet DAO's to which we are a member
    #[serde(default = "default_dao_address")]
    pub dao_addresses: Vec<Address>,
}
