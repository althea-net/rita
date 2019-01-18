use althea_types::SystemChain;
use clarity::{Address, PrivateKey};

use num256::{Int256, Uint256};

fn default_local_fee() -> u32 {
    300_000u32 // 300kWei per byte
}
fn default_max_fee() -> u32 {
    20_000_000u32 // $3/gb at $150 eth
}

fn default_close_fraction() -> Int256 {
    100.into()
}

fn default_close_threshold() -> Int256 {
    (-8400000000000000i64).into()
}

fn default_pay_threshold() -> Int256 {
    840_000_000_000_000i64.into()
}

fn default_dynamic_fee_multiplier() -> u32 {
    20
}

fn default_free_tier_throughput() -> u32 {
    1000
}

fn default_price_oracle() -> bool {
    true
}

fn default_oracle_url() -> String {
    "https://updates.altheamesh.com/prices".to_string()
}

fn default_node_list() -> Vec<String> {
    vec![
        "https://eth.althea.org:443".to_string(),
        "https://mainnet.infura.io/v3/6b080f02d7004a8394444cdf232a7081".to_string(),
    ]
}

fn default_system_chain() -> SystemChain {
    SystemChain::Ethereum
}

fn default_channel_contract_address() -> Address {
    "0x6006FD9175db7c66ca3bF2f9886767d9faCfdc8b"
        .parse()
        .unwrap()
}

/// This struct is used by both rita and rita_exit to configure the dummy payment controller and
/// debt keeper
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PaymentSettings {
    /// What we charge other nodes
    #[serde(default = "default_local_fee")]
    pub local_fee: u32,
    /// A price limit, we will not pay more than this
    #[serde(default = "default_max_fee")]
    pub max_fee: u32,
    /// For non-channel payments only, determines how much to multiply the nominal gas price
    /// to get the pay_threshold values and then again for the close_threshold
    #[serde(default = "default_dynamic_fee_multiplier")]
    pub dynamic_fee_multiplier: u32,
    /// Throughput of the free tier that this node provides in kbit/s
    #[serde(default = "default_free_tier_throughput")]
    pub free_tier_throughput: u32,
    /// The threshold above which we will kick off a payment
    #[serde(default = "default_pay_threshold")]
    pub pay_threshold: Int256,
    /// The threshold below which we will kick another node off (not implemented yet)
    #[serde(default = "default_close_threshold")]
    pub close_threshold: Int256,
    /// The amount of 'grace' to give a long term neighbor
    #[serde(default = "default_close_fraction")]
    pub close_fraction: Int256,
    /// The amount of billing cycles a node can fall behind without being subjected to the threshold
    pub buffer_period: u32,
    /// Our own eth private key we do not store address, instead it is derived from here
    pub eth_private_key: Option<PrivateKey>,
    // Our own eth Address, derived from the private key on startup and not stored
    pub eth_address: Option<Address>,
    #[serde(default)]
    pub balance: Uint256,
    #[serde(default)]
    pub nonce: Uint256,
    #[serde(default)]
    pub gas_price: Uint256,
    #[serde(default)]
    pub net_version: Option<u64>,
    /// A list of nodes to query for blockchain data
    /// this is kept seperate from the version for DAO settings node
    /// list in order to allow for the DAO and payments to exist on different
    /// chains, provided in name:port format
    #[serde(default = "default_node_list")]
    pub node_list: Vec<String>,
    #[serde(default = "default_price_oracle")]
    pub price_oracle_enabled: bool,
    #[serde(default = "default_oracle_url")]
    pub price_oracle_url: String,
    #[serde(default = "default_system_chain")]
    pub system_chain: SystemChain,
    #[serde(default = "default_channel_contract_address")]
    pub channel_contract_address: Address,
}

impl Default for PaymentSettings {
    fn default() -> Self {
        PaymentSettings {
            local_fee: default_local_fee(),
            max_fee: default_max_fee(),
            dynamic_fee_multiplier: default_dynamic_fee_multiplier(),
            free_tier_throughput: default_free_tier_throughput(),
            pay_threshold: default_pay_threshold(),
            close_threshold: default_close_threshold(),
            close_fraction: default_close_fraction(),
            buffer_period: 3,
            eth_private_key: None,
            eth_address: None,
            balance: 0u64.into(),
            nonce: 0u64.into(),
            gas_price: 0u64.into(),
            net_version: None,
            node_list: Vec::new(),
            price_oracle_enabled: true,
            price_oracle_url: default_oracle_url(),
            system_chain: default_system_chain(),
            channel_contract_address: default_channel_contract_address(),
        }
    }
}
