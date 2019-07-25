use althea_types::SystemChain;
use clarity::{Address, PrivateKey};

use num256::{Int256, Uint256};

fn default_local_fee() -> u32 {
    300_000u32 // 300kWei per byte
}
fn default_max_fee() -> u32 {
    20_000_000u32 // $3/gb at $150 eth
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

fn default_balance_warning_level() -> Uint256 {
    (10_000_000_000_000_000u64).into()
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

fn default_debts_file() -> String {
    "/etc/rita-debts.json".to_string()
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
    /// The level of balance which will trigger a warning
    #[serde(default = "default_balance_warning_level")]
    pub balance_warning_level: Uint256,
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
    /// defines the blockchain to use for currency withdraws, this may not
    /// be the system chain in some cases such as when a user wants to withdraw eth
    /// but has xdai
    #[serde(default = "default_system_chain")]
    pub withdraw_chain: SystemChain,
    /// Full file path for Debts storage
    #[serde(default = "default_debts_file")]
    pub debts_file: String,
}

impl Default for PaymentSettings {
    fn default() -> Self {
        PaymentSettings {
            local_fee: 3000000,
            max_fee: 73333333,
            dynamic_fee_multiplier: 20,
            free_tier_throughput: 1000,
            // computed as 10x the standard transaction cost on 12/2/18
            pay_threshold: 840_000_000_000_000i64.into(),
            // computed as 10x the pay threshold
            close_threshold: (-8_400_000_000_000_000i64).into(),
            balance_warning_level: (10_000_000_000_000_000u64).into(),
            eth_private_key: None,
            eth_address: None,
            balance: 0u64.into(),
            nonce: 0u64.into(),
            gas_price: 10000000000u64.into(), // 10 gwei
            net_version: None,
            node_list: Vec::new(),
            price_oracle_enabled: true,
            price_oracle_url: "https://updates.altheamesh.com/prices".to_string(),
            system_chain: SystemChain::Ethereum,
            withdraw_chain: SystemChain::Ethereum,
            debts_file: default_debts_file(),
        }
    }
}
