use althea_types::SystemChain;
use clarity::{Address, PrivateKey};
use num256::{Int256, Uint256};
use std::str::FromStr;

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
    300
}

fn default_fudge_factor() -> u8 {
    0
}

fn default_free_tier_throughput() -> u32 {
    1000
}

fn default_client_can_use_free_tier() -> bool {
    true
}

fn default_bridge_enabled() -> bool {
    true
}

fn default_debt_limit_enabled() -> bool {
    true
}

fn default_balance_warning_level() -> Uint256 {
    (10_000_000_000_000_000u64).into()
}

// make sure this matches default system chain and default DAO url
fn default_node_list() -> Vec<String> {
    vec!["https://dai.althea.org:443".to_string()]
}

// make sure this matches default node list and default DAO url
fn default_system_chain() -> SystemChain {
    SystemChain::Xdai
}

fn default_debts_file() -> String {
    "/etc/rita-debts.json".to_string()
}

fn default_bridge_addresses() -> TokenBridgeAddresses {
    TokenBridgeAddresses {
        uniswap_address: Address::from_str("0x2a1530C4C41db0B0b2bB646CB5Eb1A67b7158667").unwrap(),
        xdai_foreign_bridge_address: Address::from_str(
            "0x7301CFA0e1756B71869E93d4e4Dca5c7d0eb0AA6",
        )
        .unwrap(),
        xdai_home_bridge_address: Address::from_str("0x4aa42145Aa6Ebf72e164C9bBC74fbD3788045016")
            .unwrap(),
        foreign_dai_contract_address: Address::from_str(
            "0x6b175474e89094c44da98b954eedeac495271d0f",
        )
        .unwrap(),
        eth_full_node_url: "https://eth.althea.org".into(),
        xdai_full_node_url: "https://dai.althea.org".into(),
    }
}

fn default_simulated_transaction_fee_address() -> Address {
    "0xee8bba37508cd6f9db7c8ad0ae2b3de0168c1b36"
        .parse()
        .unwrap()
}

fn default_simulated_transaction_fee() -> u8 {
    10
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct TokenBridgeAddresses {
    pub uniswap_address: Address,
    pub xdai_home_bridge_address: Address,
    pub xdai_foreign_bridge_address: Address,
    pub foreign_dai_contract_address: Address,
    pub eth_full_node_url: String,
    pub xdai_full_node_url: String,
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
    /// If this is True the user may perform regular web browsing on the free tier, if it is
    /// false the NAT rule will be removed while the router is in the low balance state
    #[serde(default = "default_client_can_use_free_tier")]
    pub client_can_use_free_tier: bool,
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
    #[serde(default = "default_bridge_enabled")]
    pub bridge_enabled: bool,
    /// A value used to divide and add to a payment, essentailly a cheating tool for
    /// payment convergence. Computed as payment_amount + (payment_amount/fudge_factor)
    /// so a factor of 100 would be a 1% overpayment this helps cover up errors in accounting
    /// by pushing the system into overpayment and therefore convergence. Currently not used
    /// probably should be axed as cruft
    #[serde(default = "default_fudge_factor")]
    pub fudge_factor: u8,
    /// This prevents nodes from building large debts beyond the debt
    /// limit, this prevents situations where large negative debts will drain balances
    /// on deposit
    #[serde(default = "default_debt_limit_enabled")]
    pub debt_limit_enabled: bool,
    /// Token Bridge addresses
    #[serde(default = "default_bridge_addresses")]
    pub bridge_addresses: TokenBridgeAddresses,
    /// A fee sent to the maintainers of Althea to simulate transaction fee revenue, computed as a fraction of all transactions
    /// for which this is the denominator. For example a value of '20' would mean 1/20 or 5%
    /// of all transactions would be sent to the simulated_transaction_fee address. Setting the the fee value to zero will disable
    /// simulated transaction fees
    #[serde(default = "default_simulated_transaction_fee_address")]
    pub simulated_transaction_fee_address: Address,
    #[serde(default = "default_simulated_transaction_fee")]
    pub simulated_transaction_fee: u8,
}

impl Default for PaymentSettings {
    fn default() -> Self {
        PaymentSettings {
            local_fee: default_local_fee(),
            max_fee: default_max_fee(),
            dynamic_fee_multiplier: default_dynamic_fee_multiplier(),
            free_tier_throughput: default_free_tier_throughput(),
            client_can_use_free_tier: default_client_can_use_free_tier(),
            // computed as 10x the standard transaction cost on 12/2/18
            // updated in a dynamic fashion using the fee multiplyer, so default
            // doesn't matter as much as you might think
            pay_threshold: default_pay_threshold(),
            // computed as 10x the pay threshold
            close_threshold: default_close_threshold(),
            balance_warning_level: default_balance_warning_level(),
            eth_private_key: None,
            eth_address: None,
            balance: 0u64.into(),
            nonce: 0u64.into(),
            gas_price: 0u64.into(), // 10 gwei
            net_version: None,
            node_list: Vec::new(),
            system_chain: default_system_chain(),
            withdraw_chain: default_system_chain(),
            debts_file: default_debts_file(),
            bridge_enabled: default_bridge_enabled(),
            fudge_factor: 0u8,
            debt_limit_enabled: default_debt_limit_enabled(),
            bridge_addresses: default_bridge_addresses(),
            simulated_transaction_fee_address: default_simulated_transaction_fee_address(),
            simulated_transaction_fee: default_simulated_transaction_fee(),
        }
    }
}
