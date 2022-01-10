use althea_types::SystemChain;
use auto_bridge::default_bridge_addresses;
use auto_bridge::TokenBridgeAddresses;
use clarity::{Address, PrivateKey};
use num256::Uint256;

pub const XDAI_FEE_MULTIPLIER: u32 = 3000;
pub const ETH_FEE_MULTIPLIER: u32 = 20;

fn default_local_fee() -> u32 {
    0u32 // updated by oracle, denominated in wei/byte
}
fn default_max_fee() -> u32 {
    200_000_000u32 // updated by oracle denominated in wei
}

fn default_dynamic_fee_multiplier() -> u32 {
    XDAI_FEE_MULTIPLIER
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

fn default_apply_incoming_credit() -> bool {
    false
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

fn default_simulated_transaction_fee_address() -> Address {
    "0xee8bba37508cd6f9db7c8ad0ae2b3de0168c1b36"
        .parse()
        .unwrap()
}

fn default_simulated_transaction_fee() -> u8 {
    10
}

/// By default we forgive nodes of their debts on reboot
fn default_forgive_on_reboot() -> bool {
    true
}

/// This struct is used by both rita and rita_exit to configure the dummy payment controller and
/// debt keeper
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PaymentSettings {
    /// What we charge other nodes, denominated in wei/byte, represented by a u32 because that is
    /// the field size of the price field in Babel
    #[serde(default = "default_local_fee")]
    pub local_fee: u32,
    /// What we charge light client (phone) nodes specifically, denominated in wei/byte
    #[serde(default = "default_local_fee")]
    pub light_client_fee: u32,
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
    /// The level of balance which will trigger a warning
    #[serde(default = "default_balance_warning_level")]
    pub balance_warning_level: Uint256,
    /// Our own eth private key we do not store address, instead it is derived from here
    pub eth_private_key: Option<PrivateKey>,
    // Our own eth Address, derived from the private key on startup and not stored
    pub eth_address: Option<Address>,
    #[serde(default)]
    pub balance: Uint256,
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
    /// See where this is referenced in debt keeper, this option is on for exits and off everywhere
    /// else. The problem requiring it's creation is that the Exit has it's debts observed by clients
    /// who pay when it exceeds the pay threshold. Relays have no such issue and their internal balances
    /// are only observable for debugging and eventually for enforcement. So for exits it's important to apply
    /// overpayment right away to prevent clients from continuing to pay. For relays it simply won't have any
    /// bearing except to complicate debugging.
    #[serde(default = "default_apply_incoming_credit")]
    pub apply_incoming_credit_immediately: bool,
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
    /// if we forgive all debts on reboot
    #[serde(default = "default_forgive_on_reboot")]
    pub forgive_on_reboot: bool,
}

impl Default for PaymentSettings {
    fn default() -> Self {
        PaymentSettings {
            local_fee: default_local_fee(),
            light_client_fee: default_local_fee(),
            max_fee: default_max_fee(),
            dynamic_fee_multiplier: default_dynamic_fee_multiplier(),
            free_tier_throughput: default_free_tier_throughput(),
            client_can_use_free_tier: default_client_can_use_free_tier(),
            balance_warning_level: default_balance_warning_level(),
            eth_private_key: None,
            eth_address: None,
            balance: 0u64.into(),
            node_list: default_node_list(),
            system_chain: default_system_chain(),
            withdraw_chain: default_system_chain(),
            debts_file: default_debts_file(),
            bridge_enabled: default_bridge_enabled(),
            fudge_factor: 0u8,
            debt_limit_enabled: default_debt_limit_enabled(),
            apply_incoming_credit_immediately: default_apply_incoming_credit(),
            bridge_addresses: default_bridge_addresses(),
            simulated_transaction_fee_address: default_simulated_transaction_fee_address(),
            simulated_transaction_fee: default_simulated_transaction_fee(),
            forgive_on_reboot: default_forgive_on_reboot(),
        }
    }
}
