use althea_types::ContactStorage;
use althea_types::Denom;
use althea_types::SystemChain;
use auto_bridge::default_bridge_addresses;
use auto_bridge::TokenBridgeAddresses;
use clarity::{Address, PrivateKey};
use num256::Int256;
use num256::Uint256;

use crate::localization::LocalizationSettings;

fn default_max_fee() -> u32 {
    200_000_000u32 // denominated in wei/byte
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
    "/etc/rita-debts.bincode".to_string()
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

fn default_min_gas() -> Uint256 {
    2_000_000_000u128.into()
}

pub fn default_payment_threshold() -> Int256 {
    // This value is set to 1 eth constant (1e^18) * 0.3
    // 1 eth constant is 1 dollar, so this is 30 cents
    300_000_000_000_000_000i64.into()
}

fn default_enable_enforcement() -> bool {
    true
}

fn default_node_grpc() -> Vec<String> {
    vec!["https://althea.zone:9090".to_string()]
}

/// This struct is used by both rita and rita_exit to configure the dummy payment controller and
/// debt keeper
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PaymentSettings {
    /// What we charge other nodes, denominated in wei/byte, represented by a u32 because that is
    /// the field size of the price field in Babel
    pub local_fee: Option<u32>,
    /// A price limit, we will not pay more than this
    #[serde(default = "default_max_fee")]
    pub max_fee: u32,
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
    /// Default payment threshold used, which is used to calculate close thresh, which is used
    /// to determine when a router needs to be enforced
    #[serde(default = "default_payment_threshold")]
    pub payment_threshold: Int256,
    /// When this flag is false, no client is enforced
    #[serde(default = "default_enable_enforcement")]
    pub enable_enforcement: bool,
    /// Our own eth private key we do not store address, instead it is derived from here
    pub eth_private_key: Option<PrivateKey>,
    /// Our own eth Address, derived from the private key on startup and not stored
    pub eth_address: Option<Address>,
    /// Payment denoms that payment validator accepts on Althea L1. Ex usdc -> Denom {ibc/hash, 1_000_000}
    /// the nubmer is the multiplier to convert one unit of this denom to $1 since these are all
    /// assumed to be stable coins
    #[serde(default = "default_althea_l1_accepted_denoms")]
    pub althea_l1_accepted_denoms: Vec<Denom>,
    /// By default when this node makes a payment it will use this denom
    #[serde(default = "default_althea_l1_payment_denom")]
    pub althea_l1_payment_denom: Denom,
    /// GRPC Node used to create a contact object to interact with althea blockchain
    #[serde(default = "default_node_grpc")]
    pub althea_grpc_list: Vec<String>,
    /// A list of ethereum nodes to query for blockchain data
    #[serde(default = "default_node_list")]
    pub eth_node_list: Vec<String>,
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
    /// We will not send a tx with a gas price lower than this, useful for pre eip-1559 networks and
    /// post-eip1599 networks that do not respect min-fee
    #[serde(default = "default_min_gas")]
    pub min_gas: Uint256,
    /// Contact info for this node
    /// ContactStorage is a TOML serialized representation of ContactType, use the .into()
    /// traits to get ContactType for actual operations. This struct represents a full range
    /// of possibilities for contact info.
    pub contact_info: Option<ContactStorage>,
    /// Contains information like the support number for the local operator and currency symbol
    #[serde(default)]
    pub localization: LocalizationSettings,
}

/// TODO this is currently a testnet only placeholder it should be replaced
/// with a real IBC denom post Althea L1 launch
fn default_althea_l1_payment_denom() -> Denom {
    Denom {
        denom: "uUSDC".to_string(),
        decimal: 1_000_000u64,
    }
}

fn default_althea_l1_accepted_denoms() -> Vec<Denom> {
    vec![default_althea_l1_payment_denom()]
}

impl PaymentSettings {
    /// Returns false if the payment settings are invalid
    pub fn validate(&self) -> bool {
        if self.althea_grpc_list.is_empty() {
            return false;
        }
        if self.eth_node_list.is_empty() {
            return false;
        }
        if self.min_gas == 0u8.into() {
            return false;
        }
        if self.althea_l1_accepted_denoms.is_empty() {
            return false;
        }
        if self.althea_l1_payment_denom.denom.is_empty() {
            return false;
        }
        if !self
            .althea_l1_accepted_denoms
            .contains(&self.althea_l1_payment_denom)
        {
            return false;
        }
        true
    }
}

impl Default for PaymentSettings {
    fn default() -> Self {
        PaymentSettings {
            local_fee: None,
            max_fee: default_max_fee(),
            free_tier_throughput: default_free_tier_throughput(),
            client_can_use_free_tier: default_client_can_use_free_tier(),
            balance_warning_level: default_balance_warning_level(),
            payment_threshold: default_payment_threshold(),
            enable_enforcement: true,
            eth_private_key: None,
            eth_address: None,
            althea_grpc_list: default_node_grpc(),
            eth_node_list: default_node_list(),
            system_chain: default_system_chain(),
            withdraw_chain: default_system_chain(),
            debts_file: default_debts_file(),
            bridge_enabled: default_bridge_enabled(),
            debt_limit_enabled: default_debt_limit_enabled(),
            apply_incoming_credit_immediately: default_apply_incoming_credit(),
            bridge_addresses: default_bridge_addresses(),
            simulated_transaction_fee_address: default_simulated_transaction_fee_address(),
            simulated_transaction_fee: default_simulated_transaction_fee(),
            forgive_on_reboot: default_forgive_on_reboot(),
            min_gas: default_min_gas(),
            althea_l1_accepted_denoms: vec![default_althea_l1_payment_denom()],
            althea_l1_payment_denom: default_althea_l1_payment_denom(),
            contact_info: None,
            localization: LocalizationSettings::default(),
        }
    }
}
