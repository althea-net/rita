#[macro_use]
extern crate log;

use clarity::abi::{encode_call, AbiToken};
use clarity::Address;
use deep_space::client::Contact;
use deep_space::private_key::PrivateKey as PrivateKeyTrait;
use deep_space::{Coin, EthermintPrivateKey, Msg};
use num256::Uint256;
use std::time::Duration;
use web30::client::Web3;
mod error;
pub use error::GravityBridgeError;

/// Default timeout for Cosmos gRPC operations
pub const GRAVITY_CONTACT_TIMEOUT: Duration = Duration::from_secs(30);
/// Chain prefix for Althea L1
pub const ALTHEA_CHAIN_PREFIX: &str = "althea";
/// Chain prefix for Gravity Bridge chain
pub const GRAVITY_CHAIN_PREFIX: &str = "gravity";
/// Basis point divisor (1 basis point = 0.01%)
pub const BASIS_POINT_DIVISOR: u64 = 10_000;

/// This value can be defaulted because the channel can be replaced /upgraded in place if needded
fn default_ibc_channel_althea_to_gravity() -> String {
    "channel-0".to_string()
}

/// Subset of gravity module params we read each tick. The bridge_ethereum_address
/// is the live Gravity contract on ETH; reading it from chain rather than
/// hardcoding a constant means a governance migration of the contract is
/// picked up automatically. We need to query params for the chain fee anyway,
/// so this comes for free.
#[derive(Debug, Clone)]
pub struct GravityParams {
    pub bridge_ethereum_address: Address,
    pub min_chain_fee_basis_points: u64,
}

/// Compute the unwrap fee using the governance-controlled gasfree ERC20 interop fee basis points.
/// Basis points are 1/10000ths, so e.g. 100 basis points = 1%.
/// If `fee_basis_points` exceeds BASIS_POINT_DIVISOR the fee is clamped to the full amount,
/// preventing a subtraction underflow in the caller.
fn compute_unwrap_fee(amount: Uint256, fee_basis_points: u64) -> Uint256 {
    let clamped = if fee_basis_points > BASIS_POINT_DIVISOR {
        warn!(
            "fee_basis_points ({fee_basis_points}) exceeds {BASIS_POINT_DIVISOR}, clamping to {BASIS_POINT_DIVISOR}"
        );
        BASIS_POINT_DIVISOR
    } else {
        fee_basis_points
    };
    let basis_points: Uint256 = clamped.into();
    amount * basis_points / Uint256::from(BASIS_POINT_DIVISOR)
}

/// Runtime bridge instance holding all clients and keys needed for Gravity bridge operations.
#[derive(Clone)]
pub struct GravityBridge {
    /// Web3 client for Ethereum
    pub eth_web3: Web3,
    /// Web3 client for Althea L1 EVM
    pub althea_evm_web3: Web3,
    /// deep_space Contact for Althea L1 Cosmos layer
    pub althea_contact: Contact,
    /// deep_space Contact for Gravity Bridge chain
    pub gravity_contact: Contact,
    /// Cosmos private key derived from eth_privatekey (ethermint compatible)
    pub cosmos_key: EthermintPrivateKey,
    /// We operate across 3 distinct evm environments (Ethereum mainnet, Althea L1 EVM, Gnosis chain EVM)
    /// in any EVM environment you need some tokens to pay gas, since even simulated query transactions are
    /// simply simulated regular transactions. For Gnosis and Ethereum our address must have some gas tokens in it
    /// anyways to do what we are trying to do. So we don't concern ourselves. For Althea L1 evm we have gas free
    /// unwrapping, this means we don't need Althea L1 gas in our own address, but we do need to specify some address
    /// to use for simulated gas when checking our own balance. This could be removed with the addition of a balance
    /// query for EVM tokens from the cosmos side.
    pub althea_requester: Address,
    /// Gravity Bridge chain gRPC endpoint
    pub gravity_grpc_url: String,
    /// IBC channel ID for Althea -> Gravity and Gravity -> Althea transfers
    pub ibc_channel_althea_to_gravity: String,
    /// The stablecoin denom on Althea L1 Cosmos side ("ibc/1234ABCD...") that we are bridging.
    /// this can be different values with different decimals. This value is then used to query the target
    /// token address on ETH as well as the target ERC20 address on Althea L1 EVM and the denom on the Gravity chain.
    /// this way there's a minimum of configuration and no risk of mismatching values across the different chains.
    pub target_stablecoin_on_althea: Coin,
}

impl GravityBridge {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cosmos_key: EthermintPrivateKey,
        eth_full_node_url: &str,
        althea_evm_url: &str,
        gravity_grpc_url: &str,
        althea_grpc_url: &str,
        // same as default Althea L1 payment denom in the settings
        target_stablecoin_on_althea: Coin,
        // EVM address on Althea L1 with some ALTEHA token
        althea_l1_query_address: Address,
        query_timeout: Duration,
    ) -> GravityBridge {
        GravityBridge {
            eth_web3: Web3::new(eth_full_node_url, query_timeout),
            althea_evm_web3: Web3::new(althea_evm_url, query_timeout),
            althea_contact: Contact::new(althea_grpc_url, query_timeout, ALTHEA_CHAIN_PREFIX)
                .unwrap(),
            gravity_contact: Contact::new(gravity_grpc_url, query_timeout, GRAVITY_CHAIN_PREFIX)
                .unwrap(),
            cosmos_key,
            gravity_grpc_url: gravity_grpc_url.to_string(),
            ibc_channel_althea_to_gravity: default_ibc_channel_althea_to_gravity(),
            target_stablecoin_on_althea,
            althea_requester: althea_l1_query_address,
        }
    }

    pub fn get_own_eth_address(&self) -> Address {
        self.cosmos_key.as_ethereum_key().to_address()
    }

    pub fn get_own_cosmos_address(&self) -> deep_space::Address {
        self.cosmos_key.to_address(ALTHEA_CHAIN_PREFIX).unwrap()
    }

    // ---- ETH-side balance queries ----

    /// Get balance of any ERC20 token on Ethereum by address
    pub async fn get_erc20_balance_on_eth(
        &self,
        token_address: Address,
    ) -> Result<Uint256, GravityBridgeError> {
        Ok(self
            .eth_web3
            .get_erc20_balance(token_address, self.get_own_eth_address(), Vec::new())
            .await?)
    }

    // ---- Althea L1 Cosmos-side balance queries ----

    /// Get Cosmos-side balance on Althea L1 for a given denom
    pub async fn get_cosmos_balance_on_althea(
        &self,
        denom: &str,
    ) -> Result<Uint256, GravityBridgeError> {
        let our_cosmos_address = self
            .cosmos_key
            .to_address(ALTHEA_CHAIN_PREFIX)
            .map_err(|e| GravityBridgeError::CosmosGrpcError(format!("{e}")))?;
        let balance = self
            .althea_contact
            .get_balance(our_cosmos_address, denom.to_string())
            .await
            .map_err(|e| GravityBridgeError::CosmosGrpcError(format!("{e}")))?;
        match balance {
            Some(coin) => Ok(coin.amount),
            None => Ok(0u8.into()),
        }
    }

    // ---- Althea L1 EVM-side balance queries ----

    // /// Get ERC20 balance on Althea L1 EVM for a specific token address
    pub async fn get_althea_evm_erc20_balance(
        &self,
        erc20_address: Address,
    ) -> Result<Uint256, GravityBridgeError> {
        Ok(self
            .althea_evm_web3
            .get_erc20_balance_as_address(
                Some(self.althea_requester),
                erc20_address,
                self.get_own_eth_address(),
                Vec::new(),
            )
            .await?)
    }

    // ---- Gravity chain balance queries ----

    /// Get Cosmos-side balance on Gravity Bridge chain for a given denom
    pub async fn get_gravity_balance(&self, denom: &str) -> Result<Uint256, GravityBridgeError> {
        let our_gravity_address = self
            .cosmos_key
            .to_address(GRAVITY_CHAIN_PREFIX)
            .map_err(|e| GravityBridgeError::CosmosGrpcError(format!("{e}")))?;
        let balance = self
            .gravity_contact
            .get_balance(our_gravity_address, denom.to_string())
            .await
            .map_err(|e| GravityBridgeError::CosmosGrpcError(format!("{e}")))?;
        match balance {
            Some(coin) => Ok(coin.amount),
            None => Ok(0u8.into()),
        }
    }

    // ---- Bridge-in operations (ETH → Althea L1) ----

    /// Send target token to Gravity Bridge contract on Ethereum using `sendToCosmos(address,string,uint256)`.
    /// Tokens will be automatically IBC-forwarded to Althea L1 by the Gravity validator set.
    /// `gravity_contract` should come from `get_gravity_params()` so a governance migration of the
    /// bridge contract is picked up without needing a router redeploy.
    pub async fn transfer_to_gravity(
        &self,
        gravity_contract: Address,
        token_address: Address,
        amount: Uint256,
        timeout: Duration,
    ) -> Result<Uint256, GravityBridgeError> {
        // First approve the Gravity contract to spend our tokens
        let approve_payload = encode_call(
            "approve(address,uint256)",
            &[gravity_contract.into(), amount.into()],
        )
        .map_err(|e| {
            GravityBridgeError::Web3Error(web30::jsonrpc::error::Web3Error::BadInput(format!(
                "Failed to encode approve: {e}"
            )))
        })?;

        let approve_tx = self
            .eth_web3
            .prepare_transaction(
                token_address,
                approve_payload,
                0u32.into(),
                self.cosmos_key.as_ethereum_key(),
                Vec::new(),
            )
            .await?;
        let approve_hash = self.eth_web3.send_prepared_transaction(approve_tx).await?;
        self.eth_web3
            .wait_for_transaction(approve_hash, timeout, None)
            .await?;

        // Get our Cosmos address (bech32) as the destination for sendToCosmos
        let our_cosmos_address = self
            .cosmos_key
            .to_address(ALTHEA_CHAIN_PREFIX)
            .map_err(|e| GravityBridgeError::CosmosGrpcError(format!("{e}")))?;

        // Call sendToCosmos(address _tokenContract, string _destination, uint256 _amount)
        let send_payload = encode_call(
            "sendToCosmos(address,string,uint256)",
            &[
                token_address.into(),
                AbiToken::String(our_cosmos_address.to_string()),
                amount.into(),
            ],
        )
        .map_err(|e| {
            GravityBridgeError::Web3Error(web30::jsonrpc::error::Web3Error::BadInput(format!(
                "Failed to encode sendToCosmos: {e}"
            )))
        })?;

        let tx = self
            .eth_web3
            .prepare_transaction(
                gravity_contract,
                send_payload,
                0u32.into(),
                self.cosmos_key.as_ethereum_key(),
                Vec::new(),
            )
            .await?;
        let tx_hash = self.eth_web3.send_prepared_transaction(tx).await?;

        self.eth_web3
            .wait_for_transaction(tx_hash, timeout, None)
            .await?;

        info!("Sent {amount} of token {token_address} to Gravity Bridge contract, destination: {our_cosmos_address}");
        Ok(amount)
    }

    /// Unwrap gravity ERC20 → Cosmos coin on Althea L1 using MsgSendERC20ToCosmos.
    /// This is a gasfree message — fees are deducted from the token amount itself based on basis points.
    /// The `amount` parameter is the desired amount of Cosmos coins to receive (fee will be subtracted).
    /// The handler will burn `amount + fee` from the ERC20 balance.
    pub async fn unwrap_erc20_on_althea(
        &self,
        erc20_address: Address,
        amount: Uint256,
    ) -> Result<(), GravityBridgeError> {
        // Query the governance-controlled fee basis points
        let fee_basis_points = match self.get_gasfree_erc20_interop_fee_basis_points().await {
            Ok(bp) => {
                info!("Althea gasfree ERC20 interop fee basis points: {bp}");
                bp
            }
            Err(e) => {
                error!("Failed to query gasfree fee basis points, {e}");
                return Err(e);
            }
        };

        // Calculate the fee that will be charged
        let fee = compute_unwrap_fee(amount, fee_basis_points);

        if fee >= amount {
            error!(
                "Computed fee ({fee}) >= amount ({amount}) for ERC20 unwrap, aborting to prevent zero/negative send"
            );
            return Err(GravityBridgeError::InsufficientFunds {
                action: "unwrap_erc20_on_althea".to_string(),
                required: fee,
                available: amount,
            });
        }

        info!("Unwrapping {amount} ERC20 on Althea L1 fee will be subtracted from this amount (fee: {fee})");

        // The receiving address on the Cosmos side will be auto-derived from sender
        let msg = althea_proto::althea::erc20::v1::MsgSendErc20ToCosmos {
            // despite being a cosmos message we expect the hex address
            sender: self.get_own_eth_address().to_string(),
            erc20: erc20_address.to_string(),
            amount: (amount - fee).to_string(),
        };

        let msg = Msg::new("/althea.erc20.v1.MsgSendERC20ToCosmos", msg);

        // Use zero fee - the fee will be subtracted from the amount being unwrapped
        let zero_fee = Coin {
            denom: "aalthea".to_string(),
            amount: 0u64.into(),
        };

        let response = self
            .althea_contact
            .send_message(
                &[msg],
                None,
                &[zero_fee],
                Some(Duration::from_secs(30)),
                None,
                self.cosmos_key,
            )
            .await
            .map_err(|e| GravityBridgeError::CosmosGrpcError(format!("{e}")))?;

        info!(
            "Unwrapped {amount} gravity ERC20 on Althea L1 (fee {fee} charged), tx: {:?}",
            response.txhash()
        );
        Ok(())
    }

    // ---- Bridge-out operations (Althea L1 → ETH) ----

    /// IBC transfer from Althea L1 → Gravity Bridge chain.
    pub async fn ibc_transfer_to_gravity(
        &self,
        denom: &str,
        amount: Uint256,
    ) -> Result<(), GravityBridgeError> {
        let our_gravity_address = self
            .cosmos_key
            .to_address(GRAVITY_CHAIN_PREFIX)
            .map_err(|e| GravityBridgeError::CosmosGrpcError(format!("{e}")))?;

        let coin = Coin {
            denom: denom.to_string(),
            amount,
        };

        // Use deep_space's built-in IBC transfer with 10 minute timeout
        let ibc_timeout = Duration::from_secs(600);

        let response = self
            .althea_contact
            .send_ibc_transfer(
                coin,
                None, // zero fee
                our_gravity_address.to_string(),
                self.ibc_channel_althea_to_gravity.clone(),
                ibc_timeout,
                Some(Duration::from_secs(30)),
                None,
                self.cosmos_key,
            )
            .await
            .map_err(|e| GravityBridgeError::IbcError(format!("{e}")))?;

        info!(
            "IBC transferred {amount} from Althea L1 to Gravity chain, tx: {:?}",
            response.txhash()
        );
        Ok(())
    }

    /// Send tokens from Gravity Bridge chain to Ethereum via MsgSendToEth.
    /// Both chain_fee and bridge_fee are denominated in the bridged token (e.g. DAI).
    /// No GRAV gas token is needed.
    pub async fn send_to_eth(
        &self,
        denom: &str,
        amount: Uint256,
        bridge_fee: Uint256,
        chain_fee: Uint256,
        eth_dest: Address,
    ) -> Result<(), GravityBridgeError> {
        let our_gravity_address = self
            .cosmos_key
            // this will never panic unless GRAVITY_CHAIN_PREFIX is wrong
            // and thats a constant, so runtime this isn't actually a risk
            .to_address(GRAVITY_CHAIN_PREFIX)
            .unwrap();

        // Build MsgSendToEth using gravity_proto
        let msg = gravity_proto::gravity::v1::MsgSendToEth {
            sender: our_gravity_address.to_string(),
            eth_dest: eth_dest.to_string(),
            amount: Some(
                gravity_proto::cosmos_sdk_proto::cosmos::base::v1beta1::Coin {
                    denom: denom.to_string(),
                    amount: amount.to_string(),
                },
            ),
            bridge_fee: Some(
                gravity_proto::cosmos_sdk_proto::cosmos::base::v1beta1::Coin {
                    denom: denom.to_string(),
                    amount: bridge_fee.to_string(),
                },
            ),
            chain_fee: Some(
                gravity_proto::cosmos_sdk_proto::cosmos::base::v1beta1::Coin {
                    denom: denom.to_string(),
                    amount: chain_fee.to_string(),
                },
            ),
        };

        let msg = Msg::new("/gravity.v1.MsgSendToEth", msg);

        // Zero graviton fee — Gravity chain accepts 0ugraviton
        let fee_coin = Coin {
            denom: "ugraviton".to_string(),
            amount: 0u64.into(),
        };

        let response = self
            .gravity_contact
            .send_message(
                &[msg],
                None,
                &[fee_coin],
                Some(Duration::from_secs(30)),
                None,
                self.cosmos_key,
            )
            .await
            .map_err(|e| GravityBridgeError::CosmosGrpcError(format!("{e}")))?;

        info!(
            "Submitted MsgSendToEth for {amount} with bridge_fee {bridge_fee}, tx: {:?}",
            response.txhash()
        );
        Ok(())
    }

    /// Query pending SendToEth transactions on Gravity Bridge chain for our address.
    /// Returns a list of (amount, bridge_fee) tuples for pending sends.
    pub async fn get_pending_sends(&self) -> Result<Vec<(Uint256, Uint256)>, GravityBridgeError> {
        let our_gravity_address = self
            .cosmos_key
            .to_address(GRAVITY_CHAIN_PREFIX)
            .map_err(|e| GravityBridgeError::CosmosGrpcError(format!("{e}")))?;

        // Query pending sends using gravity_proto query client
        let mut client = gravity_proto::gravity::v1::query_client::QueryClient::connect(
            self.gravity_contact.get_url(),
        )
        .await
        .map_err(|e| GravityBridgeError::CosmosGrpcError(format!("{e}")))?;

        let request = gravity_proto::gravity::v1::QueryPendingSendToEth {
            sender_address: our_gravity_address.to_string(),
        };

        let response = client
            .get_pending_send_to_eth(request)
            .await
            .map_err(|e| GravityBridgeError::CosmosGrpcError(format!("{e}")))?;

        let inner = response.into_inner();
        let mut result = Vec::new();

        // Combine unbatched_transfers and transfers_in_batches
        for tx in inner
            .unbatched_transfers
            .iter()
            .chain(inner.transfers_in_batches.iter())
        {
            let amount = match tx.erc20_token.as_ref() {
                Some(c) => c.amount.parse::<Uint256>().map_err(|e| {
                    GravityBridgeError::CosmosGrpcError(format!("Failed to parse amount: {e}"))
                })?,
                None => 0u8.into(),
            };
            let fee = match tx.erc20_fee.as_ref() {
                Some(c) => c.amount.parse::<Uint256>().map_err(|e| {
                    GravityBridgeError::CosmosGrpcError(format!("Failed to parse fee: {e}"))
                })?,
                None => 0u8.into(),
            };
            result.push((amount, fee));
        }

        Ok(result)
    }

    /// Query Gravity Bridge chain governance params. Returns the live Gravity
    /// contract address on Ethereum and the min_chain_fee_basis_points used to
    /// size MsgSendToEth chain fees. A single RPC call replaces what was
    /// previously a hardcoded constant + a separate basis-points query.
    pub async fn get_gravity_params(&self) -> Result<GravityParams, GravityBridgeError> {
        let mut client = gravity_proto::gravity::v1::query_client::QueryClient::connect(
            self.gravity_contact.get_url(),
        )
        .await
        .map_err(|e| GravityBridgeError::CosmosGrpcError(format!("{e}")))?;

        let response = client
            .params(gravity_proto::gravity::v1::QueryParamsRequest {})
            .await
            .map_err(|e| GravityBridgeError::CosmosGrpcError(format!("{e}")))?;

        let params = response
            .into_inner()
            .params
            .ok_or_else(|| GravityBridgeError::CosmosGrpcError("No params in response".into()))?;

        let bridge_ethereum_address = Address::parse_and_validate(&params.bridge_ethereum_address)
            .map_err(|e| {
                GravityBridgeError::CosmosGrpcError(format!(
                    "gravity params bridge_ethereum_address invalid: {e}"
                ))
            })?;

        Ok(GravityParams {
            bridge_ethereum_address,
            min_chain_fee_basis_points: params.min_chain_fee_basis_points,
        })
    }

    /// Query Althea L1 gasfree module params to get the ERC20 interop fee basis points.
    /// This is a governance-controlled parameter that sets the fee charged for
    /// MsgSendERC20ToCosmos operations (in basis points, i.e. 1/10000ths).
    /// Default is 100 (1%).
    pub async fn get_gasfree_erc20_interop_fee_basis_points(
        &self,
    ) -> Result<u64, GravityBridgeError> {
        let mut client = althea_proto::althea::gasfree::v1::query_client::QueryClient::connect(
            self.althea_contact.get_url(),
        )
        .await
        .map_err(|e| GravityBridgeError::CosmosGrpcError(format!("{e}")))?;

        let response = client
            .params(althea_proto::althea::gasfree::v1::QueryParamsRequest {})
            .await
            .map_err(|e| GravityBridgeError::CosmosGrpcError(format!("{e}")))?;

        let params = response
            .into_inner()
            .params
            .ok_or_else(|| GravityBridgeError::CosmosGrpcError("No params in response".into()))?;

        Ok(params.gas_free_erc20_interop_fee_basis_points)
    }

    // ---- Address derivation utilities ----

    /// Query the Althea EVM ERC20 address for a given cosmos denom on Althea L1.
    /// This uses the althea::erc20 module's TokenPair registry.
    pub async fn query_althea_erc20_address(
        &self,
        denom: &str,
    ) -> Result<Address, GravityBridgeError> {
        let mut client = althea_proto::althea::erc20::v1::query_client::QueryClient::connect(
            self.althea_contact.get_url(),
        )
        .await
        .map_err(|e| GravityBridgeError::CosmosGrpcError(format!("{e}")))?;

        let response = client
            .token_pair(althea_proto::althea::erc20::v1::QueryTokenPairRequest {
                token: denom.to_string(),
            })
            .await
            .map_err(|e| GravityBridgeError::CosmosGrpcError(format!("{e}")))?;

        let token_pair = response.into_inner().token_pair.ok_or_else(|| {
            GravityBridgeError::CosmosGrpcError(format!("No token pair found for denom {}", denom))
        })?;

        token_pair
            .erc20_address
            .parse()
            .map_err(|e| GravityBridgeError::CosmosGrpcError(format!("Invalid ERC20 address: {e}")))
    }

    /// Query the IBC denom trace to get the base denom on the origin chain.
    /// Takes an IBC hash (the part after "ibc/") and returns the base denom.
    pub async fn query_ibc_denom_trace(
        &self,
        ibc_denom: &str,
    ) -> Result<String, GravityBridgeError> {
        // Extract hash from "ibc/ABC123..." format, or use as-is if already just the hash
        let hash = if ibc_denom.starts_with("ibc/") {
            ibc_denom.strip_prefix("ibc/").unwrap()
        } else {
            ibc_denom
        };

        let mut client = cosmos_sdk_proto_althea::ibc::applications::transfer::v1::query_client::QueryClient::connect(
            self.althea_contact.get_url(),
        )
        .await
        .map_err(|e| GravityBridgeError::IbcError(format!("{e}")))?;

        let response = client
            .denom_trace(
                cosmos_sdk_proto_althea::ibc::applications::transfer::v1::QueryDenomTraceRequest {
                    hash: hash.to_string(),
                },
            )
            .await
            .map_err(|e| GravityBridgeError::IbcError(format!("{e}")))?;

        let denom_trace = response.into_inner().denom_trace.ok_or_else(|| {
            GravityBridgeError::IbcError(format!("No denom trace found for hash {}", hash))
        })?;

        Ok(denom_trace.base_denom)
    }

    /// Query Gravity Bridge chain to convert a cosmos denom to its Ethereum mainnet ERC20 address.
    pub async fn query_gravity_denom_to_eth_address(
        &self,
        gravity_denom: &str,
    ) -> Result<Address, GravityBridgeError> {
        let mut client = gravity_proto::gravity::v1::query_client::QueryClient::connect(
            self.gravity_contact.get_url(),
        )
        .await
        .map_err(|e| GravityBridgeError::CosmosGrpcError(format!("{e}")))?;

        let response = client
            .denom_to_erc20(gravity_proto::gravity::v1::QueryDenomToErc20Request {
                denom: gravity_denom.to_string(),
            })
            .await
            .map_err(|e| GravityBridgeError::CosmosGrpcError(format!("{e}")))?;

        let inner = response.into_inner();
        inner.erc20.parse().map_err(|e| {
            GravityBridgeError::CosmosGrpcError(format!("Invalid ERC20 address from Gravity: {e}"))
        })
    }

    /// Derive all necessary bridge addresses from the target stablecoin denom on Althea L1.
    /// This orchestrates the following queries:
    /// 1. Althea TokenPair query: IBC denom → Althea EVM ERC20 address (for unwrapping)
    /// 2. IBC denom trace: IBC hash → Gravity chain base denom (for IBC & MsgSendToEth)
    /// 3. Gravity denom→ERC20: Gravity denom → Ethereum mainnet address (for bridging in)
    pub async fn derive_bridge_addresses(&self) -> Result<DerivedAddresses, GravityBridgeError> {
        let target_denom = &self.target_stablecoin_on_althea.denom;

        info!(
            "Deriving bridge addresses from Althea L1 denom: {}",
            target_denom
        );

        // Step 1: Query Althea ERC20 address (for unwrapping)
        let althea_evm_erc20 = self.query_althea_erc20_address(target_denom).await?;
        info!("Found Althea EVM ERC20 address: {}", althea_evm_erc20);

        // Step 2: Query IBC denom trace to get Gravity chain base denom
        let gravity_denom = self.query_ibc_denom_trace(target_denom).await?;
        info!("Found Gravity chain base denom: {}", gravity_denom);

        // Step 3: Query Gravity denom→ERC20 to get Ethereum mainnet address
        let eth_mainnet_erc20 = self
            .query_gravity_denom_to_eth_address(&gravity_denom)
            .await?;
        info!(
            "Found Ethereum mainnet ERC20 address: {}",
            eth_mainnet_erc20
        );

        Ok(DerivedAddresses {
            althea_evm_erc20,
            gravity_denom,
            eth_mainnet_erc20,
        })
    }
}

/// Derived bridge addresses from the target stablecoin on Althea L1.
/// All addresses are derived via on-chain queries to ensure configuration accuracy.
#[derive(Debug, Clone)]
pub struct DerivedAddresses {
    /// ERC20 contract address on Althea L1 EVM (for unwrapping operations)
    pub althea_evm_erc20: Address,
    /// Cosmos denom on Gravity Bridge chain (for IBC transfers and MsgSendToEth)
    pub gravity_denom: String,
    /// ERC20 contract address on Ethereum mainnet (for bridging from ETH)
    pub eth_mainnet_erc20: Address,
}
