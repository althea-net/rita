#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

use clarity::abi::{encode_call, AbiToken};
use clarity::utils::bytes_to_hex_str;
use clarity::{Address, PrivateKey};
use futures::future::join_all;
use num256::Uint256;
use std::collections::HashSet;
use std::time::Duration;
use web30::client::Web3;
use web30::jsonrpc::error::Web3Error;
use web30::types::{Log, SendTxOption, TransactionRequest, TransactionResponse};

mod error;
pub use error::TokenBridgeError;

/// These hardcoded values are obtained
// by looking at the values on Etherscan and observing gas values in practice, along with slight padding
// to ensure correct operation. These hardcoded gas values are only being used to estimate the reserve amount
pub static UNISWAP_GAS_LIMIT: u128 = 150_000;
pub static ERC20_GAS_LIMIT: u128 = 40_000;
pub static XDAI_FUNDS_UNLOCK_GAS: u128 = 180_000;
/// Minimum transfer is $2 dai which has 18 decimal precision
pub static MINIMUM_DAI_TO_BRIDGE_IN: u128 = 2_000_000_000_000_000_000;
/// Minimum amount we can transfer out to ETH from Gnosis chain they set this unusaully high IMO
pub static MINIMUM_DAI_TO_BRIDGE_OUT: u128 = 10_000_000_000_000_000_000;
/// Minimum transfer is $15 USDC which has 6 decimal precision
pub static MINIMUM_USDC_TO_CONVERT: u128 = 15_000_000;

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct TokenBridgeRpcs {
    pub eth_full_node_url: String,
    pub xdai_full_node_url: String,
    pub gravity_grpc_url: String,
}

pub fn get_usdt_address() -> Address {
    *web30::amm::USDT_CONTRACT_ADDRESS
}

/// Just a little helper struct to keep us from getting
/// the two arguments to executeSignatures() on the Eth
/// side of the xDai bridge mixed up.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct HelperWithdrawInfo {
    pub msg: Vec<u8>,
    pub sigs: Vec<u8>,
}

/// This represents the xdai withdraw event, including the address that is executing the withdraw
/// and the destination address of the withdraw on ethereum
#[derive(Clone, Debug)]
pub struct WithdrawEvent {
    pub sender: Address,
    pub receiver: Address,
    pub amount: Uint256,
    pub nonce: Uint256,
    // you think only bridging out the native token would
    // let us hardcode this but we can't becuase they upgrade dai
    // to a new token and we have to know how it's going to come out on eth
    // so we just take this value and pass it through and otherwise let the
    // contract figure it out for us.
    pub token_address: Address,
}

#[derive(Clone)]
pub struct TokenBridge {
    pub xdai_web3: Web3,
    pub eth_web3: Web3,
    pub xdai_bridge_on_eth: Address,
    pub helper_on_xdai: Address,
    pub xdai_bridge_on_xdai: Address,
    pub own_address: Address,
    pub eth_privatekey: PrivateKey,
}

impl TokenBridge {
    pub fn new(
        rpcs: TokenBridgeRpcs,
        own_address: Address,
        eth_privatekey: PrivateKey,
        timeout: Duration,
    ) -> TokenBridge {
        TokenBridge {
            xdai_bridge_on_xdai: get_xdai_bridge_on_xdai_address(),
            helper_on_xdai: get_helper_on_xdai_address(),
            xdai_bridge_on_eth: get_xdai_bridge_on_eth_address(),
            own_address,
            eth_privatekey,
            xdai_web3: Web3::new(&rpcs.xdai_full_node_url, timeout),
            eth_web3: Web3::new(&rpcs.eth_full_node_url, timeout),
        }
    }

    /// Bridge the specified amount of target token to Gnosis chain.
    pub async fn bridge_to_gnosis(
        &self,
        token_amount: Uint256,
        token: Address,
        timeout: Duration,
    ) -> Result<Uint256, TokenBridgeError> {
        let secret = self.eth_privatekey;

        // You basically just send it some dai to the bridge address and they show
        // up in the same address on the xdai side we have no idea when this has succeeded
        // since the events are not indexed
        let tx = self
            .eth_web3
            .prepare_transaction(
                token,
                encode_call(
                    "transfer(address,uint256)",
                    &[self.xdai_bridge_on_eth.into(), token_amount.into()],
                )
                .unwrap(),
                0u32.into(),
                secret,
                Vec::new(),
            )
            .await?;
        let tx_hash = self.eth_web3.send_prepared_transaction(tx).await?;

        self.eth_web3
            .wait_for_transaction(tx_hash, timeout, None)
            .await?;

        Ok(token_amount)
    }

    /// input is the packed signatures output from get_relay_message_hash
    pub async fn submit_signatures_to_unlock_funds(
        &self,
        data: HelperWithdrawInfo,
        timeout: Duration,
    ) -> Result<Uint256, TokenBridgeError> {
        let payload = get_payload_for_funds_unlock(&data);
        trace!(
            "bridge unlocking funds with! {} bytes payload! {}",
            data.msg.len(),
            bytes_to_hex_str(&payload),
        );

        let tx = self
            .eth_web3
            .prepare_transaction(
                self.xdai_bridge_on_eth,
                payload,
                0u32.into(),
                self.eth_privatekey,
                Vec::new(),
            )
            .await?;
        let txid = self.eth_web3.send_prepared_transaction(tx).await?;

        let _ = self
            .eth_web3
            .wait_for_transaction(txid, timeout, None)
            .await;
        Ok(txid)
    }
}

/// this uses the xdai helper contract on the xdai chain to retrieve the required
/// info for relaying. This call occurs on the xdai side and gets info to submit
/// to ethereum
pub async fn get_relay_message_hash(
    own_address: Address,
    xdai_web3: Web3,
    helper_on_xdai: Address,
    dest_address: Address,
    xdai_withdraw_nonce: Uint256,
    xdai_withdraw_token: Address,
    amount_sent: Uint256,
) -> Result<HelperWithdrawInfo, TokenBridgeError> {
    info!("bridge getting message using dest_address {} and nonce {} for amount {} with own address {} and helper {}",
        dest_address, xdai_withdraw_nonce, amount_sent, own_address, helper_on_xdai);
    // the hash that is then used to look up the signatures, this will always
    // succeed, whereas the signature lookup may need to wait for all sigs
    // to be submitted
    let payload = match encode_call(
        "getMessageHash(address,uint256,bytes32,address)",
        &[
            dest_address.into(),
            amount_sent.into(),
            AbiToken::Bytes(xdai_withdraw_nonce.to_be_bytes().to_vec()),
            xdai_withdraw_token.into(),
        ],
    ) {
        Ok(a) => a,
        Err(e) => {
            return Err(TokenBridgeError::Web3Error(Web3Error::BadInput(format!(
                "Error: {e}"
            ))))
        }
    };
    let msg_hash = xdai_web3
        .simulate_transaction(
            TransactionRequest::quick_tx(own_address, helper_on_xdai, payload),
            Vec::new(),
            None,
        )
        .await?;
    // this may return 0x0 if the value is not yet ready, in this case
    // we fail with a not ready error
    let payload = match encode_call("getMessage(bytes32)", &[AbiToken::Bytes(msg_hash.clone())]) {
        Ok(a) => a,
        Err(e) => {
            return Err(TokenBridgeError::Web3Error(Web3Error::BadInput(format!(
                "Error: {e}"
            ))))
        }
    };
    let msg = xdai_web3
        .simulate_transaction(
            TransactionRequest::quick_tx(own_address, helper_on_xdai, payload),
            Vec::new(),
            None,
        )
        .await?;

    if msg == vec![0] || msg.len() <= 64 {
        return Err(TokenBridgeError::HelperMessageNotReady);
    }

    let payload = match encode_call("getSignatures(bytes32)", &[AbiToken::Bytes(msg_hash)]) {
        Ok(a) => a,
        Err(e) => {
            return Err(TokenBridgeError::Web3Error(Web3Error::BadInput(format!(
                "Error: {e}"
            ))))
        }
    };
    let sigs_payload = xdai_web3
        .simulate_transaction(
            TransactionRequest::quick_tx(own_address, helper_on_xdai, payload),
            Vec::new(),
            None,
        )
        .await?;
    if sigs_payload == vec![0] || sigs_payload.len() <= 64 {
        return Err(TokenBridgeError::HelperMessageNotReady);
    }

    // what we've gotten out of this helper contract is a packed
    // encoded message, since we don't have code to unpack it or
    // even the a type definition to work with we've got to do some
    // hand massaging to get it into the right format.
    //  1. discard the first uint256 type specifier, we know what we have
    //  2. take the second uint256 it's the length in bytes of the rest of the message
    //  3. take the bytes between START (2 uint256 offset) and END (offset plus message length)
    let msg_len = Uint256::from_be_bytes(&msg[32..64]);
    let sigs_len = Uint256::from_be_bytes(&sigs_payload[32..64]);
    if msg_len > usize::MAX.into() || sigs_len > usize::MAX.into() {
        return Err(TokenBridgeError::HelperMessageIncorrect);
    }
    let msg_len: usize = msg_len.to_string().parse().unwrap();
    let sigs_len: usize = sigs_len.to_string().parse().unwrap();
    const START: usize = 2 * 32;
    // checked_add guards against `START + msg_len` wrapping on a 32-bit target where
    // msg_len is near usize::MAX. Without this a wrapped end could pass the bounds
    // check below and slice past the buffer.
    let msg_end = START
        .checked_add(msg_len)
        .ok_or(TokenBridgeError::HelperMessageIncorrect)?;
    let sigs_end = START
        .checked_add(sigs_len)
        .ok_or(TokenBridgeError::HelperMessageIncorrect)?;
    if msg_end > msg.len() || sigs_end > sigs_payload.len() {
        return Err(TokenBridgeError::HelperMessageIncorrect);
    }
    let cleaned_msg = msg[START..msg_end].to_vec();
    let cleaned_sigs = sigs_payload[START..sigs_end].to_vec();

    Ok(HelperWithdrawInfo {
        msg: cleaned_msg,
        sigs: cleaned_sigs,
    })
}
/// helper function for easier tests
pub fn get_payload_for_funds_unlock(data: &HelperWithdrawInfo) -> Vec<u8> {
    encode_call(
        "executeSignatures(bytes,bytes)",
        &[
            AbiToken::UnboundedBytes(data.msg.clone()),
            AbiToken::UnboundedBytes(data.sigs.clone()),
        ],
    )
    .unwrap()
}

pub const XDAI_BRIDGE_ON_ETH_ADDRESS: &str = "0x4aa42145Aa6Ebf72e164C9bBC74fbD3788045016";
pub const HELPER_ON_XDAI_ADDRESS: &str = "0xe30269bc61E677cD60aD163a221e464B7022fbf5";
pub const XDAI_BRIDGE_ON_XDAI_ADDRESS: &str = "0x7301CFA0e1756B71869E93d4e4Dca5c7d0eb0AA6";

pub fn get_xdai_bridge_on_eth_address() -> Address {
    Address::parse_and_validate(XDAI_BRIDGE_ON_ETH_ADDRESS).unwrap()
}
pub fn get_helper_on_xdai_address() -> Address {
    Address::parse_and_validate(HELPER_ON_XDAI_ADDRESS).unwrap()
}
pub fn get_xdai_bridge_on_xdai_address() -> Address {
    Address::parse_and_validate(XDAI_BRIDGE_ON_XDAI_ADDRESS).unwrap()
}

/// This function provides the default bridge rpcs to be used by the bridge functionality
/// these are for the most part constants, but it is possible they may be updated or changed
/// and we may need to do so without recompiling the binary. Previously the bridge addreses
/// where included here, but after several years we determined a change had never been made
/// in the contracts that didn't require logic changes on our end, so it was more trouble than help.
pub fn default_bridge_rpcs() -> TokenBridgeRpcs {
    TokenBridgeRpcs {
        eth_full_node_url: "https://eth.althea.org".into(),
        xdai_full_node_url: "https://dai.althea.org".into(),
        gravity_grpc_url: "https://gravitychain.io:9090".into(),
    }
}

/// This function checks the given transaction to see if execute_signatures has been called to unlock funds on the eth side. True implies
/// funds have already been unlocked and false implies that we need to unlock them.
pub async fn check_relayed_message(
    tx_hash: Uint256,
    web3: Web3,
    own_address: Address,
    contract: Address,
) -> Result<bool, Web3Error> {
    let payload = match encode_call("relayedMessages(bytes32)", &[tx_hash.into()]) {
        Ok(a) => a,
        Err(e) => return Err(Web3Error::BadInput(format!("Error: {e}"))),
    };

    let res = web3
        .simulate_transaction(
            TransactionRequest::quick_tx(own_address, contract, payload),
            Vec::new(),
            None,
        )
        .await?;

    // if last entry of vector is 1, true, else false
    if res[res.len() - 1] == 1 {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// This function calls the contract relayTokens(address) on the xdai blockchain by sending a function call
/// transaction. It sends the withdraw amount directly to the destination address specified by the withdrawal.
/// it is up to the caller to check if the amount is below the users maximum balance and account for gas fees
pub async fn encode_relaytokens(
    bridge: TokenBridge,
    dest_address: Address,
    amount: Uint256,
    timeout: Duration,
    // we must pass hese through to sync up with the amount we'be subtracted
    // for a full balance bridge out
    gas_price: Option<Uint256>,
    gas_limit: Option<Uint256>,
) -> Result<(), TokenBridgeError> {
    let payload = encode_call("relayTokens(address)", &[dest_address.into()]).unwrap();
    let mut options = Vec::new();
    if let Some(gp) = gas_price {
        options.push(SendTxOption::GasPrice(gp));
    }
    if let Some(gl) = gas_limit {
        options.push(SendTxOption::GasLimit(gl));
    }

    let tx = bridge
        .xdai_web3
        .prepare_transaction(
            bridge.xdai_bridge_on_xdai,
            payload,
            amount,
            bridge.eth_privatekey,
            options,
        )
        .await?;
    let tx_hash = bridge.xdai_web3.send_prepared_transaction(tx).await?;

    bridge
        .xdai_web3
        .wait_for_transaction(tx_hash, timeout, None)
        .await?;

    Ok(())
}

/// This helper function parses the data field in the logs returned from when checking for withdraw events related to us in xdai block chain
/// This parses and returns the sender/receiver addresses and the ammount.
async fn parse_withdraw_event(log_data: &Log, client: &Web3) -> Result<WithdrawEvent, Web3Error> {
    let receiver_data = &*log_data.data;
    let transaction_hash = match log_data.clone().transaction_hash {
        Some(a) => a.clone(),
        None => {
            return Err(Web3Error::BadResponse(
                "There is no transaction hash present for the given log".to_string(),
            ));
        }
    };
    let txhash = Uint256::from_be_bytes(&transaction_hash);

    // first receive receiver and ammount
    let (receiver, amount, nonce, token_address) = parse_withdraw_event_log_data(receiver_data)?;

    let sender = get_sender_from_transaction_hash(txhash, client).await?;

    Ok(WithdrawEvent {
        sender,
        receiver,
        amount,
        nonce,
        token_address,
    })
}

/// Maximum number of blocks to query in a single check_for_events call.
/// Larger ranges are automatically split into chunks of this size.
/// we need this because no values are indexed in this event, so we can't use
/// intelegent search to reduce the number of items returned and increase query speed
const EVENT_QUERY_CHUNK_SIZE: u64 = 5_000;

/// Maximum number of chunks to query in parallel
const MAX_PARALLEL_CHUNKS: usize = 8;

/// Number of times to retry a failed chunk before giving up
const CHUNK_RETRY_ATTEMPTS: usize = 50;

/// The event signature for withdraw events on the Gnosis bridge
const WITHDRAW_EVENT_SIG: &str = "UserRequestForSignature(address,uint256,bytes32,address)";

/// Carries the identity and outcome of a single chunk query back to the caller after
/// parallel execution. The retry_count lets callers log how many attempts were needed.
struct ChunkResult {
    chunk_start: u64,
    chunk_end: u64,
    /// How many times this chunk has been attempted (1 on the first try)
    retry_count: usize,
    result: Result<Vec<WithdrawEvent>, Web3Error>,
}

/// Queries a single chunk of blocks for withdraw events matching our addresses of interest.
/// Returns a ChunkResult so callers can identify which chunk succeeded or failed after
/// parallel execution and track how many attempts were made.
async fn query_withdraw_events_chunk(
    chunk_start: u64,
    chunk_end: u64,
    retry_count: usize,
    contract: Address,
    xdai_client: &Web3,
    search_addresses: &HashSet<Address>,
) -> ChunkResult {
    let logs = xdai_client
        .check_for_events(
            chunk_start.into(),
            Some(chunk_end.into()),
            vec![contract],
            vec![WITHDRAW_EVENT_SIG],
        )
        .await;

    let logs = match logs {
        Ok(logs) => logs,
        Err(e) => {
            return ChunkResult {
                chunk_start,
                chunk_end,
                retry_count,
                result: Err(e),
            }
        }
    };

    let mut events = Vec::new();
    for log in logs.iter() {
        match parse_withdraw_event(log, xdai_client).await {
            Ok(withdraw_event) => {
                if search_addresses.contains(&withdraw_event.sender)
                    || search_addresses.contains(&withdraw_event.receiver)
                {
                    events.push(withdraw_event);
                }
            }
            Err(e) => {
                return ChunkResult {
                    chunk_start,
                    chunk_end,
                    retry_count,
                    result: Err(e),
                }
            }
        }
    }

    ChunkResult {
        chunk_start,
        chunk_end,
        retry_count,
        result: Ok(events),
    }
}

/// When we submit our bridge out transaction this event is generated and has information we need to relay the final transaction to unlock the funds on the
/// eth side. Large block ranges are automatically chunked into pieces of EVENT_QUERY_CHUNK_SIZE
/// and queried in parallel (up to MAX_PARALLEL_CHUNKS at a time) to avoid RPC timeouts or
/// response size limits, allowing callers to search millions of blocks efficiently.
/// Failed chunks are retried up to CHUNK_RETRY_ATTEMPTS times.
pub async fn find_user_request_for_signatures_event(
    start: Uint256,
    end: Uint256,
    contract: Address,
    xdai_web3: Web3,
    search_addresses: HashSet<Address>,
) -> Result<Vec<WithdrawEvent>, Web3Error> {
    // Convert to u64 for chunking arithmetic, these block numbers will never exceed u64
    let start_u64: u64 = start
        .to_string()
        .parse()
        .map_err(|_| Web3Error::BadInput(format!("Start block {start} overflows u64")))?;
    let end_u64: u64 = end
        .to_string()
        .parse()
        .map_err(|_| Web3Error::BadInput(format!("End block {end} overflows u64")))?;

    // Build all chunk ranges up front, each starting at retry_count=0
    let mut pending_chunks: Vec<(u64, u64, usize)> = Vec::new();
    let mut chunk_start = start_u64;
    while chunk_start < end_u64 {
        let chunk_end = std::cmp::min(chunk_start + EVENT_QUERY_CHUNK_SIZE, end_u64);
        pending_chunks.push((chunk_start, chunk_end, 0));
        chunk_start = chunk_end;
    }

    info!(
        "Querying withdraw events across {} chunks [{} -> {}]",
        pending_chunks.len(),
        start_u64,
        end_u64
    );

    let mut all_events: Vec<WithdrawEvent> = Vec::new();
    let mut attempt = 0;

    while !pending_chunks.is_empty() && attempt < CHUNK_RETRY_ATTEMPTS {
        if attempt > 0 {
            info!(
                "Retrying {} failed chunks (attempt {}/{})",
                pending_chunks.len(),
                attempt + 1,
                CHUNK_RETRY_ATTEMPTS,
            );
        }

        let mut failed_chunks: Vec<(u64, u64, usize)> = Vec::new();

        // Process chunks in batches of MAX_PARALLEL_CHUNKS
        for batch in pending_chunks.chunks(MAX_PARALLEL_CHUNKS) {
            let futures: Vec<_> = batch
                .iter()
                .map(|(cs, ce, retries)| {
                    query_withdraw_events_chunk(
                        *cs,
                        *ce,
                        *retries + 1,
                        contract,
                        &xdai_web3,
                        &search_addresses,
                    )
                })
                .collect();

            let results = join_all(futures).await;

            for chunk_result in results {
                match chunk_result.result {
                    Ok(events) => {
                        all_events.extend(events);
                    }
                    Err(Web3Error::BadInput(ref msg)) => {
                        // Deterministic parse error — the same log data will always fail.
                        // This should never happen when interacting with the real bridge
                        // contract, so escalate immediately rather than retrying.
                        error!(
                            "Parse error in chunk [{} -> {}]: {msg} — this should not happen with the real bridge contract",
                            chunk_result.chunk_start,
                            chunk_result.chunk_end,
                        );
                        return Err(Web3Error::BadInput(format!(
                            "Parse error in chunk [{} -> {}]: {msg}",
                            chunk_result.chunk_start, chunk_result.chunk_end,
                        )));
                    }
                    Err(Web3Error::ClarityError(ref e)) => {
                        // Deterministic parse/address error — escalate immediately.
                        error!(
                            "Parse error (ClarityError) in chunk [{} -> {}]: {e} — this should not happen with the real bridge contract",
                            chunk_result.chunk_start,
                            chunk_result.chunk_end,
                        );
                        return Err(Web3Error::BadInput(format!(
                            "ClarityError in chunk [{} -> {}]: {e}",
                            chunk_result.chunk_start, chunk_result.chunk_end,
                        )));
                    }
                    Err(e) => {
                        warn!(
                            "Chunk [{} -> {}] failed on attempt {}: {e}, will retry",
                            chunk_result.chunk_start,
                            chunk_result.chunk_end,
                            chunk_result.retry_count,
                        );
                        failed_chunks.push((
                            chunk_result.chunk_start,
                            chunk_result.chunk_end,
                            chunk_result.retry_count,
                        ));
                    }
                }
            }
        }

        pending_chunks = failed_chunks;
        attempt += 1;

        // Sleep before retrying to avoid hammering the RPC endpoint
        if !pending_chunks.is_empty() {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    if !pending_chunks.is_empty() {
        let ranges: Vec<String> = pending_chunks
            .iter()
            .map(|(s, e, retries)| format!("[{s} -> {e}] ({retries} attempts)"))
            .collect();
        return Err(Web3Error::BadResponse(format!(
            "Failed to query {} chunks after {} retries: {}",
            pending_chunks.len(),
            CHUNK_RETRY_ATTEMPTS,
            ranges.join(", ")
        )));
    }

    info!(
        "Found {} withdraw events across all chunks",
        all_events.len()
    );

    Ok(all_events)
}

/// This helper function parses the 'Data' field in the Logs returned from when checking for the event signature "UserRequestForSignature(address,uint256)"
/// This parses and returns the receiver Address and the ammount field.
fn parse_withdraw_event_log_data(
    data: &[u8],
) -> Result<(Address, Uint256, Uint256, Address), Web3Error> {
    if data.len() < 128 {
        return Err(Web3Error::BadInput(
            "Length of the log data is not long enough".to_string(),
        ));
    }

    // The address is 20 bytes, and a word is 32 bytes, so our actual address is stored from bytes 12 - 32
    let address_bytes = &data[12..32];
    let address = Address::from_slice(address_bytes)?;

    // The next word in payload represents the ammount. this is bytes 32 - 64
    let ammount_bytes = &data[32..64];
    let ammount = Uint256::from_be_bytes(ammount_bytes);

    // next word is the nonce, which is 32 bytes
    let nonce = &data[64..96];
    let nonce = Uint256::from_be_bytes(nonce);

    // finaly we have the bridge out token address, which is 32 bytes but only the last 20 bytes are used
    let token_address_bytes = &data[96 + 12..128];
    let token_address = Address::from_slice(token_address_bytes)?;

    Ok((address, ammount, nonce, token_address))
}

/// This helper function parses the transaction_hash field in the Logs returned when checking for the event signature "UserRequestForSignature(address,uint256)"
/// This parses and returns the nonce value and the senders Address
async fn get_sender_from_transaction_hash(
    txhash: Uint256,
    client: &Web3,
) -> Result<Address, Web3Error> {
    let response = client.eth_get_transaction_by_hash(txhash).await?;

    let tx_res = match response {
        Some(a) => a,
        None => {
            return Err(Web3Error::BadResponse(
                "No Transaction present for the given Hash".to_string(),
            ));
        }
    };

    let sender = match tx_res {
        TransactionResponse::Eip1559 { from, .. } => from,
        TransactionResponse::Eip2930 { from, .. } => from,
        TransactionResponse::Legacy { from, .. } => from,
    };
    Ok(sender)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    const TIMEOUT: Duration = Duration::from_secs(600);

    fn new_token_bridge() -> TokenBridge {
        let pk = PrivateKey::from_str(&format!(
            "FE1FC0A7A29503BAF72274A{}601D67309E8F3{}D22",
            "AA3ECDE6DB3E20", "29F7AB4BA52"
        ))
        .unwrap();

        TokenBridge::new(
            TokenBridgeRpcs {
                eth_full_node_url: "https://eth.altheamesh.com".into(),
                xdai_full_node_url: "https://dai.altheamesh.com".into(),
                gravity_grpc_url: "https://gravitychain.io:9090".into(),
            },
            pk.to_address(),
            pk,
            TIMEOUT,
        )
    }

    fn eth_to_wei(eth: f64) -> Uint256 {
        let wei = (eth * 1000000000000000000f64) as u64;
        wei.into()
    }

    /// ensures all bridge addresses pass EIP-55 parsing
    #[test]
    fn validate_bridge_addresses() {
        Address::parse_and_validate(XDAI_BRIDGE_ON_ETH_ADDRESS)
            .expect("Invalid xdai home bridge address");
        Address::parse_and_validate(HELPER_ON_XDAI_ADDRESS)
            .expect("Invalid xdai home helper address");
        Address::parse_and_validate(XDAI_BRIDGE_ON_XDAI_ADDRESS)
            .expect("Invalid xdai foreign bridge address");
    }

    #[test]
    #[ignore]
    fn test_dai_to_xdai_bridge() {
        let runner = actix::System::new();

        let token_bridge = new_token_bridge();

        runner.block_on(async move {
            // All we can really do here is test that it doesn't throw. Check your balances in
            // 5-10 minutes to see if the money got transferred.
            token_bridge
                .bridge_to_gnosis(
                    eth_to_wei(0.01f64),
                    *web30::amm::USDS_CONTRACT_ADDRESS,
                    TIMEOUT,
                )
                .await
                .unwrap();
        });
    }

    #[test]
    #[ignore]
    fn test_check_withdrawals() {
        let runner = actix::System::new();

        let token_bridge = new_token_bridge();

        let blocks_to_check: Uint256 = 100_000u32.into();
        runner.block_on(async move {
            let current_block = token_bridge.xdai_web3.eth_block_number().await.unwrap();
            let start = current_block - blocks_to_check;
            let mut h = HashSet::new();
            let test_addr = "0x9cF30e6c56439D571ec07774dF6E326Aeff1C97B"
                .parse()
                .unwrap();
            //h.insert(token_bridge.own_address);
            h.insert(test_addr);
            // res is empty since we use a dummy address
            let res = find_user_request_for_signatures_event(
                start,
                current_block,
                token_bridge.xdai_bridge_on_xdai,
                token_bridge.xdai_web3,
                h,
            )
            .await
            .unwrap();
            println!("{res:#?}");
        });
    }

    /// This tests the function check_relayed_message(). This is not deterministic and will fail since the hard coded transaction id
    /// used during testing has be unlock. To test for a 'false' result, initiate a withdrawal using test_xdai_transfer_withdraw() and then
    /// use that tx_has to run this function, before unlocking the funds.
    #[test]
    #[ignore]
    fn test_check_relayed_message() {
        let runner = actix::System::new();
        runner.block_on(async move {
            let eth_full_node_url = "https://eth.althea.net";
            let eth_web3 = Web3::new(eth_full_node_url, TIMEOUT);

            let own_address = "0xB5E7AcD8f1D5F8f8EA2DEf72C34Fe4B02c759329";
            let own_address = own_address.parse().unwrap();

            // this transaction has been unlocked
            let tx_hash = "0x87e07391e045f5c03bba91db7a4fd7e1116f52aad0f02832254ed6cc896641a9";
            let tx_hash = Uint256::from_str(tx_hash).unwrap();

            let contract = get_xdai_bridge_on_eth_address();

            let res = match check_relayed_message(tx_hash, eth_web3.clone(), own_address, contract)
                .await
            {
                Ok(a) => a,
                Err(e) => panic!("Received an Error: {e}"),
            };

            assert!(res);

            // this transaction has not been unlocked
            let tx_hash = "0xf75cd74e3643bb0d17780589e0f18840c89ff77532f5ac38fbff885468091620";
            let tx_hash = Uint256::from_str(tx_hash).unwrap();

            let res = match check_relayed_message(tx_hash, eth_web3.clone(), own_address, contract)
                .await
            {
                Ok(a) => a,
                Err(e) => panic!("Received an Error: {e}"),
            };

            assert!(!res);
        })
    }

    /// Tests that find_user_request_for_signatures_event can query 1M+ blocks
    /// using parallel chunked queries without timing out or hitting RPC limits.
    /// Uses a known address that has had withdraw activity.
    #[test]
    #[ignore]
    fn test_parallel_chunked_event_query_1m_blocks() {
        let runner = actix::System::new();
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
            .try_init()
            .ok();

        runner.block_on(async move {
            let client = Web3::new("https://dai.althea.net", TIMEOUT);
            let bridge_address = get_xdai_bridge_on_xdai_address();

            let current_block = client
                .eth_block_number()
                .await
                .unwrap_or_else(|e| panic!("Failed to get block number: {e:?}"));

            // Search 1.2 million blocks back — this is the ops-side search depth
            let blocks_to_search: Uint256 = 1_200_000u64.into();
            let start_block = current_block - blocks_to_search;

            let mut addresses = HashSet::new();
            // Use a known address that has had bridge activity
            addresses.insert(
                "0x9cF30e6c56439D571ec07774dF6E326Aeff1C97B"
                    .parse()
                    .unwrap(),
            );

            println!(
                "Querying {} blocks [{} -> {}] in parallel chunks of {}",
                blocks_to_search, start_block, current_block, EVENT_QUERY_CHUNK_SIZE
            );

            let start_time = std::time::Instant::now();
            let result = find_user_request_for_signatures_event(
                start_block,
                current_block,
                bridge_address,
                client,
                addresses,
            )
            .await;

            let elapsed = start_time.elapsed();
            match result {
                Ok(events) => {
                    println!(
                        "Successfully queried 1.2M blocks in {:.1}s, found {} events",
                        elapsed.as_secs_f64(),
                        events.len()
                    );
                    for event in &events {
                        println!(
                            "  sender={} receiver={} amount={} nonce={}",
                            event.sender, event.receiver, event.amount, event.nonce
                        );
                    }
                }
                Err(e) => {
                    panic!(
                        "Failed to query 1.2M blocks after {:.1}s: {e}",
                        elapsed.as_secs_f64()
                    );
                }
            }
        });
    }
}
