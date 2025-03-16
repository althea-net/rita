#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

use clarity::abi::{encode_call, AbiToken};
use clarity::utils::bytes_to_hex_str;
use clarity::{Address, PrivateKey};
use num256::Uint256;
use std::collections::HashSet;
use std::time::{Duration, Instant};
use web30::amm::{DAI_CONTRACT_ADDRESS as DAI_CONTRACT_ON_ETH, USDC_CONTRACT_ADDRESS};
use web30::client::Web3;
use web30::jsonrpc::error::Web3Error;
use web30::types::{Log, TransactionRequest, TransactionResponse};

mod error;
pub use error::TokenBridgeError;

/// These hardcoded values are obtained
// by looking at the values on Etherscan and observing gas values in practice, along with slight padding
// to ensure correct operation. These hardcoded gas values are only being used to estimate the reserve amount
pub static UNISWAP_GAS_LIMIT: u128 = 150_000;
pub static ERC20_GAS_LIMIT: u128 = 40_000;
pub static XDAI_FUNDS_UNLOCK_GAS: u128 = 180_000;
/// Minimum transfer is $5 dai which has 18 decimal precision
pub static MINIMUM_DAI_TO_SEND: u128 = 2_000_000_000_000_000_000;
/// Minimum transfer is $15 USDC which has 6 decimal precision
pub static MINIMUM_USDC_TO_CONVERT: u128 = 15_000_000;

fn default_helper_on_xdai_address() -> Address {
    default_bridge_addresses().helper_on_xdai
}

fn default_xdai_bridge_on_eth_address() -> Address {
    default_bridge_addresses().xdai_bridge_on_eth
}

fn default_xdai_bridge_on_xdai_address() -> Address {
    default_bridge_addresses().xdai_bridge_on_xdai
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct TokenBridgeAddresses {
    #[serde(default = "default_xdai_bridge_on_eth_address")]
    pub xdai_bridge_on_eth: Address,
    #[serde(default = "default_helper_on_xdai_address")]
    pub helper_on_xdai: Address,
    #[serde(default = "default_xdai_bridge_on_xdai_address")]
    pub xdai_bridge_on_xdai: Address,
    pub eth_full_node_url: String,
    pub xdai_full_node_url: String,
}

pub fn get_usdt_address() -> Address {
    "0xdAC17F958D2ee523a2206206994597C13D831ec7"
        .parse()
        .unwrap()
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
    pub txid: Uint256,
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
        addresses: TokenBridgeAddresses,
        own_address: Address,
        eth_privatekey: PrivateKey,
        eth_full_node_url: String,
        xdai_full_node_url: String,
        timeout: Duration,
    ) -> TokenBridge {
        TokenBridge {
            xdai_bridge_on_xdai: addresses.xdai_bridge_on_xdai,
            helper_on_xdai: addresses.helper_on_xdai,
            xdai_bridge_on_eth: addresses.xdai_bridge_on_eth,
            own_address,
            eth_privatekey,
            xdai_web3: Web3::new(&xdai_full_node_url, timeout),
            eth_web3: Web3::new(&eth_full_node_url, timeout),
        }
    }

    /// Bridge `dai_amount` dai to xdai
    pub async fn dai_to_xdai_bridge(
        &self,
        dai_amount: Uint256,
        timeout: Duration,
    ) -> Result<Uint256, TokenBridgeError> {
        let secret = self.eth_privatekey;

        let allowance = self
            .eth_web3
            .get_erc20_allowance(
                *DAI_CONTRACT_ON_ETH,
                self.eth_privatekey.to_address(),
                self.xdai_bridge_on_eth,
            )
            .await?;
        trace!("Current DAI allowance on the bridge is {}", allowance);
        if dai_amount > allowance {
            trace!("Executing approval for DAI transfer");
            // approve 1000 dai at a time, this reduces gas costs for the user
            self.eth_web3
                .erc20_approve(
                    *DAI_CONTRACT_ON_ETH,
                    // 1000 dai
                    1000000000000000000000u128.into(),
                    self.eth_privatekey,
                    self.xdai_bridge_on_eth,
                    Some(timeout),
                    vec![],
                )
                .await?;
        }

        let tx = self
            .eth_web3
            .prepare_transaction(
                self.xdai_bridge_on_eth,
                encode_call(
                    "relayTokens(address,uint256)",
                    &[self.eth_privatekey.to_address().into(), dai_amount.into()],
                )
                .unwrap(),
                0u32.into(),
                secret,
                vec![],
            )
            .await?;
        let tx_hash = self.eth_web3.send_prepared_transaction(tx).await?;

        self.eth_web3
            .wait_for_transaction(tx_hash, timeout, None)
            .await?;

        Ok(dai_amount)
    }

    pub async fn get_dai_balance(&self) -> Result<Uint256, TokenBridgeError> {
        let dai_address = *DAI_CONTRACT_ON_ETH;
        Ok(self
            .eth_web3
            .get_erc20_balance(dai_address, self.own_address)
            .await?)
    }

    pub async fn get_usdc_balance(&self) -> Result<Uint256, TokenBridgeError> {
        let usdc_address = *USDC_CONTRACT_ADDRESS;
        Ok(self
            .eth_web3
            .get_erc20_balance(usdc_address, self.own_address)
            .await?)
    }

    pub async fn get_usdt_balance(&self) -> Result<Uint256, TokenBridgeError> {
        let usdt_address = get_usdt_address();
        Ok(self
            .eth_web3
            .get_erc20_balance(usdt_address, self.own_address)
            .await?)
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
    xdai_withdraw_txid: Uint256,
    amount_sent: Uint256,
) -> Result<HelperWithdrawInfo, TokenBridgeError> {
    info!("bridge getting message hashes");
    // the hash that is then used to look up the signatures, this will always
    // succeed, whereas the signature lookup may need to wait for all sigs
    // to be submitted
    let payload = match encode_call(
        "getMessageHash(address,uint256,bytes32)",
        &[
            dest_address.into(),
            amount_sent.into(),
            AbiToken::Bytes(xdai_withdraw_txid.to_be_bytes().to_vec()),
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
    let msg_end = START + (msg_len);
    let sigs_end = START + (sigs_len);
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
pub const HELPER_ON_XDAI_ADDRESS: &str = "0x6A92e97A568f5F58590E8b1f56484e6268CdDC51";
pub const XDAI_BRIDGE_ON_XDAI_ADDRESS: &str = "0x7301CFA0e1756B71869E93d4e4Dca5c7d0eb0AA6";

/// This function provides the default bridge addresses to be used by the token contract,
/// these are for the most part constants, but it is possible they may be updated or changed
/// if the xDai or Maker DAO or Uniswap team deploy new contracts
pub fn default_bridge_addresses() -> TokenBridgeAddresses {
    TokenBridgeAddresses {
        helper_on_xdai: HELPER_ON_XDAI_ADDRESS.parse().unwrap(),
        xdai_bridge_on_eth: XDAI_BRIDGE_ON_ETH_ADDRESS.parse().unwrap(),
        xdai_bridge_on_xdai: XDAI_BRIDGE_ON_XDAI_ADDRESS.parse().unwrap(),
        eth_full_node_url: "https://eth.althea.org".into(),
        xdai_full_node_url: "https://dai.althea.org".into(),
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
/// The transaction sends real money that the user requested to the destination address from user's wallet.
pub async fn encode_relaytokens(
    bridge: TokenBridge,
    dest_address: Address,
    amount: Uint256,
    timeout: Duration,
) -> Result<(), TokenBridgeError> {
    let payload = encode_call("relayTokens(address)", &[dest_address.into()]).unwrap();
    let options = Vec::new();

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

/// Helper function that returns the start and end block number when searching for events
fn compute_start_end(
    iter: u64,
    latest_block: Uint256,
    total_blocks: u64,
    max_iter: u64,
) -> (Uint256, Uint256) {
    let start_block = (latest_block - total_blocks.into()) + (max_iter * iter).into();
    let end_block = if start_block + max_iter.into() > latest_block {
        latest_block
    } else {
        start_block + max_iter.into()
    };

    (start_block, end_block)
}

/// This helper function parses the data field in the logs returned from when checking for withdraw events related to us in xdai block chain
/// This parses and returns the sender/receiver addresses and the ammount.
async fn parse_withdraw_event(log_data: &Log, client: &Web3) -> Result<WithdrawEvent, Web3Error> {
    let receiver_data = &*log_data.data;
    let sender_data = match log_data.clone().transaction_hash {
        Some(a) => a.clone(),
        None => {
            return Err(Web3Error::BadResponse(
                "There is no transaction hash present for the given log".to_string(),
            ));
        }
    };
    let sender_data = &*sender_data;

    // first receive receiver and ammount
    let (receiver, amount) = parse_receiver_data(receiver_data)?;

    let (sender, tx_hash) = parse_sender_data(sender_data, client).await?;

    Ok(WithdrawEvent {
        sender,
        receiver,
        amount,
        txid: tx_hash,
    })
}

/// This function is called at regular intervals to check the 'n' most recent blocks for the event signature 'UserRequestForSignature(_receiver,valueToTransfer)'
/// This event is called when a user request a withdrawal process, but withdrawals may not be reliable in cases such as when there is a power outage or
/// if the user does not have enough eth funds to unlock the funds on their side. To alleviate this, this function is called, looks for withdrawal events related to
/// us and returns these events.
pub async fn check_withdrawals(
    blocks_to_check: u64,
    contract: Address,
    xdai_web3: Web3,
    search_addresses: HashSet<Address>,
    // The total amount of time this operation has to complete
    // during that time failed requests will be retried
    // if None exit will occur on the first error
    retry_timeout: Option<Duration>,
) -> Result<Vec<WithdrawEvent>, Web3Error> {
    /// Total number of blocks on the xdai blockchain we retrieve at once. If the blocks to check is greater than this we loop.
    const MAX_ITER: u64 = 500;
    let mut blocks_left: u64 = blocks_to_check;
    let mut vec_of_withdraws = Vec::new();
    let start_time = Instant::now();

    //get latest xdai block
    let xdai_client = xdai_web3;
    let xdai_latest_block = xdai_client.eth_block_number().await?;
    let mut iter: u64 = 0;

    // iterate MAX_ITER blocks at a time
    loop {
        let (start, end) = compute_start_end(iter, xdai_latest_block, blocks_to_check, MAX_ITER);
        iter += 1;

        //We search for the phrase UserRequestForSignature(_receiver,valueToTransfer)
        let phrase_sig = "UserRequestForSignature(address,uint256)";

        let mut logs = xdai_client
            .check_for_events(start, Some(end), vec![contract], vec![phrase_sig])
            .await;
        if let Some(timeout) = retry_timeout {
            while logs.is_err() && (Instant::now() - start_time) < timeout {
                logs = xdai_client
                    .check_for_events(start, Some(end), vec![contract], vec![phrase_sig])
                    .await;
            }
        }

        for log in logs?.iter() {
            let withdraw_event = parse_withdraw_event(log, &xdai_client).await?;
            for &search_address in search_addresses.iter() {
                if withdraw_event.sender == search_address {
                    vec_of_withdraws.push(withdraw_event.clone());
                }
            }
        }

        // Break from loop if there are no more blocks to check
        if MAX_ITER > blocks_left {
            break;
        }
        blocks_left -= MAX_ITER;
    }

    Ok(vec_of_withdraws)
}

/// This helper function parses the 'Data' field in the Logs returned from when checking for the event signature "UserRequestForSignature(address,uint256)"
/// This parses and returns the receiver Address and the ammount field.
fn parse_receiver_data(data: &[u8]) -> Result<(Address, Uint256), Web3Error> {
    if data.len() < 64 {
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

    Ok((address, ammount))
}

/// This helper function parses the transaction_hash field in the Logs returned when checking for the event signature "UserRequestForSignature(address,uint256)"
/// This parses and returns the senders Address
async fn parse_sender_data(data: &[u8], client: &Web3) -> Result<(Address, Uint256), Web3Error> {
    // Transaction hash should be one word
    if data.len() < 32 {
        return Err(Web3Error::BadInput(
            "Length of the transaction hash is not long enough".to_string(),
        ));
    }

    let tx_hash = Uint256::from_be_bytes(data);
    let response = client.eth_get_transaction_by_hash(tx_hash).await?;

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
    Ok((sender, tx_hash))
}

#[cfg(test)]
mod tests {
    use clarity::utils::hex_str_to_bytes;

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
            default_bridge_addresses(),
            pk.to_address(),
            pk,
            "https://eth.altheamesh.com".into(),
            "https://dai.altheamesh.com".into(),
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
    fn test_funds_unlock_boilerplate() {
        let runner = actix::System::new();

        let bridge = new_token_bridge();

        runner.block_on(async move {
            let details = get_relay_message_hash(
                bridge.own_address,
                bridge.xdai_web3.clone(),
                bridge.helper_on_xdai,
                bridge.own_address,
                "0x83b76e9e2acfaf57422f1fc194fd672a2bc267f8fe7a6220d78df3a9260b0a65"
                    .parse()
                    .unwrap(),
                38279145422101674969u128.into(),
            )
            .await
            .unwrap();
            println!(
                "Got sigs, msg: {} sigs {}",
                bytes_to_hex_str(&details.msg),
                bytes_to_hex_str(&details.sigs),
            );
            bridge
                .submit_signatures_to_unlock_funds(details, TIMEOUT)
                .await
                .unwrap();
            actix::System::current().stop();
        });
    }

    #[test]
    #[ignore]
    /// This tests unlocking funds from the POA Xdai bridge using a lot of specially collected
    /// test data for the entire process
    fn test_funds_unlock() {
        use futures::future::join;
        let runner = actix::System::new();
        let dest_address = "0x310d72afc5eef50b52a47362b6dd1913d4c87972"
            .parse()
            .unwrap();
        let correct_payload_1 = hex_str_to_bytes("0x3f7658fd000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000068310d72afc5eef50b52a47362b6dd1913d4c8797200000000000000000000000000000000000000000000000191d1a75300d852c57b2606e78f2b6b1622598084446fcab1af95828465b0745f345052379ad4c3654aa42145aa6ebf72e164c9bbc74fbd378804501600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c4031b1c1cd0e52f961e3fe727d5fb76ac7ea6789c4359a124c4ea662451471218dcc87e10b8aa42f77d03075e5bbdd768b01f359090d228543aa9cf98e7cac1ac43502829b2e01a41c3b9647ebe869a5030e5d3ac885926bbffe8a709fb06b0701e12a879575df42e83cbbb0087a82814be3390ff2fda83234866d91bc61e405e2be750a17d8c38ff65aadb5bdb42643355584290c0e907a07c3f37983444814ad1035d1e487ee5aa9273fa59dc5d6afc707eb5e2ca6a6d0991e6cf5f773db18552a80ca000000000000000000000000000000000000000000000000000000000").unwrap();
        let _correct_msg_hash_1 =
            hex_str_to_bytes("0xab89d6524aeb99b0afb21bc4acbcad80d99b22decb725a8b91901ef2fc60b8ee")
                .unwrap();
        let correct_msg_1 = hex_str_to_bytes("0x310d72afc5eef50b52a47362b6dd1913d4c8797200000000000000000000000000000000000000000000000191d1a75300d852c57b2606e78f2b6b1622598084446fcab1af95828465b0745f345052379ad4c3654aa42145aa6ebf72e164c9bbc74fbd3788045016").unwrap();
        let correct_sigs_1 = hex_str_to_bytes("0x031b1c1cd0e52f961e3fe727d5fb76ac7ea6789c4359a124c4ea662451471218dcc87e10b8aa42f77d03075e5bbdd768b01f359090d228543aa9cf98e7cac1ac43502829b2e01a41c3b9647ebe869a5030e5d3ac885926bbffe8a709fb06b0701e12a879575df42e83cbbb0087a82814be3390ff2fda83234866d91bc61e405e2be750a17d8c38ff65aadb5bdb42643355584290c0e907a07c3f37983444814ad1035d1e487ee5aa9273fa59dc5d6afc707eb5e2ca6a6d0991e6cf5f773db18552a80ca0").unwrap();
        let tx_id_1 = "0x7b2606e78f2b6b1622598084446fcab1af95828465b0745f345052379ad4c365"
            .parse()
            .unwrap();
        let amount_1 = 28954107454279930565u128;
        let correct_payload_2 = hex_str_to_bytes("0x3f7658fd000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000068310d72afc5eef50b52a47362b6dd1913d4c87972000000000000000000000000000000000000000000000002133ad7f325e3fbd983b76e9e2acfaf57422f1fc194fd672a2bc267f8fe7a6220d78df3a9260b0a654aa42145aa6ebf72e164c9bbc74fbd378804501600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c4031c1b1b9421be403593fed7ce937bcf6c1f59bc418d04ed6b3dd5f1a75109923ba969306a1bec5bb6b9d5a625af09fffa94a8f4e6c0e1f97e45e53701627af6b2bbd517b8a090e28b6f7d9e86b8ad5c6c6f4778c3e41e2c83b8fe216b425020389fffe263e350426291d8daae63d788acb0cb676d8efb5e5176865d7ddc8089d4260376213ef8ebcb05ff18181eee34edfec9524cc7c6398fef8c7b6ecc31c09fe80bd70dbb75c1380a000c8d231dc5f49db2a3948ee2d9c87fd083c334969d5c54e65500000000000000000000000000000000000000000000000000000000").unwrap();
        let _correct_msg_hash_2 =
            hex_str_to_bytes("0xcfdd7edcad5241f5f1660879fa46ecd545dbb52c87c361286a32162dc0e64e13")
                .unwrap();
        let correct_msg_2 =
            hex_str_to_bytes("0x310d72afc5eef50b52a47362b6dd1913d4c87972000000000000000000000000000000000000000000000002133ad7f325e3fbd983b76e9e2acfaf57422f1fc194fd672a2bc267f8fe7a6220d78df3a9260b0a654aa42145aa6ebf72e164c9bbc74fbd3788045016")
                .unwrap();
        let correct_sigs_2 =
            hex_str_to_bytes("0x031c1b1b9421be403593fed7ce937bcf6c1f59bc418d04ed6b3dd5f1a75109923ba969306a1bec5bb6b9d5a625af09fffa94a8f4e6c0e1f97e45e53701627af6b2bbd517b8a090e28b6f7d9e86b8ad5c6c6f4778c3e41e2c83b8fe216b425020389fffe263e350426291d8daae63d788acb0cb676d8efb5e5176865d7ddc8089d4260376213ef8ebcb05ff18181eee34edfec9524cc7c6398fef8c7b6ecc31c09fe80bd70dbb75c1380a000c8d231dc5f49db2a3948ee2d9c87fd083c334969d5c54e655")
                .unwrap();
        let tx_id_2 = "0x83b76e9e2acfaf57422f1fc194fd672a2bc267f8fe7a6220d78df3a9260b0a65"
            .parse()
            .unwrap();
        let amount_2 = 38279145422101674969u128;

        let mut bridge = new_token_bridge();
        // this will break any tx sending! but we don't do that here.
        bridge.own_address = dest_address;

        runner.block_on(async move {
            // this test may fail if we can't reach our xdai node cluster as we actually go out, call the contract and check
            let details_1 = get_relay_message_hash(
                bridge.own_address,
                bridge.xdai_web3.clone(),
                bridge.helper_on_xdai,
                bridge.own_address,
                tx_id_1,
                amount_1.into(),
            );
            let details_2 = get_relay_message_hash(
                bridge.own_address,
                bridge.xdai_web3,
                bridge.helper_on_xdai,
                bridge.own_address,
                tx_id_2,
                amount_2.into(),
            );
            let (details_1, details_2) = join(details_1, details_2).await;
            let details_1 = details_1.unwrap();
            let details_2 = details_2.unwrap();
            assert_eq!(
                bytes_to_hex_str(&details_1.msg),
                bytes_to_hex_str(&correct_msg_1)
            );
            assert_eq!(
                bytes_to_hex_str(&details_1.sigs),
                bytes_to_hex_str(&correct_sigs_1)
            );
            assert_eq!(
                bytes_to_hex_str(&details_2.msg),
                bytes_to_hex_str(&correct_msg_2)
            );
            assert_eq!(
                bytes_to_hex_str(&details_2.sigs),
                bytes_to_hex_str(&correct_sigs_2)
            );

            let payload_1 = get_payload_for_funds_unlock(&details_1);
            let payload_2 = get_payload_for_funds_unlock(&details_2);
            assert_eq!(
                bytes_to_hex_str(&payload_1),
                bytes_to_hex_str(&correct_payload_1)
            );
            assert_eq!(
                bytes_to_hex_str(&payload_2),
                bytes_to_hex_str(&correct_payload_2)
            );
            actix::System::current().stop();
        });
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
                .dai_to_xdai_bridge(eth_to_wei(0.01f64), TIMEOUT)
                .await
                .unwrap();
        });
    }

    #[test]
    #[ignore]
    fn test_check_withdrawals() {
        let runner = actix::System::new();

        let token_bridge = new_token_bridge();

        let blocks_to_check = 100_000;
        runner.block_on(async move {
            let mut h = HashSet::new();
            h.insert(token_bridge.own_address);
            // res is empty since we use a dummy address
            let res = check_withdrawals(
                blocks_to_check,
                token_bridge.xdai_bridge_on_xdai,
                token_bridge.xdai_web3,
                h,
                Some(Duration::from_secs(600)),
            )
            .await
            .unwrap();
            println!("{res:?}");
        });
    }

    #[test]
    fn test_parse_data() {
        let data: [u8; 64] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 121, 48, 20, 183, 133, 34, 51, 49, 47, 6, 31, 35,
            114, 158, 231, 84, 35, 113, 40, 143, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 52, 10, 173, 33, 179, 183, 0, 0, 0,
        ];

        let address_bytes = [
            121, 48, 20, 183, 133, 34, 51, 49, 47, 6, 31, 35, 114, 158, 231, 84, 35, 113, 40, 143,
        ];
        assert_eq!(&data[12..32], address_bytes);

        let ammount_bytes = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 52, 10, 173, 33,
            179, 183, 0, 0, 0,
        ];
        assert_eq!(&data[32..64], ammount_bytes);

        let (address, ammount) = parse_receiver_data(&data).unwrap();

        assert_eq!(address, Address::from_slice(&address_bytes).unwrap());
        assert_eq!(ammount, Uint256::from_be_bytes(&ammount_bytes));

        assert_eq!(address.as_bytes(), address_bytes);
    }

    #[test]
    #[ignore]
    fn test_looping_logic() {
        let runner = actix::System::new();
        runner.block_on(async move {
            let max_iter = 10000;

            let mut blocks_to_search = 99999;
            let xdai_client = Web3::new("https://dai.althea.net", Duration::from_secs(5));
            let latest_block = xdai_client.eth_block_number().await.unwrap();

            let (start, end) = compute_start_end(0, latest_block, blocks_to_search, max_iter);
            assert_eq!(start, latest_block - blocks_to_search.into());
            assert_eq!(end, start + max_iter.into());

            blocks_to_search = 9999;
            let (start, end) = compute_start_end(0, latest_block, blocks_to_search, max_iter);
            assert_eq!(start, latest_block - blocks_to_search.into());
            assert_eq!(end, start + blocks_to_search.into());

            blocks_to_search = 10000;
            let (start, end) = compute_start_end(0, latest_block, blocks_to_search, max_iter);
            assert_eq!(start, latest_block - blocks_to_search.into());
            assert_eq!(end, start + blocks_to_search.into());

            blocks_to_search = 10001;
            let (start, end) = compute_start_end(0, latest_block, blocks_to_search, max_iter);
            assert_eq!(start, latest_block - blocks_to_search.into());
            assert_eq!(end, start + max_iter.into());

            let (start, end) = compute_start_end(1, latest_block, blocks_to_search, max_iter);
            assert_eq!(start, latest_block - 1u32.into());
            assert_eq!(end, start + 1u32.into());
        });
    }

    /// This tests that the function 'get_payload_for_funds_unlock' is working correctly and generating the correct bytes to use.
    /// To test this, we look at a successful transaction on etherscan.io, and compare the raw input to that generated by this function.
    #[test]
    #[ignore]
    fn test_withdraw_encoding() {
        let dest_address = "0xffcbadeb2a7cc87563e22a8fb4ee120eb73b2d82";
        let dest_address = dest_address.parse().unwrap();

        let own_address = "0x5e53002339223011ba4bc1e5faf61fb42544e2c9";
        let own_address = own_address.parse().unwrap();

        let xdai_full_node_url = "https://dai.althea.net";
        let xdai_web3 = Web3::new(xdai_full_node_url, TIMEOUT);

        let helper_on_xdai = default_bridge_addresses().helper_on_xdai;

        //580 dai
        let amount_sent = 580000000000000000000_u128.into();

        let tx_hash = "0xcaa7620d9f16834cf2c5ebb53365ddcf85eb84ed1734c4d884079536d78fe544";
        let xdai_withdraw_txid = Uint256::from_str(tx_hash).unwrap();

        //execute sigs raw input
        let raw_input = "3f7658fd000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000068ffcbadeb2a7cc87563e22a8fb4ee120eb73b2d8200000000000000000000000000000000000000000000001f711def073e900000caa7620d9f16834cf2c5ebb53365ddcf85eb84ed1734c4d884079536d78fe5444aa42145aa6ebf72e164c9bbc74fbd378804501600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c4031c1b1c8adc5f301a19fbf3c2266c4398645a0a31d301e121fe3d2957ece5779735b81099735b004675c6cf61e20d465b036ebae2e2f29a73914a2a08460bfac341f02201e30f07e72456171643e35a6f31648d56093039924151d69388fad441d910502b55a5c6092e4a6ee81540631c6726252f55485c299b6b71aa7547437ee9ff332e605650e13af2251e1d3b0136d2d8062e001a8f46b76b241aea89b525fba71432ad622b5f1cb2a4dcaf5e942456ba1544a5bdb3d5b483c2691e4d6a5e49253400000000000000000000000000000000000000000000000000000000";

        let runner = actix::System::new();

        runner.block_on(async move {
            let payload = get_relay_message_hash(
                own_address,
                xdai_web3,
                helper_on_xdai,
                dest_address,
                xdai_withdraw_txid,
                amount_sent,
            )
            .await
            .unwrap();
            // get encoded info
            let encoded_data = get_payload_for_funds_unlock(&payload);
            let encoded_string = bytes_to_hex_str(&encoded_data);

            assert_eq!(raw_input, encoded_string);
        })
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

            let contract = default_bridge_addresses().xdai_bridge_on_eth;

            let res = match check_relayed_message(tx_hash, eth_web3.clone(), own_address, contract)
                .await
            {
                Ok(a) => a,
                Err(e) => panic!("Received an Error: {}", e),
            };

            assert!(res);

            // this transaction has not been unlocked
            let tx_hash = "0xf75cd74e3643bb0d17780589e0f18840c89ff77532f5ac38fbff885468091620";
            let tx_hash = Uint256::from_str(tx_hash).unwrap();

            let res = match check_relayed_message(tx_hash, eth_web3.clone(), own_address, contract)
                .await
            {
                Ok(a) => a,
                Err(e) => panic!("Received an Error: {}", e),
            };

            assert!(!res);
        })
    }
}
