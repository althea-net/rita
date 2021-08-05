#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

use clarity::abi::{encode_call, Token};
use clarity::utils::bytes_to_hex_str;
use clarity::{Address, PrivateKey};
use num::Bounded;
use num256::Uint256;
use std::time::Duration;
use web30::address_to_event;
use web30::client::Web3;
use web30::jsonrpc::error::Web3Error;
use web30::types::Log;
use web30::types::SendTxOption;

mod error;
pub use error::TokenBridgeError;

// The estimate gas call is wildly inaccurate so we need to hardcode the expected gas
// consumption of the following operations. These hardcoded values are obtained
// by looking at the values on Etherscan and observing gas values in practice, along with slight padding
// to ensure correct operation
pub static UNISWAP_GAS_LIMIT: u128 = 80_000;
pub static ERC20_GAS_LIMIT: u128 = 40_000;
pub static ETH_TRANSACTION_GAS_LIMIT: u128 = 21_000;
pub static XDAI_FUNDS_UNLOCK_GAS: u128 = 180_000;

fn default_helper_on_xdai_address() -> Address {
    default_bridge_addresses().helper_on_xdai
}

fn default_uniswap_on_eth_address() -> Address {
    default_bridge_addresses().uniswap_on_eth_address
}

fn default_xdai_bridge_on_eth_address() -> Address {
    default_bridge_addresses().xdai_bridge_on_eth
}

fn default_xdai_bridge_on_xdai_address() -> Address {
    default_bridge_addresses().xdai_bridge_on_xdai
}

fn default_dai_erc20_contract_on_eth() -> Address {
    default_bridge_addresses().dai_erc20_contract_on_eth
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct TokenBridgeAddresses {
    #[serde(default = "default_uniswap_on_eth_address")]
    pub uniswap_on_eth_address: Address,
    #[serde(default = "default_xdai_bridge_on_eth_address")]
    pub xdai_bridge_on_eth: Address,
    #[serde(default = "default_helper_on_xdai_address")]
    pub helper_on_xdai: Address,
    #[serde(default = "default_xdai_bridge_on_xdai_address")]
    pub xdai_bridge_on_xdai: Address,
    #[serde(default = "default_dai_erc20_contract_on_eth")]
    pub dai_erc20_contract_on_eth: Address,
    pub eth_full_node_url: String,
    pub xdai_full_node_url: String,
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
    pub uniswap_on_eth_address: Address,
    pub xdai_bridge_on_eth: Address,
    pub helper_on_xdai: Address,
    pub xdai_bridge_on_xdai: Address,
    pub dai_erc20_contract_on_eth: Address,
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
            uniswap_on_eth_address: addresses.uniswap_on_eth_address,
            xdai_bridge_on_xdai: addresses.xdai_bridge_on_xdai,
            helper_on_xdai: addresses.helper_on_xdai,
            xdai_bridge_on_eth: addresses.xdai_bridge_on_eth,
            dai_erc20_contract_on_eth: addresses.dai_erc20_contract_on_eth,
            own_address,
            eth_privatekey,
            xdai_web3: Web3::new(&xdai_full_node_url, timeout),
            eth_web3: Web3::new(&eth_full_node_url, timeout),
        }
    }

    /// This just sends some Eth. Returns the tx hash.
    pub async fn eth_transfer(
        &self,
        to: Address,
        amount: Uint256,
        timeout: Duration,
        options: Vec<SendTxOption>,
    ) -> Result<(), TokenBridgeError> {
        let web3 = self.eth_web3.clone();
        let own_address = self.own_address;
        let secret = self.eth_privatekey;

        let tx_hash = web3
            .send_transaction(to, Vec::new(), amount, own_address, secret, options)
            .await?;

        web3.wait_for_transaction(tx_hash, timeout, None).await?;
        Ok(())
    }

    /// Price of ETH in Dai
    pub async fn eth_to_dai_price(&self, amount: Uint256) -> Result<Uint256, TokenBridgeError> {
        let web3 = self.eth_web3.clone();
        let uniswap_address = self.uniswap_on_eth_address;
        let own_address = self.own_address;

        let tokens_bought = web3
            .contract_call(
                uniswap_address,
                "getEthToTokenInputPrice(uint256)",
                &[amount.into()],
                own_address,
                None,
            )
            .await?;

        Ok(Uint256::from_bytes_be(match tokens_bought.get(0..32) {
            Some(val) => val,
            None => {
                return Err(TokenBridgeError::BadUniswapOutput(format!(
                    "Malformed output from uniswap getEthToTokenInputPrice call {:?}",
                    tokens_bought
                )))
            }
        }))
    }

    /// Price of Dai in Eth
    pub async fn dai_to_eth_price(&self, amount: Uint256) -> Result<Uint256, TokenBridgeError> {
        let web3 = self.eth_web3.clone();
        let uniswap_address = self.uniswap_on_eth_address;
        let own_address = self.own_address;

        let eth_bought = web3
            .contract_call(
                uniswap_address,
                "getTokenToEthInputPrice(uint256)",
                &[amount.into()],
                own_address,
                None,
            )
            .await?;

        Ok(Uint256::from_bytes_be(match eth_bought.get(0..32) {
            Some(val) => val,
            None => {
                return Err(TokenBridgeError::BadUniswapOutput(format!(
                    "Malformed output from uniswap getEthToTokenInputPrice call {:?}",
                    eth_bought
                )))
            }
        }))
    }

    /// Sell `eth_amount` ETH for Dai.
    /// This function will error out if it takes longer than 'timeout' and the transaction is guaranteed not
    /// to be executed on the blockchain after this time. The transaction will be accepted and some gas
    /// will be paid but the actual exchange will not complete as the contract will throw if the timeout time
    /// has elapsed
    pub async fn eth_to_dai_swap(
        &self,
        eth_amount: Uint256,
        timeout: Duration,
    ) -> Result<Uint256, TokenBridgeError> {
        let uniswap_address = self.uniswap_on_eth_address;
        let own_address = self.own_address;
        let secret = self.eth_privatekey;
        let web3 = self.eth_web3.clone();

        let block = web3.eth_get_latest_block().await?;
        let expected_dai = self.eth_to_dai_price(eth_amount.clone()).await?;

        // Equivalent to `amount * (1 - 0.025)` without using decimals
        let expected_dai = (expected_dai / 40u64.into()) * 39u64.into();
        let deadline = block.timestamp + timeout.as_secs().into();
        let payload = encode_call(
            "ethToTokenSwapInput(uint256,uint256)",
            &[expected_dai.into(), deadline.into()],
        )
        .unwrap();

        let _tx = web3
            .send_transaction(
                uniswap_address,
                payload,
                eth_amount,
                own_address,
                secret,
                vec![SendTxOption::GasLimit(UNISWAP_GAS_LIMIT.into())],
            )
            .await?;

        let topic = address_to_event(own_address);
        let topics = vec![topic];

        let response = web3
            .wait_for_event(
                timeout,
                vec![uniswap_address],
                "TokenPurchase(address,uint256,uint256)",
                vec![topics],
                |_| true,
            )
            .await?;

        let transferred_dai = Uint256::from_bytes_be(&response.topics[3]);
        Ok(transferred_dai)
    }

    /// Checks if the uniswap contract has been approved to spend dai from our account.
    pub async fn check_if_uniswap_dai_approved(&self) -> Result<bool, TokenBridgeError> {
        let web3 = self.eth_web3.clone();
        let uniswap_address = self.uniswap_on_eth_address;
        let dai_address = self.dai_erc20_contract_on_eth;
        let own_address = self.own_address;

        let allowance = web3
            .contract_call(
                dai_address,
                "allowance(address,address)",
                &[own_address.into(), uniswap_address.into()],
                own_address,
                None,
            )
            .await?;

        let allowance = Uint256::from_bytes_be(match allowance.get(0..32) {
            Some(val) => val,
            None => {
                return Err(TokenBridgeError::BadUniswapOutput(format!(
                    "Malformed output from uniswap getEthToTokenInputPrice call {:?}",
                    allowance
                )))
            }
        });

        // Check if the allowance remaining is greater than half of a Uint256- it's as good
        // a test as any.
        Ok(allowance > (Uint256::max_value() / 2u32.into()))
    }

    /// Sends transaction to the DAI contract to approve uniswap transactions, this future will not
    /// resolve until the process is either successful for the timeout finishes
    pub async fn approve_uniswap_dai_transfers(
        &self,
        timeout: Duration,
    ) -> Result<(), TokenBridgeError> {
        let dai_address = self.dai_erc20_contract_on_eth;
        let own_address = self.own_address;
        let uniswap_address = self.uniswap_on_eth_address;
        let secret = self.eth_privatekey;
        let web3 = self.eth_web3.clone();

        let payload = encode_call(
            "approve(address,uint256)",
            &[uniswap_address.into(), Uint256::max_value().into()],
        )
        .unwrap();

        let _res = web3
            .send_transaction(
                dai_address,
                payload,
                0u32.into(),
                own_address,
                secret,
                vec![SendTxOption::GasPriceMultiplier(2.0)],
            )
            .await?;

        let topics = vec![
            address_to_event(own_address),
            address_to_event(uniswap_address),
        ];

        let _res = web3
            .wait_for_event(
                timeout,
                vec![dai_address],
                "Approval(address,address,uint256)",
                vec![topics],
                |_| true,
            )
            .await?;

        Ok(())
    }

    /// Sell `dai_amount` Dai for ETH
    /// This function will error out if it takes longer than 'timeout' and the transaction is guaranteed not
    /// to be accepted on the blockchain after this time.
    pub async fn dai_to_eth_swap(
        &self,
        dai_amount: Uint256,
        timeout: Duration,
    ) -> Result<Uint256, TokenBridgeError> {
        let uniswap_address = self.uniswap_on_eth_address;
        let own_address = self.own_address;
        let secret = self.eth_privatekey;
        let web3 = self.eth_web3.clone();

        let is_approved = self.check_if_uniswap_dai_approved().await?;
        trace!("uniswap approved {}", is_approved);
        if !is_approved {
            self.approve_uniswap_dai_transfers(Duration::from_secs(600))
                .await?;
        }

        let block = web3.eth_get_latest_block().await?;
        let expected_eth = self.dai_to_eth_price(dai_amount.clone()).await?;
        // Equivalent to `amount * (1 - 0.025)` without using decimals
        let expected_eth = (expected_eth / 40u64.into()) * 39u64.into();
        let deadline = block.timestamp + timeout.as_secs().into();
        let payload = encode_call(
            "tokenToEthSwapInput(uint256,uint256,uint256)",
            &[dai_amount.into(), expected_eth.into(), deadline.into()],
        )
        .unwrap();

        let _tx = web3
            .send_transaction(
                uniswap_address,
                payload,
                0u32.into(),
                own_address,
                secret,
                vec![
                    SendTxOption::GasLimit(UNISWAP_GAS_LIMIT.into()),
                    SendTxOption::GasPriceMultiplier(2.0),
                ],
            )
            .await?;

        let topic = address_to_event(own_address);
        let topics = vec![topic];

        let response = web3
            .wait_for_event(
                timeout,
                vec![uniswap_address],
                "EthPurchase(address,uint256,uint256)",
                vec![topics],
                |_| true,
            )
            .await?;

        let transfered_eth = Uint256::from_bytes_be(&response.topics[3]);
        Ok(transfered_eth)
    }

    /// Bridge `dai_amount` dai to xdai
    pub async fn dai_to_xdai_bridge(
        &self,
        dai_amount: Uint256,
        timeout: Duration,
    ) -> Result<Uint256, TokenBridgeError> {
        let eth_web3 = self.eth_web3.clone();
        let own_address = self.own_address;
        let secret = self.eth_privatekey;

        // You basically just send it some dai to the bridge address and they show
        // up in the same address on the xdai side we have no idea when this has succeeded
        // since the events are not indexed
        let tx_hash = eth_web3
            .send_transaction(
                self.dai_erc20_contract_on_eth,
                encode_call(
                    "transfer(address,uint256)",
                    &[self.xdai_bridge_on_eth.into(), dai_amount.clone().into()],
                )
                .unwrap(),
                0u32.into(),
                own_address,
                secret,
                vec![SendTxOption::GasLimit(ERC20_GAS_LIMIT.into())],
            )
            .await?;

        eth_web3
            .wait_for_transaction(tx_hash, timeout, None)
            .await?;

        Ok(dai_amount)
    }

    /// Bridge `xdai_amount` xdai to dai, because xdai gas is strange we take in the
    /// gas price as an argument. This allows all the existing xdai gas optimizations performed
    /// in settings to handle the extra complexity. Remember on xdai you pay the full amount you
    /// promise, not the lowest in the block like ETH so any temptation to specify a high number
    /// and let it all get sorted out later is a bad idea.
    pub async fn xdai_to_dai_bridge(
        &self,
        xdai_amount: Uint256,
        xdai_gas_price: Uint256,
    ) -> Result<Uint256, TokenBridgeError> {
        let xdai_web3 = self.xdai_web3.clone();

        let own_address = self.own_address;
        let secret = self.eth_privatekey;

        // You basically just send it some coins to the contract address on the Xdai side
        // and it will show up on the Eth side in the same address
        Ok(xdai_web3
            .send_transaction(
                self.xdai_bridge_on_xdai,
                Vec::new(),
                xdai_amount,
                own_address,
                secret,
                vec![
                    SendTxOption::GasPrice(xdai_gas_price),
                    SendTxOption::NetworkId(100u64),
                ],
            )
            .await?)
    }

    pub async fn get_dai_balance(&self, address: Address) -> Result<Uint256, TokenBridgeError> {
        let web3 = self.eth_web3.clone();
        let dai_address = self.dai_erc20_contract_on_eth;
        Ok(web3.get_erc20_balance(dai_address, address).await?)
    }

    /// this uses the xdai helper contract on the xdai chain to retrieve the required
    /// info for relaying. This call occurs on the xdai side and gets info to submit
    /// to ethereum
    pub async fn get_relay_message_hash(
        &self,
        xdai_withdraw_txid: Uint256,
        amount_sent: Uint256,
    ) -> Result<HelperWithdrawInfo, TokenBridgeError> {
        info!("bridge getting message hashes");
        let own_address = self.own_address;
        // the hash that is then used to look up the signatures, this will always
        // succeed, whereas the signature lookup may need to wait for all sigs
        // to be submitted
        let msg_hash = self
            .xdai_web3
            .contract_call(
                self.helper_on_xdai,
                "getMessageHash(address,uint256,bytes32)",
                &[
                    own_address.into(),
                    amount_sent.into(),
                    Token::Bytes(xdai_withdraw_txid.to_bytes_be()),
                ],
                own_address,
                None,
            )
            .await?;
        // this may return 0x0 if the value is not yet ready, in this case
        // we fail with a not ready error
        let msg = self
            .xdai_web3
            .contract_call(
                self.helper_on_xdai,
                "getMessage(bytes32)",
                &[Token::Bytes(msg_hash.clone())],
                own_address,
                None,
            )
            .await?;
        if msg == vec![0] || msg.len() <= 64 {
            return Err(TokenBridgeError::HelperMessageNotReady);
        }
        let sigs_payload = self
            .xdai_web3
            .contract_call(
                self.helper_on_xdai,
                "getSignatures(bytes32)",
                &[Token::Bytes(msg_hash)],
                own_address,
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
        let msg_len = Uint256::from_bytes_be(&msg[32..64]);
        let sigs_len = Uint256::from_bytes_be(&sigs_payload[32..64]);
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

    /// input is the packed signatures output from get_relay_message_hash
    pub async fn submit_signatures_to_unlock_funds(
        &self,
        data: HelperWithdrawInfo,
        timeout: Duration,
    ) -> Result<Uint256, TokenBridgeError> {
        let own_address = self.own_address;
        let payload = get_payload_for_funds_unlock(&data);
        trace!(
            "bridge unlocking funds with! {} bytes payload! {}",
            data.msg.len(),
            bytes_to_hex_str(&payload),
        );

        let txid = self
            .eth_web3
            .send_transaction(
                self.xdai_bridge_on_eth,
                payload,
                0u32.into(),
                own_address,
                self.eth_privatekey,
                vec![SendTxOption::GasLimit(XDAI_FUNDS_UNLOCK_GAS.into())],
            )
            .await?;

        let _ = self
            .eth_web3
            .wait_for_transaction(txid.clone(), timeout, None)
            .await;
        Ok(txid)
    }
}

/// helper function for easier tests
fn get_payload_for_funds_unlock(data: &HelperWithdrawInfo) -> Vec<u8> {
    encode_call(
        "executeSignatures(bytes,bytes)",
        &[
            Token::UnboundedBytes(data.msg.clone()),
            Token::UnboundedBytes(data.sigs.clone()),
        ],
    )
    .unwrap()
}

pub const UNISWAP_ON_ETH_ADDRESS: &str = "0x2a1530C4C41db0B0b2bB646CB5Eb1A67b7158667";
pub const XDAI_BRIDGE_ON_ETH_ADDRESS: &str = "0x4aa42145Aa6Ebf72e164C9bBC74fbD3788045016";
pub const HELPER_ON_XDAI_ADDRESS: &str = "0x6A92e97A568f5F58590E8b1f56484e6268CdDC51";
pub const XDAI_BRIDGE_ON_XDAI_ADDRESS: &str = "0x7301CFA0e1756B71869E93d4e4Dca5c7d0eb0AA6";
pub const DAI_ERC20_CONTRACT_ON_ETH_ADDRESS: &str = "0x6B175474E89094C44Da98b954EedeAC495271d0F";

/// This function provides the default bridge addresses to be used by the token contract,
/// these are for the most part constants, but it is possible they may be updated or changed
/// if the xDai or Maker DAO or Uniswap team deploy new contracts
pub fn default_bridge_addresses() -> TokenBridgeAddresses {
    TokenBridgeAddresses {
        uniswap_on_eth_address: UNISWAP_ON_ETH_ADDRESS.parse().unwrap(),
        dai_erc20_contract_on_eth: DAI_ERC20_CONTRACT_ON_ETH_ADDRESS.parse().unwrap(),
        helper_on_xdai: HELPER_ON_XDAI_ADDRESS.parse().unwrap(),
        xdai_bridge_on_eth: XDAI_BRIDGE_ON_ETH_ADDRESS.parse().unwrap(),
        xdai_bridge_on_xdai: XDAI_BRIDGE_ON_XDAI_ADDRESS.parse().unwrap(),
        eth_full_node_url: "https://eth.althea.org".into(),
        xdai_full_node_url: "https://dai.althea.org".into(),
    }
}

/// This function calls the contract relayTokens(address) on the xdai blockchain by sending a function call
/// transaction. It sends the withdraw amount directly to the destination address specified by the withdrawal.
/// The transaction sends real money that the user requested to the destination address from user's wallet.
pub async fn encode_relaytokens(
    bridge: TokenBridge,
    dest_address: Address,
    timeout: Duration,
) -> Result<(), TokenBridgeError> {
    let payload = encode_call("relayTokens(address)", &[dest_address.into()]).unwrap();
    let options = Vec::new();

    let tx_hash = bridge
        .xdai_web3
        .send_transaction(
            bridge.xdai_bridge_on_xdai,
            payload,
            0u32.into(),
            bridge.own_address,
            bridge.eth_privatekey,
            options,
        )
        .await?;

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
    let start_block = (latest_block.clone() - total_blocks.into()) + (max_iter * iter).into();
    let end_block = if start_block.clone() + max_iter.into() > latest_block {
        latest_block
    } else {
        start_block.clone() + max_iter.into()
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
    search_addresses: Vec<Address>,
) -> Result<Vec<WithdrawEvent>, Web3Error> {
    /// Total number of blocks on the xdai blockchain we retrieve at once. If the blocks to check is greater than this we loop.
    const MAX_ITER: u64 = 10_000;
    let mut blocks_left: u64 = blocks_to_check;
    let mut vec_of_withdraws = Vec::new();

    //get latest xdai block
    let xdai_client = xdai_web3;
    let xdai_latest_block = xdai_client.eth_block_number().await?;
    let mut iter: u64 = 0;

    // iterate MAX_ITER blocks at a time
    loop {
        let (start, end) =
            compute_start_end(iter, xdai_latest_block.clone(), blocks_to_check, MAX_ITER);
        iter += 1;

        //We search for the phrase UserRequestForSignature(_receiver,valueToTransfer)
        let phrase_sig = "UserRequestForSignature(address,uint256)";

        let logs = xdai_client
            .check_for_events(start, Some(end), vec![contract], vec![phrase_sig])
            .await?;

        for log in logs.iter() {
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
    let ammount = Uint256::from_bytes_be(ammount_bytes);

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

    let tx_hash = Uint256::from_bytes_be(data);
    let response = client.eth_get_transaction_by_hash(tx_hash.clone()).await?;

    let tx_res = match response {
        Some(a) => a,
        None => {
            return Err(Web3Error::BadResponse(
                "No Transaction present for the given Hash".to_string(),
            ));
        }
    };

    let sender = tx_res.from;
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
            pk.to_public_key().unwrap(),
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
        Address::parse_and_validate(UNISWAP_ON_ETH_ADDRESS).expect("Invalid uniswap address");
        Address::parse_and_validate(XDAI_BRIDGE_ON_ETH_ADDRESS)
            .expect("Invalid xdai home bridge address");
        Address::parse_and_validate(HELPER_ON_XDAI_ADDRESS)
            .expect("Invalid xdai home helper address");
        Address::parse_and_validate(XDAI_BRIDGE_ON_XDAI_ADDRESS)
            .expect("Invalid xdai foreign bridge address");
        Address::parse_and_validate(DAI_ERC20_CONTRACT_ON_ETH_ADDRESS)
            .expect("Invalid foreign dai contract address");
    }

    #[test]
    #[ignore]
    fn test_is_approved() {
        let pk = PrivateKey::from_str(&format!(
            "FE1FC0A7A29503BAF72274A{}601D67309E8F3{}D22",
            "AA3ECDE6DB3E20", "29F7AB4BA52"
        ))
        .unwrap();

        let token_bridge = new_token_bridge();

        let unapproved_token_bridge = TokenBridge::new(
            default_bridge_addresses(),
            Address::parse_and_validate("0x79AE13432950bF5CDC3499f8d4Cf5963c3F0d42c").unwrap(),
            pk,
            "https://eth.altheamesh.com".into(),
            "https://dai.altheamesh.com".into(),
            TIMEOUT,
        );

        let runner = actix::System::new();

        runner.block_on(async move {
            let is_approved = token_bridge.check_if_uniswap_dai_approved().await.unwrap();
            assert!(is_approved);
            let is_approved = unapproved_token_bridge
                .check_if_uniswap_dai_approved()
                .await
                .unwrap();
            assert!(is_approved);
        });
    }

    #[test]
    #[ignore]
    fn test_funds_unlock_boilerplate() {
        let runner = actix::System::new();

        let bridge = new_token_bridge();

        runner.block_on(async move {
            let details = bridge
                .get_relay_message_hash(
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
            let details_1 = bridge.get_relay_message_hash(tx_id_1, amount_1.into());
            let details_2 = bridge.get_relay_message_hash(tx_id_2, amount_2.into());
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
    fn test_eth_to_dai_swap() {
        let runner = actix::System::new();

        let token_bridge = new_token_bridge();

        runner.block_on(async move {
            let one_cent_in_eth = token_bridge
                .dai_to_eth_price(eth_to_wei(0.01f64))
                .await
                .unwrap();
            token_bridge
                .eth_to_dai_swap(one_cent_in_eth, TIMEOUT)
                .await
                .unwrap();
        });
    }

    #[test]
    #[ignore]
    fn test_dai_to_eth_swap() {
        let runner = actix::System::new();
        let token_bridge = new_token_bridge();

        runner.block_on(async move {
            token_bridge
                .approve_uniswap_dai_transfers(TIMEOUT)
                .await
                .unwrap();
            token_bridge
                .dai_to_eth_swap(eth_to_wei(0.01f64), TIMEOUT)
                .await
                .unwrap();
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
    fn test_xdai_to_dai_bridge() {
        let runner = actix::System::new();

        let token_bridge = new_token_bridge();

        runner.block_on(async move {
            // All we can really do here is test that it doesn't throw. Check your balances in
            // 5-10 minutes to see if the money got transferred.
            token_bridge
                .xdai_to_dai_bridge(eth_to_wei(0.01f64), 1_000_000_000u64.into())
                .await
                .unwrap();
        });
    }

    #[test]
    fn test_check_withdrawals() {
        let runner = actix::System::new();

        let token_bridge = new_token_bridge();

        let blocks_to_check = 10000;
        runner.block_on(async move {
            // res is empty since we use a dummy address
            let res = check_withdrawals(
                blocks_to_check,
                token_bridge.xdai_bridge_on_xdai,
                token_bridge.xdai_web3,
                vec![token_bridge.own_address],
            )
            .await
            .unwrap();
            println!("{:?}", res);
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
        assert_eq!(ammount, Uint256::from_bytes_be(&ammount_bytes));

        assert_eq!(address.as_bytes(), address_bytes);
    }

    #[test]
    fn test_looping_logic() {
        let runner = actix::System::new();
        runner.block_on(async move {
            let max_iter = 10000;

            let mut blocks_to_search = 99999;
            let xdai_client = Web3::new("https://dai.althea.net", Duration::from_secs(5));
            let latest_block = xdai_client.eth_block_number().await.unwrap();

            let (start, end) =
                compute_start_end(0, latest_block.clone(), blocks_to_search, max_iter);
            assert_eq!(start, latest_block.clone() - blocks_to_search.into());
            assert_eq!(end, start + max_iter.into());

            blocks_to_search = 9999;
            let (start, end) =
                compute_start_end(0, latest_block.clone(), blocks_to_search, max_iter);
            assert_eq!(start, latest_block.clone() - blocks_to_search.into());
            assert_eq!(end, start + blocks_to_search.into());

            blocks_to_search = 10000;
            let (start, end) =
                compute_start_end(0, latest_block.clone(), blocks_to_search, max_iter);
            assert_eq!(start, latest_block.clone() - blocks_to_search.into());
            assert_eq!(end, start + blocks_to_search.into());

            blocks_to_search = 10001;
            let (start, end) =
                compute_start_end(0, latest_block.clone(), blocks_to_search, max_iter);
            assert_eq!(start, latest_block.clone() - blocks_to_search.into());
            assert_eq!(end, start + max_iter.into());

            let (start, end) =
                compute_start_end(1, latest_block.clone(), blocks_to_search, max_iter);
            assert_eq!(start, latest_block - 1u32.into());
            assert_eq!(end, start + 1u32.into());
        });
    }
}
