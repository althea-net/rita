#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

use clarity::abi::{encode_call, Token};
use clarity::{Address, PrivateKey};
use num::Bounded;
use num256::Uint256;
use std::{str::FromStr, time::Duration};
use web30::address_to_event;
use web30::client::Web3;
use web30::types::SendTxOption;

mod error;
pub use error::TokenBridgeError;

// the estimate gas call is wildly inaccurate so we need to hardcode the expected gas
// consumption of the following operations.
pub static UNISWAP_GAS_LIMIT: u128 = 80_000;
pub static ERC20_GAS_LIMIT: u128 = 40_000;
pub static ETH_TRANSACTION_GAS_LIMIT: u128 = 21_000;

fn default_xdai_home_helper_address() -> Address {
    default_bridge_addresses().xdai_home_helper_address
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct TokenBridgeAddresses {
    pub uniswap_address: Address,
    pub xdai_home_bridge_address: Address,
    #[serde(default = "default_xdai_home_helper_address")]
    pub xdai_home_helper_address: Address,
    pub xdai_foreign_bridge_address: Address,
    pub foreign_dai_contract_address: Address,
    pub eth_full_node_url: String,
    pub xdai_full_node_url: String,
}

/// Just a little helper struct to keep us from getting
/// the two arguments to executeSignatures() on the Eth
/// side of the xDai bridge mixed up.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct HelperWithdrawInfo {
    msg: Vec<u8>,
    sigs: Vec<u8>,
}

#[derive(Clone)]
pub struct TokenBridge {
    pub xdai_web3: Web3,
    pub eth_web3: Web3,
    pub uniswap_address: Address,
    /// This is the address of the xDai bridge on Eth
    pub xdai_foreign_bridge_address: Address,
    /// This is the address of the xDai bridge on xDai
    pub xdai_home_bridge_address: Address,
    /// This is the helper contract on xDai
    pub xdai_home_helper_address: Address,
    /// This is the address of the Dai token contract on Eth
    pub foreign_dai_contract_address: Address,
    pub own_address: Address,
    pub secret: PrivateKey,
}

impl TokenBridge {
    pub fn new(
        addresses: TokenBridgeAddresses,
        own_address: Address,
        secret: PrivateKey,
        eth_full_node_url: String,
        xdai_full_node_url: String,
        timeout: Duration,
    ) -> TokenBridge {
        TokenBridge {
            uniswap_address: addresses.uniswap_address,
            xdai_home_bridge_address: addresses.xdai_home_bridge_address,
            xdai_foreign_bridge_address: addresses.xdai_foreign_bridge_address,
            foreign_dai_contract_address: addresses.foreign_dai_contract_address,
            xdai_home_helper_address: addresses.xdai_home_helper_address,
            own_address,
            secret,
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
        let secret = self.secret;

        let tx_hash = web3
            .send_transaction(to, Vec::new(), amount, own_address, secret, options)
            .await?;

        web3.wait_for_transaction(tx_hash, timeout, None).await?;
        Ok(())
    }

    /// Price of ETH in Dai
    pub async fn eth_to_dai_price(&self, amount: Uint256) -> Result<Uint256, TokenBridgeError> {
        let web3 = self.eth_web3.clone();
        let uniswap_address = self.uniswap_address;
        let own_address = self.own_address;

        let tokens_bought = web3
            .contract_call(
                uniswap_address,
                "getEthToTokenInputPrice(uint256)",
                &[amount.into()],
                own_address,
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
        let uniswap_address = self.uniswap_address;
        let own_address = self.own_address;

        let eth_bought = web3
            .contract_call(
                uniswap_address,
                "getTokenToEthInputPrice(uint256)",
                &[amount.into()],
                own_address,
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
        let uniswap_address = self.uniswap_address;
        let own_address = self.own_address;
        let secret = self.secret;
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
        let mut topics = Vec::new();
        topics.push(topic);

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
        let uniswap_address = self.uniswap_address;
        let dai_address = self.foreign_dai_contract_address;
        let own_address = self.own_address;

        let allowance = web3
            .contract_call(
                dai_address,
                "allowance(address,address)",
                &[own_address.into(), uniswap_address.into()],
                own_address,
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
        let dai_address = self.foreign_dai_contract_address;
        let own_address = self.own_address;
        let uniswap_address = self.uniswap_address;
        let secret = self.secret;
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
                vec![SendTxOption::GasPriceMultiplier(2u32.into())],
            )
            .await?;

        let mut topics = Vec::new();
        topics.push(address_to_event(own_address));
        topics.push(address_to_event(uniswap_address));

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
        let uniswap_address = self.uniswap_address;
        let own_address = self.own_address;
        let secret = self.secret;
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
                    SendTxOption::GasPriceMultiplier(2u32.into()),
                ],
            )
            .await?;

        let topic = address_to_event(own_address);
        let mut topics = Vec::new();
        topics.push(topic);

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
        let foreign_dai_contract_address = self.foreign_dai_contract_address;
        let xdai_foreign_bridge_address = self.xdai_foreign_bridge_address;
        let own_address = self.own_address;
        let secret = self.secret;

        // You basically just send it some dai to the bridge address and they show
        // up in the same address on the xdai side we have no idea when this has succeeded
        // since the events are not indexed
        let tx_hash = eth_web3
            .send_transaction(
                foreign_dai_contract_address,
                encode_call(
                    "transfer(address,uint256)",
                    &[
                        xdai_foreign_bridge_address.into(),
                        dai_amount.clone().into(),
                    ],
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

        let xdai_home_bridge_address = self.xdai_home_bridge_address;

        let own_address = self.own_address;
        let secret = self.secret;

        // You basically just send it some coins to the contract address on the Xdai side
        // and it will show up on the Eth side in the same address
        Ok(xdai_web3
            .send_transaction(
                xdai_home_bridge_address,
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
        let dai_address = self.foreign_dai_contract_address;
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
        let own_address = self.own_address;
        // the hash that is then used to look up the signatures, this will always
        // succeed, whereas the signature lookup may need to wait for all sigs
        // to be submitted
        let msg_hash = self
            .xdai_web3
            .contract_call(
                self.xdai_home_helper_address,
                "getMessageHash(address,uint256,bytes32)",
                &[
                    own_address.into(),
                    amount_sent.into(),
                    Token::Bytes(xdai_withdraw_txid.to_bytes_be()),
                ],
                own_address,
            )
            .await?;
        // this may return 0x0 if the value is not yet ready, in this case
        // we fail with a not ready error
        let msg = self
            .xdai_web3
            .contract_call(
                self.xdai_home_helper_address,
                "getMessage(bytes32)",
                &[Token::Bytes(msg_hash.clone())],
                own_address,
            )
            .await?;
        if msg == vec![0] {
            return Err(TokenBridgeError::HelperMessageNotReady);
        }
        let sigs_payload = self
            .xdai_web3
            .contract_call(
                self.xdai_home_helper_address,
                "getSignatures(bytes32)",
                &[Token::Bytes(msg_hash)],
                own_address,
            )
            .await?;

        Ok(HelperWithdrawInfo {
            msg,
            sigs: sigs_payload,
        })
    }

    /// input is the packed signatures output from get_relay_message_hash
    pub async fn submit_signatures_to_unlock_funds(
        &self,
        data: HelperWithdrawInfo,
        timeout: Duration,
    ) -> Result<Uint256, TokenBridgeError> {
        let own_address = self.own_address;
        let payload = encode_call(
            "executeSignatures(bytes32,bytes32)",
            &[data.msg.into(), data.sigs.into()],
        )
        .unwrap();

        let txid = self
            .eth_web3
            .send_transaction(
                self.xdai_home_bridge_address,
                payload,
                0u32.into(),
                own_address,
                self.secret,
                Vec::new(),
            )
            .await?;

        let _ = self
            .eth_web3
            .wait_for_transaction(txid.clone(), timeout, None)
            .await;
        Ok(txid)
    }
}

pub const UNISWAP_ADDRESS: &str = "0x2a1530C4C41db0B0b2bB646CB5Eb1A67b7158667";
pub const XDAI_HOME_BRIDGE_ADDRESS: &str = "0x4aa42145Aa6Ebf72e164C9bBC74fbD3788045016";
// TODO this is a misnomer change to FOREIGN
pub const XDAI_HOME_HELPER_ADDRESS: &str = "0x6A92e97A568f5F58590E8b1f56484e6268CdDC51";
pub const XDAI_FOREIGN_BRIDGE_ADDRESS: &str = "0x7301CFA0e1756B71869E93d4e4Dca5c7d0eb0AA6";
pub const FOREIGN_DAI_CONTRACT_ADDRESS: &str = "0x6B175474E89094C44Da98b954EedeAC495271d0F";

/// This function provides the default bridge addresses to be used by the token contract,
/// these are for the most part constants, but it is possible they may be updated or changed
/// if the xDai or Maker DAO or Uniswap team deploy new contracts
pub fn default_bridge_addresses() -> TokenBridgeAddresses {
    TokenBridgeAddresses {
        uniswap_address: Address::from_str(UNISWAP_ADDRESS).unwrap(),
        xdai_home_bridge_address: Address::from_str(XDAI_HOME_BRIDGE_ADDRESS).unwrap(),
        xdai_home_helper_address: Address::from_str(XDAI_HOME_HELPER_ADDRESS).unwrap(),
        xdai_foreign_bridge_address: Address::from_str(XDAI_FOREIGN_BRIDGE_ADDRESS).unwrap(),
        foreign_dai_contract_address: Address::from_str(FOREIGN_DAI_CONTRACT_ADDRESS).unwrap(),
        eth_full_node_url: "https://eth.althea.org".into(),
        xdai_full_node_url: "https://dai.althea.org".into(),
    }
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
        Address::parse_and_validate(UNISWAP_ADDRESS).expect("Invalid uniswap address");
        Address::parse_and_validate(XDAI_HOME_BRIDGE_ADDRESS)
            .expect("Invalid xdai home bridge address");
        Address::parse_and_validate(XDAI_HOME_HELPER_ADDRESS)
            .expect("Invalid xdai home helper address");
        Address::parse_and_validate(XDAI_FOREIGN_BRIDGE_ADDRESS)
            .expect("Invalid xdai foreign bridge address");
        Address::parse_and_validate(FOREIGN_DAI_CONTRACT_ADDRESS)
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

        let system = actix::System::new("test");

        let token_bridge = new_token_bridge();

        let unapproved_token_bridge = TokenBridge::new(
            default_bridge_addresses(),
            Address::parse_and_validate("0x79AE13432950bF5CDC3499f8d4Cf5963c3F0d42c").unwrap(),
            pk,
            "https://eth.altheamesh.com".into(),
            "https://dai.altheamesh.com".into(),
            TIMEOUT,
        );

        actix::spawn(async move {
            let is_approved = token_bridge.check_if_uniswap_dai_approved().await.unwrap();
            assert!(is_approved);
            let is_approved = unapproved_token_bridge
                .check_if_uniswap_dai_approved()
                .await
                .unwrap();
            assert!(is_approved);
            actix::System::current().stop();
        });
        system.run().unwrap();
    }

    #[test]
    #[ignore]
    fn test_eth_to_dai_swap() {
        let system = actix::System::new("test");

        let token_bridge = new_token_bridge();

        actix::spawn(async move {
            let one_cent_in_eth = token_bridge
                .dai_to_eth_price(eth_to_wei(0.01f64))
                .await
                .unwrap();
            token_bridge
                .eth_to_dai_swap(one_cent_in_eth, TIMEOUT)
                .await
                .unwrap();
            actix::System::current().stop();
        });

        system.run().unwrap();
    }

    #[test]
    #[ignore]
    fn test_dai_to_eth_swap() {
        let system = actix::System::new("test");
        let token_bridge = new_token_bridge();

        actix::spawn(async move {
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

        system.run().unwrap();
    }

    #[test]
    #[ignore]
    fn test_dai_to_xdai_bridge() {
        let system = actix::System::new("test");

        let token_bridge = new_token_bridge();

        actix::spawn(async move {
            // All we can really do here is test that it doesn't throw. Check your balances in
            // 5-10 minutes to see if the money got transferred.
            token_bridge
                .dai_to_xdai_bridge(eth_to_wei(0.01f64), TIMEOUT)
                .await
                .unwrap();
            actix::System::current().stop();
        });

        system.run().unwrap();
    }

    #[test]
    #[ignore]
    fn test_xdai_to_dai_bridge() {
        let system = actix::System::new("test");

        let token_bridge = new_token_bridge();

        actix::spawn(async move {
            // All we can really do here is test that it doesn't throw. Check your balances in
            // 5-10 minutes to see if the money got transferred.
            token_bridge
                .xdai_to_dai_bridge(eth_to_wei(0.01f64), 1_000_000_000u64.into())
                .await
                .unwrap();
            actix::System::current().stop();
        });

        system.run().unwrap();
    }
}
