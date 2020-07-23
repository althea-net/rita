#[macro_use]
extern crate log;

use clarity::abi::encode_call;
use clarity::{Address, PrivateKey};
use failure::bail;
use failure::Error;
use num::Bounded;
use num256::Uint256;
use std::time::Duration;
use tokio::time::timeout as future_timeout;
use web30::client::Web3;
use web30::types::SendTxOption;

// the estimate gas call is wildly inaccurate so we need to hardcode the expected gas
// consumption of the following operations.
pub static UNISWAP_GAS_LIMIT: u128 = 80_000;
pub static ERC20_GAS_LIMIT: u128 = 40_000;
pub static ETH_TRANSACTION_GAS_LIMIT: u128 = 21_000;

#[derive(Clone)]
pub struct TokenBridge {
    pub xdai_web3: Web3,
    pub eth_web3: Web3,
    pub uniswap_address: Address,
    /// This is the address of the xDai bridge on Eth
    pub xdai_foreign_bridge_address: Address,
    /// This is the address of the xDai bridge on xDai
    pub xdai_home_bridge_address: Address,
    /// This is the address of the Dai token contract on Eth
    pub foreign_dai_contract_address: Address,
    pub own_address: Address,
    pub secret: PrivateKey,
}

impl TokenBridge {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        uniswap_address: Address,
        xdai_home_bridge_address: Address,
        xdai_foreign_bridge_address: Address,
        foreign_dai_contract_address: Address,
        own_address: Address,
        secret: PrivateKey,
        eth_full_node_url: String,
        xdai_full_node_url: String,
    ) -> TokenBridge {
        TokenBridge {
            uniswap_address,
            xdai_home_bridge_address,
            xdai_foreign_bridge_address,
            foreign_dai_contract_address,
            own_address,
            secret,
            xdai_web3: Web3::new(&xdai_full_node_url, Duration::from_secs(10)),
            eth_web3: Web3::new(&eth_full_node_url, Duration::from_secs(10)),
        }
    }

    /// This just sends some Eth. Returns the tx hash.
    pub async fn eth_transfer(
        &self,
        to: Address,
        amount: Uint256,
        timeout: u64,
    ) -> Result<(), Error> {
        let web3 = self.eth_web3.clone();
        let own_address = self.own_address;
        let secret = self.secret;

        let tx_hash = web3
            .send_transaction(to, Vec::new(), amount, own_address, secret, vec![])
            .await?;

        future_timeout(
            Duration::from_secs(timeout),
            web3.wait_for_transaction(tx_hash.into()),
        )
        .await??;
        Ok(())
    }

    /// Price of ETH in Dai
    pub async fn eth_to_dai_price(&self, amount: Uint256) -> Result<Uint256, Error> {
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
            None => bail!(
                "Malformed output from uniswap getEthToTokenInputPrice call {:?}",
                tokens_bought
            ),
        }))
    }

    /// Price of Dai in Eth
    pub async fn dai_to_eth_price(&self, amount: Uint256) -> Result<Uint256, Error> {
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
            None => bail!(
                "Malformed output from uniswap getTokenToEthInputPrice call {:?}",
                eth_bought
            ),
        }))
    }

    /// Sell `eth_amount` ETH for Dai.
    /// This function will error out if it takes longer than 'timeout' and the transaction is guaranteed not
    /// to be accepted on the blockchain after this time.
    pub async fn eth_to_dai_swap(
        &self,
        eth_amount: Uint256,
        timeout: u64,
    ) -> Result<Uint256, Error> {
        let uniswap_address = self.uniswap_address;
        let own_address = self.own_address;
        let secret = self.secret;
        let web3 = self.eth_web3.clone();

        let block = web3.eth_get_latest_block().await?;
        let expected_dai = self.eth_to_dai_price(eth_amount.clone()).await?;

        // Equivalent to `amount * (1 - 0.025)` without using decimals
        let expected_dai = (expected_dai / 40u64.into()) * 39u64.into();
        let deadline = block.timestamp + timeout.into();
        let payload = encode_call(
            "ethToTokenSwapInput(uint256,uint256)",
            &[expected_dai.into(), deadline.into()],
        );

        let _tx = future_timeout(
            Duration::from_secs(timeout),
            web3.send_transaction(
                uniswap_address,
                payload,
                eth_amount,
                own_address,
                secret,
                vec![SendTxOption::GasLimit(UNISWAP_GAS_LIMIT.into())],
            ),
        )
        .await??;

        let response = future_timeout(
            Duration::from_secs(timeout),
            web3.wait_for_event_alt(
                uniswap_address,
                "TokenPurchase(address,uint256,uint256)",
                Some(vec![own_address.into()]),
                None,
                None,
                |_| true,
            ),
        )
        .await??;

        let transfered_dai = Uint256::from_bytes_be(&response.topics[3]);
        Ok(transfered_dai)
    }

    /// Checks if the uniswap contract has been approved to spend dai from our account.
    pub async fn check_if_uniswap_dai_approved(&self) -> Result<bool, Error> {
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
            None => bail!(
                "Malformed output from uniswap getTokenToEthInputPrice call {:?}",
                allowance
            ),
        });

        // Check if the allowance remaining is greater than half of a Uint256- it's as good
        // a test as any.
        Ok(allowance > (Uint256::max_value() / 2u32.into()))
    }

    /// Sends transaction to the DAI contract to approve uniswap transactions, this future will not
    /// resolve until the process is either successful for the timeout finishes
    pub async fn approve_uniswap_dai_transfers(&self, timeout: Duration) -> Result<(), Error> {
        let dai_address = self.foreign_dai_contract_address;
        let own_address = self.own_address;
        let uniswap_address = self.uniswap_address;
        let secret = self.secret;
        let web3 = self.eth_web3.clone();

        let payload = encode_call(
            "approve(address,uint256)",
            &[uniswap_address.into(), Uint256::max_value().into()],
        );

        let _res = future_timeout(
            timeout,
            web3.send_transaction(
                dai_address,
                payload,
                0u32.into(),
                own_address,
                secret,
                vec![],
            ),
        )
        .await??;

        let _res = future_timeout(
            timeout,
            web3.wait_for_event_alt(
                dai_address,
                "Approval(address,address,uint256)",
                Some(vec![own_address.into()]),
                Some(vec![uniswap_address.into()]),
                None,
                |_| true,
            ),
        )
        .await??;

        Ok(())
    }

    /// Sell `dai_amount` Dai for ETH
    /// This function will error out if it takes longer than 'timeout' and the transaction is guaranteed not
    /// to be accepted on the blockchain after this time.
    pub async fn dai_to_eth_swap(
        &self,
        dai_amount: Uint256,
        timeout: u64,
    ) -> Result<Uint256, Error> {
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
        let deadline = block.timestamp + timeout.into();
        let payload = encode_call(
            "tokenToEthSwapInput(uint256,uint256,uint256)",
            &[dai_amount.into(), expected_eth.into(), deadline.into()],
        );

        let _tx = future_timeout(
            Duration::from_secs(timeout),
            web3.send_transaction(
                uniswap_address,
                payload,
                0u32.into(),
                own_address,
                secret,
                vec![SendTxOption::GasLimit(UNISWAP_GAS_LIMIT.into())],
            ),
        )
        .await?;

        let response = future_timeout(
            Duration::from_secs(timeout),
            web3.wait_for_event_alt(
                uniswap_address,
                "EthPurchase(address,uint256,uint256)",
                Some(vec![own_address.into()]),
                None,
                None,
                |_| true,
            ),
        )
        .await??;

        let transfered_eth = Uint256::from_bytes_be(&response.topics[3]);
        Ok(transfered_eth)
    }

    /// Bridge `dai_amount` dai to xdai
    pub async fn dai_to_xdai_bridge(
        &self,
        dai_amount: Uint256,
        timeout: u64,
    ) -> Result<Uint256, Error> {
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
                ),
                0u32.into(),
                own_address,
                secret,
                vec![SendTxOption::GasLimit(ERC20_GAS_LIMIT.into())],
            )
            .await?;

        future_timeout(
            Duration::from_secs(timeout),
            eth_web3.wait_for_transaction(tx_hash.into()),
        )
        .await??;

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
    ) -> Result<Uint256, Error> {
        let xdai_web3 = self.xdai_web3.clone();

        let xdai_home_bridge_address = self.xdai_home_bridge_address;

        let own_address = self.own_address;
        let secret = self.secret;

        // You basically just send it some coins to the contract address on the Xdai side
        // and it will show up on the Eth side in the same address
        xdai_web3
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
            .await
    }

    pub async fn get_dai_balance(&self, address: Address) -> Result<Uint256, Error> {
        let web3 = self.eth_web3.clone();
        let dai_address = self.foreign_dai_contract_address;
        let own_address = self.own_address;
        let balance = web3
            .contract_call(
                dai_address,
                "balanceOf(address)",
                &[address.into()],
                own_address,
            )
            .await?;

        Ok(Uint256::from_bytes_be(match balance.get(0..32) {
            Some(val) => val,
            None => bail!(
                "Got bad output for DAI balance from the full node {:?}",
                balance
            ),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn new_token_bridge() -> TokenBridge {
        let pk = PrivateKey::from_str(&format!(
            "FE1FC0A7A29503BAF72274A{}601D67309E8F3{}D22",
            "AA3ECDE6DB3E20", "29F7AB4BA52"
        ))
        .unwrap();

        TokenBridge::new(
            Address::from_str("0x09cabEC1eAd1c0Ba254B09efb3EE13841712bE14").unwrap(),
            Address::from_str("0x7301CFA0e1756B71869E93d4e4Dca5c7d0eb0AA6").unwrap(),
            Address::from_str("0x4aa42145Aa6Ebf72e164C9bBC74fbD3788045016").unwrap(),
            Address::from_str("0x89d24A6b4CcB1B6fAA2625fE562bDD9a23260359").unwrap(),
            Address::from_str("0x79AE13432950bF5CDC3499f8d4Cf5963c3F0d42c").unwrap(),
            pk,
            "https://eth.althea.org".into(),
            "https://dai.althea.org".into(),
        )
    }

    fn eth_to_wei(eth: f64) -> Uint256 {
        let wei = (eth * 1000000000000000000f64) as u64;
        wei.into()
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
            Address::from_str("0x09cabEC1eAd1c0Ba254B09efb3EE13841712bE14").unwrap(),
            Address::from_str("0x7301CFA0e1756B71869E93d4e4Dca5c7d0eb0AA6").unwrap(),
            Address::from_str("0x4aa42145Aa6Ebf72e164C9bBC74fbD3788045016").unwrap(),
            Address::from_str("0x89d24A6b4CcB1B6fAA2625fE562bDD9a23260359").unwrap(),
            Address::from_str("0x6d943740746934b2f5D9c9E6Cb1908758A42452f").unwrap(),
            pk,
            "https://eth.althea.org".into(),
            "https://dai.althea.org".into(),
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
                .eth_to_dai_swap(one_cent_in_eth, 600)
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
                .approve_uniswap_dai_transfers(Duration::from_secs(600))
                .await
                .unwrap();
            token_bridge
                .dai_to_eth_swap(eth_to_wei(0.01f64), 600)
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
                .dai_to_xdai_bridge(eth_to_wei(0.01f64), 600)
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
