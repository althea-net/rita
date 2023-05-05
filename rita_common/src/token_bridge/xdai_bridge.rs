use crate::token_bridge::*;
use auto_bridge::check_relayed_message;
use auto_bridge::get_payload_for_funds_unlock;
use auto_bridge::get_usdt_address;
use auto_bridge::HelperWithdrawInfo;
use auto_bridge::MINIMUM_DAI_TO_SEND;
use auto_bridge::MINIMUM_USDC_TO_CONVERT;
use auto_bridge::{check_withdrawals, get_relay_message_hash};
use auto_bridge::{TokenBridge as TokenBridgeCore, TokenBridgeError};
use clarity::utils::display_uint256_as_address;
use futures::future::join3;
use num256::Uint256;
use rand::{thread_rng, Rng};
use std::collections::HashSet;
use web30::amm::DAI_CONTRACT_ADDRESS;
use web30::amm::USDC_CONTRACT_ADDRESS;
use web30::jsonrpc::error::Web3Error;
use web30::types::TransactionRequest;

/// Transfers dai present in eth address from previous xdai_bridge iterations to the xdai chain.
/// This also assists in rescuing any stranded dai balance because of failures in depositing flow.
pub async fn transfer_dai(
    bridge: TokenBridgeCore,
    dai_balance: Uint256,
) -> Result<(), TokenBridgeError> {
    info!("Our DAI balance is {}, sending to xDai!", dai_balance);
    detailed_state_change(DetailedBridgeState::DaiToXdai {
        amount: dai_balance,
    });

    // Remove up to U16_MAX wei from this transaction, this is well under a cent.
    // what this does is randomly change the tx hash and help prevent 'stuck' transactions
    // thanks to anti-spam mechanisms. Payments get this 'for free' thanks to changing debts
    // numbers. And other tx's here do thanks to changing exchange rates and other external factors
    // this is the only transaction that will be exactly the same for a very long period.
    let mut rng = thread_rng();
    let some_wei: u16 = rng.gen();
    let amount = dai_balance - Uint256::from(some_wei);

    // Over the bridge into xDai
    bridge
        .dai_to_xdai_bridge(amount, ETH_TRANSFER_TIMEOUT)
        .await?;
    Ok(())
}

/// Processes the withdrawing state, returns true if any action was taken
pub async fn process_withdraws(bridge: &TokenBridgeCore) -> bool {
    let mut writer = get_bridge_state();
    if writer.withdraw_in_progress {
        let withdraw_details = match &writer.withdraw_details {
            Some(a) => a.clone(),
            None => {
                error!("No withdraw information present");
                writer.withdraw_in_progress = false;
                set_bridge_state(writer.clone());
                return false;
            }
        };
        let amount = withdraw_details.amount;
        let address = withdraw_details.to;
        match withdraw(withdraw_details).await {
            Ok(_) => {
                info!(
                    "Initiating withdrawal of amount {} to address {}",
                    amount, address
                );
            }
            Err(e) => error!("Received an error when initiating a withdrawal: {}", e),
        };

        //reset the withdraw lock
        writer.withdraw_in_progress = false;
        writer.withdraw_details = None;
        set_bridge_state(writer);
        return true;
    }
    // check for withdrawal events and execute them, this always runs so that it catches
    // any waiting withdraw events for this router
    match simulated_withdrawal_on_eth(bridge).await {
        Ok(()) => {
            info!(
                "Checking for withdraw events related to us (address: {})",
                bridge.own_address
            );
        }
        Err(e) => {
            info!("Received error when trying to unlock funds: {}", e);
        }
    }
    false
}

/// The logic for the Eth -> Xdai bridge operation that runs every tick that also handles withdrawals.
/// We start by checking the lazy static lock to check for any new withdrawals that were requested.
/// If we find one, we initiate this withdrawal and reset the lock. Next we loop through events
/// on the xdai blockchain to find any withdrawals related to us, and if so we unlock these funds.
/// We then rescue any stuck dai and send any eth that we have over to the xdai chain.
pub async fn xdai_bridge(bridge: TokenBridgeCore) {
    let (our_dai_balance, our_usdc_balance, our_usdt_balance) = join3(
        bridge.get_dai_balance(),
        bridge.get_usdc_balance(),
        bridge.get_usdt_balance(),
    )
    .await;
    let our_dai_balance = match our_dai_balance {
        Ok(val) => val,
        Err(e) => {
            warn!("Failed to get our dai balance with {}", e);
            return;
        }
    };
    let our_usdc_balance = match our_usdc_balance {
        Ok(val) => val,
        Err(e) => {
            warn!("Failed to get our usdc balance with {}", e);
            return;
        }
    };
    let our_usdt_balance = match our_usdt_balance {
        Ok(val) => val,
        Err(e) => {
            warn!("Failed to get our usdt balance with {}", e);
            return;
        }
    };

    // process withdraws, if any are processed be done for this iteration
    if process_withdraws(&bridge).await {
        return;
    }

    info!(
        "Our USDC balance is {} Our USDT balance is {} Minimum to convert is {}",
        our_usdc_balance, our_usdt_balance, MINIMUM_USDC_TO_CONVERT
    );
    let mut token_to_swap = None;
    let mut token_amount = None;
    if our_usdc_balance >= MINIMUM_USDC_TO_CONVERT.into() {
        token_to_swap = Some(*USDC_CONTRACT_ADDRESS);
        token_amount = Some(our_usdc_balance);
    } else if our_usdt_balance >= MINIMUM_USDC_TO_CONVERT.into() {
        token_to_swap = Some(get_usdt_address());
        token_amount = Some(our_usdt_balance);
    }

    if let (Some(token), Some(token_amount)) = (token_to_swap, token_amount) {
        let res = bridge
            .eth_web3
            .swap_uniswap_v3(
                bridge.eth_privatekey,
                token,
                *DAI_CONTRACT_ADDRESS,
                Some(100u16.into()),
                token_amount,
                None,
                Some(get_min_amount_out(token_amount)),
                None,
                None,
                None,
                Some(ETH_TRANSFER_TIMEOUT),
            )
            .await;
        info!(
            "Swap from {} to dai on uniswap returned with {:?}",
            token, res
        );
        detailed_state_change(DetailedBridgeState::Swap);
    }

    info!(
        "Our dai balance {} minimum dai to send {}",
        our_dai_balance, MINIMUM_DAI_TO_SEND
    );
    if our_dai_balance >= MINIMUM_DAI_TO_SEND.into() {
        // transfer dai exchanged from eth during previous iterations
        let res = transfer_dai(bridge.clone(), our_dai_balance).await;
        info!("DAI send to xdai returned with {:?}", res);
        return;
    }

    detailed_state_change(DetailedBridgeState::NoOp);
}

/// This function is called inside the bridge loop. It retrieves the 'n' most recent blocks
/// (where 'n' is the const 'BLOCKS' that is currently set to 40,032, which represents 1 week of blocks on xdai chain) that
/// have withdraw events related to our address. It then simulates these events and submits
/// the signatures needed to unlock the funds.
pub async fn simulated_withdrawal_on_eth(bridge: &TokenBridgeCore) -> Result<(), TokenBridgeError> {
    let client = bridge.xdai_web3.clone();
    let mut h = HashSet::new();
    h.insert(bridge.own_address);

    let events = check_withdrawals(BLOCKS, bridge.xdai_bridge_on_xdai, client, h).await?;

    for event in events.iter() {
        let txid = event.txid;
        let amount = event.amount;

        let withdraw_info = get_relay_message_hash(
            bridge.own_address,
            bridge.xdai_web3.clone(),
            bridge.helper_on_xdai,
            event.receiver,
            txid,
            amount,
        )
        .await?;

        // check if the event has already unlocked the funds or not
        let res = match check_relayed_message(
            event.txid,
            bridge.eth_web3.clone(),
            bridge.own_address,
            bridge.xdai_bridge_on_eth,
        )
        .await
        {
            Ok(a) => a,
            Err(e) => {
                error!(
                    "Received Error when checking for signature 'relayedMessages': {}, skipping",
                    e
                );
                continue;
            }
        };

        if res {
            trace!(
                "Transaction with Id: {} has already been unlocked, skipping",
                display_uint256_as_address(txid)
            );
            continue;
        } else {
            //unlock this transaction
            trace!(
                "Tx Hash is {} with the amount of {} for a withdraw event",
                display_uint256_as_address(txid),
                amount
            );
            let _res = bridge
                .submit_signatures_to_unlock_funds(withdraw_info, SIGNATURES_TIMEOUT)
                .await?;
            detailed_state_change(DetailedBridgeState::DaiToDest {
                amount_of_dai: amount,
                dest_address: event.receiver,
            });
        }
    }

    Ok(())
}

/// In order to avoid Ethereum dex sandwitch attacks we need to specify a minimum amount out of DAI
/// since both USDT and USDC are 6 decimal tokens this function simply does the decimal conversion to ensure
/// we get 99% of the vlaue of our USDC or UDST out in DAI. If either token is depegged this will result in problems
fn get_min_amount_out(mut input: Uint256) -> Uint256 {
    // multiply by 1*10^12 to go from 1*10^6 value to -> 1*10^18 value
    input *= 1_000_000_000_000u128.into();
    // remove 2.5% off the top, so we need at least 95% of the face value of the USDC or USDT
    input = input - input / 40u8.into();
    input
}

/// This function simulates the withdraw event given to it. Based on this information, we can decide if we want to
/// process this transaction by using real money. This allows us to unlock the funds on the 'eth' side. This function is currently not in use
/// and we use check_relayed_message() instead for simplicity.
#[allow(dead_code)]
pub async fn simulate_signature_submission(
    bridge: &TokenBridgeCore,
    data: &HelperWithdrawInfo,
) -> Result<Vec<u8>, Web3Error> {
    let payload = get_payload_for_funds_unlock(data);
    bridge
        .eth_web3
        .simulate_transaction(
            TransactionRequest::quick_tx(bridge.own_address, bridge.xdai_bridge_on_eth, payload),
            None,
        )
        .await
}
