use crate::token_bridge::*;
use clarity::utils::display_uint256_as_address;
use gnosis_bridge::check_relayed_message;
use gnosis_bridge::get_payload_for_funds_unlock;
use gnosis_bridge::HelperWithdrawInfo;
use gnosis_bridge::MINIMUM_DAI_TO_BRIDGE_IN;
use gnosis_bridge::{find_user_request_for_signatures_event, get_relay_message_hash};
use gnosis_bridge::{TokenBridge as TokenBridgeCore, TokenBridgeError};
use num256::Uint256;
use std::collections::HashSet;
use web30::jsonrpc::error::Web3Error;
use web30::types::TransactionRequest;

/// Transfers the target token present in eth address to the Gnosis chain.
/// This also assists in rescuing any stranded dai balance because of failures in depositing flow.
pub async fn transfer_token_to_gnosis(
    bridge: TokenBridgeCore,
    balance: Uint256,
    target_token: Address,
) -> Result<(), TokenBridgeError> {
    info!("Our balance for token {target_token} is {balance}, sending to Gnosis!");
    detailed_state_change(DetailedBridgeState::DaiToXdai { amount: balance });

    // Over the bridge into Gnosis
    bridge
        .bridge_to_gnosis(balance, target_token, ETH_TRANSFER_TIMEOUT)
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
                writer.clear_withdraw();
                set_bridge_state(writer.clone());
                return false;
            }
        };
        let amount = withdraw_details.amount;
        let address = withdraw_details.to;
        match withdraw(withdraw_details).await {
            Ok(_) => {
                info!("Initiating withdrawal of amount {amount} to address {address}");
            }
            Err(e) => error!("Received an error when initiating a withdrawal: {e}"),
        };

        //reset the withdraw lock
        writer.clear_withdraw();
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
            info!("Received error when trying to unlock funds: {e}");
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
    // process withdraws, if any are processed be done for this iteration
    if process_withdraws(&bridge).await {
        return;
    }

    // the gnosis bridge uses USDS now not dai
    let target_token = *web30::amm::USDS_CONTRACT_ADDRESS;

    swap_stablecoins_to_target_token(&bridge.eth_web3, &bridge.eth_privatekey, target_token).await;

    let target_token_balance = match bridge
        .eth_web3
        .get_erc20_balance(target_token, bridge.own_address, vec![])
        .await
    {
        Ok(a) => a,
        Err(e) => {
            error!("Error when fetching balance for token {target_token}: {e}");
            return;
        }
    };

    info!("Our target token balance {target_token_balance} minimum target token to send {MINIMUM_DAI_TO_BRIDGE_IN}");
    if target_token_balance >= MINIMUM_DAI_TO_BRIDGE_IN.into() {
        // transfer target token exchanged from eth during previous iterations
        let res =
            transfer_token_to_gnosis(bridge.clone(), target_token_balance, target_token).await;
        info!("Target token send to xdai returned with {res:?}");
        return;
    }

    detailed_state_change(DetailedBridgeState::NoOp);
}

/// This function is called inside the bridge loop. It retrieves the 'n' most recent blocks
/// (where 'n' is the const 'BLOCKS' that is currently set to 720, which represents 1 hour of blocks on xdai chain) that
/// have withdraw events related to our address. It then simulates these events and submits
/// the signatures needed to unlock the funds.
pub async fn simulated_withdrawal_on_eth(bridge: &TokenBridgeCore) -> Result<(), TokenBridgeError> {
    let client = bridge.xdai_web3.clone();
    let mut h = HashSet::new();
    h.insert(bridge.own_address);

    info!("Checking withdraw events on xdai chain for the past {EVENT_SEARCH_BLOCKS} blocks");
    let current_block = client.eth_block_number().await?;
    let event_blocks: Uint256 = EVENT_SEARCH_BLOCKS.into();
    let start_block = if current_block > event_blocks {
        current_block - event_blocks
    } else {
        0u8.into()
    };
    let events = find_user_request_for_signatures_event(
        start_block,
        current_block,
        bridge.xdai_bridge_on_xdai,
        bridge.xdai_web3.clone(),
        h,
    )
    .await?;

    info!(
        "Found {} withdraw events related to us in the past {EVENT_SEARCH_BLOCKS} blocks {:#?}",
        events.len(),
        events
    );
    for event in events.iter() {
        let withdraw_info = get_relay_message_hash(
            bridge.own_address,
            bridge.xdai_web3.clone(),
            bridge.helper_on_xdai,
            event.receiver,
            event.nonce,
            event.token_address,
            event.amount,
        )
        .await?;
        info!(
            "Got withdraw info for nonce {}, amount {}, receiver {}",
            display_uint256_as_address(event.nonce),
            event.amount,
            event.receiver
        );

        // check if the event has already unlocked the funds or not
        let res = match check_relayed_message(
            event.nonce,
            bridge.eth_web3.clone(),
            bridge.own_address,
            bridge.xdai_bridge_on_eth,
        )
        .await
        {
            Ok(a) => a,
            Err(e) => {
                error!(
                    "Received Error when checking for signature 'relayedMessages': {e}, skipping"
                );
                continue;
            }
        };

        if res {
            continue;
        } else {
            // Log the unlock tx hash on success - this is the on-chain proof a withdraw
            // landed and is invaluable for ops debugging. The `?` already propagates errors.
            let tx_hash = bridge
                .submit_signatures_to_unlock_funds(withdraw_info, SIGNATURES_TIMEOUT)
                .await?;
            info!(
                "Submitted signatures to unlock funds on ETH for receiver {}, amount {}, tx {tx_hash}",
                event.receiver, event.amount
            );
            detailed_state_change(DetailedBridgeState::DaiToDest {
                amount_of_dai: event.amount,
                dest_address: event.receiver,
            });
        }
    }

    Ok(())
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
            Vec::new(),
            None,
        )
        .await
}
