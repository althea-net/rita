use crate::token_bridge::*;
use gnosis_bridge::encode_relaytokens;
use gnosis_bridge::TokenBridge as TokenBridgeCore;
use gnosis_bridge::TokenBridgeError;
use gnosis_bridge::MINIMUM_DAI_TO_BRIDGE_OUT;
use gravity_bridge::GravityBridge;
use gravity_bridge::BASIS_POINT_DIVISOR;
use num256::Uint256;
use num_traits::CheckedAdd;

/// The fraction of the withdraw amount to use as the bridge fee (relayer tip)
/// for MsgSendToEth. 1% incentivizes relayers to batch the transaction.
const BRIDGE_FEE_FRACTION: u128 = 100; // 1/100 = 1%

/// Minimum payout the user must actually receive after fees, denominated in the
/// token's smallest unit. Below this we skip the MsgSendToEth rather than
/// silently sending a near-zero amount where fees ate the balance.
const MIN_SEND_AMOUNT: u128 = 1_000;

/// Compute the bridge fee (relayer tip) as a fraction of the total amount.
fn compute_bridge_fee(amount: Uint256) -> Uint256 {
    amount / BRIDGE_FEE_FRACTION.into()
}

/// Compute the chain fee using the governance-controlled min_chain_fee_basis_points.
/// Basis points are 1/10000ths, so e.g. 200 basis points = 2%.
/// `basis_points` is clamped to BASIS_POINT_DIVISOR so a misconfigured
/// governance parameter cannot push the fee above 100% of the amount.
fn compute_chain_fee(amount: Uint256, basis_points: u64) -> Uint256 {
    let clamped = basis_points.min(BASIS_POINT_DIVISOR);
    if clamped != basis_points {
        warn!(
            "min_chain_fee_basis_points ({basis_points}) exceeds {BASIS_POINT_DIVISOR}, clamping"
        );
    }
    amount * Uint256::from(clamped) / Uint256::from(BASIS_POINT_DIVISOR)
}

/// Sum pending sends amounts
fn sum_pending(pending: &[(Uint256, Uint256)]) -> Uint256 {
    pending
        .iter()
        .fold(0u8.into(), |acc: Uint256, (amount, _fee)| acc + *amount)
}

/// Main tick function for the Althea L1 bridge conveyor belt.
///
/// This parallels `xdai_bridge()` and implements the conveyor belt for AltheaL1.
pub async fn althea_bridge(gravity_bridge: GravityBridge, gnosis_bridge: TokenBridgeCore) {
    if let Err(e) = gnosis_migration_step(&gnosis_bridge).await {
        warn!("Gnosis migration step failed, continuing: {e}");
    }

    // Derive bridge addresses from target denom on Althea L1, this lets us provide only the ibc/hash of
    // usdc or whatever token in the config and then the address of that token on ETH and Althea L1 evm is derived.
    // This won't work if you chose a stablecoin that is native to Althea L1 and doesn't have an ERC20 wrapper on Gravity
    // but in that case you also wouldn't need to bridge it in would you?
    let addresses = match gravity_bridge.derive_bridge_addresses().await {
        Ok(addr) => addr,
        Err(e) => {
            warn!("Failed to derive bridge addresses, skipping this tick: {e}");
            return;
        }
    };

    // Fetch gravity module params once per tick. Returns both the live Gravity
    // contract address on ETH (used for bridge-in) and the min chain fee basis
    // points (used for bridge-out). A governance migration of the contract is
    // picked up here without a router redeploy.
    let gravity_params = match gravity_bridge.get_gravity_params().await {
        Ok(p) => p,
        Err(e) => {
            warn!("Failed to fetch gravity params, skipping this tick: {e}");
            return;
        }
    };

    // process withdraws, any time we have tokens on Gravity we pretty much
    // want to finish bridging out. This implemetnation does not self relay tokens
    // to Ethereum from Gravity TODO how do we handle a long withdraw delay on batch relaying?
    if process_althea_withdraws(&gravity_bridge, &addresses, &gravity_params).await {
        return; // Don't do bridge-in on same tick as bridge-out
    }

    // swaps any one of a list of common tokens into the target token on Uniswap v3 because these tokens are so
    // common we only a single hop router and don't search for a better price across multiple hops.
    swap_stablecoins_to_target_token(
        &gravity_bridge.eth_web3,
        &gravity_bridge.cosmos_key.as_ethereum_key(),
        addresses.eth_mainnet_erc20,
    )
    .await;

    // Send target token → Gravity Bridge contract on ETH if we have any
    // if we have another token we'll swap it later, then come back here in the next loop round
    let target_token_balance = match gravity_bridge
        .get_erc20_balance_on_eth(addresses.eth_mainnet_erc20)
        .await
    {
        Ok(b) => b,
        Err(e) => {
            warn!("Failed to get target token balance: {e}");
            return;
        }
    };
    // gravity enforces no minimum on deposits so we just check if the value is nonzero
    if target_token_balance > 0u8.into() {
        info!("Our target token balance is {target_token_balance}, sending to Gravity Bridge");
        detailed_state_change(DetailedBridgeState::TokenToGravity {
            amount: TokenAmount::untyped(target_token_balance),
        });
        match gravity_bridge
            .transfer_to_gravity(
                gravity_params.bridge_ethereum_address,
                addresses.eth_mainnet_erc20,
                target_token_balance,
                ETH_TRANSFER_TIMEOUT,
            )
            .await
        {
            Ok(_) => info!("Target token sent to Gravity Bridge successfully"),
            Err(e) => warn!("Failed to send target token to Gravity Bridge: {e}"),
        }
        return;
    }

    // Unwrap any ERC20-wrapped tokens on Althea L1 EVM
    // Tokens arrive here automatically via Gravity auto-forwarding after sendToCosmos
    let wrapped_balance = match gravity_bridge
        .get_althea_evm_erc20_balance(addresses.althea_evm_erc20)
        .await
    {
        Ok(b) => b,
        Err(e) => {
            warn!("Failed to get wrapped ERC20 balance on Althea: {e}");
            return;
        }
    };
    if wrapped_balance > 0u8.into() {
        info!("Wrapped ERC20 balance on Althea L1: {wrapped_balance}, unwrapping");
        detailed_state_change(DetailedBridgeState::UnwrappingErc20 {
            amount: TokenAmount::untyped(wrapped_balance),
        });
        match gravity_bridge
            .unwrap_erc20_on_althea(addresses.althea_evm_erc20, wrapped_balance)
            .await
        {
            Ok(_) => info!("ERC20 unwrap on Althea L1 successful"),
            Err(e) => warn!("Failed to unwrap ERC20 on Althea L1: {e}"),
        }
        return;
    }

    detailed_state_change(DetailedBridgeState::NoOp);
}

/// Bridge-out (withdrawal) conveyor belt for Althea L1.
///
/// Bridge-out crosses two chains (Althea → Gravity → ETH) and each hop is async.
/// Rather than doing both steps in a single tick (which would lose funds on reboot
/// between IBC send and MsgSendToEth), each tick polls and advances whichever
/// stage currently holds funds — the same conveyor belt approach used for bridge-in.
///
/// Returns true if any bridge-out action was taken (caller should skip bridge-in).
pub async fn process_althea_withdraws(
    bridge: &GravityBridge,
    addresses: &gravity_bridge::DerivedAddresses,
    gravity_params: &gravity_bridge::GravityParams,
) -> bool {
    // --- Stage 3: Check for pending SendToEth on Gravity already submitted ---
    // If we already submitted MsgSendToEth, just report status and wait for
    // a relayer to batch it. Nothing for us to do.
    match bridge.get_pending_sends().await {
        Ok(pending) => {
            if !pending.is_empty() {
                let total = sum_pending(&pending);
                info!(
                    "Found {} pending SendToEth transactions, total amount: {total}",
                    pending.len()
                );
                detailed_state_change(DetailedBridgeState::GravityToEthPending {
                    amount: TokenAmount::untyped(total),
                });
                return true;
            }
        }
        Err(e) => {
            warn!("Failed to query pending sends on Gravity: {e}");
            // Continue to check other stages
        }
    }

    // --- Stage 2: Check for balance on Gravity chain (IBC arrived) ---
    // Tokens landed on Gravity via IBC from a previous tick. Submit MsgSendToEth
    // with chain_fee + bridge_fee denominated in the bridged token (no GRAV needed).
    // The min chain fee basis points come from the params we already fetched at the
    // start of the tick.
    let min_chain_fee_bp = gravity_params.min_chain_fee_basis_points;
    info!("Gravity min_chain_fee_basis_points: {min_chain_fee_bp}");

    match bridge.get_gravity_balance(&addresses.gravity_denom).await {
        Ok(gravity_balance) => {
            if gravity_balance > 0u8.into() {
                // Get withdraw details to determine destination address
                let mut state = get_bridge_state();
                let eth_dest = match &state.withdraw_details {
                    Some(w) => w.to,
                    None => {
                        warn!("Balance on Gravity but no withdraw details - using router address as fallback");
                        bridge.get_own_eth_address()
                    }
                };

                let bridge_fee = compute_bridge_fee(gravity_balance);
                let chain_fee = compute_chain_fee(gravity_balance, min_chain_fee_bp);
                // Checked addition guards against overflow if a bug or extreme input pushes
                // either fee close to Uint256::MAX. Saturating to MAX would also work but
                // explicit failure surfaces the bug instead of producing a silent zero send.
                let total_fee = match bridge_fee.checked_add(&chain_fee) {
                    Some(s) => s,
                    None => {
                        warn!(
                            "Fee overflow computing bridge_fee ({bridge_fee}) + chain_fee ({chain_fee}); skipping bridge-out"
                        );
                        return true;
                    }
                };
                let min_send: Uint256 = MIN_SEND_AMOUNT.into();
                // Require fees + minimum payout to fit in balance, so we never submit
                // a near-zero send where fees ate ~100% of what the user gets.
                let required = match total_fee.checked_add(&min_send) {
                    Some(r) => r,
                    None => {
                        warn!("Required-amount overflow; skipping bridge-out");
                        return true;
                    }
                };
                if required > gravity_balance {
                    warn!(
                        "Balance on Gravity ({gravity_balance}) too small to cover bridge_fee ({bridge_fee}) + chain_fee ({chain_fee}) + min payout ({MIN_SEND_AMOUNT}), skipping bridge-out"
                    );
                    return true;
                }
                let send_amount = gravity_balance - total_fee;
                info!(
                    "Balance on Gravity chain: {gravity_balance}, submitting MsgSendToEth to {eth_dest} (amount: {send_amount}, bridge_fee: {bridge_fee}, chain_fee: {chain_fee})"
                );
                detailed_state_change(DetailedBridgeState::WaitingOnGravity {
                    amount: TokenAmount::untyped(gravity_balance),
                });
                match bridge
                    .send_to_eth(
                        &addresses.gravity_denom,
                        send_amount,
                        bridge_fee,
                        chain_fee,
                        eth_dest,
                    )
                    .await
                {
                    Ok(_) => {
                        detailed_state_change(DetailedBridgeState::GravityToEthPending {
                            amount: TokenAmount::untyped(send_amount),
                        });
                        // Clear withdraw details now that MsgSendToEth is submitted
                        state.clear_withdraw();
                        set_bridge_state(state);
                    }
                    Err(e) => {
                        warn!("Failed to submit MsgSendToEth: {e}");
                    }
                }
                return true;
            }
        }
        Err(e) => {
            warn!("Failed to query balance on Gravity chain: {e}");
        }
    }

    // --- Stage 1: New withdraw request → IBC transfer Althea → Gravity ---
    let mut state = get_bridge_state();
    if !state.withdraw_in_progress {
        return false;
    }

    let withdraw = match &state.withdraw_details {
        Some(w) => w.clone(),
        None => {
            state.clear_withdraw();
            set_bridge_state(state);
            return false;
        }
    };

    // Get the cosmos balance to verify we have enough to withdraw
    let cosmos_balance = match bridge
        .get_cosmos_balance_on_althea(&addresses.gravity_denom)
        .await
    {
        Ok(b) => b,
        Err(e) => {
            warn!(
                "Failed to get cosmos balance on Althea for withdraw (will retry next tick): {e}"
            );
            // Don't clear state - this is likely a transient RPC error
            return true;
        }
    };

    if cosmos_balance < withdraw.amount {
        warn!(
            "Insufficient cosmos balance {} for withdrawal of {} - canceling withdraw request",
            cosmos_balance, withdraw.amount
        );
        // This is a permanent failure - user needs to add funds
        state.clear_withdraw();
        set_bridge_state(state);
        return false;
    }

    // IBC transfer from Althea L1 to Gravity chain
    // On next tick, Stage 2 will pick up the balance on Gravity and submit MsgSendToEth
    info!(
        "Initiating IBC transfer of {} from Althea L1 to Gravity chain",
        withdraw.amount
    );
    detailed_state_change(DetailedBridgeState::AltheaToGravityIbc {
        amount: TokenAmount::untyped(withdraw.amount),
    });

    match bridge
        .ibc_transfer_to_gravity(&addresses.gravity_denom, withdraw.amount)
        .await
    {
        Ok(_) => {
            info!("IBC transfer to Gravity initiated successfully");
            // Keep withdraw_details so Stage 2 can use the destination address
            // It will be cleared after successful MsgSendToEth submission
        }
        Err(e) => {
            warn!("Failed IBC transfer to Gravity (will retry next tick): {e}");
            // Don't clear state - retry on next tick
            // This handles transient network/RPC failures gracefully
        }
    }
    true
}

/// Gnosis migration step — perpetually recovers funds from Gnosis chain.
///
/// This runs at the start of every `althea_bridge()` tick as a prepend.
/// It drains legacy xDai (now USDS) funds from Gnosis → ETH, where the normal Gravity bridge-in
/// conveyor belt picks them up. Errors are returned (not panicked) so the caller
/// can log and continue.
async fn gnosis_migration_step(gnosis_bridge: &TokenBridgeCore) -> Result<(), TokenBridgeError> {
    // Check native xDai balance on Gnosis chain
    let xdai_balance = gnosis_bridge
        .xdai_web3
        .eth_get_balance(gnosis_bridge.own_address)
        .await?;
    // how much we need to reserve for the transfer
    const GAS_FOR_TRANSFER: u128 = 300_000;
    // Bump 25% over the live oracle price. The fetched price is a snapshot; by the time
    // the tx hits a block the network gas price may have risen, leaving an under-priced
    // tx pending forever (and blocking subsequent ticks because xDai balance > minimum
    // is still true). Reserving the bumped price for the gas cost subtraction also
    // prevents shipping funds we can't actually pay to land on chain.
    let live_gas_price = gnosis_bridge.xdai_web3.eth_gas_price().await?;
    let gas_price = live_gas_price * Uint256::from(125u32) / Uint256::from(100u32);
    let gas_cost = Uint256::from(GAS_FOR_TRANSFER) * gas_price;

    if xdai_balance > MINIMUM_DAI_TO_BRIDGE_OUT.into() {
        if xdai_balance <= gas_cost {
            warn!(
                "Gnosis migration: skipping relay, xDai balance {} does not cover estimated gas cost {}",
                xdai_balance, gas_cost
            );
        } else {
            let bridge_amount = xdai_balance - gas_cost;
            if bridge_amount >= MINIMUM_DAI_TO_BRIDGE_OUT.into() {
                info!("Gnosis migration: found {xdai_balance} xDai, sending to ETH for Gravity bridge-in");
                detailed_state_change(DetailedBridgeState::GnosisMigration {
                    amount: xdai_balance,
                });
                let result = encode_relaytokens(
                    gnosis_bridge.clone(),
                    gnosis_bridge.own_address, // send to self on ETH
                    bridge_amount,             // leave some xDai for gas
                    ETH_TRANSFER_TIMEOUT,
                    Some(gas_price),
                    Some(Uint256::from(GAS_FOR_TRANSFER)),
                )
                .await;

                result?;
            } else {
                warn!(
                    "Gnosis migration: skipping relay, balance {} minus gas cost {} leaves {} which is below minimum bridge amount {}",
                    xdai_balance, gas_cost, bridge_amount, MINIMUM_DAI_TO_BRIDGE_OUT
                );
            }
        }
    }

    // Always check for pending Gnosis withdrawal events and unlock funds on ETH
    simulated_withdrawal_on_eth(gnosis_bridge).await?;
    Ok(())
}
