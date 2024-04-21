use crate::blockchain_oracle::get_oracle_balance;
use crate::rita_loop::get_web3_server;
use crate::token_bridge::setup_withdraw as bridge_withdraw;
use crate::token_bridge::Withdraw as WithdrawMsg;
use actix_web_async::http::StatusCode;
use actix_web_async::web::Path;
use actix_web_async::HttpResponse;
use althea_types::SystemChain;
use clarity::Address;
use num256::Uint256;
use std::time::Duration;
use web30::client::Web3;

pub const WITHDRAW_TIMEOUT: Duration = Duration::from_secs(10);

async fn withdraw_handler(address: Address, amount: Option<Uint256>) -> HttpResponse {
    debug!("/withdraw/{:#x}/{:?} hit", address, amount);
    let payment_settings = settings::get_rita_common().payment;
    let system_chain = payment_settings.system_chain;
    let withdraw_chain = payment_settings.withdraw_chain;
    let balance = get_oracle_balance();
    let full_node = get_web3_server();
    let web3 = Web3::new(&full_node, WITHDRAW_TIMEOUT);
    let mut gas_price = match web3.eth_gas_price().await {
        Ok(gp) => gp,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    // if no amount is specified we are withdrawing our entire balance
    let mut amount = if let Some(amount) = amount {
        amount
    } else {
        match balance {
            Some(value) => value,
            None => return HttpResponse::BadRequest().finish(),
        }
    };

    let tx_gas: Uint256 =
        if (system_chain, withdraw_chain) == (SystemChain::Xdai, SystemChain::Ethereum) {
            // this is the hardcoded gas price over in token bridge so we have to use it
            gas_price = 10_000_000_000u128.into();
            // this is a contract call
            80000u32.into()
        } else {
            21000u32.into()
        };

    let tx_cost = gas_price * tx_gas;
    match balance {
        Some(value) => {
            if amount + tx_cost >= value {
                amount = value - tx_cost;
            }
        }
        None => error!("Unable to retrieve balance for withdrawing"),
    }

    match (system_chain, withdraw_chain) {
        (SystemChain::Ethereum, SystemChain::Ethereum) => {
            eth_compatible_withdraw(address, amount).await
        }
        (SystemChain::Sepolia, SystemChain::Sepolia) => {
            eth_compatible_withdraw(address, amount).await
        }
        (SystemChain::Xdai, SystemChain::Xdai) => eth_compatible_withdraw(address, amount).await,
        (SystemChain::Xdai, SystemChain::Ethereum) => xdai_to_eth_withdraw(address, amount),
        (_, _) => HttpResponse::build(StatusCode::from_u16(500u16).unwrap()).json(format!(
            "System chain is {system_chain} but withdraw chain is {withdraw_chain}, withdraw impossible!"
        )),
    }
}

pub async fn withdraw(path: Path<(Address, Uint256)>) -> HttpResponse {
    withdraw_handler(path.0, Some(path.1)).await
}

pub async fn withdraw_all(path: Path<Address>) -> HttpResponse {
    let address = path.into_inner();
    debug!("/withdraw_all/{} hit", address);
    withdraw_handler(address, None).await
}

/// Withdraw for eth compatible chains, pulls from the queued withdraw
/// and executes it
pub async fn eth_compatible_withdraw(dest: Address, amount: Uint256) -> HttpResponse {
    let full_node = get_web3_server();
    let web3 = Web3::new(&full_node, WITHDRAW_TIMEOUT);
    let payment_settings = settings::get_rita_common().payment;

    let tx = web3
        .prepare_transaction(
            dest,
            Vec::new(),
            amount,
            payment_settings.eth_private_key.unwrap(),
            vec![],
        )
        .await;
    match tx {
        Ok(tx) => {
            let transaction_status = web3.send_prepared_transaction(tx).await;
            if let Err(e) = transaction_status {
                HttpResponse::InternalServerError()
                    .json(format!("Withdraw failed with {:?} try again!", e))
            } else {
                HttpResponse::Ok().json(format!("Successful withdraw of {} to {}", amount, dest))
            }
        }
        Err(e) => HttpResponse::InternalServerError()
            .json(format!("Withdraw failed with {:?} try again!", e)),
    }
}

/// This handler invokes a withdraw function that sets a bool (as a lock) and withdraw information
/// as a lazy static. This is done in a sync context since our handler uses the older version of
/// futures. From there our xdai_loop ticks, looks at the lazy static for updated information and
/// sends out a transaction to the contract 'relayTokens' on xdai blockchain, that sends the funds
/// directly to an external address without eth conversion. This can be done in the async context
/// using new futures. From there we constantly check the blockchain for any withdrawal events.
/// We send these events as a contract call to simulate them, and those that do succeed, we execute
/// to unlock the funds on eth side.
fn xdai_to_eth_withdraw(address: Address, amount: Uint256) -> HttpResponse {
    match bridge_withdraw(WithdrawMsg {
        to: address,
        amount,
    }) {
        Ok(_) => HttpResponse::Ok().json("View endpoints for progress"),
        Err(e) => HttpResponse::build(StatusCode::from_u16(500u16).unwrap()).json(format!("{e:?}")),
    }
}
