use crate::rita_common::blockchain_oracle::zero_window_start;
use crate::rita_common::rita_loop::get_web3_server;
use crate::rita_common::token_bridge::withdraw as bridge_withdraw;
use crate::rita_common::token_bridge::Withdraw as WithdrawMsg;
use crate::SETTING;
use actix_web::http::StatusCode;
use actix_web::HttpResponse;
use actix_web::Path;
use althea_types::SystemChain;
use clarity::{Address, Transaction};
use failure::Error;
use futures01::{future, Future};
use num256::Uint256;
use settings::RitaCommonSettings;
use std::boxed::Box;
use std::time::Duration;
use web30::client::Web3;

pub const WITHDRAW_TIMEOUT: Duration = Duration::from_secs(10);

pub fn withdraw(
    path: Path<(Address, Uint256)>,
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let address = path.0;
    let amount = path.1.clone();
    debug!("/withdraw/{:#x}/{} hit", address, amount);
    let payment_settings = SETTING.get_payment();
    let system_chain = payment_settings.system_chain;
    let withdraw_chain = payment_settings.withdraw_chain;
    drop(payment_settings);

    match (system_chain, withdraw_chain) {
        (SystemChain::Ethereum, SystemChain::Ethereum) => eth_compatable_withdraw(address, amount),
        (SystemChain::Rinkeby, SystemChain::Rinkeby) => eth_compatable_withdraw(address, amount),
        (SystemChain::Xdai, SystemChain::Xdai) => eth_compatable_withdraw(address, amount),
        (SystemChain::Xdai, SystemChain::Ethereum) => xdai_to_eth_withdraw(address, amount, false),
        (_, _) => Box::new(future::ok(
            HttpResponse::new(StatusCode::from_u16(500u16).unwrap())
                .into_builder()
                .json(format!(
                    "System chain is {} but withdraw chain is {}, withdraw impossible!",
                    system_chain, withdraw_chain
                )),
        )),
    }
}

pub fn withdraw_all(path: Path<Address>) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let address = path.into_inner();
    debug!("/withdraw_all/{} hit", address);
    let payment_settings = SETTING.get_payment();
    let system_chain = payment_settings.system_chain;
    let withdraw_chain = payment_settings.withdraw_chain;
    let mut gas_price = payment_settings.gas_price.clone();
    let balance = payment_settings.balance.clone();
    drop(payment_settings);

    zero_window_start();

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
    let amount = balance - tx_cost;
    match (system_chain, withdraw_chain) {
        (SystemChain::Ethereum, SystemChain::Ethereum) => eth_compatable_withdraw(address, amount),
        (SystemChain::Rinkeby, SystemChain::Rinkeby) => eth_compatable_withdraw(address, amount),
        (SystemChain::Xdai, SystemChain::Xdai) => eth_compatable_withdraw(address, amount),
        (SystemChain::Xdai, SystemChain::Ethereum) => xdai_to_eth_withdraw(address, amount, true),
        (_, _) => Box::new(future::ok(
            HttpResponse::new(StatusCode::from_u16(500u16).unwrap())
                .into_builder()
                .json(format!(
                    "System chain is {} but withdraw chain is {}, withdraw impossible!",
                    system_chain, withdraw_chain
                )),
        )),
    }
}

/// Withdraw for eth compatible chains
fn eth_compatable_withdraw(
    address: Address,
    amount: Uint256,
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let full_node = get_web3_server();
    let web3 = Web3::new(&full_node, WITHDRAW_TIMEOUT);
    let payment_settings = SETTING.get_payment();
    if payment_settings.eth_address.is_none() {
        return Box::new(future::ok(
            HttpResponse::new(StatusCode::from_u16(504u16).unwrap())
                .into_builder()
                .json("No Address configured, withdraw impossible!"),
        ));
    };

    let tx = Transaction {
        nonce: payment_settings.nonce.clone(),
        gas_price: payment_settings.gas_price.clone(),
        gas_limit: 21_000u32.into(),
        to: address,
        value: amount,
        data: Vec::new(),
        signature: None,
    };
    let transaction_signed = tx.sign(
        &payment_settings
            .eth_private_key
            .expect("No private key configured!"),
        payment_settings.net_version,
    );

    let transaction_bytes = match transaction_signed.to_bytes() {
        Ok(bytes) => bytes,
        Err(e) => {
            return Box::new(future::ok(
                HttpResponse::new(StatusCode::from_u16(500u16).unwrap())
                    .into_builder()
                    .json(format!("Transaction to bytes failed! {:?}", e)),
            ));
        }
    };

    let transaction_status = web3.eth_send_raw_transaction(transaction_bytes);

    Box::new(transaction_status.then(move |result| match result {
        Ok(tx_id) => Box::new(future::ok({
            SETTING.get_payment_mut().nonce += 1u64.into();
            HttpResponse::Ok().json(format!("txid:{:#066x}", tx_id))
        })),
        Err(e) => {
            if e.to_string().contains("nonce") {
                Box::new(future::ok(
                    HttpResponse::new(StatusCode::from_u16(500u16).unwrap())
                        .into_builder()
                        .json(format!("The nonce was not updated, try again {:?}", e)),
                ))
            } else {
                Box::new(future::ok(
                    HttpResponse::new(StatusCode::from_u16(500u16).unwrap())
                        .into_builder()
                        .json(format!("Full node failed to send transaction! {:?}", e)),
                ))
            }
        }
    }))
}

/// Cross chain bridge withdraw from Xdai -> ETH
fn xdai_to_eth_withdraw(
    address: Address,
    amount: Uint256,
    withdraw_all: bool,
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    Box::new(
        match bridge_withdraw(WithdrawMsg {
            to: address,
            amount,
            withdraw_all,
        }) {
            Ok(_) => Box::new(future::ok(
                HttpResponse::Ok().json("View endpoints for progress"),
            )),
            Err(e) => Box::new(future::ok(
                HttpResponse::new(StatusCode::from_u16(500u16).unwrap())
                    .into_builder()
                    .json(format!("{:?}", e)),
            )),
        },
    )
}
