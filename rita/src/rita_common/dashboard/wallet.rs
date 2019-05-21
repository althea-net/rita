use crate::rita_common::oracle::update_nonce;
use crate::rita_common::rita_loop::get_web3_server;
use crate::SETTING;
use ::actix_web::http::StatusCode;
use ::actix_web::HttpResponse;
use ::actix_web::Path;
use ::settings::RitaCommonSettings;
use clarity::{Address, Transaction};
use failure::Error;
use futures::{future, Future};
use std::boxed::Box;
use std::time::Duration;
use web30::client::Web3;

pub const WITHDRAW_TIMEOUT: Duration = Duration::from_secs(10);

pub fn withdraw(path: Path<(Address, u64)>) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let address = path.0;
    let amount = path.1;
    debug!("/withdraw/{:#x}/{} hit", address, amount);

    let full_node = get_web3_server();
    let web3 = Web3::new(&full_node, WITHDRAW_TIMEOUT);
    let payment_settings = SETTING.get_payment();
    let our_address = match payment_settings.eth_address {
        Some(address) => address,
        None => {
            return Box::new(future::ok(
                HttpResponse::new(StatusCode::from_u16(504u16).unwrap())
                    .into_builder()
                    .json("No Address configured, withdraw impossible!"),
            ))
        }
    };

    let tx = Transaction {
        nonce: payment_settings.nonce.clone(),
        gas_price: payment_settings.gas_price.clone(),
        gas_limit: "21000".parse().unwrap(),
        to: address,
        value: amount.into(),
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
                HttpResponse::new(StatusCode::from_u16(504u16).unwrap())
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
            update_nonce(our_address, &web3, full_node);
            if e.to_string().contains("nonce") {
                Box::new(future::ok(
                    HttpResponse::new(StatusCode::from_u16(504u16).unwrap())
                        .into_builder()
                        .json(format!("The nonce was not updated, try again {:?}", e)),
                ))
            } else {
                Box::new(future::ok(
                    HttpResponse::new(StatusCode::from_u16(504u16).unwrap())
                        .into_builder()
                        .json(format!("Full node failed to send transaction! {:?}", e)),
                ))
            }
        }
    }))
}
