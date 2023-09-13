use std::{
    thread,
    time::{Duration, Instant},
};

use actix::System;
use clarity::{
    abi::{encode_call, AbiToken},
    Address, PrivateKey, Uint256,
};
use futures::future::join_all;
use web30::{
    client::Web3,
    jsonrpc::error::Web3Error,
    types::{SendTxOption, TransactionResponse},
};

use crate::{
    get_reg_batch, remove_client_from_reg_batch, REGISTRATION_LOOP_SPEED, TX_TIMEOUT, WEB3_TIMEOUT,
};

/// This loop pull a queue of routers to be registered, batches them and setting up their
/// nonces, and sends a registrations request for all of them
pub fn register_client_batch_loop(
    web3_url: String,
    contract_addr: Address,
    our_private_key: PrivateKey,
) {
    let mut last_restart = Instant::now();
    thread::spawn(move || {
        // this will always be an error, so it's really just a loop statement
        // with some fancy destructuring
        while let Err(e) = {
            let web3 = web3_url.clone();
            thread::spawn(move || {
                // Our Exit state variabl
                let runner = System::new();

                runner.block_on(async move {
                    loop {
                        let start = Instant::now();
                        info!("Registration Loop tick");

                        let reg_clients = get_reg_batch();
                        let contact = Web3::new(&web3, WEB3_TIMEOUT);
                        let mut nonce_retries = 0;
                        let mut nonce;
                        loop {
                            match contact
                                .eth_get_transaction_count(our_private_key.to_address())
                                .await
                            {
                                Ok(a) => {
                                    nonce = a;
                                    break;
                                }
                                Err(e) => {
                                    error!("Unable to get nonce to register routers: {}", e);
                                    if nonce_retries > 10 {
                                        error!("Cant register routers, panicing!");
                                        let sys = System::current();
                                        sys.stop();
                                        panic!(
                                            "{}",
                                            format!(
                                                "Unable to get nonce to register routers: {}",
                                                e
                                            )
                                        );
                                    }
                                    nonce_retries += 1;
                                    thread::sleep(Duration::from_secs(5));
                                    continue;
                                }
                            }
                        }

                        let mut batch = vec![];
                        for id in reg_clients {
                            match contact
                                .send_transaction(
                                    contract_addr,
                                    match encode_call(
                                        "add_registered_user((string,string,address))",
                                        &[AbiToken::Struct(vec![
                                            AbiToken::String(id.mesh_ip.to_string()),
                                            AbiToken::String(id.wg_public_key.to_string()),
                                            AbiToken::Address(id.eth_address),
                                        ])],
                                    ) {
                                        Ok(a) => a,
                                        Err(e) => {
                                            error!(
                                            "REGISTRATION ERROR: Why cant we encode this call? {}",
                                            e
                                        );
                                            continue;
                                        }
                                    },
                                    0u32.into(),
                                    our_private_key,
                                    vec![SendTxOption::Nonce(nonce)],
                                )
                                .await
                            {
                                Ok(tx_id) => {
                                    //increment nonce for next tx
                                    nonce += 1u64.into();
                                    remove_client_from_reg_batch(id);
                                    batch.push(tx_id);
                                }
                                Err(e) => {
                                    error!(
                                        "Failed registration for {} with {}",
                                        id.wg_public_key, e
                                    );
                                }
                            }
                        }

                        // Join on txs
                        let res = wait_for_txids(batch, &contact).await;
                        trace!("Received Transactions: {:?}", res);

                        info!("Registration loop elapsed in = {:?}", start.elapsed());
                        if start.elapsed() < REGISTRATION_LOOP_SPEED {
                            info!(
                                "Registration Loop sleeping for {:?}",
                                REGISTRATION_LOOP_SPEED - start.elapsed()
                            );
                            thread::sleep(REGISTRATION_LOOP_SPEED - start.elapsed());
                        }
                        info!("Registration loop sleeping Done!");
                    }
                });
            })
            .join()
        } {
            error!(
                "Rita client Exit Manager loop thread paniced! Respawning {:?}",
                e
            );
            if Instant::now() - last_restart < Duration::from_secs(60) {
                error!("Restarting too quickly, leaving it to auto rescue!");
                let sys = System::current();
                sys.stop_with_code(121);
            }
            last_restart = Instant::now();
        }
    });
}

/// utility function that waits for a large number of txids to enter a block
async fn wait_for_txids(
    txids: Vec<Uint256>,
    web3: &Web3,
) -> Vec<Result<TransactionResponse, Web3Error>> {
    let mut wait_for_txid = Vec::new();
    for txid in txids {
        let wait = web3.wait_for_transaction(txid, TX_TIMEOUT, None);
        wait_for_txid.push(wait);
    }
    join_all(wait_for_txid).await
}
