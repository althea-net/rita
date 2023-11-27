use std::{
    net::IpAddr,
    thread,
    time::{Duration, Instant},
};

use num_traits::cast::ToPrimitive;

use actix::System;
use clarity::{
    abi::{encode_call, AbiToken},
    Address, PrivateKey, Transaction, Uint256,
};
use futures::future::{join4, join_all};
use web30::{
    client::Web3,
    jsonrpc::error::Web3Error,
    types::{TransactionRequest, TransactionResponse},
};

use crate::{
    get_reg_batch, remove_client_from_reg_batch, REGISTRATION_LOOP_SPEED, TX_TIMEOUT, WEB3_TIMEOUT,
};

pub const MAX_BATCH_SIZE: usize = 100;

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

                        register_client_batch_internal(
                            web3.clone(),
                            contract_addr,
                            our_private_key,
                        )
                        .await;

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

async fn get_base_fee_per_gas(contact: &Web3) -> Result<Option<Uint256>, Web3Error> {
    match contact.eth_get_latest_block().await {
        Ok(eth_block) => Ok(eth_block.base_fee_per_gas),
        Err(e) => Err(e),
    }
}

pub fn set_tx_data(tx: &mut Transaction, encoding: Vec<u8>) {
    match tx {
        Transaction::Legacy { .. } | Transaction::Eip2930 { .. } => {}
        Transaction::Eip1559 { data, .. } => *data = encoding,
    }
}

pub fn set_tx_nonce(tx: &mut Transaction, n: Uint256) {
    match tx {
        Transaction::Legacy { .. } | Transaction::Eip2930 { .. } => {}
        Transaction::Eip1559 { nonce, .. } => *nonce = n,
    }
}

pub async fn register_client_batch_internal(
    web3: String,
    contract_addr: Address,
    our_private_key: PrivateKey,
) {
    info!("Register batch clients tick");
    let reg_clients = get_reg_batch();
    let contact = Web3::new(&web3, WEB3_TIMEOUT);

    // request tx params
    let chain_id_fut = contact.net_version();
    let nonce_fut = contact.eth_get_transaction_count(our_private_key.to_address());
    let our_balance_fut = contact.eth_get_balance(our_private_key.to_address());
    let base_fee_per_gas_fut = get_base_fee_per_gas(&contact);
    let our_balance;
    let mut nonce;
    let chain_id;
    let base_fee_per_gas;

    let (our_balance_fut, nonce_fut, base_fee_per_gas_fut, chain_id_fut) = join4(
        our_balance_fut,
        nonce_fut,
        base_fee_per_gas_fut,
        chain_id_fut,
    )
    .await;

    match (
        our_balance_fut,
        nonce_fut,
        base_fee_per_gas_fut,
        chain_id_fut,
    ) {
        (Ok(a), Ok(b), Ok(c), Ok(d)) => {
            our_balance = a;
            nonce = b;
            base_fee_per_gas = c;
            chain_id = d;
            info!("Received all tx params successfully!");
        }
        error => {
            error!(
                "Atleast one of the four requested params failed: {:?}",
                error
            );
            error!("Cant register routers, panicing!");
            let sys = System::current();
            sys.stop();
            panic!(
                "{}",
                format!("Unable to get params to register routers:\n {:?}", error)
            );
        }
    }

    let mut max_fee_per_gas = match base_fee_per_gas {
        Some(bf) => bf * 2u8.into(),
        None => {
            // No point in keep this loop running if it cant register any routers
            panic!("Pre London, cant get base fee");
        }
    };

    let base_fee_per_gas = base_fee_per_gas.unwrap();

    // Create a tx template to use for our reg batch
    let mut prepared_tx = Transaction::Eip1559 {
        chain_id: chain_id.into(),
        nonce,
        max_priority_fee_per_gas: 1u8.into(),
        max_fee_per_gas,
        // populated later
        gas_limit: 0u8.into(),
        to: contract_addr,
        value: 0u32.into(),
        // populated later, using some dummy for now
        data: encode_call(
            "addRegisteredUser((uint128,uint256,address))",
            &[AbiToken::Struct(vec![
                AbiToken::Uint(0u8.into()),
                AbiToken::Uint(0u8.into()),
                AbiToken::Address(our_private_key.to_address()),
            ])],
        )
        .expect("Why does this fail?"),
        signature: None,
        access_list: vec![],
    };

    let mut gas_limit = contact
        .eth_estimate_gas(TransactionRequest::from_transaction(
            &prepared_tx,
            our_private_key.to_address(),
        ))
        .await
        .expect("Cannot get gas estimate to setup gas limit");

    // multiply limit by gasLimitMultiplier
    let gas_limit_128 = gas_limit.to_u128();
    if let Some(v) = gas_limit_128 {
        gas_limit = ((v as f32 * 5.0) as u128).into()
    } else {
        gas_limit *= 5_u128.into()
    }
    prepared_tx.set_gas_limit(gas_limit);

    // this is an edge case where we are about to send a transaction that can't possibly be valid
    if max_fee_per_gas * gas_limit > our_balance {
        if base_fee_per_gas * gas_limit > our_balance {
            let err = Web3Error::InsufficientGas {
                balance: our_balance,
                base_gas: base_fee_per_gas,
                gas_required: gas_limit,
            };
            error!("{:?}", err);
            panic!("{:?}", err);
        }
        // this will give some value >= base_fee_per_gas * gas_limit
        // in post-london and some non zero value in pre-london
        max_fee_per_gas = our_balance / gas_limit;
    }
    prepared_tx.set_max_fee_per_gas(max_fee_per_gas);

    info!("Starting client batching");
    // Start batching tx for each client
    let mut batch: Vec<Uint256> = vec![];
    trace!("Reg clients are: {:?}", reg_clients);
    // we limit batch size to 100 clients at a time
    let mut batch_len = 0;
    for id in reg_clients {
        if let IpAddr::V6(mesh_ip_v6) = id.mesh_ip {
            let mut prepared_tx_copy = prepared_tx.clone();
            set_tx_data(
                &mut prepared_tx_copy,
                match encode_call(
                    "addRegisteredUser((uint128,uint256,address))",
                    &[AbiToken::Struct(vec![
                        AbiToken::Uint(u128::from(mesh_ip_v6).into()),
                        AbiToken::Uint(id.wg_public_key.into()),
                        AbiToken::Address(id.eth_address),
                    ])],
                ) {
                    Ok(a) => a,
                    Err(e) => {
                        error!("REGISTRATION ERROR: Why cant we encode this call? {}", e);
                        continue;
                    }
                },
            );
            set_tx_nonce(&mut prepared_tx_copy, nonce);
            let prepared_tx_copy: Transaction = prepared_tx_copy.sign(&our_private_key, None);

            match contact.send_prepared_transaction(prepared_tx_copy).await {
                Ok(tx_id) => {
                    //increment nonce for next tx
                    nonce += 1u64.into();
                    batch_len += 1;
                    remove_client_from_reg_batch(id);
                    info!(
                        "BATCH CLIENT {}: {} with txid {}",
                        batch_len, id.mesh_ip, tx_id
                    );
                    batch.push(tx_id);
                    if batch_len >= MAX_BATCH_SIZE {
                        break;
                    }
                }
                Err(e) => {
                    error!("Failed registration for {} with {}", id.wg_public_key, e);
                }
            }
        } else {
            error!("{} Doesnt have a v6 mesh ip??", id);
        }
    }

    // Join on txs
    let res = wait_for_txids(batch, &contact).await;
    for e in res {
        match e {
            Err(e) => error!("Failed tx with {}", e),
            _ => info!("Tx is ok!"),
        }
    }
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
