use actix::System;
use althea_types::Identity;
use clarity::{Address, PrivateKey};
use log::{error, info};
use std::{
    collections::HashSet,
    thread,
    time::{Duration, Instant},
};
use web30::{client::Web3, types::SendTxOption};

use crate::{
    client_db::{add_users_to_registered_list, get_all_registered_clients},
    rita_client_registration::{
        get_reg_queue, remove_client_from_reg_queue, REGISTRATION_LOOP_SPEED, TX_TIMEOUT,
        WEB3_TIMEOUT,
    },
};

pub const MAX_BATCH_SIZE: usize = 75;

/// Utility function used to easily perform O(1) lookups against the identities list
pub fn get_clients_hashset(input: Vec<Identity>) -> HashSet<Identity> {
    let mut output = HashSet::new();
    for i in input {
        output.insert(i);
    }
    output
}

/// This function starts  a separate thread that monitors the registraiton batch lazy static variable and every REGISTRATION_LOOP_SPEED seconds
/// sends a batch register tx to the smart contract
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
            let web3_url = web3_url.clone();
            thread::spawn(move || {
                let web3_url = web3_url.clone();
                // Our Exit state variabl
                let runner = System::new();

                runner.block_on(async move {
                    loop {
                        let start = Instant::now();
                        // there is no one in the queue
                        let list = get_reg_queue();
                        if list.is_empty() {
                            thread::sleep(WEB3_TIMEOUT);
                            continue
                        }

                        let web3 = Web3::new(&web3_url, WEB3_TIMEOUT);
                        // get a copy of all existing clients, we do this in order to handle a potential future edgecase where more than one registration server
                        // is operating at a time and the same user attempts to register to more than one before the transaction can be sent. Without this check
                        // once a already registered user is in the queue all future transactions would fail and the server would no longer operate correctly
                        let all_clients = match get_all_registered_clients(&web3, our_private_key.to_address(), contract_addr).await {
                            Ok(all_clients) => all_clients,
                            Err(e) => {
                                error!("Failed to get list of already registered clients {:?}, retrying", e);
                                continue;
                            },
                        };
                        let all_clients = get_clients_hashset(all_clients);

                        let mut clients_to_register = Vec::new();
                        for client in list {
                            if !all_clients.contains(&client) {
                                clients_to_register.push(client);
                                if clients_to_register.len() > MAX_BATCH_SIZE {
                                    break;
                                }
                            }
                        }
                        // there is no one once we filter already registered users
                        if clients_to_register.is_empty() {
                            thread::sleep(WEB3_TIMEOUT);
                            continue
                        }

                        info!("Prepped user batch sending register tx");
                        match add_users_to_registered_list(
                            &web3,
                            clients_to_register.clone(),
                            contract_addr,
                            our_private_key,
                            Some(TX_TIMEOUT),
                            vec![SendTxOption::GasPriorityFee(1000000000u128.into()), SendTxOption::GasMaxFee(4000000000u128.into())],
                        )
                        .await
                        {
                            Ok(_) => {
                                info!(
                                    "Successfully registered {} clients!",
                                    clients_to_register.len()
                                );
                                // remove all the successfully registered clients from the queue
                                for client in clients_to_register {
                                    remove_client_from_reg_queue(client);
                                }
                            }
                            Err(e) => {
                                error!("Failed to register clients with {:?}, will try again!", e)
                            }
                        }

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
            error!("Registration loop thread panicked! Respawning {:?}", e);
            if Instant::now() - last_restart < Duration::from_secs(60) {
                error!("Restarting too quickly, leaving it to auto rescue!");
                let sys = System::current();
                sys.stop_with_code(121);
            }
            last_restart = Instant::now();
        }
    });
}
