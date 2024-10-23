use crate::{
    client_db::{add_users_to_registered_list, check_user_admin, get_all_registered_clients},
    sms_auth::{REGISTRATION_LOOP_SPEED, TX_TIMEOUT, WEB3_TIMEOUT},
};
use althea_types::Identity;
use clarity::{Address, PrivateKey};
use crossbeam::queue::SegQueue;
use log::{error, info};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Instant,
};
use web30::{client::Web3, types::SendTxOption};

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct RegistrationRequest {
    pub identity: Identity,
    pub contract: Address,
}

pub const MAX_BATCH_SIZE: usize = 75;

/// Utility function used to easily perform O(1) lookups against the identities list
pub fn get_clients_hashset(input: Vec<Identity>) -> HashSet<Identity> {
    let mut output = HashSet::new();
    for i in input {
        output.insert(i);
    }
    output
}

/// This function  monitors the registration queue lock free queue. It will dequeue any new entries and attempt to register them
/// in a batch sent every REGISTRATION_LOOP_SPEED seconds. This function will also check if the user is already registered before attempting to register them
pub async fn register_client_batch_loop(
    rpc_url: String,
    our_private_key: PrivateKey,
    registration_queue: Arc<SegQueue<RegistrationRequest>>,
) {
    // local copy of the registration queue, entries are copied off of the
    // registration queue and into this local queue before being processed
    // each key in the hashmap represents a list of users waiting to be registered
    // for a given database contract
    let mut local_queue: HashMap<Address, HashSet<RegistrationRequest>> = HashMap::new();
    loop {
        let start = Instant::now();
        // copy all entries from the registration queue into the local queue
        // creating new entries for each contract address as needed
        while let Some(reg_request) = registration_queue.pop() {
            let contract_addr = reg_request.contract;
            match local_queue.get_mut(&contract_addr) {
                Some(queue) => {
                    queue.insert(reg_request);
                }
                None => {
                    let mut new_queue = HashSet::new();
                    new_queue.insert(reg_request);
                    local_queue.insert(contract_addr, new_queue);
                }
            }
        }
        let web3 = Web3::new(&rpc_url, WEB3_TIMEOUT);

        for (contract_addr, list) in local_queue.iter_mut() {
            if list.is_empty() {
                continue;
            }

            match check_user_admin(
                &web3,
                *contract_addr,
                our_private_key.to_address(),
                our_private_key,
            )
            .await
            {
                Ok(b) => {
                    if !b {
                        error!(
                            "We are not a user admin for contract {:?}, skipping registration",
                            contract_addr
                        );
                        continue;
                    }
                }
                Err(e) => {
                    error!("Failed to check if we are a user admin {:?}, retrying", e);
                    continue;
                }
            }

            // list of existing users to check against, prevent duplicate registrations
            let all_clients = match get_all_registered_clients(
                &web3,
                our_private_key.to_address(),
                *contract_addr,
            )
            .await
            {
                Ok(all_clients) => all_clients,
                Err(e) => {
                    error!(
                        "Failed to get list of already registered clients {:?}, retrying",
                        e
                    );
                    continue;
                }
            };
            let all_clients = get_clients_hashset(all_clients);

            let mut clients_to_register = Vec::new();
            for client in list.iter() {
                if !all_clients.contains(&client.identity) {
                    clients_to_register.push(client);
                    if clients_to_register.len() > MAX_BATCH_SIZE {
                        break;
                    }
                }
            }
            // there is no one to register once we filter already registered users
            if clients_to_register.is_empty() {
                continue;
            }

            info!(
                "Prepped user batch sending register tx against contract {:?} from our address {} with balance {} and clients {:#?}",
                contract_addr,
                our_private_key.to_address(),
                web3.eth_get_balance(our_private_key.to_address()).await.unwrap(),
                clients_to_register
            );
            match add_users_to_registered_list(
                &web3,
                clients_to_register.iter().map(|x| x.identity).collect(),
                *contract_addr,
                our_private_key,
                Some(TX_TIMEOUT),
                vec![
                    SendTxOption::GasPriorityFee(1000000000u128.into()),
                    SendTxOption::GasMaxFee(4000000000u128.into()),
                ],
            )
            .await
            {
                Ok(_) => {
                    info!(
                        "Successfully registered {} clients!",
                        clients_to_register.len()
                    );
                    // remove all the successfully registered clients from the queue
                    list.clear();
                }
                Err(e) => {
                    error!("Failed to register clients with {:?}, will try again!", e)
                }
            }
        }

        info!("Registration loop elapsed in = {:?}", start.elapsed());
        if start.elapsed() < REGISTRATION_LOOP_SPEED {
            info!(
                "Registration Loop sleeping for {:?}",
                REGISTRATION_LOOP_SPEED - start.elapsed()
            );
            tokio::time::sleep(REGISTRATION_LOOP_SPEED - start.elapsed()).await;
        }
    }
}
