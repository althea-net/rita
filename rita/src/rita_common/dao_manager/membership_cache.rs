use super::*;

#[derive(Debug)]
pub struct DAOEntry {
    on_list: bool,
    dao_address: Address,
    id: Identity,
    last_updated: Instant,
}

/// Called by returning DAO requests, sends a message to TunnelManager
pub struct CacheCallback {
    id: Identity,
    dao_address: Address,
    response: Data,
}

impl Message for CacheCallback {
    type Result = ();
}

impl Handler<CacheCallback> for DAOManager {
    type Result = ();

    fn handle(&mut self, msg: CacheCallback, _: &mut Context<Self>) -> Self::Result {
        let their_id = msg.id;
        let dao_address = msg.dao_address;
        let response = msg.response;
        trace!("Got response {:?} from DAO", response);

        let has_vec = self.ident2dao.contains_key(&their_id);
        //let on_dao = != Uint256::zero();
        let on_dao = true;

        if has_vec {
            let entry_vec = self.ident2dao.get_mut(&their_id).unwrap();
            let mut found_entry = false;
            if let Some(entry) = entry_vec
                .iter_mut()
                .find(|ref i| dao_address == i.dao_address)
            {
                entry.on_list = on_dao;
                entry.last_updated = Instant::now();
                found_entry = true;
                trace!("Updating exising entry {:?}", entry);
                send_membership_message(on_dao, their_id);
            }

            // We can't place this into the match because the mutable ref lives even
            // in the none case where it's obviously not being used. Until the borrow
            // checker is smart enough to allow that this will have to do
            if !found_entry {
                // A list exists but does not contain an entry from this dao
                // create one and insert it into the list
                let entry = DAOEntry {
                    on_list: on_dao,
                    dao_address: dao_address,
                    id: their_id,
                    last_updated: Instant::now(),
                };
                trace!("Adding new cache entry to existing ID {:?}", entry);
                entry_vec.push(entry);
                send_membership_message(on_dao, their_id);
            }
        } else {
            // No entry exists in the HashMap for this ID, create one
            let entry = DAOEntry {
                on_list: on_dao,
                dao_address: dao_address,
                id: their_id,
                last_updated: Instant::now(),
            };
            trace!("Creating new ID in cache {:?}", entry);
            self.ident2dao.insert(their_id, vec![entry]);

            send_membership_message(on_dao, their_id);
        }
    }
}

/// True if timestamp does not need to be updated
fn timer_check(timestamp: Instant) -> bool {
    Instant::now() - timestamp < Duration::new(SETTING.get_dao().cache_timeout_seconds, 0)
}

/// Sends off a message to TunnelManager about the dao state
fn send_membership_message(on_dao: bool, their_id: Identity) {
    TunnelManager::from_registry().do_send(TunnelStateChange {
        identity: their_id,
        action: if on_dao {
            TunnelAction::MembershipConfirmed
        } else {
            TunnelAction::MembershipExpired
        },
    });
}

/// Checks if an identity is in at least one of the set of DAO's we are a member of.
/// will check the cache first before going out and updating via web3
pub fn check_cache(their_id: Identity, ident2dao: &HashMap<Identity, Vec<DAOEntry>>) {
    trace!("Checking the DAOManager Cache for {:?}", their_id);
    let dao_settings = SETTING.get_dao();
    // we don't care about subnet DAO's, short circuit.
    if !dao_settings.dao_enforcement || dao_settings.dao_addresses.is_empty() {
        trace!("DAO enforcement disabled DAOMAnager doing nothing!");
        send_membership_message(true, their_id);
        return;
    }
    // TODO when we start enforcing dao state more strictly we will need
    // to detect when we are bootstrapping and explicitly allow everyone

    match ident2dao.get(&their_id) {
        // Cache hit
        Some(membership_list) => {
            for entry in membership_list.iter() {
                if entry.on_list && timer_check(entry.last_updated) {
                    trace!("{:?} is on the SubnetDAO {:?}", their_id, entry.dao_address);
                    send_membership_message(true, their_id);
                } else if !timer_check(entry.last_updated) {
                    trace!("Cache entry has expired, updating");
                    get_membership(entry.dao_address, entry.id);
                }
            }
            trace!("{:?} is not on any SubnetDAO", their_id);
            send_membership_message(false, their_id);
        }
        // Cache miss, do a lookup for all DAO's
        None => {
            for dao in dao_settings.dao_addresses.iter() {
                get_membership(*dao, their_id);
            }
        }
    }
}

fn get_membership(dao_address: Address, target: Identity) {
    let full_node = get_web3_server();
    let web3 = Web3::new(&full_node);
    let payment_settings = SETTING.get_payment();
    let our_address = payment_settings.eth_address.expect("No address!");
    // the lack of ToLowerHex for Vec, Ip, Ipv6 and &[u8] is apalling, TODO implement upstream
    let ip = match target.mesh_ip {
        IpAddr::V6(ip) => ip.octets(),
        _ => {
            error!("MeshIP must be ipv6 and is not!");
            return;
        }
    };
    drop(payment_settings);
    trace!("Getting DAO membership from {}", full_node);
    let get_member = [0x37, 0x66, 0x79, 0xb0];
    let mut call_data = Vec::new();
    for byte in get_member.iter() {
        call_data.push(*byte);
    }
    for byte in ip.iter() {
        call_data.push(*byte);
    }

    // since this is a read-only request so lots of values are None
    let tx = TransactionRequest {
        from: our_address,
        to: Some(dao_address),
        gas: None,
        gas_price: None,
        value: None,
        data: Some(Data(call_data)),
        nonce: None,
    };

    let res = web3.eth_call(tx).then(move |response| match response {
        Ok(val) => {
            DAOManager::from_registry().do_send(CacheCallback {
                id: target,
                dao_address: dao_address,
                response: val,
            });
            Ok(())
        }
        Err(e) => {
            warn!("Get Membership Web3 call failed {:?}", e);
            Ok(())
        }
    });
    Arbiter::spawn(res);
}
