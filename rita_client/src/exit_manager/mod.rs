//! This module contains utility functions for dealing with the exit signup and connection procedure
//! the procedure goes as follows.
//!
//! Exit is preconfigured with wireguard, mesh ip, and eth address info, this removes the possibility
//! of an effective MITM attack.
//!
//! The exit is queried for info about it that might change, such as it's subnet settings and default
//! route.
//!
//! Once the 'general' settings are acquire we contact the exit with our email, after getting an email
//! we input the confirmation code.
//!
//! The exit then serves up our user specific settings (our own exit internal ip) which we configure
//! and open the wg_exit tunnel. The exit performs the other side of this operation after querying
//! the database and finding a new entry.
//!
//! Signup is complete and the user may use the connection

mod exit_switcher;
mod time_sync;

use crate::exit_manager::time_sync::maybe_set_local_to_exit_time;
use crate::rita_loop::CLIENT_LOOP_TIMEOUT;
use crate::traffic_watcher::{query_exit_debts, QueryExitDebts};
use crate::RitaClientError;

use actix_web_async::Result;
use althea_kernel_interface::{
    exit_client_tunnel::ClientExitTunnelConfig, DefaultRoute, KernelInterfaceError,
};
use althea_types::ExitClientDetails;
use althea_types::ExitDetails;
use althea_types::Identity;
use althea_types::WgKey;
use althea_types::{EncryptedExitClientIdentity, EncryptedExitState};
use althea_types::{ExitClientIdentity, ExitRegistrationDetails, ExitState, ExitVerifMode};
use exit_switcher::{get_babel_routes, set_best_exit};

use rita_common::blockchain_oracle::low_balance;
use rita_common::KI;
use settings::client::{ExitServer, SelectedExit};
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::Nonce;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::RwLock;

/// The number of times ExitSwitcher will try to connect to an unresponsive exit before blacklisting its ip
const MAX_BLACKLIST_STRIKES: u16 = 100;

lazy_static! {
    pub static ref EXIT_MANAGER: Arc<RwLock<ExitManager>> =
        Arc::new(RwLock::new(ExitManager::default()));
}

/// This enum has two types of warnings for misbehaving exits, a hard warning which blacklists this ip immediatly, and a
/// soft warning. When an exit receives MAX_BLACKLIST_STIKES soft warnings, this exit is blacklisted.
pub enum WarningType {
    HardWarning,
    SoftWarning,
}

/// This struct holds all the blacklisted ip that are considered when exit switching as well as keeps track
/// of non reponsive exits with a penalty system. After 'n' strikes this ip is added to a the blacklist
#[derive(Default, Debug, Clone)]
pub struct ExitBlacklist {
    blacklisted_exits: HashSet<IpAddr>,
    potential_blacklists: HashMap<IpAddr, u16>,
}

/// An actor which pays the exit
#[derive(Default)]
pub struct ExitManager {
    pub nat_setup: bool,
    /// This struct hold infomation about exits that have misbehaved and are blacklisted, or are being watched
    /// to being blacklisted through bad responses.
    pub exit_blacklist: ExitBlacklist,
    /// Hashmap of Structs containing information of current exit we are connected to and tracking exit, if connected to one
    /// It also holds information about metrics and degradation values. Look at doc comment on 'set_best_exit' for more
    /// information on what these mean
    pub selected_exit_list: HashMap<String, SelectedExit>,
}

pub fn get_selected_exit(exit: String) -> Option<IpAddr> {
    match EXIT_MANAGER.read().unwrap().selected_exit_list.get(&exit) {
        Some(a) => a.selected_id,
        None => None,
    }
}

pub fn get_selected_exit_metric(exit: String) -> Option<u16> {
    match EXIT_MANAGER.read().unwrap().selected_exit_list.get(&exit) {
        Some(a) => a.selected_id_metric,
        None => None,
    }
}

pub fn get_selected_exit_tracking(exit: String) -> Option<IpAddr> {
    match EXIT_MANAGER.read().unwrap().selected_exit_list.get(&exit) {
        Some(a) => a.tracking_exit,
        None => None,
    }
}

pub fn get_selected_exit_degradation(exit: String) -> Option<u16> {
    match EXIT_MANAGER.read().unwrap().selected_exit_list.get(&exit) {
        Some(a) => a.selected_id_degradation,
        None => None,
    }
}

pub fn set_selected_exit(exit: String, exit_info: SelectedExit) {
    EXIT_MANAGER
        .write()
        .unwrap()
        .selected_exit_list
        .insert(exit, exit_info);
}

pub fn set_em_nat(val: bool) {
    EXIT_MANAGER.write().unwrap().nat_setup = val;
}

pub fn get_em_nat() -> bool {
    EXIT_MANAGER.read().unwrap().nat_setup
}

fn linux_setup_exit_tunnel(
    exit: String,
    current_exit: &ExitServer,
    general_details: &ExitDetails,
    our_details: &ExitClientDetails,
) -> Result<(), RitaClientError> {
    let mut rita_client = settings::get_rita_client();
    let mut network = rita_client.network;
    let local_mesh_ip = network.mesh_ip;

    // TODO this should be refactored to return a value
    KI.update_settings_route(&mut network.last_default_route);

    if let Err(KernelInterfaceError::RuntimeError(v)) = KI.setup_wg_if_named("wg_exit") {
        return Err(RitaClientError::MiscStringError(v));
    }

    let args = ClientExitTunnelConfig {
        endpoint: SocketAddr::new(
            get_selected_exit(exit).expect("There should be an exit ip here"),
            general_details.wg_exit_port,
        ),
        pubkey: current_exit.wg_public_key,
        private_key_path: network.wg_private_key_path.clone(),
        listen_port: rita_client.exit_client.wg_listen_port,
        local_ip: our_details.client_internal_ip,
        netmask: general_details.netmask,
        rita_hello_port: network.rita_hello_port,
        user_specified_speed: network.user_bandwidth_limit,
    };

    rita_client.network = network;
    settings::set_rita_client(rita_client);

    KI.set_client_exit_tunnel_config(args, local_mesh_ip)?;
    KI.set_route_to_tunnel(&general_details.server_internal_ip)?;

    KI.create_client_nat_rules()?;

    Ok(())
}

fn restore_nat() {
    if let Err(e) = KI.restore_client_nat() {
        error!("Failed to restore client nat! {:?}", e);
    }
}

fn remove_nat() {
    if let Err(e) = KI.block_client_nat() {
        error!("Failed to block client nat! {:?}", e);
    }
}

pub async fn get_exit_info(to: &SocketAddr) -> Result<ExitState, RitaClientError> {
    let endpoint = format!("http://[{}]:{}/exit_info", to.ip(), to.port());

    let client = awc::Client::default();
    let mut response = match client.get(&endpoint).send().await {
        Ok(a) => a,
        Err(e) => return Err(RitaClientError::SendRequestError(e.to_string())),
    };
    let response_json = response.json().await?;

    Ok(response_json)
}

fn encrypt_exit_client_id(
    exit_pubkey: &PublicKey,
    id: ExitClientIdentity,
) -> EncryptedExitClientIdentity {
    let network_settings = settings::get_rita_client().network;
    let our_publickey = network_settings.wg_public_key.expect("No public key?");
    let our_secretkey = network_settings
        .wg_private_key
        .expect("No private key?")
        .into();

    let plaintext = serde_json::to_string(&id)
        .expect("Failed to serialize ExitState!")
        .into_bytes();
    let nonce = box_::gen_nonce();
    let ciphertext = box_::seal(&plaintext, &nonce, exit_pubkey, &our_secretkey);

    EncryptedExitClientIdentity {
        nonce: nonce.0,
        pubkey: our_publickey,
        encrypted_exit_client_id: ciphertext,
    }
}

/// Blacklist an exit ip from being selected. This prevents rogue ip within the selected subnet to cause
/// blackhole attacks. Exits that cant be decrypted are immediately blacklisted and those exits that fail to respond after
/// MAX_BLACKLIST_STRIKES warning strikes are blacklisted
fn blacklist_strike_ip(ip: IpAddr, warning: WarningType) {
    let writer = &mut (*EXIT_MANAGER.write().unwrap()).exit_blacklist;

    match warning {
        WarningType::SoftWarning => {
            if let Some(warning_count) = writer.potential_blacklists.get(&ip).cloned() {
                if warning_count >= MAX_BLACKLIST_STRIKES {
                    writer.blacklisted_exits.insert(ip);
                    writer.potential_blacklists.remove(&ip);
                } else {
                    writer.potential_blacklists.insert(ip, warning_count + 1);
                }
            } else {
                writer.potential_blacklists.insert(ip, 1);
            }
        }
        WarningType::HardWarning => {
            writer.blacklisted_exits.insert(ip);
        }
    }
}

/// Resets the the warnings from this ip in this blacklist. This function is called whenever we
fn reset_blacklist_warnings(ip: IpAddr) {
    let writer = &mut (*EXIT_MANAGER.write().unwrap()).exit_blacklist;

    // This condition should not be reached since if an exit is blacklisted, we should never sucessfully connect to it
    if writer.blacklisted_exits.contains(&ip) {
        error!("Was able to successfully connect to a blacklisted exit, error in blacklist logic");
        writer.blacklisted_exits.remove(&ip);
    }

    if writer.potential_blacklists.contains_key(&ip) {
        writer.potential_blacklists.remove(&ip);
    }
}

/// This function clears all blacklist information from the datastore. This function is only called in the situation
/// of false positives where exits that are not supposed to be blacklist have been blacklisted, perhaps for being unresposive for
/// long periods of time
fn reset_exit_blacklist() {
    let writer = &mut (*EXIT_MANAGER.write().unwrap()).exit_blacklist;

    writer.blacklisted_exits.clear();
    writer.potential_blacklists.clear();
}

fn decrypt_exit_state(
    exit_state: EncryptedExitState,
    exit_pubkey: PublicKey,
) -> Result<ExitState, RitaClientError> {
    let rita_client = settings::get_rita_client();
    let network_settings = rita_client.network;
    let our_secretkey = network_settings
        .wg_private_key
        .expect("No private key?")
        .into();
    let ciphertext = exit_state.encrypted_exit_state;
    let nonce = Nonce(exit_state.nonce);
    let decrypted_exit_state: ExitState =
        match box_::open(&ciphertext, &nonce, &exit_pubkey, &our_secretkey) {
            Ok(decrypted_bytes) => match String::from_utf8(decrypted_bytes) {
                Ok(json_string) => match serde_json::from_str(&json_string) {
                    Ok(exit_state) => exit_state,
                    Err(e) => {
                        return Err(e.into());
                    }
                },
                Err(e) => {
                    error!("Could not deserialize exit state with {:?}", e);
                    return Err(e.into());
                }
            },
            Err(_) => {
                error!("Could not decrypt exit state");
                return Err(RitaClientError::MiscStringError(
                    "Could not decrypt exit state".to_string(),
                ));
            }
        };
    Ok(decrypted_exit_state)
}

async fn send_exit_setup_request(
    exit_pubkey: WgKey,
    to: SocketAddr,
    ident: ExitClientIdentity,
) -> Result<ExitState, RitaClientError> {
    let endpoint = format!("http://[{}]:{}/secure_setup", to.ip(), to.port());
    let ident = encrypt_exit_client_id(&exit_pubkey.into(), ident);

    let client = awc::Client::default();

    let response = client
        .post(&endpoint)
        .timeout(CLIENT_LOOP_TIMEOUT)
        .send_json(&ident)
        .await;
    let mut response = match response {
        Ok(a) => {
            reset_blacklist_warnings(to.ip());
            a
        }
        Err(awc::error::SendRequestError::Timeout) => {
            // Did not get a response, is it a rogue exit or some netork error?
            blacklist_strike_ip(to.ip(), WarningType::SoftWarning);
            return Err(RitaClientError::SendRequestError(
                awc::error::SendRequestError::Timeout.to_string(),
            ));
        }
        Err(e) => return Err(RitaClientError::SendRequestError(e.to_string())),
    };

    let value = response.json().await?;

    match decrypt_exit_state(value, exit_pubkey.into()) {
        Err(e) => {
            blacklist_strike_ip(to.ip(), WarningType::HardWarning);
            Err(e)
        }
        a => {
            reset_blacklist_warnings(to.ip());
            a
        }
    }
}

async fn send_exit_status_request(
    exit_pubkey: WgKey,
    to: &SocketAddr,
    ident: ExitClientIdentity,
) -> Result<ExitState, RitaClientError> {
    let endpoint = format!("http://[{}]:{}/secure_status", to.ip(), to.port());
    let ident = encrypt_exit_client_id(&exit_pubkey.into(), ident);

    let client = awc::Client::default();
    let response = client
        .post(&endpoint)
        .timeout(CLIENT_LOOP_TIMEOUT)
        .send_json(&ident)
        .await;

    let mut response = match response {
        Ok(a) => {
            reset_blacklist_warnings(to.ip());
            a
        }
        Err(awc::error::SendRequestError::Timeout) => {
            // Did not get a response, is it a rogue exit or some netork error?
            blacklist_strike_ip(to.ip(), WarningType::SoftWarning);
            return Err(RitaClientError::SendRequestError(
                awc::error::SendRequestError::Timeout.to_string(),
            ));
        }
        Err(e) => return Err(RitaClientError::SendRequestError(e.to_string())),
    };
    let value = response.json().await?;

    match decrypt_exit_state(value, exit_pubkey.into()) {
        Err(e) => {
            blacklist_strike_ip(to.ip(), WarningType::HardWarning);
            Err(e)
        }
        Ok(a) => {
            reset_blacklist_warnings(to.ip());
            Ok(a)
        }
    }
}

async fn exit_general_details_request(exit: String) -> Result<(), RitaClientError> {
    let current_exit = match settings::get_rita_client().exit_client.exits.get(&exit) {
        Some(current_exit) => current_exit.clone(),
        None => {
            return Err(RitaClientError::NoExitError(exit));
        }
    };

    info!("Getting details for exit: {:?}", exit);
    let current_exit_ip = get_selected_exit(exit.clone()).expect("There should be an exit ip here");

    info!("Current exit ip is : {:?}", current_exit_ip);

    let endpoint = SocketAddr::new(current_exit_ip, current_exit.registration_port);

    info!(
        "sending exit general details request to {} with endpoint {:?}",
        exit, endpoint
    );
    let exit_details = get_exit_info(&endpoint).await?;
    let mut rita_client = settings::get_rita_client();
    let current_exit = match rita_client.exit_client.exits.get_mut(&exit) {
        Some(exit) => exit,
        None => return Err(RitaClientError::ExitNotFound(exit)),
    };
    current_exit.info = exit_details;
    settings::set_rita_client(rita_client);
    Ok(())
}

pub async fn exit_setup_request(exit: String, code: Option<String>) -> Result<(), RitaClientError> {
    let exit_client = settings::get_rita_client().exit_client;
    let current_exit = match exit_client.exits.get(&exit) {
        Some(exit_struct) => exit_struct.clone(),
        None => return Err(RitaClientError::ExitNotFound(exit)),
    };

    let current_exit_ip = get_selected_exit(exit.clone());

    // If exit is not setup in lazy static, set up with subnet ip
    let exit_server = match current_exit_ip {
        Some(a) => a,
        None => {
            // set this ip in the lazy static
            initialize_selected_exit_list(exit.clone(), current_exit.clone());
            current_exit.subnet.ip()
        }
    };
    let exit_pubkey = current_exit.wg_public_key;

    let exit_auth_type = match current_exit.info.general_details() {
        Some(details) => details.verif_mode,
        None => {
            return Err(RitaClientError::MiscStringError(
                "Exit is not ready to be setup!".to_string(),
            ))
        }
    };

    let mut reg_details: ExitRegistrationDetails =
        match settings::get_rita_client().exit_client.contact_info {
            Some(val) => val.into(),
            None => {
                if let ExitVerifMode::Off = exit_auth_type {
                    ExitRegistrationDetails {
                        email: None,
                        email_code: None,
                        phone: None,
                        phone_code: None,
                        sequence_number: None,
                    }
                } else {
                    return Err(RitaClientError::MiscStringError(
                        "No registration info set!".to_string(),
                    ));
                }
            }
        };

    match exit_auth_type {
        ExitVerifMode::Email => {
            reg_details.email_code = code;
        }
        ExitVerifMode::Phone => {
            reg_details.phone_code = code;
        }
        ExitVerifMode::Off => {}
    }

    let ident = ExitClientIdentity {
        global: match settings::get_rita_client().get_identity() {
            Some(id) => id,
            None => {
                return Err(RitaClientError::MiscStringError(
                    "Identity has no mesh IP ready yet".to_string(),
                ));
            }
        },
        wg_port: exit_client.wg_listen_port,
        reg_details,
    };

    let endpoint = SocketAddr::new(exit_server, current_exit.registration_port);

    info!(
        "sending exit setup request {:?} to {}, using {:?}",
        ident, exit, endpoint
    );

    let exit_response = send_exit_setup_request(exit_pubkey, endpoint, ident).await?;
    let mut rita_client = settings::get_rita_client();

    let current_exit = match rita_client.exit_client.exits.get_mut(&exit) {
        Some(exit_struct) => exit_struct,
        None => return Err(RitaClientError::ExitNotFound(exit)),
    };

    info!("Setting an exit setup response");
    current_exit.info = exit_response;
    settings::set_rita_client(rita_client);

    Ok(())
}

async fn exit_status_request(exit: String) -> Result<(), RitaClientError> {
    let current_exit = match settings::get_rita_client().exit_client.exits.get(&exit) {
        Some(current_exit) => current_exit.clone(),
        None => {
            return Err(RitaClientError::NoExitError(exit));
        }
    };
    let reg_details = match settings::get_rita_client().exit_client.contact_info {
        Some(val) => val.into(),
        None => {
            return Err(RitaClientError::MiscStringError(
                "No valid details".to_string(),
            ))
        }
    };

    let current_exit_ip = get_selected_exit(exit.clone());

    let exit_server = current_exit_ip.expect("There should be an exit ip here");
    let exit_pubkey = current_exit.wg_public_key;
    let ident = ExitClientIdentity {
        global: match settings::get_rita_client().get_identity() {
            Some(id) => id,
            None => {
                return Err(RitaClientError::MiscStringError(
                    "Identity has no mesh IP ready yet".to_string(),
                ));
            }
        },
        wg_port: settings::get_rita_client().exit_client.wg_listen_port,
        reg_details,
    };

    let endpoint = SocketAddr::new(exit_server, current_exit.registration_port);

    trace!(
        "sending exit status request to {} using {:?}",
        exit,
        endpoint
    );

    let exit_response = send_exit_status_request(exit_pubkey, &endpoint, ident).await?;
    let mut rita_client = settings::get_rita_client();
    let current_exit = match rita_client.exit_client.exits.get_mut(&exit) {
        Some(exit_struct) => exit_struct,
        None => return Err(RitaClientError::ExitNotFound(exit)),
    };
    current_exit.info = exit_response.clone();
    settings::set_rita_client(rita_client);

    trace!("Got exit status response {:?}", exit_response);
    Ok(())
}

fn correct_default_route(input: Option<DefaultRoute>) -> bool {
    match input {
        Some(v) => v.is_althea_default_route(),
        None => false,
    }
}

/// This function initializes the Selected Exit list every tick by adding an entry if there isnt one
/// THe reason we store this info is to get general details of all exits on the manual peers list
/// This function call should be moved to another location as it doesnt need to be called on every tick, only on startup
fn initialize_selected_exit_list(exit: String, server: ExitServer) {
    let list = &mut EXIT_MANAGER.write().unwrap().selected_exit_list;

    info!(
        "Setting initialized IP for exit {} with ip: {}",
        exit,
        server.subnet.ip()
    );
    list.entry(exit).or_insert_with(|| SelectedExit {
        selected_id: Some(server.subnet.ip()),
        selected_id_degradation: None,
        tracking_exit: None,
        selected_id_metric: None,
    });
}

pub async fn exit_manager_tick() {
    info!("Exit_Switcher: exit manager tick");
    let client_can_use_free_tier = { settings::get_rita_client().payment.client_can_use_free_tier };

    //  Get mut rita client to setup exits
    let rita_client = settings::get_rita_client();
    let current_exit = match rita_client.clone().exit_client.current_exit {
        Some(a) => a,
        None => "".to_string(),
    };
    let last_exit = get_selected_exit(current_exit.clone());
    let mut exits = rita_client.exit_client.exits;

    // Initialize all exits ip addrs in local lazy static if they havent been set already
    for (k, s) in exits.clone() {
        initialize_selected_exit_list(k, s);
    }

    let exit_ser_ref = exits.get_mut(&current_exit);

    // code that connects to the current exit server
    info!("About to setup exit tunnel!");
    if let Some(exit) = exit_ser_ref {
        info!("We have selected an exit!, {:?}", exit.clone());
        if let Some(general_details) = exit.clone().info.general_details() {
            info!("We have details for the selected exit!");

            // Logic to determnine what the best exit is and if we should switch
            let babel_port = settings::get_rita_client().network.babel_port;
            let exit_subnet = exit.subnet;

            let routes = match get_babel_routes(babel_port) {
                Ok(a) => a,
                Err(_) => {
                    warn!("No babel routes present to setup an exit");
                    return;
                }
            };

            info!("Exit_Switcher: Calling set best exit");
            let selected_exit = match set_best_exit(current_exit.clone(), exit_subnet, routes) {
                Ok(a) => Some(a),
                Err(e) => {
                    warn!("Found no exit yet : {}", e);
                    return;
                }
            };

            info!("Exit_Switcher: After selecting best exit this tick, we have selected_id: {:?}, selected_metric: {:?}, tracking_ip: {:?}", get_selected_exit(current_exit.clone()), get_selected_exit_metric(current_exit.clone()), get_selected_exit_tracking(current_exit.clone()));

            // check the exit's time and update locally if it's very different
            maybe_set_local_to_exit_time(exit.clone()).await;

            // Determine states to setup tunnels
            let signed_up_for_exit = exit.info.our_details().is_some();
            let exit_has_changed = !(last_exit.is_some()
                && selected_exit.is_some()
                && last_exit.unwrap() == selected_exit.unwrap());
            let correct_default_route = correct_default_route(KI.get_default_route());
            let current_exit_id = selected_exit;

            match (signed_up_for_exit, exit_has_changed, correct_default_route) {
                (true, true, _) => {
                    trace!("Exit change, setting up exit tunnel");
                    linux_setup_exit_tunnel(
                        current_exit,
                        exit,
                        &general_details.clone(),
                        exit.info.our_details().unwrap(),
                    )
                    .expect("failure setting up exit tunnel");
                    set_em_nat(true);
                }
                (true, false, false) => {
                    trace!("DHCP overwrite setup exit tunnel again");
                    linux_setup_exit_tunnel(
                        current_exit,
                        exit,
                        &general_details.clone(),
                        exit.info.our_details().unwrap(),
                    )
                    .expect("failure setting up exit tunnel");
                    set_em_nat(true);
                }
                _ => {}
            }

            // Adds and removes the nat rules in low balance situations
            // this prevents the free tier from being confusing (partially working)
            // when deployments are not interested in having a sufficiently fast one
            let low_balance = low_balance();
            let nat_setup = get_em_nat();
            trace!(
                "client can use free tier {} low balance {}",
                client_can_use_free_tier,
                low_balance
            );
            match (low_balance, client_can_use_free_tier, nat_setup) {
                // remove when we have a low balance, do not have a free tier
                // and have a nat setup.
                (true, false, true) => {
                    trace!("removing exit tunnel!");
                    remove_nat();
                    set_em_nat(false);
                }
                // restore when our balance is not low and our nat is not setup
                // regardless of the free tier value
                (false, _, false) => {
                    trace!("restoring exit tunnel!");
                    restore_nat();
                    set_em_nat(true);
                }
                // restore if the nat is not setup and the free tier is enabled
                // this only happens when settings change under the hood
                (true, true, false) => {
                    trace!("restoring exit tunnel!");
                    restore_nat();
                    set_em_nat(true);
                }
                _ => {}
            }

            // run billing at all times when an exit is setup
            if signed_up_for_exit {
                let exit_price = general_details.clone().exit_price;
                let exit_internal_addr = general_details.clone().server_internal_ip;
                let exit_port = exit.registration_port;
                let exit_id = Identity::new(
                    current_exit_id.expect("There should be a selected mesh ip here"),
                    exit.eth_address,
                    exit.wg_public_key,
                    None,
                );
                let babel_port = settings::get_rita_client().network.babel_port;
                info!("We are signed up for the selected exit!");

                let routes = match get_babel_routes(babel_port) {
                    Ok(a) => a,
                    Err(_) => {
                        error!("No babel routes present to query exit debts");
                        return;
                    }
                };

                query_exit_debts(QueryExitDebts {
                    exit_id,
                    exit_price,
                    routes,
                    exit_internal_addr,
                    exit_port,
                })
                .await;
            }
        }
    }

    // code that manages requesting details to exits
    let servers = { settings::get_rita_client().exit_client.exits };

    for (k, s) in servers {
        match s.info {
            ExitState::Denied { .. } | ExitState::Disabled | ExitState::GotInfo { .. } => {}

            ExitState::New { .. } => {
                match exit_general_details_request(k.clone()).await {
                    Ok(_) => {
                        trace!("exit details request to {} was successful", k);
                    }
                    Err(e) => {
                        trace!("exit details request to {} failed with {:?}", k, e);
                    }
                };
            }

            ExitState::Registered { .. } => {
                match exit_status_request(k.clone()).await {
                    Ok(_) => {
                        trace!("exit status request to {} was successful", k);
                    }
                    Err(e) => {
                        trace!("exit status request to {} failed with {:?}", k, e);
                    }
                };
            }

            state => {
                trace!("Waiting on exit state {:?} for {}", state, k);
            }
        }
    }

    // This block runs after an exit manager tick (an exit is selected),
    // and looks at the ipv6 subnet assigned to our router in the ExitState struct
    // which should be present after requesting general status from a registered exit.
    // This subnet is then added the lan network interface on the router to be used by slaac
    trace!("Setting up ipv6 for slaac");
    let rita_settings = settings::get_rita_client();
    let current_exit = rita_settings.exit_client.current_exit;
    if let Some(exit) = current_exit {
        let exit_ser = rita_settings.exit_client.exits.get(&exit);
        if let Some(exit_ser) = exit_ser {
            let exit_info = exit_ser.info.clone();

            if let ExitState::Registered { our_details, .. } = exit_info {
                if let Some(ipv6_sub) = our_details.internet_ipv6_subnet {
                    KI.setup_ipv6_slaac(ipv6_sub)
                }
            }
        }
    }
}
