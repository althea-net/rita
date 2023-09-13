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

pub mod exit_loop;
pub mod exit_switcher;
pub mod time_sync;

use crate::rita_loop::CLIENT_LOOP_TIMEOUT;
use crate::RitaClientError;
use actix_web_async::Result;
use althea_kernel_interface::{
    exit_client_tunnel::ClientExitTunnelConfig, DefaultRoute, KernelInterfaceError,
};
use althea_types::ExitClientDetails;
use althea_types::WgKey;
use althea_types::{EncryptedExitClientIdentity, EncryptedExitState};
use althea_types::{EncryptedExitList, ExitDetails, ExitList};
use althea_types::{ExitClientIdentity, ExitRegistrationDetails, ExitState, ExitVerifMode};
use babel_monitor::structs::Route;
use ipnetwork::IpNetwork;
use rita_common::KI;
use settings::client::{ExitServer, SelectedExit};
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::Nonce;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
use std::time::Instant;

/// The number of times ExitSwitcher will try to connect to an unresponsive exit before blacklisting its ip
const MAX_BLACKLIST_STRIKES: u16 = 100;

lazy_static! {
    pub static ref SELECTED_EXIT_LIST: Arc<RwLock<SelectedExitList>> =
        Arc::new(RwLock::new(SelectedExitList::default()));
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

#[derive(Default)]
pub struct SelectedExitList {
    /// Hashmap of Structs containing information of current exit we are connected to and tracking exit, if connected to one
    /// It also holds information about metrics and degradation values. Look at doc comment on 'set_best_exit' for more
    /// information on what these mean
    pub selected_exit_list: HashMap<String, SelectedExit>,
    /// This struct hold infomation about exits that have misbehaved and are blacklisted, or are being watched
    /// to being blacklisted through bad responses.
    pub exit_blacklist: ExitBlacklist,
}

/// Data to use identity whether a clients wg exit tunnel needs to be setup up again across ticks
#[derive(Default, Clone)]
pub struct LastExitStates {
    last_exit: Option<IpAddr>,
    last_exit_details: Option<ExitState>,
}

/// An actor which pays the exit
#[derive(Clone)]
pub struct ExitManager {
    pub nat_setup: bool,
    /// Every tick we query an exit endpoint to get a list of exits in that cluster. We use this list for exit switching
    pub exit_list: ExitList,
    /// Store last exit here, when we see an exit change, we reset wg tunnels
    pub last_exit_state: LastExitStates,
    /// Store exit connection status. If no update in > 10, perform a power cycle
    pub last_connection_time: Instant,
    /// Store the last exit status request for all registered exits
    pub last_status_request: Option<Instant>,
}

impl Default for ExitManager {
    fn default() -> Self {
        ExitManager {
            nat_setup: false,
            exit_list: ExitList::default(),
            last_exit_state: LastExitStates::default(),
            last_connection_time: Instant::now(),
            last_status_request: None,
        }
    }
}

/// This functions sets the exit list ONLY IF the list arguments provived is not empty. This is need for the following edge case:
/// When an exit goes down, the endpoint wont repsond, so we have no exits to switch to. By setting only when we have a length > 1
/// we assure that we switch when an exit goes down
pub fn set_exit_list(list: ExitList, em_state: &mut ExitManager) -> bool {
    if !list.exit_list.is_empty() {
        em_state.exit_list = list;
        return true;
    }
    false
}

pub fn get_selected_exit_ip(exit: String) -> Option<IpAddr> {
    match SELECTED_EXIT_LIST
        .read()
        .unwrap()
        .selected_exit_list
        .get(&exit)
    {
        Some(a) => a.selected_id,
        None => None,
    }
}

pub fn get_full_selected_exit(exit: String) -> Option<SelectedExit> {
    SELECTED_EXIT_LIST
        .read()
        .unwrap()
        .selected_exit_list
        .get(&exit)
        .cloned()
}

pub fn set_selected_exit(exit: String, exit_info: SelectedExit) {
    SELECTED_EXIT_LIST
        .write()
        .unwrap()
        .selected_exit_list
        .insert(exit, exit_info);
}

pub fn get_exit_blacklist() -> HashSet<IpAddr> {
    SELECTED_EXIT_LIST
        .read()
        .unwrap()
        .exit_blacklist
        .blacklisted_exits
        .clone()
}

fn linux_setup_exit_tunnel(
    exit: String,
    general_details: &ExitDetails,
    our_details: &ExitClientDetails,
    exit_list: &ExitList,
) -> Result<(), RitaClientError> {
    let mut rita_client = settings::get_rita_client();
    let mut network = rita_client.network;
    let local_mesh_ip = network.mesh_ip;

    // TODO this should be refactored to return a value
    KI.update_settings_route(&mut network.last_default_route)?;
    info!("Updated settings route");

    if let Err(KernelInterfaceError::RuntimeError(v)) = KI.setup_wg_if_named("wg_exit") {
        return Err(RitaClientError::MiscStringError(v));
    }

    let selected_ip = get_selected_exit_ip(exit).expect("There should be an exit ip here");
    let args = ClientExitTunnelConfig {
        endpoint: SocketAddr::new(selected_ip, exit_list.wg_exit_listen_port),
        pubkey: get_exit_pubkey(selected_ip, exit_list),
        private_key_path: network.wg_private_key_path.clone(),
        listen_port: rita_client.exit_client.wg_listen_port,
        local_ip: our_details.client_internal_ip,
        netmask: general_details.netmask,
        rita_hello_port: network.rita_hello_port,
        user_specified_speed: network.user_bandwidth_limit,
    };

    info!("Args while setting up wg_exit on client are: {:?}", args);

    rita_client.network = network;
    settings::set_rita_client(rita_client);

    KI.set_client_exit_tunnel_config(args, local_mesh_ip)?;
    KI.set_route_to_tunnel(&general_details.server_internal_ip)?;
    KI.set_ipv6_route_to_tunnel()?;

    KI.create_client_nat_rules()?;

    Ok(())
}

/// From a exit list, find the corresponding wg public key of our current connected exit to
/// set up wg tunnels
fn get_exit_pubkey(ip: IpAddr, exit_list: &ExitList) -> WgKey {
    for id in exit_list.exit_list.clone() {
        if id.mesh_ip == ip {
            return id.wg_public_key;
        }
    }

    panic!("Unable to find a valid wg key for current exit, please check that all exit Identities are properly setup on the exit");
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
        Err(e) => {
            warn!("Unable to get exit info with {}", e);
            return Err(RitaClientError::SendRequestError(e.to_string()));
        }
    };
    let response_json = response.json().await?;

    info!("Received {:?} from endpoint {:?}", response_json, endpoint);
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
    let writer = &mut SELECTED_EXIT_LIST.write().unwrap().exit_blacklist;

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
    let writer = &mut SELECTED_EXIT_LIST.write().unwrap().exit_blacklist;

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
    let writer = &mut SELECTED_EXIT_LIST.write().unwrap().exit_blacklist;

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
    error!("Trying to hit endpoint: {:?}", endpoint);

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

    trace!("Getting details for exit: {:?}", exit);
    let current_exit_ip =
        get_selected_exit_ip(exit.clone()).expect("There should be a selected ip here");

    trace!("Current exit ip is : {:?}", current_exit_ip);

    let endpoint = SocketAddr::new(current_exit_ip, current_exit.registration_port);

    trace!(
        "sending exit general details request to {} with endpoint {:?}",
        exit,
        endpoint
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

    let current_exit_ip = get_selected_exit_ip(exit.clone());

    // If exit is not setup in lazy static, set up with subnet ip
    let exit_server = match current_exit_ip {
        Some(a) => a,
        None => {
            // set this ip in the lazy static
            initialize_selected_exit_list(exit.clone(), current_exit.clone());
            current_exit.root_ip
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

    let current_exit_ip = get_selected_exit_ip(exit.clone());

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

async fn get_cluster_ip_list(exit: String) -> Result<ExitList, RitaClientError> {
    let current_exit_cluster = match settings::get_rita_client().exit_client.exits.get(&exit) {
        Some(current_exit) => current_exit.clone(),
        None => {
            return Err(RitaClientError::NoExitError(exit));
        }
    };

    let exit_pubkey = current_exit_cluster.wg_public_key;
    let reg_details = match settings::get_rita_client().exit_client.contact_info {
        Some(val) => val.into(),
        None => {
            return Err(RitaClientError::MiscStringError(
                "No valid details".to_string(),
            ))
        }
    };
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

    let current_exit_ip = get_selected_exit_ip(exit.clone());
    let exit_server = current_exit_ip.expect("There should be an exit ip here");

    let endpoint = format!(
        "http://[{}]:{}/exit_list",
        exit_server, current_exit_cluster.registration_port
    );
    let ident = encrypt_exit_client_id(&exit_pubkey.into(), ident);

    let client = awc::Client::default();
    let response = client
        .post(&endpoint)
        .timeout(CLIENT_LOOP_TIMEOUT)
        .send_json(&ident)
        .await;
    let mut response = match response {
        Ok(a) => {
            reset_blacklist_warnings(exit_server);
            a
        }
        Err(awc::error::SendRequestError::Timeout) => {
            // Did not get a response, is it a rogue exit or some netork error?
            blacklist_strike_ip(exit_server, WarningType::SoftWarning);
            return Err(RitaClientError::SendRequestError(
                awc::error::SendRequestError::Timeout.to_string(),
            ));
        }
        Err(e) => return Err(RitaClientError::SendRequestError(e.to_string())),
    };

    let value = response.json().await?;

    match decrypt_exit_list(value, exit_pubkey.into()) {
        Err(e) => {
            blacklist_strike_ip(exit_server, WarningType::HardWarning);
            Err(e)
        }
        Ok(a) => {
            reset_blacklist_warnings(exit_server);
            Ok(a)
        }
    }
}

fn decrypt_exit_list(
    exit_list: EncryptedExitList,
    exit_pubkey: PublicKey,
) -> Result<ExitList, RitaClientError> {
    let rita_client = settings::get_rita_client();
    let network_settings = rita_client.network;
    let our_secretkey = network_settings
        .wg_private_key
        .expect("No private key?")
        .into();
    let ciphertext = exit_list.exit_list;
    let nonce = Nonce(exit_list.nonce);
    let ret: ExitList = match box_::open(&ciphertext, &nonce, &exit_pubkey, &our_secretkey) {
        Ok(decrypted_bytes) => match String::from_utf8(decrypted_bytes) {
            Ok(json_string) => match serde_json::from_str(&json_string) {
                Ok(ip_list) => ip_list,
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
    Ok(ret)
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
    let list = &mut SELECTED_EXIT_LIST.write().unwrap().selected_exit_list;

    info!(
        "Setting initialized IP for exit {} with ip: {}",
        exit, server.root_ip
    );
    list.entry(exit).or_insert_with(|| SelectedExit {
        selected_id: Some(server.root_ip),
        selected_id_degradation: None,
        tracking_exit: None,
        selected_id_metric: None,
    });
}

/// This function takes a list of babel routes and uses this to insert ip -> route
/// instances in the hashmap. This is an optimization that allows us to reduce route lookups from O(n * m ) to O(m + n)
/// when trying to find exit ips in our cluster
fn get_routes_hashmap(routes: Vec<Route>) -> HashMap<IpAddr, Route> {
    let mut ret = HashMap::new();
    for r in routes {
        ret.insert(r.prefix.ip(), r);
    }

    ret
}

pub fn get_client_pub_ipv6() -> Option<IpNetwork> {
    let rita_settings = settings::get_rita_client();
    let current_exit = rita_settings.exit_client.current_exit;
    if let Some(exit) = current_exit {
        let exit_ser = rita_settings.exit_client.exits.get(&exit);
        if let Some(exit_ser) = exit_ser {
            let exit_info = exit_ser.info.clone();

            if let ExitState::Registered { our_details, .. } = exit_info {
                return our_details.internet_ipv6_subnet;
            }
        }
    }
    None
}

/// Verifies ipv4 connectivity by pinging 1.1.1.1
pub fn run_ping_test() -> bool {
    let cloudflare: IpAddr = Ipv4Addr::new(1, 1, 1, 1).into();
    let timeout = Duration::from_secs(5);
    match KI.ping_check(&cloudflare, timeout, None) {
        Ok(out) => out,
        Err(e) => {
            error!("ipv4 ping error: {:?}", e);
            false
        }
    }
}

/// Verfies if exit has changed to reestablish wg tunnels
/// 1.) When exit instance ip has changed
/// 2.) Exit reg details have chaged
pub fn has_exit_changed(
    state: LastExitStates,
    selected_exit: Option<IpAddr>,
    cluster: ExitServer,
) -> bool {
    let last_exit = state.last_exit;

    let instance_has_changed = !(last_exit.is_some()
        && selected_exit.is_some()
        && last_exit.unwrap() == selected_exit.unwrap());

    let last_exit_details = state.last_exit_details;
    let exit_reg_has_changed =
        !(last_exit_details.is_some() && last_exit_details.unwrap() == cluster.info);

    instance_has_changed | exit_reg_has_changed
}

#[cfg(test)]
mod tests {
    use althea_types::SystemChain;

    use super::*;

    #[test]
    fn test_exit_has_changed() {
        let mut exit_server = ExitServer {
            root_ip: "fd00::1337".parse().unwrap(),
            subnet: None,
            eth_address: "0xd2C5b6dd6ca641BE4c90565b5d3DA34C14949A53"
                .parse()
                .unwrap(),
            registration_port: 3452,
            wg_public_key: "V9I9yrxAqFqLV+9GeT5pnXPwk4Cxgfvl30Fv8khVGsM="
                .parse()
                .unwrap(),
            description: "Dummy exit server!".to_string(),
            info: ExitState::New,
        };
        let dummy_exit_details = ExitDetails {
            server_internal_ip: "172.0.0.1".parse().unwrap(),
            netmask: 0,
            wg_exit_port: 123,
            exit_price: 123,
            exit_currency: SystemChain::Xdai,
            description: "".to_string(),
            verif_mode: ExitVerifMode::Off,
        };
        let mut last_states = LastExitStates::default();

        // Exit moves from New -> GotInfo
        exit_server.info = ExitState::GotInfo {
            general_details: dummy_exit_details.clone(),
            message: "".to_string(),
        };

        // An ip is selected and setup in last_states
        let selected_exit = Some("fd00::2602".parse().unwrap());

        assert!(has_exit_changed(
            last_states.clone(),
            selected_exit,
            exit_server.clone()
        ));

        // Last states get updated next tick
        last_states.last_exit = Some("fd00::2602".parse().unwrap());
        last_states.last_exit_details = Some(exit_server.info.clone());
        assert!(!has_exit_changed(
            last_states.clone(),
            selected_exit,
            exit_server.clone()
        ));

        // Registration Details change
        exit_server.info = ExitState::Registered {
            general_details: dummy_exit_details.clone(),
            our_details: ExitClientDetails {
                client_internal_ip: "172.1.1.1".parse().unwrap(),
                internet_ipv6_subnet: None,
            },
            message: "".to_string(),
        };
        assert!(has_exit_changed(
            last_states.clone(),
            selected_exit,
            exit_server.clone()
        ));

        // next tick last stats get updated accordingly
        last_states.last_exit_details = Some(exit_server.info.clone());

        // Registration detail for client change
        exit_server.info = ExitState::Registered {
            general_details: dummy_exit_details,
            our_details: ExitClientDetails {
                client_internal_ip: "172.1.1.14".parse().unwrap(),
                internet_ipv6_subnet: None,
            },
            message: "".to_string(),
        };
        assert!(has_exit_changed(
            last_states.clone(),
            selected_exit,
            exit_server.clone()
        ));

        // next tick its updated accordingly
        last_states.last_exit_details = Some(exit_server.info.clone());
        assert!(!has_exit_changed(last_states, selected_exit, exit_server));
    }
}
