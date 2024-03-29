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

use crate::heartbeat::get_selected_exit_server;
use crate::rita_loop::CLIENT_LOOP_TIMEOUT;
use crate::RitaClientError;
use actix_web_async::Result;
use althea_kernel_interface::{
    exit_client_tunnel::ClientExitTunnelConfig, DefaultRoute, KernelInterfaceError,
};
use althea_types::exit_identity_to_id;
use althea_types::ExitClientDetails;
use althea_types::ExitListV2;
use althea_types::Identity;
use althea_types::WgKey;
use althea_types::{EncryptedExitClientIdentity, EncryptedExitState};
use althea_types::{EncryptedExitList, ExitDetails};
use althea_types::{ExitClientIdentity, ExitRegistrationDetails, ExitState};
use babel_monitor::structs::Route;
use ipnetwork::IpNetwork;
use rita_common::KI;
use settings::client::{ExitServer, SelectedExit};
use settings::get_rita_client;
use settings::set_rita_client;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::Nonce;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Instant;

/// The number of times ExitSwitcher will try to connect to an unresponsive exit before blacklisting its ip
const MAX_BLACKLIST_STRIKES: u16 = 100;

lazy_static! {
    pub static ref SELECTED_EXIT_DETAILS: Arc<RwLock<SelectedExitDetails>> =
        Arc::new(RwLock::new(SelectedExitDetails::default()));
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
pub struct SelectedExitDetails {
    /// information of current exit we are connected to and tracking exit, if connected to one
    /// It also holds information about metrics and degradation values. Look at doc comment on 'set_best_exit' for more
    /// information on what these mean
    pub selected_exit: SelectedExit,
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
#[derive(Clone, Default)]
pub struct ExitManager {
    pub nat_setup: bool,
    /// Every tick we query an exit endpoint to get a list of exits in that cluster. We use this list for exit switching
    pub exit_list: ExitListV2,
    /// Store last exit here, when we see an exit change, we reset wg tunnels
    pub last_exit_state: LastExitStates,
    pub last_status_request: Option<Instant>,
}

/// This functions sets the exit list ONLY IF the list arguments provived is not empty. This is need for the following edge case:
/// When an exit goes down, the endpoint wont repsond, so we have no exits to switch to. By setting only when we have a length > 1
/// we assure that we switch when an exit goes down
pub fn set_exit_list(list: ExitListV2, em_state: &mut ExitManager) -> bool {
    if !list.exit_list.is_empty() {
        em_state.exit_list = list;
        return true;
    }
    false
}

pub fn get_current_exit() -> Option<IpAddr> {
    SELECTED_EXIT_DETAILS
        .read()
        .unwrap()
        .selected_exit
        .selected_id
}

pub fn get_full_selected_exit() -> SelectedExit {
    SELECTED_EXIT_DETAILS.read().unwrap().selected_exit.clone()
}

pub fn set_selected_exit(exit_info: SelectedExit) {
    SELECTED_EXIT_DETAILS.write().unwrap().selected_exit = exit_info;
}

pub fn get_exit_blacklist() -> HashSet<IpAddr> {
    SELECTED_EXIT_DETAILS
        .read()
        .unwrap()
        .exit_blacklist
        .blacklisted_exits
        .clone()
}

fn linux_setup_exit_tunnel(
    general_details: &ExitDetails,
    our_details: &ExitClientDetails,
) -> Result<(), RitaClientError> {
    let mut rita_client = settings::get_rita_client();
    let mut network = rita_client.network;
    let local_mesh_ip = network.mesh_ip;

    // TODO this should be refactored to return a value
    KI.update_settings_route(&mut network.last_default_route)?;
    info!("Updated settings route");

    if let Err(KernelInterfaceError::RuntimeError(v)) = KI.create_blank_wg_interface("wg_exit") {
        return Err(RitaClientError::MiscStringError(v));
    }

    let selected_exit = get_selected_exit_server().expect("There should be a selected exit here");
    let args = ClientExitTunnelConfig {
        endpoint: SocketAddr::new(
            selected_exit.exit_id.mesh_ip,
            selected_exit.wg_exit_listen_port,
        ),
        pubkey: selected_exit.exit_id.wg_public_key,
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
    let writer = &mut SELECTED_EXIT_DETAILS.write().unwrap().exit_blacklist;

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
    let writer = &mut SELECTED_EXIT_DETAILS.write().unwrap().exit_blacklist;

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
    let writer = &mut SELECTED_EXIT_DETAILS.write().unwrap().exit_blacklist;

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

/// When we retrieve an exit list from an exit, add the compatible exits to the exit server list.
/// This allows these exits to move to GotInfo state, allowing us to switch or connect quickly
pub fn add_exits_to_exit_server_list(list: ExitListV2) {
    let mut rita_client = settings::get_rita_client();
    let mut exits = rita_client.exit_client.exits;

    for e in list.exit_list {
        exits.entry(e.mesh_ip).or_insert(ExitServer {
            exit_id: exit_identity_to_id(e.clone()),
            registration_port: e.registration_port,
            wg_exit_listen_port: e.wg_exit_listen_port,
            info: ExitState::New,
        });
    }

    // Update settings with new exits
    rita_client.exit_client.exits = exits;
    set_rita_client(rita_client);
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

/// Registration is simply one of the exits requesting an update to a global smart contract
/// with our information.
pub async fn exit_setup_request(code: Option<String>) -> Result<(), RitaClientError> {
    let exit_client = settings::get_rita_client().exit_client;

    for (_, exit) in exit_client.exits {
        match &exit.info {
            ExitState::New { .. } | ExitState::Pending { .. } => {
                let exit_pubkey = exit.exit_id.wg_public_key;

                let mut reg_details: ExitRegistrationDetails =
                    match settings::get_rita_client().exit_client.contact_info {
                        Some(val) => val.into(),
                        None => {
                            return Err(RitaClientError::MiscStringError(
                                "No registration info set!".to_string(),
                            ))
                        }
                    };

                // Send a verification code if we have one
                reg_details.phone_code = code;

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

                let endpoint = SocketAddr::new(exit.exit_id.mesh_ip, exit.registration_port);

                info!(
                    "sending exit setup request {:?} to {:?}, using {:?}",
                    ident, exit, endpoint
                );

                let exit_response = send_exit_setup_request(exit_pubkey, endpoint, ident).await?;

                info!("Setting an exit setup response");
                let mut rita_client = get_rita_client();
                if let Some(exit_to_update) =
                    rita_client.exit_client.exits.get_mut(&exit.exit_id.mesh_ip)
                {
                    exit_to_update.info = exit_response;
                } else {
                    warn!("Could not find an exit we just queried?");
                }

                set_rita_client(rita_client);
                return Ok(());
            }
            ExitState::Denied { message } => {
                warn!(
                    "Exit {} is in ExitState DENIED with {}, not able to be setup",
                    exit.exit_id.mesh_ip, message
                );
            }
            ExitState::Registered { .. } => {
                warn!(
                    "Exit {} already reports us as registered",
                    exit.exit_id.mesh_ip
                )
            }
            ExitState::GotInfo { .. } => {
                warn!("This state should be removed for new clients and is kept around for backward compatibilty, how did we reach it?");
            }
        }
    }

    Err(RitaClientError::MiscStringError(
        "Could not find a valid exit to register to!".to_string(),
    ))
}

async fn exit_status_request(exit: IpAddr) -> Result<(), RitaClientError> {
    let current_exit = match settings::get_rita_client().exit_client.exits.get(&exit) {
        Some(current_exit) => current_exit.clone(),
        None => {
            return Err(RitaClientError::NoExitError(exit.to_string()));
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

    let exit_pubkey = current_exit.exit_id.wg_public_key;
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

    let endpoint = SocketAddr::new(current_exit.exit_id.mesh_ip, current_exit.registration_port);

    trace!(
        "sending exit status request to {} using {:?}",
        exit,
        endpoint
    );

    let exit_response = send_exit_status_request(exit_pubkey, &endpoint, ident).await?;
    let mut rita_client = settings::get_rita_client();
    let current_exit = match rita_client.exit_client.exits.get_mut(&exit) {
        Some(exit_struct) => exit_struct,
        None => return Err(RitaClientError::ExitNotFound(exit.to_string())),
    };
    current_exit.info = exit_response.clone();
    settings::set_rita_client(rita_client);

    trace!("Got exit status response {:?}", exit_response);
    Ok(())
}

/// Hits the exit_list endpoint for a given exit.
async fn get_exit_list(exit: IpAddr) -> Result<ExitListV2, RitaClientError> {
    let current_exit = match settings::get_rita_client().exit_client.exits.get(&exit) {
        Some(current_exit) => current_exit.clone(),
        None => {
            return Err(RitaClientError::NoExitError(exit.to_string()));
        }
    };

    let exit_pubkey = current_exit.exit_id.wg_public_key;
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

    let exit_server = current_exit.exit_id.mesh_ip;

    let endpoint = format!(
        "http://[{}]:{}/exit_list_v2",
        exit_server, current_exit.registration_port
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
) -> Result<ExitListV2, RitaClientError> {
    let rita_client = settings::get_rita_client();
    let network_settings = rita_client.network;
    let our_secretkey = network_settings
        .wg_private_key
        .expect("No private key?")
        .into();
    let ciphertext = exit_list.exit_list;
    let nonce = Nonce(exit_list.nonce);
    let ret: ExitListV2 = match box_::open(&ciphertext, &nonce, &exit_pubkey, &our_secretkey) {
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

/// Exits are ready to switch to when they are in the Registered State, we return list of exits that are
pub fn get_ready_to_switch_exits(exit_list: ExitListV2) -> Vec<Identity> {
    let exits = get_rita_client().exit_client.exits;

    let mut ret = vec![];
    for exit in exit_list.exit_list {
        match exits.get(&exit.mesh_ip) {
            Some(server) => {
                if let ExitState::Registered { .. } = server.info {
                    ret.push(exit_identity_to_id(exit));
                }
            }
            None => {
                error!("Exit List logic error! All entries of exit list should be setup in config!")
            }
        }
    }
    ret
}

pub fn get_client_pub_ipv6() -> Option<IpNetwork> {
    let rita_settings = settings::get_rita_client();
    let current_exit = get_current_exit();
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
    use althea_types::{ExitVerifMode, SystemChain};

    use super::*;

    #[test]
    fn test_exit_has_changed() {
        let mut exit_server = ExitServer {
            exit_id: Identity {
                mesh_ip: "fd00::1337".parse().unwrap(),
                eth_address: "0xd2C5b6dd6ca641BE4c90565b5d3DA34C14949A53"
                    .parse()
                    .unwrap(),
                wg_public_key: "V9I9yrxAqFqLV+9GeT5pnXPwk4Cxgfvl30Fv8khVGsM="
                    .parse()
                    .unwrap(),
                nickname: None,
            },

            registration_port: 3452,
            wg_exit_listen_port: 59998,

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
