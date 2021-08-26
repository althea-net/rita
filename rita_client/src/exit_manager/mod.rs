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

use crate::rita_loop::CLIENT_LOOP_TIMEOUT;
use crate::traffic_watcher::{query_exit_debts, QueryExitDebts};
use actix_web::client::Connection;

use actix_web::{client, HttpMessage, Result};
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
use failure::Error;
use futures01::future;
use futures01::Future;
use rita_common::blockchain_oracle::low_balance;
use rita_common::KI;
use settings::client::ExitServer;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::Nonce;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
use tokio::net::TcpStream as TokioTcpStream;

lazy_static! {
    pub static ref EXIT_MANAGER: Arc<RwLock<ExitManager>> =
        Arc::new(RwLock::new(ExitManager::default()));
}

fn linux_setup_exit_tunnel(
    current_exit: &ExitServer,
    general_details: &ExitDetails,
    our_details: &ExitClientDetails,
) -> Result<(), Error> {
    let mut rita_client = settings::get_rita_client();
    let mut network = rita_client.network;
    // TODO this should be refactored to return a value
    KI.update_settings_route(&mut network.last_default_route);

    if let Err(KernelInterfaceError::RuntimeError(v)) = KI.setup_wg_if_named("wg_exit") {
        return Err(format_err!("{}", v));
    }

    let args = ClientExitTunnelConfig {
        endpoint: SocketAddr::new(
            current_exit.selected_exit.selected_id.unwrap(),
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

    KI.set_client_exit_tunnel_config(args)?;
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

pub async fn get_exit_info(to: &SocketAddr) -> Result<ExitState, Error> {
    let endpoint = format!("http://[{}]:{}/exit_info", to.ip(), to.port());

    let client = awc::Client::default();
    let mut response = match client.get(&endpoint).send().await {
        Ok(a) => a,
        Err(e) => {
            bail!("Error with get request for exit info: {}", e);
        }
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

fn decrypt_exit_state(
    exit_state: EncryptedExitState,
    exit_pubkey: PublicKey,
) -> Result<ExitState, Error> {
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
                return Err(format_err!("Could not decrypt exit state"));
            }
        };
    Ok(decrypted_exit_state)
}

fn send_exit_setup_request(
    exit_pubkey: WgKey,
    to: &SocketAddr,
    ident: ExitClientIdentity,
) -> impl Future<Item = ExitState, Error = Error> {
    let endpoint = format!("http://[{}]:{}/secure_setup", to.ip(), to.port());
    let ident = encrypt_exit_client_id(&exit_pubkey.into(), ident);

    let stream = TokioTcpStream::connect(to);

    stream.from_err().and_then(move |stream| {
        client::post(&endpoint)
            .timeout(Duration::from_secs(600))
            .with_connection(Connection::from_stream(stream))
            .json(ident)
            .unwrap()
            .send()
            .from_err()
            .and_then(move |response| {
                response
                    .json()
                    .from_err()
                    .and_then(move |value: EncryptedExitState| {
                        decrypt_exit_state(value, exit_pubkey.into())
                    })
            })
    })
}

async fn send_exit_status_request(
    exit_pubkey: WgKey,
    to: &SocketAddr,
    ident: ExitClientIdentity,
) -> Result<ExitState, Error> {
    let endpoint = format!("http://[{}]:{}/secure_status", to.ip(), to.port());
    let ident = encrypt_exit_client_id(&exit_pubkey.into(), ident);

    let client = awc::Client::default();
    let response = client
        .post(&endpoint)
        .timeout(CLIENT_LOOP_TIMEOUT)
        .send_json(&ident)
        .await;

    let mut response = match response {
        Ok(a) => a,
        Err(e) => bail!("Error with post request for exit status: {}", e),
    };
    let value = response.json().await?;

    decrypt_exit_state(value, exit_pubkey.into())
}

async fn exit_general_details_request(exit: String) -> Result<(), Error> {
    let current_exit = match settings::get_rita_client().exit_client.exits.get(&exit) {
        Some(current_exit) => current_exit.clone(),
        None => {
            return Err(format_err!("No valid exit for {}", exit));
        }
    };

    let current_exit_ip = match current_exit.selected_exit.selected_id {
        Some(a) => a,
        None => return Err(format_err!("No valid exit for {}", exit)),
    };

    let endpoint = SocketAddr::new(current_exit_ip, current_exit.registration_port);

    trace!("sending exit general details request to {}", exit);
    let exit_details = get_exit_info(&endpoint).await?;
    let mut rita_client = settings::get_rita_client();
    let current_exit = match rita_client.exit_client.exits.get_mut(&exit) {
        Some(exit) => exit,
        None => bail!("Could not find exit {}", exit),
    };
    current_exit.info = exit_details;
    settings::set_rita_client(rita_client);
    Ok(())
}

pub fn exit_setup_request(
    exit: String,
    code: Option<String>,
) -> Box<dyn Future<Item = (), Error = Error>> {
    let exit_client = settings::get_rita_client().exit_client;
    let current_exit = match exit_client.exits.get(&exit) {
        Some(exit_struct) => exit_struct.clone(),
        None => return Box::new(future::err(format_err!("Could not find exit {:?}", exit))),
    };

    let current_exit_ip = match current_exit.selected_exit.selected_id {
        Some(a) => a,
        None => {
            return Box::new(future::err(format_err!(
                "Found exitServer: {:?}, but no exit ip",
                exit
            )))
        }
    };

    let exit_server = current_exit_ip;
    let exit_pubkey = current_exit.wg_public_key;

    let exit_auth_type = match current_exit.info.general_details() {
        Some(details) => details.verif_mode,
        None => return Box::new(future::err(format_err!("Exit is not ready to be setup!"))),
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
                    }
                } else {
                    return Box::new(future::err(format_err!("No registration info set!")));
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
                return Box::new(future::err(format_err!(
                    "Identity has no mesh IP ready yet"
                )));
            }
        },
        wg_port: exit_client.wg_listen_port,
        reg_details,
    };

    let endpoint = SocketAddr::new(exit_server, current_exit.registration_port);

    trace!(
        "sending exit setup request {:?} to {}, using {:?}",
        ident,
        exit,
        endpoint
    );

    Box::new(
        send_exit_setup_request(exit_pubkey, &endpoint, ident)
            .from_err()
            .and_then(move |exit_response| {
                let mut rita_client = settings::get_rita_client();

                let current_exit = match rita_client.exit_client.exits.get_mut(&exit) {
                    Some(exit_struct) => exit_struct,
                    None => bail!("Could not find exit {:?}", exit),
                };

                current_exit.info = exit_response;
                settings::set_rita_client(rita_client);

                Ok(())
            }),
    )
}

async fn exit_status_request(exit: String) -> Result<(), Error> {
    let current_exit = match settings::get_rita_client().exit_client.exits.get(&exit) {
        Some(current_exit) => current_exit.clone(),
        None => {
            return Err(format_err!("No valid exit for {}", exit));
        }
    };
    let reg_details = match settings::get_rita_client().exit_client.contact_info {
        Some(val) => val.into(),
        None => return Err(format_err!("No valid details")),
    };

    let current_exit_ip = match current_exit.selected_exit.selected_id {
        Some(a) => a,
        None => return Err(format_err!("No valid exit for {}", exit)),
    };

    let exit_server = current_exit_ip;
    let exit_pubkey = current_exit.wg_public_key;
    let ident = ExitClientIdentity {
        global: match settings::get_rita_client().get_identity() {
            Some(id) => id,
            None => {
                return Err(format_err!("Identity has no mesh IP ready yet"));
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
        None => bail!("Could not find exit {:?}", exit),
    };
    current_exit.info = exit_response.clone();
    settings::set_rita_client(rita_client);
    trace!("Got exit status response {:?}", exit_response);
    Ok(())
}

/// An actor which pays the exit
#[derive(Default)]
pub struct ExitManager {
    // used to determine if we've changed exits
    pub last_exit: Option<ExitServer>,
    pub nat_setup: bool,
}

fn correct_default_route(input: Option<DefaultRoute>) -> bool {
    match input {
        Some(v) => v.is_althea_default_route(),
        None => false,
    }
}

pub async fn exit_manager_tick() {
    info!("Exit_Switcher: exit manager tick");
    let client_can_use_free_tier = { settings::get_rita_client().payment.client_can_use_free_tier };

    //  Get mut rita client server to setup exits
    let mut rita_client = settings::get_rita_client();
    let current_exit = match rita_client.clone().exit_client.current_exit {
        Some(a) => a,
        None => "".to_string(),
    };
    let mut exits = rita_client.exit_client.exits;

    let exit_ser_ref = exits.get_mut(&current_exit);

    // code that connects to the current exit server
    info!("About to setup exit tunnel!");
    if let Some(exit) = exit_ser_ref {
        info!("We have selected an exit!");
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
            let selected_exit = match set_best_exit(exit_subnet, routes, exit) {
                Ok(a) => Some(a),
                Err(e) => {
                    warn!("Found no exit yet : {}", e);
                    return;
                }
            };

            //set in rita client
            let exit = exit.clone();
            rita_client.exit_client.exits = exits;
            settings::set_rita_client(rita_client);

            info!("Exit_Switcher: After selecting best exit this tick, we have selected_id: {:?}, selected_metric: {:?}, tracking_ip: {:?}", exit.clone().selected_exit.selected_id, exit.clone().selected_exit.selected_id_metric, exit.clone().selected_exit.tracking_exit);

            // Determine states to setup tunnels
            let mut writer = &mut *EXIT_MANAGER.write().unwrap();
            let signed_up_for_exit = exit.info.our_details().is_some();
            let exit_has_changed = !(writer.last_exit.is_some()
                && writer
                    .last_exit
                    .clone()
                    .unwrap()
                    .selected_exit
                    .selected_id
                    .is_some()
                && writer
                    .last_exit
                    .clone()
                    .unwrap()
                    .selected_exit
                    .selected_id
                    .unwrap()
                    == selected_exit.unwrap());
            let correct_default_route = correct_default_route(KI.get_default_route());

            match (signed_up_for_exit, exit_has_changed, correct_default_route) {
                (true, true, _) => {
                    trace!("Exit change, setting up exit tunnel");
                    linux_setup_exit_tunnel(
                        &exit,
                        &general_details.clone(),
                        exit.info.our_details().unwrap(),
                    )
                    .expect("failure setting up exit tunnel");
                    writer.nat_setup = true;
                    writer.last_exit = Some(exit.clone());
                }
                (true, false, false) => {
                    trace!("DHCP overwrite setup exit tunnel again");
                    linux_setup_exit_tunnel(
                        &exit,
                        &general_details.clone(),
                        exit.info.our_details().unwrap(),
                    )
                    .expect("failure setting up exit tunnel");
                    writer.nat_setup = true;
                }
                _ => {}
            }

            // Adds and removes the nat rules in low balance situations
            // this prevents the free tier from being confusing (partially working)
            // when deployments are not interested in having a sufficiently fast one
            let low_balance = low_balance();
            let nat_setup = writer.nat_setup;
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
                    writer.nat_setup = false;
                }
                // restore when our balance is not low and our nat is not setup
                // regardless of the free tier value
                (false, _, false) => {
                    trace!("restoring exit tunnel!");
                    restore_nat();
                    writer.nat_setup = true;
                }
                // restore if the nat is not setup and the free tier is enabled
                // this only happens when settings change under the hood
                (true, true, false) => {
                    trace!("restoring exit tunnel!");
                    restore_nat();
                    writer.nat_setup = true;
                }
                _ => {}
            }

            // run billing at all times when an exit is setup
            if signed_up_for_exit {
                let exit_price = general_details.clone().exit_price;
                let exit_internal_addr = general_details.clone().server_internal_ip;
                let exit_port = exit.registration_port;
                let exit_id = Identity::new(
                    exit.selected_exit.selected_id.unwrap(),
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
}
