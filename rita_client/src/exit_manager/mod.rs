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

use crate::rita_loop::Tick;
use crate::rita_loop::CLIENT_LOOP_TIMEOUT;
use crate::traffic_watcher::{QueryExitDebts, TrafficWatcher};
use actix::registry::SystemService;
use actix::{Actor, Arbiter, Context, Handler, ResponseFuture, Supervised};
use actix_web::client::Connection;
use actix_web::{client, HttpMessage, Result};
use althea_kernel_interface::{
    exit_client_tunnel::ClientExitTunnelConfig, DefaultRoute, KernelInterfaceError,
};
use althea_types::ExitClientDetails;
use althea_types::ExitDetails;
use althea_types::WgKey;
use althea_types::{EncryptedExitClientIdentity, EncryptedExitState};
use althea_types::{ExitClientIdentity, ExitRegistrationDetails, ExitState, ExitVerifMode};
use babel_monitor_legacy::open_babel_stream_legacy;
use babel_monitor_legacy::parse_routes_legacy;
use babel_monitor_legacy::start_connection_legacy;
use failure::Error;
use futures01::future;
use futures01::future::join_all;
use futures01::Future;
use rita_common::blockchain_oracle::low_balance;
use rita_common::KI;
use settings::client::ExitServer;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::Nonce;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::util::FutureExt;

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
        endpoint: SocketAddr::new(current_exit.id.mesh_ip, general_details.wg_exit_port),
        pubkey: current_exit.id.wg_public_key,
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

pub fn get_exit_info(to: &SocketAddr) -> impl Future<Item = ExitState, Error = Error> {
    let endpoint = format!("http://[{}]:{}/exit_info", to.ip(), to.port());

    let stream = TokioTcpStream::connect(to);

    stream.from_err().and_then(move |stream| {
        client::get(&endpoint)
            .with_connection(Connection::from_stream(stream))
            .finish()
            .unwrap()
            .send()
            .from_err()
            .and_then(|response| response.json().from_err().and_then(Ok))
    })
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

fn send_exit_status_request(
    exit_pubkey: WgKey,
    to: &SocketAddr,
    ident: ExitClientIdentity,
) -> impl Future<Item = ExitState, Error = Error> {
    let endpoint = format!("http://[{}]:{}/secure_status", to.ip(), to.port());
    let ident = encrypt_exit_client_id(&exit_pubkey.into(), ident);

    let stream = TokioTcpStream::connect(to);

    stream.from_err().and_then(move |stream| {
        client::post(&endpoint)
            .timeout(CLIENT_LOOP_TIMEOUT)
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

fn exit_general_details_request(exit: String) -> impl Future<Item = (), Error = Error> {
    let current_exit = match settings::get_rita_client().exit_client.exits.get(&exit) {
        Some(current_exit) => current_exit.clone(),
        None => {
            return Box::new(future::err(format_err!("No valid exit for {}", exit)))
                as Box<dyn Future<Item = (), Error = Error>>;
        }
    };

    let endpoint = SocketAddr::new(current_exit.id.mesh_ip, current_exit.registration_port);

    trace!("sending exit general details request to {}", exit);
    let r = get_exit_info(&endpoint).and_then(move |exit_details| {
        let mut rita_client = settings::get_rita_client();
        let current_exit = match rita_client.exit_client.exits.get_mut(&exit) {
            Some(exit) => exit,
            None => bail!("Could not find exit {}", exit),
        };
        current_exit.info = exit_details;

        settings::set_rita_client(rita_client);
        Ok(())
    });

    Box::new(r)
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
    let exit_server = current_exit.id.mesh_ip;
    let exit_pubkey = current_exit.id.wg_public_key;
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

fn exit_status_request(exit: String) -> impl Future<Item = (), Error = Error> {
    let current_exit = match settings::get_rita_client().exit_client.exits.get(&exit) {
        Some(current_exit) => current_exit.clone(),
        None => {
            return Box::new(future::err(format_err!("No valid exit for {}", exit)))
                as Box<dyn Future<Item = (), Error = Error>>;
        }
    };
    let reg_details = match settings::get_rita_client().exit_client.contact_info {
        Some(val) => val.into(),
        None => return Box::new(future::err(format_err!("No valid details"))),
    };

    let exit_server = current_exit.id.mesh_ip;
    let exit_pubkey = current_exit.id.wg_public_key;
    let ident = ExitClientIdentity {
        global: match settings::get_rita_client().get_identity() {
            Some(id) => id,
            None => {
                return Box::new(future::err(format_err!(
                    "Identity has no mesh IP ready yet"
                )));
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

    let r =
        send_exit_status_request(exit_pubkey, &endpoint, ident).and_then(move |exit_response| {
            let mut rita_client = settings::get_rita_client();

            let current_exit = match rita_client.exit_client.exits.get_mut(&exit) {
                Some(exit_struct) => exit_struct,
                None => bail!("Could not find exit {:?}", exit),
            };

            current_exit.info = exit_response.clone();
            settings::set_rita_client(rita_client);

            trace!("Got exit status response {:?}", exit_response);

            Ok(())
        });

    Box::new(r)
}

/// An actor which pays the exit
#[derive(Default)]
pub struct ExitManager {
    // used to determine if we've changed exits
    last_exit: Option<ExitServer>,
    nat_setup: bool,
}

impl Actor for ExitManager {
    type Context = Context<Self>;
}

impl Supervised for ExitManager {}
impl SystemService for ExitManager {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("Exit Manager started");
        self.last_exit = None;
    }
}

fn correct_default_route(input: Option<DefaultRoute>) -> bool {
    match input {
        Some(v) => v.is_althea_default_route(),
        None => false,
    }
}

impl Handler<Tick> for ExitManager {
    type Result = ResponseFuture<(), Error>;

    fn handle(&mut self, _: Tick, _ctx: &mut Context<Self>) -> Self::Result {
        // scopes our access to SETTING and prevent
        // holding a readlock while exit tunnel setup requires a write lock
        // roughly the same as a drop(); inline
        let client_can_use_free_tier =
            { settings::get_rita_client().payment.client_can_use_free_tier };
        let exit_server = {
            settings::get_rita_client()
                .exit_client
                .get_current_exit()
                .cloned()
        };

        // code that connects to the current exit server
        trace!("About to setup exit tunnel!");
        if let Some(exit) = exit_server {
            trace!("We have selected an exit!");
            if let Some(general_details) = exit.info.general_details() {
                trace!("We have details for the selected exit!");

                let signed_up_for_exit = exit.info.our_details().is_some();
                let exit_has_changed =
                    !(self.last_exit.is_some() && self.last_exit.clone().unwrap() == exit);
                let correct_default_route = correct_default_route(KI.get_default_route());

                match (signed_up_for_exit, exit_has_changed, correct_default_route) {
                    (true, true, _) => {
                        info!("Exit change, setting up exit tunnel");
                        linux_setup_exit_tunnel(
                            &exit,
                            &general_details.clone(),
                            &exit.info.our_details().unwrap(),
                        )
                        .expect("failure setting up exit tunnel");
                        self.nat_setup = true;
                        self.last_exit = Some(exit.clone());
                    }
                    (true, false, false) => {
                        info!("DHCP overwrite setup exit tunnel again");
                        linux_setup_exit_tunnel(
                            &exit,
                            &general_details.clone(),
                            &exit.info.our_details().unwrap(),
                        )
                        .expect("failure setting up exit tunnel");
                        self.nat_setup = true;
                    }
                    _ => {}
                }

                // Adds and removes the nat rules in low balance situations
                // this prevents the free tier from being confusing (partially working)
                // when deployments are not interested in having a sufficiently fast one
                let low_balance = low_balance();
                let nat_setup = self.nat_setup;
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
                        self.nat_setup = false;
                    }
                    // restore when our balance is not low and our nat is not setup
                    // regardless of the free tier value
                    (false, _, false) => {
                        trace!("restoring exit tunnel!");
                        restore_nat();
                        self.nat_setup = true;
                    }
                    // restore if the nat is not setup and the free tier is enabled
                    // this only happens when settings change under the hood
                    (true, true, false) => {
                        trace!("restoring exit tunnel!");
                        restore_nat();
                        self.nat_setup = true;
                    }
                    _ => {}
                }

                // run billing at all times when an exit is setup
                if signed_up_for_exit {
                    let exit_price = general_details.exit_price;
                    let exit_internal_addr = general_details.server_internal_ip;
                    let exit_port = exit.registration_port;
                    let exit_id = exit.id;
                    let babel_port = settings::get_rita_client().network.babel_port;
                    trace!("We are signed up for the selected exit!");

                    Arbiter::spawn(
                        open_babel_stream_legacy(babel_port)
                            .from_err()
                            .and_then(move |stream| {
                                start_connection_legacy(stream).and_then(move |stream| {
                                    parse_routes_legacy(stream).and_then(move |routes| {
                                        TrafficWatcher::from_registry().do_send(QueryExitDebts {
                                            exit_id,
                                            exit_price,
                                            routes: routes.1,
                                            exit_internal_addr,
                                            exit_port,
                                        });
                                        Ok(())
                                    })
                                })
                            })
                            .timeout(CLIENT_LOOP_TIMEOUT)
                            .then(|ret| {
                                if let Err(e) = ret {
                                    error!("Failed to watch client traffic with {:?}", e)
                                }
                                Ok(())
                            }),
                    );
                }
            }
        }

        // code that manages requesting details to exits
        let servers = { settings::get_rita_client().exit_client.exits };

        let mut futs: Vec<Box<dyn Future<Item = (), Error = Error>>> = Vec::new();

        for (k, s) in servers {
            match s.info {
                ExitState::Denied { .. } | ExitState::Disabled | ExitState::GotInfo { .. } => {}
                ExitState::New { .. } => {
                    futs.push(Box::new(exit_general_details_request(k.clone()).then(
                        move |res| {
                            match res {
                                Ok(_) => {
                                    trace!("exit details request to {} was successful", k);
                                }
                                Err(e) => {
                                    trace!("exit details request to {} failed with {:?}", k, e);
                                }
                            };
                            Ok(())
                        },
                    )));
                }
                ExitState::Registered { .. } => {
                    futs.push(Box::new(exit_status_request(k.clone()).then(move |res| {
                        match res {
                            Ok(_) => {
                                trace!("exit status request to {} was successful", k);
                            }
                            Err(e) => {
                                trace!("exit status request to {} failed with {:?}", k, e);
                            }
                        };
                        Ok(())
                    })));
                }
                state => {
                    trace!("Waiting on exit state {:?} for {}", state, k);
                }
            }
        }

        Box::new(join_all(futs).and_then(|_| Ok(()))) as ResponseFuture<(), Error>
    }
}
