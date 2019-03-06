//! This module contains utility functions for dealing with the exit signup and connection procedure
//! the procedure goes as follows.
//!
//! Exit is preconfigured with wireguard, mesh ip, and eth address info, this removes the possiblity
//! of an effective MITM attack.
//!
//! The exit is quiered for info about it that might change, such as it's subnet settings and default
//! route.
//!
//! Once the 'general' settings are aquired we contact the exit with our email, after getting an email
//! we input the confirmation code.
//!
//! The exit then serves up our user specific settings (our own exit internal ip) which we configure
//! and open the wg_exit tunnel. The exit performs the other side of this operation after querying
//! the database and finding a new entry.
//!
//! Signup is complete and the user may use the connection

use ::actix::prelude::*;
use ::actix::registry::SystemService;
use ::actix_web::client::Connection;
use ::actix_web::*;
use std::net::IpAddr;

use althea_types::{ExitClientIdentity, ExitState, ExitVerifMode};

use crate::SETTING;
use settings::client::ExitServer;
use settings::client::RitaClientSettings;
use settings::RitaCommonSettings;

use crate::rita_client::rita_loop::Tick;
use crate::rita_client::traffic_watcher::{TrafficWatcher, Watch};
use crate::rita_common::oracle::low_balance;

use futures::future;
use futures::future::join_all;
use futures::Future;

use tokio::net::TcpStream as TokioTcpStream;

use log::LevelFilter;
use syslog::Error as LogError;
use syslog::{init_udp, Facility};

use crate::KI;
use failure::Error;
use std::net::SocketAddr;
use std::time::Duration;

/// enables remote logging if the user has configured it
fn enable_remote_logging(server_internal_ip: IpAddr) -> Result<(), LogError> {
    // now that the exit tunnel is up we can start logging over it
    let log = SETTING.get_log();
    let key = SETTING
        .get_network()
        .wg_public_key
        .expect("Tried to init remove logging without WgKey!");
    trace!("About to enable remote logging");
    let level: LevelFilter = match log.level.parse() {
        Ok(level) => level,
        Err(_) => LevelFilter::Error,
    };
    let res = init_udp(
        &format!("0.0.0.0:{}", log.send_port),
        &format!("{}:{}", server_internal_ip, log.dest_port),
        format!("{} {}", key, env!("CARGO_PKG_VERSION")),
        Facility::LOG_USER,
        level,
    );
    info!("Remote logging enabled with {:?}", res);
    res
}

fn linux_setup_exit_tunnel() -> Result<(), Error> {
    KI.update_settings_route(&mut SETTING.get_network_mut().default_route)?;

    let exit_client = SETTING.get_exit_client();
    let current_exit = exit_client.get_current_exit().unwrap();
    let general_details = current_exit.info.general_details().unwrap();
    let our_details = current_exit.info.our_details().unwrap();

    KI.setup_wg_if_named("wg_exit")?;
    KI.set_client_exit_tunnel_config(
        SocketAddr::new(current_exit.id.mesh_ip, general_details.wg_exit_port),
        current_exit.id.wg_public_key,
        SETTING.get_network().wg_private_key_path.clone(),
        SETTING.get_exit_client().wg_listen_port,
        our_details.client_internal_ip,
        general_details.netmask,
        SETTING.get_network().rita_hello_port,
    )?;
    KI.set_route_to_tunnel(&general_details.server_internal_ip)?;

    let lan_nics = &SETTING.get_exit_client().lan_nics;
    for nic in lan_nics {
        KI.add_client_nat_rules(&nic)?;
    }

    Ok(())
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
            .and_then(|response| {
                response
                    .json()
                    .from_err()
                    .and_then(|val: ExitState| Ok(val))
            })
    })
}

pub fn send_exit_setup_request(
    to: &SocketAddr,
    ident: ExitClientIdentity,
) -> impl Future<Item = ExitState, Error = Error> {
    let endpoint = format!("http://[{}]:{}/setup", to.ip(), to.port());

    let stream = TokioTcpStream::connect(to);

    stream.from_err().and_then(move |stream| {
        client::post(&endpoint)
            .timeout(Duration::from_secs(8))
            .with_connection(Connection::from_stream(stream))
            .json(ident)
            .unwrap()
            .send()
            .from_err()
            .and_then(|response| {
                response
                    .json()
                    .from_err()
                    .and_then(|val: ExitState| Ok(val))
            })
    })
}

pub fn send_exit_status_request(
    to: &SocketAddr,
    ident: ExitClientIdentity,
) -> impl Future<Item = ExitState, Error = Error> {
    let endpoint = format!("http://[{}]:{}/status", to.ip(), to.port());

    let stream = TokioTcpStream::connect(to);

    stream.from_err().and_then(move |stream| {
        client::post(&endpoint)
            .with_connection(Connection::from_stream(stream))
            .json(ident)
            .unwrap()
            .send()
            .from_err()
            .and_then(|response| {
                response
                    .json()
                    .from_err()
                    .and_then(|val: ExitState| Ok(val))
            })
    })
}

fn exit_general_details_request(exit: String) -> impl Future<Item = (), Error = Error> {
    let current_exit = match SETTING.get_exits().get(&exit) {
        Some(current_exit) => current_exit.clone(),
        None => {
            return Box::new(future::err(format_err!("No valid exit for {}", exit)))
                as Box<dyn Future<Item = (), Error = Error>>;
        }
    };

    let endpoint = SocketAddr::new(current_exit.id.mesh_ip, current_exit.registration_port);

    trace!("sending exit general details request to {}", exit);

    let r = get_exit_info(&endpoint).and_then(move |exit_details| {
        let mut exits = SETTING.get_exits_mut();

        let current_exit = match exits.get_mut(&exit) {
            Some(exit) => exit,
            None => bail!("Could not find exit {}", exit),
        };

        match exit_details {
            ExitState::GotInfo { .. } => {
                trace!("Got exit info response {:?}", exit_details);
            }
            _ => bail!("got incorrect state from exit details request"),
        }

        current_exit.info = exit_details;

        Ok(())
    });

    Box::new(r)
}

pub fn exit_setup_request(
    exit: String,
    code: Option<String>,
) -> Box<dyn Future<Item = (), Error = Error>> {
    let current_exit = match SETTING.get_exits().get(&exit) {
        Some(exit_struct) => exit_struct.clone(),
        None => return Box::new(future::err(format_err!("Could not find exit {:?}", exit))),
    };
    let exit_auth_type = match current_exit.info.general_details() {
        Some(details) => details.verif_mode,
        None => return Box::new(future::err(format_err!("Exit is not ready to be setup!"))),
    };
    let exit_server = current_exit.id.mesh_ip;
    let mut reg_details = SETTING.get_exit_client().reg_details.clone().unwrap();
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
        global: match SETTING.get_identity() {
            Some(id) => id,
            None => {
                return Box::new(future::err(format_err!(
                    "Identity has no mesh IP ready yet"
                )));
            }
        },
        wg_port: SETTING.get_exit_client().wg_listen_port,
        reg_details,
        low_balance: low_balance(),
    };

    let endpoint = SocketAddr::new(exit_server, current_exit.registration_port);

    trace!(
        "sending exit setup request {:?} to {}, using {:?}",
        ident,
        exit,
        endpoint
    );

    Box::new(
        send_exit_setup_request(&endpoint, ident)
            .from_err()
            .and_then(move |exit_response| {
                let mut exits = SETTING.get_exits_mut();

                let current_exit = match exits.get_mut(&exit) {
                    Some(exit_struct) => exit_struct,
                    None => bail!("Could not find exit {:?}", exit),
                };

                current_exit.info = exit_response.clone();

                trace!("Got exit setup response {:?}", exit_response.clone());

                Ok(())
            }),
    )
}

fn exit_status_request(exit: String) -> impl Future<Item = (), Error = Error> {
    let current_exit = match SETTING.get_exits().get(&exit) {
        Some(current_exit) => current_exit.clone(),
        None => {
            return Box::new(future::err(format_err!("No valid exit for {}", exit)))
                as Box<dyn Future<Item = (), Error = Error>>;
        }
    };

    let exit_server = current_exit.id.mesh_ip;
    let ident = ExitClientIdentity {
        global: match SETTING.get_identity() {
            Some(id) => id,
            None => {
                return Box::new(future::err(format_err!(
                    "Identity has no mesh IP ready yet"
                )));
            }
        },
        wg_port: SETTING.get_exit_client().wg_listen_port,
        reg_details: SETTING.get_exit_client().reg_details.clone().unwrap(),
        low_balance: low_balance(),
    };

    let endpoint = SocketAddr::new(exit_server, current_exit.registration_port);

    trace!(
        "sending exit status request to {} using {:?}",
        exit,
        endpoint
    );

    let r = send_exit_status_request(&endpoint, ident)
        .from_err()
        .and_then(move |exit_response| {
            let mut exits = SETTING.get_exits_mut();

            let current_exit = match exits.get_mut(&exit) {
                Some(exit_struct) => exit_struct,
                None => bail!("Could not find exit {:?}", exit),
            };

            current_exit.info = exit_response.clone();

            trace!("Got exit setup response {:?}", exit_response.clone());

            Ok(())
        });
    Box::new(r)
}

/// An actor which pays the exit
#[derive(Default)]
pub struct ExitManager {
    // used to determine if we need to change the logging state
    last_exit: Option<ExitServer>,
    // used to store the logging state on startup so we don't double init logging
    // as that would cause a panic
    remote_logging_setting: bool,
    remote_logging_already_started: bool,
    // if we are currently limiting our own connection speed due to a low balance.
    local_limiting: bool,
}

impl Actor for ExitManager {
    type Context = Context<Self>;
}

impl Supervised for ExitManager {}
impl SystemService for ExitManager {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("Exit Manager started");
        self.last_exit = None;
        self.remote_logging_setting = SETTING.get_log().enabled;
        self.remote_logging_already_started = false;
        self.local_limiting = false;
    }
}

impl Handler<Tick> for ExitManager {
    type Result = ResponseFuture<(), Error>;

    fn handle(&mut self, _: Tick, _ctx: &mut Context<Self>) -> Self::Result {
        let exit_server = { SETTING.get_exit_client().get_current_exit().cloned() };

        // code that connects to the current exit server
        trace!("About to setup exit tunnel!");
        if let Some(exit) = exit_server {
            trace!("We have selected an exit!");
            if let Some(ref general_details) = exit.info.general_details() {
                trace!("We have details for the selected exit!");
                // only run if we have our own details and we either have no setup exit or the chosen
                // exit has changed, if all of that is good we check if the default route is still correct
                // and change it again if it's not.
                if exit.info.our_details().is_some()
                    && !(self.last_exit.is_some() && self.last_exit.clone().unwrap() == exit)
                {
                    trace!("Exit change, setting up exit tunnel");
                    linux_setup_exit_tunnel().expect("failure setting up exit tunnel");

                    self.last_exit = Some(exit.clone());
                } else if exit.info.our_details().is_some()
                    && !KI
                        .get_default_route()
                        .unwrap_or_default()
                        .contains(&String::from("wg_exit"))
                {
                    trace!("DHCP overwrite setup exit tunnel again");
                    trace!("Exit change, setting up exit tunnel");
                    linux_setup_exit_tunnel().expect("failure setting up exit tunnel");
                }

                // enable remote logging only if it has not already been started
                if !self.remote_logging_already_started
                    && self.remote_logging_setting
                    && option_env!("NO_REMOTE_LOG").is_none()
                {
                    let res = enable_remote_logging(general_details.server_internal_ip);
                    self.remote_logging_already_started = true;
                    info!("logging status {:?}", res);
                }

                // run billing at all times when an exit is setup
                if self.last_exit.is_some() {
                    let exit_price = general_details.exit_price;
                    let exit_id = exit.id;
                    trace!("We are signed up for the selected exit!");
                    Arbiter::spawn(
                        TrafficWatcher::from_registry()
                            .send(Watch {
                                exit_id: exit_id,
                                exit_price: exit_price,
                            })
                            .then(|res| match res {
                                Ok(val) => Ok(val),
                                Err(e) => {
                                    error!("Client traffic watcher failed with {:?}", e);
                                    Err(e)
                                }
                            })
                            .then(|_| Ok(())),
                    );
                }
            }
        }

        // Self limit bandwidth consumption if we have a low balance
        let free_tier_throughput = SETTING.get_payment().free_tier_throughput;
        if self.last_exit.is_some() && low_balance() && !self.local_limiting {
            // TODO send notification to user via sms
            warn!("Balance is low! sending notification and limiting usage");
            let _ = KI.set_classless_limit("wg_exit", free_tier_throughput);
            self.local_limiting = true;
        } else if self.last_exit.is_some() && low_balance() && self.local_limiting {
            info!("Balance is above the payment level, removing local limits");
            let _ = KI.delete_qdisc("wg_exit");
            self.local_limiting = false;
        }

        // code that manages requesting details to exits
        let servers = { SETTING.get_exits().clone() };

        let mut futs: Vec<Box<dyn Future<Item = (), Error = Error>>> = Vec::new();

        for (k, s) in servers {
            match s.info {
                ExitState::Denied { .. }
                | ExitState::Disabled
                | ExitState::GotInfo {
                    auto_register: false,
                    ..
                } => {}
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
