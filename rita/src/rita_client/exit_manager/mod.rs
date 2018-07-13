use actix::prelude::*;
use actix::registry::SystemService;
use actix_web::client::Connection;
use actix_web::*;

use althea_types::{ExitClientIdentity, ExitState};

use settings::{RitaClientSettings, RitaCommonSettings};
use SETTING;

use rita_client::rita_loop::Tick;
use rita_client::traffic_watcher::{TrafficWatcher, Watch};

use futures::Future;

use tokio::net::TcpStream as TokioTcpStream;

use failure::Error;
use std::net::SocketAddr;
use KI;
use std::time::Duration;

fn linux_setup_exit_tunnel() -> Result<(), Error> {
    KI.update_settings_route(&mut SETTING.get_network_mut().default_route)?;

    let exit_client = SETTING.get_exit_client();
    let current_exit = exit_client.get_current_exit().unwrap();
    let general_details = current_exit.info.general_details().unwrap();
    let our_details = current_exit.info.our_details().unwrap();

    KI.setup_wg_if_named("wg_exit")?;
    KI.set_client_exit_tunnel_config(
        SocketAddr::new(current_exit.id.mesh_ip, general_details.wg_exit_port),
        current_exit.id.wg_public_key.clone(),
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
            .timeout(Duration::from_secs(2))
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
    let exits = SETTING.get_exits();
    let current_exit = &exits[&exit];
    let exit_server = current_exit.id.mesh_ip;

    let endpoint = SocketAddr::new(exit_server, current_exit.registration_port);

    trace!("sending exit general details request to {}", exit);

    get_exit_info(&endpoint).and_then(move |exit_details| {
        let mut exits = SETTING.get_exits_mut();

        let current_exit = exits.get_mut(&exit).unwrap();

        match exit_details {
            ExitState::GotInfo { .. } => {
                trace!("Got exit info response {:?}", exit_details);
            }
            _ => bail!("got incorrect state from exit details request"),
        }

        current_exit.info = exit_details;

        Ok(())
    })
}

fn exit_setup_request(exit: String, code: Option<String>) -> impl Future<Item = (), Error = Error> {
    let exits = SETTING.get_exits();
    let current_exit = &exits[&exit];
    let exit_server = current_exit.id.mesh_ip;
    let mut reg_details = SETTING.get_exit_client().reg_details.clone().unwrap();
    reg_details.email_code = code;

    let ident = ExitClientIdentity {
        global: SETTING.get_identity(),
        wg_port: SETTING.get_exit_client().wg_listen_port.clone(),
        reg_details,
    };

    trace!("sending exit setup request {:?} to {}", ident, exit);

    let endpoint = SocketAddr::new(exit_server, current_exit.registration_port);

    send_exit_setup_request(&endpoint, ident)
        .from_err()
        .and_then(move |exit_response| {
            let mut exits = SETTING.get_exits_mut();

            let current_exit = exits.get_mut(&exit).unwrap();

            current_exit.info = exit_response.clone();

            trace!("Got exit setup response {:?}", exit_response.clone());

            Ok(())
        })
}

fn exit_status_request(exit: String) -> impl Future<Item = (), Error = Error> {
    let exits = SETTING.get_exits();
    let current_exit = &exits[&exit];
    let exit_server = current_exit.id.mesh_ip;
    let ident = ExitClientIdentity {
        global: SETTING.get_identity(),
        wg_port: SETTING.get_exit_client().wg_listen_port.clone(),
        reg_details: SETTING.get_exit_client().reg_details.clone().unwrap(),
    };

    let endpoint = SocketAddr::new(exit_server, current_exit.registration_port);

    trace!("sending exit status request to {}", exit);

    send_exit_status_request(&endpoint, ident)
        .from_err()
        .and_then(move |exit_response| {
            let mut exits = SETTING.get_exits_mut();

            let current_exit = exits.get_mut(&exit).unwrap();

            current_exit.info = exit_response.clone();

            trace!("Got exit setup response {:?}", exit_response.clone());

            Ok(())
        })
}

/// An actor which pays the exit
#[derive(Default)]
pub struct ExitManager;

impl Actor for ExitManager {
    type Context = Context<Self>;
}

impl Supervised for ExitManager {}
impl SystemService for ExitManager {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("Exit Manager started");
    }
}

impl Handler<Tick> for ExitManager {
    type Result = Result<(), Error>;

    fn handle(&mut self, _: Tick, _ctx: &mut Context<Self>) -> Self::Result {
        let exit_server = {
            SETTING
                .get_exit_client()
                .get_current_exit()
                .map(|c| c.clone())
        };

        // code that connects to the current exit server
        if let Some(exit) = exit_server {
            if let Some(ref general_details) = exit.info.general_details() {
                if let Some(_) = exit.info.our_details() {
                    linux_setup_exit_tunnel().expect("failure setting up exit tunnel");
                    TrafficWatcher::from_registry()
                        .do_send(Watch(exit.id.clone(), general_details.exit_price));
                }
            }
        }

        // code that manages requesting details to exits
        let servers = { SETTING.get_exits().clone() };

        for (k, s) in servers {
            match s.info {
                ExitState::Denied { .. }
                | ExitState::Disabled
                | ExitState::GotInfo {
                    auto_register: false,
                    ..
                } => {}
                ExitState::New { .. } => {
                    Arbiter::spawn(exit_general_details_request(k.clone()).then(move |res| {
                        match res {
                            Ok(_) => {
                                info!("exit details request to {} was successful", k);
                            }
                            Err(e) => {
                                info!("exit details request to {} failed with {:?}", k, e);
                            }
                        };
                        Ok(())
                    }));
                }
                ExitState::Registering { .. }
                | ExitState::GotInfo {
                    auto_register: true,
                    ..
                } => {
                    Arbiter::spawn(exit_setup_request(k.clone(), None).then(move |res| {
                        match res {
                            Ok(_) => {
                                info!("exit setup request (no code) to {} was successful", k);
                            }
                            Err(e) => {
                                info!("exit setup request to {} failed with {:?}", k, e);
                            }
                        };
                        Ok(())
                    }));
                }
                ExitState::Pending {
                    email_code: Some(email_code),
                    ..
                } => {
                    Arbiter::spawn(
                        exit_setup_request(k.clone(), Some(email_code.clone())).then(move |res| {
                            match res {
                                Ok(_) => {
                                    info!("exit setup request (with code) to {} was successful", k);
                                }
                                Err(e) => {
                                    info!("exit setup request to {} failed with {:?}", k, e);
                                }
                            };
                            Ok(())
                        }),
                    );
                }
                ExitState::Registered { .. } => {
                    Arbiter::spawn(exit_status_request(k.clone()).then(move |res| {
                        match res {
                            Ok(_) => {
                                info!("exit status request to {} was successful", k);
                            }
                            Err(e) => {
                                info!("exit status request to {} failed with {:?}", k, e);
                            }
                        };
                        Ok(())
                    }));
                }
                _ => {
                    info!("waiting on one time code for {}", k);
                }
            }
        }

        Ok(())
    }
}
