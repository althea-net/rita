use actix::prelude::*;
use actix::registry::SystemService;

use althea_types::{ExitClientDetails, ExitClientIdentity, ExitState};

use settings::{RitaClientSettings, RitaCommonSettings};
use SETTING;

use rita_client::rita_loop::Tick;
use rita_client::traffic_watcher::{TrafficWatcher, Watch};
use rita_common::http_client::{ExitSetupRequest, GetExitInfo, HTTPClient};

use futures::Future;

use failure::Error;
use std::net::SocketAddr;
use KI;

fn linux_setup_exit_tunnel() -> Result<(), Error> {
    KI.update_settings_route(&mut SETTING.get_network_mut().default_route)?;

    let exit_client = SETTING.get_exit_client();
    let current_exit = exit_client.get_current_exit().unwrap();
    let general_details = current_exit.general_details.as_ref().unwrap();
    let our_details = current_exit.our_details.as_ref().unwrap();

    KI.setup_wg_if_named("wg_exit")?;
    KI.set_client_exit_tunnel_config(
        SocketAddr::new(current_exit.id.mesh_ip, general_details.wg_exit_port),
        current_exit.id.wg_public_key.clone(),
        SETTING.get_network().wg_private_key_path.clone(),
        SETTING.get_exit_client().wg_listen_port,
        our_details.client_internal_ip,
        general_details.netmask,
    )?;
    KI.set_route_to_tunnel(&general_details.server_internal_ip)?;

    let lan_nics = &SETTING.get_exit_client().lan_nics;
    for nic in lan_nics {
        KI.add_client_nat_rules(&nic)?;
    }

    Ok(())
}

fn exit_general_details_request(exit: String) -> ResponseFuture<(), Error> {
    let exits = SETTING.get_exits();
    let current_exit = &exits[&exit];
    let exit_server = current_exit.id.mesh_ip;

    let endpoint = SocketAddr::new(exit_server, current_exit.registration_port);

    Box::new(
        HTTPClient::from_registry()
            .send(GetExitInfo { to: endpoint })
            .from_err()
            .and_then(move |exit_details| {
                let exit_details = exit_details?;

                let mut exits = SETTING.get_exits_mut();

                let current_exit = exits.get_mut(&exit).unwrap();

                current_exit.state = ExitState::GotInfo;

                trace!("Got exit info response {:?}", exit_details.clone());

                current_exit.general_details = Some(exit_details);

                Ok(())
            }),
    )
}

fn exit_setup_request(exit: String) -> ResponseFuture<(), Error> {
    let exits = SETTING.get_exits();
    let current_exit = &exits[&exit];
    let exit_server = current_exit.id.mesh_ip;
    let ident = ExitClientIdentity {
        global: SETTING.get_identity(),
        wg_port: SETTING.get_exit_client().wg_listen_port.clone(),
        reg_details: SETTING.get_exit_client().reg_details.clone().unwrap(),
    };

    let endpoint = SocketAddr::new(exit_server, current_exit.registration_port);

    Box::new(
        HTTPClient::from_registry()
            .send(ExitSetupRequest {
                to: endpoint,
                ident,
            })
            .from_err()
            .and_then(move |exit_response| {
                let exit_response = exit_response?;

                let mut exits = SETTING.get_exits_mut();

                let current_exit = exits.get_mut(&exit).unwrap();

                current_exit.message = exit_response.message.clone();
                current_exit.state = exit_response.state.clone();

                trace!("Got exit setup response {:?}", exit_response.clone());

                match exit_response.details {
                    Some(details) => {
                        current_exit.our_details = Some(ExitClientDetails {
                            client_internal_ip: details.client_internal_ip,
                        });
                    }
                    None => bail!("Got no details from exit"),
                }

                Ok(())
            }),
    )
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
            if let Some(ref general_details) = exit.general_details {
                if let Some(_) = exit.our_details {
                    linux_setup_exit_tunnel().expect("failure setting up exit tunnel");
                    TrafficWatcher::from_registry()
                        .do_send(Watch(exit.id.clone(), general_details.exit_price));
                }
            }
        }

        // code that manages requesting details to exits
        let servers = { SETTING.get_exits().clone() };

        for (k, s) in servers {
            match s.state {
                ExitState::Denied | ExitState::Disabled | ExitState::Registered => {}
                ExitState::New => {
                    Arbiter::handle().spawn(exit_general_details_request(k.clone()).then(
                        move |res| {
                            match res {
                                Ok(_) => {
                                    info!("exit details request to {} was successful", k);
                                }
                                Err(e) => {
                                    info!("exit details request to {} failed with {:?}", k, e);
                                }
                            };
                            Ok(())
                        },
                    ));
                }
                ExitState::GotInfo | ExitState::Pending => {
                    Arbiter::handle().spawn(exit_setup_request(k.clone()).then(move |res| {
                        match res {
                            Ok(_) => {
                                info!("exit setup request to {} was successful", k);
                            }
                            Err(e) => {
                                info!("exit setup request to {} failed with {:?}", k, e);
                            }
                        };
                        Ok(())
                    }));
                }
            }
        }

        Ok(())
    }
}
