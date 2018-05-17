use althea_types::ExitClientIdentity;

use actix::registry::SystemService;
use actix_web::*;

use futures::Future;

use rita_exit::db_client::{DbClient, SetupClient};

use std::boxed::Box;

use settings::{RitaCommonSettings, RitaExitSettings};
use SETTING;

use althea_types::{ExitServerIdentity, ExitServerReply, ExitState};
use exit_db::models::Client;
use failure::Error;
use rita_exit::db_client::ListClients;
use std::net::SocketAddr;

pub fn setup_request(
    their_id: Json<ExitClientIdentity>,
    req: HttpRequest,
) -> Box<Future<Item = Json<ExitServerReply>, Error = Error>> {
    trace!("Received requester identity, {:?}", their_id);
    let remote_socket: SocketAddr = req.connection_info().remote().unwrap().parse().unwrap();
    DbClient::from_registry()
        .send(SetupClient(their_id.into_inner(), remote_socket.ip()))
        .from_err()
        .and_then(move |reply| {
            let id;
            let message;
            let state;
            if let Ok(ip) = reply {
                id = Some(ExitServerIdentity {
                    own_local_ip: ip,
                    server_local_ip: SETTING.get_exit_network().own_internal_ip,
                    wg_port: SETTING.get_exit_network().wg_tunnel_port,
                    global: SETTING.get_identity(),
                    price: SETTING.get_exit_network().exit_price,
                    netmask: SETTING.get_exit_network().netmask,
                });
                message = "Registration OK".to_string();
                state = ExitState::Registered;
            } else {
                id = None;
                message = format!("{:?}", reply);
                state = ExitState::Denied;
            }

            Ok(Json(ExitServerReply {
                identity: id,
                state,
                message,
            }))
        })
        .responder()
}

pub fn list_clients(_req: HttpRequest) -> Box<Future<Item = Json<Vec<Client>>, Error = Error>> {
    DbClient::from_registry()
        .send(ListClients {})
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}
