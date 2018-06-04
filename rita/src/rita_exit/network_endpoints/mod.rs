use actix::registry::SystemService;
use actix_web::*;

use futures::Future;

use rita_exit::db_client::{DbClient, SetupClient};

use std::boxed::Box;
use std::time::SystemTime;

use settings::RitaExitSettings;
use SETTING;

use althea_types::{
    ExitClientDetails, ExitClientIdentity, ExitDetails, ExitServerReply, ExitState, RTTimestamps,
};
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
            let details;
            let message;
            let state;
            if let Ok(ip) = reply {
                details = Some(ExitClientDetails {
                    client_internal_ip: ip,
                });
                message = "Registration OK".to_string();
                state = ExitState::Registered;
            } else {
                details = None;
                message = format!("{:?}", reply);
                state = ExitState::Denied;
            }

            Ok(Json(ExitServerReply {
                details,
                state,
                message,
            }))
        })
        .responder()
}

pub fn get_exit_info(_req: HttpRequest) -> Result<Json<ExitDetails>, Error> {
    Ok(Json(ExitDetails {
        server_internal_ip: SETTING.get_exit_network().own_internal_ip,
        wg_exit_port: SETTING.get_exit_network().wg_tunnel_port,
        exit_price: SETTING.get_exit_network().exit_price,
        netmask: SETTING.get_exit_network().netmask,
        description: SETTING.get_description(),
    }))
}

pub fn list_clients(_req: HttpRequest) -> Box<Future<Item = Json<Vec<Client>>, Error = Error>> {
    DbClient::from_registry()
        .send(ListClients {})
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

/// An endpoint handler for the inner tunnel RTT. It responds with the request arrival and
/// transmission time timestamps; presently the two values are very close because no exit-side
/// processing happens yet.
pub fn rtt(_req: HttpRequest) -> Result<Json<RTTimestamps>> {
    Ok(Json(RTTimestamps {
        exit_rx: SystemTime::now(),
        exit_tx: SystemTime::now(),
    }))
}
