use actix::registry::SystemService;
use actix_web::*;

use futures;
use futures::Future;

use rita_exit::db_client::{get_exit_info, ClientStatus, DbClient, SetupClient};

use std::boxed::Box;
use std::time::SystemTime;

use althea_types::{ExitClientIdentity, ExitState, RTTimestamps};

use rita_common::tunnel_manager::{GetPhyIpFromMeshIp, TunnelManager};

use exit_db::models::Client;
use failure::Error;
use rita_exit::db_client::ListClients;
use std::net::SocketAddr;

pub fn setup_request(
    their_id: (Json<ExitClientIdentity>, HttpRequest),
) -> Box<Future<Item = Json<ExitState>, Error = Error>> {
    trace!("Received requester identity, {:?}", their_id.0);
    let remote_mesh_socket: SocketAddr = their_id
        .1
        .connection_info()
        .remote()
        .unwrap()
        .parse()
        .unwrap();
    let remote_mesh_ip = remote_mesh_socket.ip();
    Box::new(
        TunnelManager::from_registry()
            .send(GetPhyIpFromMeshIp(remote_mesh_ip))
            .from_err()
            .and_then(|phy_ip| match phy_ip {
                Ok(phy_ip) => Box::new(
                    DbClient::from_registry()
                        .send(SetupClient(their_id.0.into_inner(), phy_ip))
                        .from_err()
                        .and_then(move |reply| Ok(Json(reply?))),
                ) as FutureResponse<Json<ExitState>, Error>,
                Err(e) => {
                    Box::new(futures::future::err(e)) as FutureResponse<Json<ExitState>, Error>
                }
            }),
    )
}

pub fn status_request(
    their_id: Json<ExitClientIdentity>,
) -> impl Future<Item = Json<ExitState>, Error = Error> {
    trace!("Received requester identity, {:?}", their_id);
    DbClient::from_registry()
        .send(ClientStatus(their_id.into_inner()))
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn get_exit_info_http(_req: HttpRequest) -> Result<Json<ExitState>, Error> {
    Ok(Json(ExitState::GotInfo {
        general_details: get_exit_info(),
        message: "Got info successfully".to_string(),
        auto_register: false,
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

#[cfg(not(feature = "development"))]
pub fn nuke_db(_req: HttpRequest) -> Result<HttpResponse, Error> {
    // This is returned on production builds.
    Ok(HttpResponse::NotFound().finish())
}

#[cfg(feature = "development")]
pub fn nuke_db(_req: HttpRequest) -> Box<Future<Item = HttpResponse, Error = Error>> {
    trace!("nuke_db: Truncating all data from the database");
    DbClient::from_registry()
        .send(TruncateTables {})
        .from_err()
        .and_then(move |_| Ok(HttpResponse::NoContent().finish()))
        .responder()
}
