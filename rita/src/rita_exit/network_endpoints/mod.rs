//! Network endpoints for rita-exit that are not dashboard or local infromational endpoints
//! these are called by rita instances to operate the mesh

use crate::rita_common::debt_keeper::DebtKeeper;
use crate::rita_common::debt_keeper::GetDebtsList;
#[cfg(feature = "development")]
use crate::rita_exit::database::db_client::DbClient;
#[cfg(feature = "development")]
use crate::rita_exit::database::db_client::TruncateTables;
use crate::rita_exit::database::{client_status, get_exit_info, signup_client};
use ::actix_web::{AsyncResponder, HttpRequest, HttpResponse, Json, Result};
#[cfg(feature = "development")]
use actix::SystemService;
use actix::SystemService;
#[cfg(feature = "development")]
use actix_web::AsyncResponder;
use althea_types::Identity;
use althea_types::{ExitClientIdentity, ExitState, RTTimestamps};
use failure::Error;
use futures::Future;
use num256::Int256;
use std::net::SocketAddr;
use std::time::SystemTime;

pub fn setup_request(
    their_id: (Json<ExitClientIdentity>, HttpRequest),
) -> Result<Json<ExitState>, Error> {
    trace!("Received requester identity for setup, {:?}", their_id.0);
    let client_mesh_ip = their_id.0.global.mesh_ip;
    let client = their_id.0.into_inner();
    let remote_mesh_socket: SocketAddr = their_id
        .1
        .connection_info()
        .remote()
        .unwrap()
        .parse()
        .unwrap();

    let remote_mesh_ip = remote_mesh_socket.ip();
    if remote_mesh_ip == client_mesh_ip {
        Ok(Json(signup_client(client)?))
    } else {
        Ok(Json(ExitState::Denied {
            message: "The request ip does not match the signup ip".to_string(),
        }))
    }
}

pub fn status_request(their_id: Json<ExitClientIdentity>) -> Result<Json<ExitState>, Error> {
    trace!("Received requester identity for status, {:?}", their_id);
    let client = their_id.into_inner();

    Ok(Json(client_status(client)?))
}

pub fn get_exit_info_http(_req: HttpRequest) -> Result<Json<ExitState>, Error> {
    Ok(Json(ExitState::GotInfo {
        general_details: get_exit_info(),
        message: "Got info successfully".to_string(),
        auto_register: false,
    }))
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

/// Used by clients to get their debt from the exits. While it is in theory possible for the
/// client to totally compute their own bill it's not possible for the exit and the client
/// to agree on the billed amount in the presence of packet loss. Normally Althea is pay per forward
/// which means packet loss simply resolves to overpayment, but the exit is being paid for uploaded traffic
/// (the clients download traffic) which breaks this assumption
pub fn get_client_debt(
    client: Json<Identity>,
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let client = client.into_inner();
    DebtKeeper::from_registry()
        .send(GetDebtsList {})
        .from_err()
        .and_then(move |reply| match reply {
            Ok(debts) => {
                for debt in debts {
                    if debt.identity == client {
                        return Ok(
                            HttpResponse::Ok().json(debt.payment_details.debt * Int256::from(-1))
                        );
                    }
                }
                Ok(HttpResponse::NotFound().json("No client by that ID"))
            }
            Err(e) => {
                error!("Failed to contact debt keeper {:?}", e);
                Ok(HttpResponse::InternalServerError().json("Internal Error"))
            }
        })
        .responder()
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
