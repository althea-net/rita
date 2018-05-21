use althea_types::{LocalIdentity, PaymentTx};

use actix::registry::SystemService;
use actix_web::*;

use futures::Future;

use rita_common;

use rita_common::payment_controller::PaymentController;

use rita_common::tunnel_manager::{GetLocalIdentity, OpenTunnel, TunnelManager};

use std::boxed::Box;

use std::net::SocketAddr;

pub fn make_payments(
    pmt: Json<PaymentTx>,
    req: HttpRequest,
) -> Box<Future<Item = HttpResponse, Error = Error>> {
    info!("Got Payment from {:?}", req.connection_info().remote());
    trace!("Received payment: {:?}", pmt,);
    PaymentController::from_registry()
        .send(rita_common::payment_controller::PaymentReceived(
            pmt.into_inner(),
        ))
        .from_err()
        .and_then(|_| Ok(HttpResponse::Ok().into()))
        .responder()
}

pub fn hello_response(
    their_id: Json<LocalIdentity>,
    req: HttpRequest,
) -> Box<Future<Item = Json<LocalIdentity>, Error = Error>> {
    info!("Got Hello from {:?}", req.connection_info().remote());

    let remote_ip = req
        .connection_info()
        .remote()
        .unwrap()
        .parse::<SocketAddr>()
        .unwrap()
        .ip();

    trace!("Received neighbour identity: {:?}", their_id);

    TunnelManager::from_registry()
        .send(GetLocalIdentity { from: remote_ip })
        .from_err()
        .and_then(move |reply| {
            info!("opening tunnel in hello_response for {:?}", their_id);
            TunnelManager::from_registry().do_send(OpenTunnel(their_id.into_inner(), remote_ip));
            Ok(Json(reply))
        })
        .responder()
}

pub fn version(_req: HttpRequest) -> String {
    format!(
        "crate ver {}\ngit hash {}",
        env!("CARGO_PKG_VERSION"),
        env!("GIT_HASH")
    )
}
