use althea_types::{LocalIdentity, PaymentTx};

use actix::registry::SystemService;
use actix_web::*;

use futures::Future;

use rita_common;

use rita_common::payment_controller::PaymentController;

use rita_common::tunnel_manager::{GetLocalIdentity, OpenTunnel, TunnelManager};

use std::boxed::Box;

use serde_json;

use bytes::Bytes;

pub fn make_payments(req: HttpRequest) -> Box<Future<Item = HttpResponse, Error = Error>> {
    info!("Got Payment from {:?}", req.connection_info().remote());

    req.body()
        .from_err()
        .and_then(move |bytes: Bytes| {
            info!("Payment body: {:?}", bytes);
            let pmt: PaymentTx = serde_json::from_slice(&bytes[..]).unwrap();

            trace!("Received payment: {:?}", pmt,);
            PaymentController::from_registry()
                .do_send(rita_common::payment_controller::PaymentReceived(pmt));
            Ok(httpcodes::HTTPOk.into())
        })
        .responder()
}

pub fn hello_response(req: HttpRequest) -> Box<Future<Item = Json<LocalIdentity>, Error = Error>> {
    info!("Got Hello from {:?}", req.connection_info().remote());

    req.body()
        .from_err()
        .and_then(move |bytes: Bytes| {
            info!("Hello body: {:?}", bytes,);
            let their_id: LocalIdentity = serde_json::from_slice(&bytes[..]).unwrap();

            trace!("Received neighbour identity: {:?}", their_id);

            TunnelManager::from_registry()
                .send(GetLocalIdentity {
                    requester: their_id.clone(),
                })
                .then(move |reply| {
                    info!("opening tunnel in hello_response for {:?}", their_id);
                    TunnelManager::from_registry().do_send(OpenTunnel(their_id));
                    Ok(Json(reply.unwrap()))
                })
        })
        .responder()
}
