use althea_types::{Identity, LocalIdentity, PaymentTx};
use num256::Uint256;

use actix;
use actix::registry::SystemService;
use actix_web::*;
use actix_web::dev::*;

use futures::Future;

use payment_controller;
use payment_controller::PaymentController;

use debt_keeper;
use debt_keeper::{DebtKeeper, GetDebt};

use althea_kernel_interface::KernelInterface;

use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::io::Read;
use std::boxed::Box;
use std::net::SocketAddr;

use serde_json;

use bytes::Bytes;

use SETTING;

use failure::Error;

pub fn make_payments(req: HttpRequest) -> Box<Future<Item = HttpResponse, Error = Error>> {
    trace!(
        "Started processing payment from {:?}",
        req.connection_info().remote()
    );

    req.body()
        .from_err()
        .and_then(move |bytes: Bytes| {
            trace!(
                "Payment body: {:?} from {:?}",
                bytes,
                req.connection_info().remote()
            );
            let pmt: PaymentTx = serde_json::from_slice(&bytes[..]).unwrap();

            trace!(
                "Received payment from {:?}, Payment: {:?}",
                pmt,
                req.connection_info().remote()
            );
            PaymentController::from_registry().do_send(payment_controller::PaymentReceived(pmt));
            Ok(httpcodes::HTTPOk.into())
        })
        .responder()
}

pub fn get_debt(req: HttpRequest) -> Box<Future<Item = Json<Uint256>, Error = Error>> {
    trace!("Getting debt for {:?}", req.connection_info().remote());

    let conn_info: SocketAddr = req.connection_info().remote().unwrap().parse().unwrap();

    req.body()
        .from_err()
        .and_then(move |bytes: Bytes| {
            trace!("Debt request body: {:?} from {:?}", bytes, conn_info);
            let their_id: Identity = serde_json::from_slice(&bytes[..]).unwrap();

            trace!("Received requester identity, {:?}", their_id);
            DebtKeeper::from_registry()
                .send(GetDebt {
                    from: their_id.clone(),
                })
                .from_err()
                .and_then(move |reply| {
                    trace!("got debt {:?} for {:?}", reply, their_id);

                    Ok(Json(reply.unwrap()))
                })
        })
        .responder()
}
