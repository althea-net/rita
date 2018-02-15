use althea_types::{PaymentTx, Identity};

use actix::registry::SystemService;
use actix_web::*;
use actix_web::dev::*;

use futures::Future;

use payment_controller;
use payment_controller::PaymentController;

use tunnel_manager::TunnelManager;

use std::sync::mpsc::Sender;
use std::sync::{Mutex, Arc};
use std::io::Read;
use std::boxed::Box;

use serde_json;

use bytes::Bytes;

use settings::SETTING;

pub fn make_payments(req: HttpRequest) -> Box<Future<Item=HttpResponse, Error=Error>> {
    trace!("Started processing payment from {:?}", req.connection_info().remote());

    req.body().from_err().and_then(move |bytes: Bytes| {
        println!("==== BODY ==== {:?} from {:?}", bytes, req.connection_info().remote());
        let pmt: PaymentTx = serde_json::from_slice(&bytes[..]).unwrap();

        trace!("Received payment from {:?}, Payment: {:?}", pmt, req.connection_info().remote());
        PaymentController::from_registry().do_send(payment_controller::PaymentReceived(pmt));
        Ok(httpcodes::HTTPOk.into())
    }).responder()
}

pub fn hello_response(req: HttpRequest) -> Result<Json<Identity>> {
    // let id_str = req.body().limit(1024).wait().unwrap();
    // let id: Identity = serde_json::from_slice(&id_str).unwrap();

    // trace!("Received neighbour identity, Payment: {:?}", id);
    Ok(Json(SETTING.get_identity()))
}