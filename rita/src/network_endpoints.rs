use althea_types::PaymentTx;

use payment_controller;
use payment_controller::{PAYMENT_CONTROLLER};
use tunnel_manager::TunnelManager;

extern crate num256;
use num256::Int256;

use rouille::{Request, Response};

extern crate serde;
extern crate serde_json;

extern crate rand;

use std::sync::mpsc::Sender;
use std::sync::{Mutex, Arc};
use std::io::Read;

pub fn make_payments(request: &Request) -> Response {
    if let Some(mut data) = request.data() {
        let mut pmt_str = String::new();
        data.read_to_string(&mut pmt_str).unwrap();
        let pmt: PaymentTx = serde_json::from_str(&pmt_str).unwrap();
        trace!("Received payment, Payment: {:?}", pmt);

        PAYMENT_CONTROLLER.do_send(payment_controller::PaymentReceived(pmt));
        // Arbiter::r
        Response::text("Payment Recieved")
    } else {
        Response::text("Payment Error")
    }
}

//pub fn hello_response(request: &Request,
//                     tm: Arc<Mutex<TunnelManager>>) -> Response {
//    if let Some(mut data) = request.data() {
//        let mut neighbor_id = String::new();
//        data.read_to_string(&mut neighbor_id).unwrap();
//        let id: LocalIdentity = serde_json::from_str(&neighbor_id).unwrap();
//        trace!("Received neighbour identity, Payment: {:?}", LocalIdentity);
//
//        Response::text("Hello OK")
//    } else {
//        Response::text("Hello Error")
//    }
//}