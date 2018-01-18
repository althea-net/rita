use althea_types::PaymentTx;
use debt_keeper::DebtAdjustment;

use payment_controller::{PaymentControllerMsg};
extern crate num256;
use num256::Int256;

use rouille::{Request, Response};

extern crate serde;
extern crate serde_json;

extern crate rand;

use std::sync::mpsc::Sender;
use std::sync::{Mutex, Arc};
use std::io::Read;

pub fn make_payments(request: &Request,
                     m_tx: Arc<Mutex<Sender<DebtAdjustment>>>,
                     pc: Arc<Mutex<Sender<PaymentControllerMsg>>>)
    -> Response {
    if let Some(mut data) = request.data() {
        let mut pmt_str = String::new();
        data.read_to_string(&mut pmt_str).unwrap();
        let pmt: PaymentTx = serde_json::from_str(&pmt_str).unwrap();
        trace!("Received payment, Payment: {:?}", pmt);
        m_tx.lock().unwrap().send(
            DebtAdjustment {
                ident: pmt.from,
                amount: Int256::from(pmt.amount.clone())
            }
        ).unwrap();
        pc.lock().unwrap().send(PaymentControllerMsg::PaymentReceived(pmt.clone())).unwrap();
        Response::text("Payment Recieved")
    } else {
        Response::text("Payment Error")
    }
}