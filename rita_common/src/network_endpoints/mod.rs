//! Network endptoints for common Rita functionality (such as exchanging hello messages)

use crate::payment_validator::{validate_later, ToValidate};
use crate::peer_listener::Peer;
use crate::tm_identity_callback;
use crate::tunnel_manager::id_callback::IdentityCallback;

use actix_web::HttpRequest as OldHttpRequest;
use actix_web_async::http::StatusCode;
use actix_web_async::web::Json;

use actix_web_async::{HttpRequest, HttpResponse};
use althea_types::{LocalIdentity, PaymentTx};
use std::time::Instant;

/// The recieve side of the make payments call
pub fn make_payments(pmt: (Json<PaymentTx>, HttpRequest)) -> HttpResponse {
    let txid = pmt.0.txid.clone();
    let our_address = settings::get_rita_common().payment.eth_address.unwrap();

    // we didn't get a txid, probably an old client.
    // why don't we need an Either up here? Because the types ultimately match?
    if txid.is_none() {
        error!("Did not find txid, payment failed!");
        return HttpResponse::build(StatusCode::from_u16(400u16).unwrap())
            .json("txid not provided! Invalid payment!");
    } else if pmt.0.to.eth_address != our_address {
        return HttpResponse::build(StatusCode::from_u16(400u16).unwrap()).json(format!(
            "We are not {} our address is {}! Invalid payment",
            pmt.0.to.eth_address, our_address
        ));
    }
    let txid = txid.unwrap();
    info!(
        "Got Payment from {} for {} with txid {:#066x}",
        pmt.0.from.wg_public_key, pmt.0.amount, txid,
    );
    let ts = ToValidate {
        payment: pmt.0.into_inner(),
        received: Instant::now(),
        checked: false,
    };
    validate_later(ts);

    HttpResponse::Ok().json("Payment Received!")
}

pub fn hello_response(req: (Json<LocalIdentity>, HttpRequest)) -> HttpResponse {
    let their_id = *req.0;

    let err_mesg = "Malformed hello tcp packet!";
    let socket = match req.1.peer_addr() {
        Some(val) => val,
        None => return HttpResponse::build(StatusCode::from_u16(400u16).unwrap()).json(err_mesg),
    };

    trace!("Got Hello from {:?}", req.1.peer_addr());
    trace!("opening tunnel in hello_response for {:?}", their_id);

    let peer = Peer {
        contact_socket: socket,
        ifidx: 0, // only works because we lookup ifname in kernel interface
    };

    let tunnel = tm_identity_callback(IdentityCallback::new(their_id, peer, None, None));
    let tunnel = match tunnel {
        Some(val) => val,
        None => {
            return HttpResponse::build(StatusCode::from_u16(400u16).unwrap())
                .json("Tunnel open failure")
        }
    };

    HttpResponse::Ok().json(LocalIdentity {
        global: match settings::get_rita_common().get_identity() {
            Some(id) => id,
            None => {
                return HttpResponse::build(StatusCode::from_u16(400u16).unwrap())
                    .json("Identity has no mesh ip ready")
            }
        },
        wg_port: tunnel.0.listen_port,
        have_tunnel: Some(tunnel.1),
    })
}

pub fn version(_req: OldHttpRequest) -> String {
    format!(
        "crate ver {}\ngit hash {}",
        env!("CARGO_PKG_VERSION"),
        settings::get_git_hash(),
    )
}
