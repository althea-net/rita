//! Network endptoints for common Rita functionality (such as exchanging hello messages)

use crate::RitaCommonError;
use crate::payment_validator::{validate_later, ToValidate};
use crate::peer_listener::Peer;
use crate::tunnel_manager::id_callback::IdentityCallback;
use crate::tunnel_manager::TunnelManager;

use actix::registry::SystemService;
use actix_web::http::StatusCode;
use actix_web::{AsyncResponder, HttpRequest, HttpResponse, Json, Result};
use althea_types::{LocalIdentity, PaymentTx};
use futures01::{future, Future};
use std::boxed::Box;
use std::net::SocketAddr;
use std::time::Instant;

#[derive(Serialize)]
pub struct JsonStatusResponse {
    response: String,
}

impl JsonStatusResponse {
    pub fn new(ret_val: Result<String, RitaCommonError>) -> Result<Json<JsonStatusResponse>, RitaCommonError> {
        let res_string = match ret_val {
            Ok(msg) => msg,
            Err(e) => format!("{}", e),
        };

        Ok(Json(JsonStatusResponse {
            response: res_string,
        }))
    }
}

/// The recieve side of the make payments call
pub fn make_payments(pmt: (Json<PaymentTx>, HttpRequest)) -> HttpResponse {
    let txid = pmt.0.txid.clone();
    let our_address = settings::get_rita_common().payment.eth_address.unwrap();

    // we didn't get a txid, probably an old client.
    // why don't we need an Either up here? Because the types ultimately match?
    if txid.is_none() {
        error!("Did not find txid, payment failed!");
        return HttpResponse::new(StatusCode::from_u16(400u16).unwrap())
            .into_builder()
            .json("txid not provided! Invalid payment!");
    } else if pmt.0.to.eth_address != our_address {
        return HttpResponse::new(StatusCode::from_u16(400u16).unwrap())
            .into_builder()
            .json(format!(
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

pub fn hello_response(
    req: (Json<LocalIdentity>, HttpRequest),
) -> Box<dyn Future<Item = Json<LocalIdentity>, Error = RitaCommonError>> {
    let their_id = *req.0;

    let err_mesg = "Malformed hello tcp packet!";
    let socket = match req.1.connection_info().remote() {
        Some(val) => match val.parse::<SocketAddr>() {
            Ok(val) => val,
            Err(_e) => return Box::new(future::err(RitaCommonError::MiscStringError(err_mesg.to_string())))
        },
        None => return Box::new(future::err(RitaCommonError::MiscStringError(err_mesg.to_string())))
    };

    trace!("Got Hello from {:?}", req.1.connection_info().remote());
    trace!("opening tunnel in hello_response for {:?}", their_id);

    let peer = Peer {
        contact_socket: socket,
        ifidx: 0, // only works because we lookup ifname in kernel interface
    };

    // We send the callback, which can safely allocate a port because it already successfully
    // contacted a neighbor. The exception to this is when the TCP session fails at exactly
    // the wrong time.
    Box::new(
        TunnelManager::from_registry()
            .send(IdentityCallback::new(their_id, peer, None, None))
            .from_err()
            .and_then(|tunnel| {
                let tunnel = match tunnel {
                    Some(val) => val,
                    None => return Err(RitaCommonError::MiscStringError("tunnel open failure!".to_string()))
                };

                Ok(Json(LocalIdentity {
                    global: match settings::get_rita_common().get_identity() {
                        Some(id) => id,
                        None => return Err(RitaCommonError::MiscStringError("Identity has no mesh IP ready yet".to_string()))
                    },
                    wg_port: tunnel.0.listen_port,
                    have_tunnel: Some(tunnel.1),
                }))
            })
            .responder(),
    )
}

pub fn version(_req: HttpRequest) -> String {
    format!(
        "crate ver {}\ngit hash {}",
        env!("CARGO_PKG_VERSION"),
        settings::get_git_hash(),
    )
}
