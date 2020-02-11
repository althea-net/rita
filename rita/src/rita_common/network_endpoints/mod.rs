//! Network endptoints for common Rita functionality (such as exchanging hello messages)

use crate::rita_common::payment_validator::{PaymentValidator, ToValidate, ValidateLater};
use crate::rita_common::peer_listener::Peer;
use crate::rita_common::tunnel_manager::id_callback::IdentityCallback;
use crate::rita_common::tunnel_manager::TunnelManager;
use crate::SETTING;
use actix::registry::SystemService;
use actix_web::http::StatusCode;
use actix_web::{AsyncResponder, HttpRequest, HttpResponse, Json, Result};
use althea_types::{LocalIdentity, PaymentTx};
use failure::Error;
use futures01::{future, Future};
use settings::RitaCommonSettings;
use std::boxed::Box;
use std::net::SocketAddr;
use std::time::Instant;

#[derive(Serialize)]
pub struct JsonStatusResponse {
    response: String,
}

impl JsonStatusResponse {
    pub fn new(ret_val: Result<String, Error>) -> Result<Json<JsonStatusResponse>, Error> {
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
pub fn make_payments(
    pmt: (Json<PaymentTx>, HttpRequest),
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let txid = pmt.0.txid.clone();

    // we didn't get a txid, probably an old client.
    // why don't we need an Either up here? Because the types ultimately match?
    if txid.is_none() {
        error!("Did not find txid, payment failed!");
        return Box::new(future::ok(
            HttpResponse::new(StatusCode::from_u16(400u16).unwrap())
                .into_builder()
                .json("txid not provided! Invalid payment!"),
        ));
    }
    let txid = txid.unwrap();
    info!(
        "Got Payment from {:?} for {} with txid {:#066x}",
        pmt.1.connection_info().remote(),
        pmt.0.amount,
        txid,
    );
    let ts = ToValidate {
        payment: pmt.0.into_inner(),
        recieved: Instant::now(),
        checked: false,
    };
    PaymentValidator::from_registry().do_send(ValidateLater(ts));

    Box::new(future::ok(HttpResponse::Ok().json("Payment Received!")))
}

pub fn hello_response(
    req: (Json<LocalIdentity>, HttpRequest),
) -> Box<dyn Future<Item = Json<LocalIdentity>, Error = Error>> {
    let their_id = *req.0;

    let err_mesg = "Malformed hello tcp packet!";
    let socket = match req.1.connection_info().remote() {
        Some(val) => match val.parse::<SocketAddr>() {
            Ok(val) => val,
            Err(_e) => return Box::new(future::err(format_err!("{}", err_mesg))),
        },
        None => return Box::new(future::err(format_err!("{}", err_mesg))),
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
                    None => return Err(format_err!("tunnel open failure!")),
                };

                Ok(Json(LocalIdentity {
                    global: match SETTING.get_identity() {
                        Some(id) => id,
                        None => return Err(format_err!("Identity has no mesh IP ready yet")),
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
        env!("GIT_HASH")
    )
}
