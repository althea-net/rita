//! Actor used for handling the dispatch of hello messages
//!
//! The call path goes like this
//!
//! peer listener gets udp ImHere -> TunnelManager tries to contact peer with hello
//! -> hello manager actually manages that request -> hello manager calls back to tunnel manager

use crate::peer_listener::Peer;
use crate::tunnel_manager::id_callback::IdentityCallback;
use crate::{tm_identity_callback, RitaCommonError};
use actix::{Actor, Context, Handler, Message, ResponseFuture, Supervised, SystemService};
use actix_web::client::Connection;
use actix_web::{client, HttpMessage, Result};
use althea_types::LocalIdentity;
use futures01::future::ok as future_ok;
use futures01::Future;
use tokio::net::TcpStream as TokioTcpStream;

#[derive(Default)]
pub struct HelloHandler;

impl Actor for HelloHandler {
    type Context = Context<Self>;
}

impl Supervised for HelloHandler {}
impl SystemService for HelloHandler {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("HelloHandler started");
    }
}

#[derive(Debug)]
pub struct Hello {
    pub my_id: LocalIdentity,
    pub to: Peer,
}

impl Message for Hello {
    type Result = Result<(), RitaCommonError>;
}

/// Handler for sending hello messages, it's important that any path by which this handler
/// may crash is handled such that ports are returned to tunnel manager, otherwise we end
/// up with a port leak which will eventually crash the program
impl Handler<Hello> for HelloHandler {
    type Result = ResponseFuture<(), RitaCommonError>;
    fn handle(&mut self, msg: Hello, _: &mut Self::Context) -> Self::Result {
        trace!("Sending Hello {:?}", msg);

        let stream = TokioTcpStream::connect(&msg.to.contact_socket);

        let endpoint = format!(
            "http://[{}]:{}/hello",
            msg.to.contact_socket.ip(),
            msg.to.contact_socket.port()
        );

        Box::new(stream.then(move |stream| {
            trace!("stream status {:?}, to: {:?}", stream, &msg.to);
            let mut network_request = client::post(&endpoint);
            let peer = msg.to;
            let wg_port = msg.my_id.wg_port;

            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    trace!("Error getting stream from hello {:?}", e);
                    return Box::new(future_ok(()))
                        as Box<dyn Future<Item = (), Error = RitaCommonError>>;
                }
            };

            let network_request = network_request.with_connection(Connection::from_stream(stream));

            let network_json = network_request.json(&msg.my_id);

            let network_json = match network_json {
                Ok(n) => n,
                Err(e) => {
                    trace!("Error serializing our request {:?}", e);
                    return Box::new(future_ok(()))
                        as Box<dyn Future<Item = (), Error = RitaCommonError>>;
                }
            };

            trace!("sending hello request {:?}", network_json);

            let http_result = network_json.send().then(move |response| {
                trace!("got response from Hello {:?}", response);
                match response {
                    Ok(response) => Box::new(response.json().then(move |val| match val {
                        Ok(val) => {
                            tm_identity_callback(IdentityCallback::new(
                                val,
                                peer,
                                Some(wg_port),
                                None,
                            ));
                            Ok(())
                        }
                        Err(e) => {
                            trace!("Got error deserializing Hello {:?}", e);
                            Ok(())
                        }
                    }))
                        as Box<dyn Future<Item = (), Error = RitaCommonError>>,
                    Err(e) => {
                        trace!("Got error getting Hello response {:?}", e);
                        Box::new(future_ok(()))
                            as Box<dyn Future<Item = (), Error = RitaCommonError>>
                    }
                }
            });

            Box::new(http_result) as Box<dyn Future<Item = (), Error = RitaCommonError>>
        }))
    }
}
