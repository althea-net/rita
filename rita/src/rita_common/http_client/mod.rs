use std::net::SocketAddr;

use tokio_core::net::TcpStream as TokioTcpStream;

use actix::prelude::*;
use actix::registry::SystemService;
use actix_web::*;

use futures::Future;

use althea_types::{ExitClientIdentity, ExitDetails, ExitServerReply, Identity, LocalIdentity};

use settings::RitaCommonSettings;
use SETTING;

use actix_web::client::Connection;
use failure::Error;

#[derive(Default)]
pub struct HTTPClient;

impl Actor for HTTPClient {
    type Context = Context<Self>;
}

impl Supervised for HTTPClient {}
impl SystemService for HTTPClient {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("HTTP Client started");
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Hello {
    pub my_id: Identity,
    pub to: SocketAddr,
}

impl Message for Hello {
    type Result = Result<LocalIdentity, Error>;
}

impl Handler<Hello> for HTTPClient {
    type Result = ResponseFuture<LocalIdentity, Error>;
    fn handle(&mut self, msg: Hello, _: &mut Self::Context) -> Self::Result {
        info!("sending {:?}", msg);

        let stream = TokioTcpStream::connect2(&msg.to);

        let endpoint = format!("http://[{}]:{}/hello", msg.to.ip(), msg.to.port());

        Box::new(stream.from_err().and_then(move |stream| {
            trace!("stream status {:?}, to: {:?}", stream, &msg.to);
            let mut req = client::post(&endpoint);

            let req = req.with_connection(Connection::from_stream(stream));

            let req = if SETTING.get_future() {
                req.json(&msg.my_id)
            } else {
                // TODO: REMOVE IN ALPHA 5
                req.json(LocalIdentity {
                    global: msg.my_id.clone(),
                    wg_port: 12345,
                })
            };

            req.unwrap().send().from_err().and_then(|response| {
                response
                    .json()
                    .from_err()
                    .and_then(|val: LocalIdentity| Ok(val))
            })
        }))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct GetExitInfo {
    pub to: SocketAddr,
}

pub fn get_exit_info(msg: GetExitInfo) -> impl Future<Item = ExitDetails, Error = Error> {
    let endpoint = format!("http://[{}]:{}/exit_info", msg.to.ip(), msg.to.port());

    let stream = TokioTcpStream::connect2(&msg.to);

    stream.from_err().and_then(move |stream| {
        client::get(&endpoint)
            .with_connection(Connection::from_stream(stream))
            .finish()
            .unwrap()
            .send()
            .from_err()
            .and_then(|response| {
                response
                    .json()
                    .from_err()
                    .and_then(|val: ExitDetails| Ok(val))
            })
    })
}

#[derive(Debug, Eq, PartialEq)]
pub struct ExitSetupRequest {
    pub to: SocketAddr,
    pub ident: ExitClientIdentity,
}

pub fn send_exit_setup_request(
    msg: ExitSetupRequest,
) -> impl Future<Item = ExitServerReply, Error = Error> {
    let endpoint = format!("http://[{}]:{}/setup", msg.to.ip(), msg.to.port());

    let stream = TokioTcpStream::connect2(&msg.to);

    stream.from_err().and_then(move |stream| {
        client::post(&endpoint)
            .with_connection(Connection::from_stream(stream))
            .json(msg.ident)
            .unwrap()
            .send()
            .from_err()
            .and_then(|response| {
                response
                    .json()
                    .from_err()
                    .and_then(|val: ExitServerReply| Ok(val))
            })
    })
}
