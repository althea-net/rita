use std::net::{SocketAddr, TcpStream};
use std::time::Duration;
use std::io::{Read, Write};

use minihttpse::Response;

use actix::prelude::*;
use actix_web::*;

use futures::Future;

use actix::registry::SystemService;

use serde_json;

use althea_types::LocalIdentity;

use failure::Error;

#[derive(Debug, Fail)]
pub enum HTTPClientError {
    #[fail(display = "HTTP Parse Error")]
    HTTPParseError,
}

pub struct HTTPClient {
    executors: Addr<Syn, HTTPSyncExecutor>,
}

impl Actor for HTTPClient {
    type Context = Context<Self>;
}

impl Supervised for HTTPClient {}
impl SystemService for HTTPClient {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("HTTP Client started");
    }
}
impl Default for HTTPClient {
    fn default() -> HTTPClient {
        HTTPClient {
            executors: SyncArbiter::start(10, || HTTPSyncExecutor {}),
        }
    }
}

pub struct HTTPSyncExecutor;

impl Actor for HTTPSyncExecutor {
    type Context = SyncContext<Self>;
}

#[derive(Debug)]
pub struct Hello {
    pub my_id: LocalIdentity,
    pub to: SocketAddr,
}

impl Message for Hello {
    type Result = Result<LocalIdentity, Error>;
}

impl Handler<Hello> for HTTPClient {
    type Result = ResponseFuture<LocalIdentity, Error>;
    fn handle(&mut self, msg: Hello, _: &mut Self::Context) -> Self::Result {
        Box::new(self.executors.send(msg).then(|r| r.unwrap()))
    }
}

impl Handler<Hello> for HTTPSyncExecutor {
    type Result = Result<LocalIdentity, Error>;

    fn handle(&mut self, msg: Hello, _: &mut Self::Context) -> Self::Result {
        info!("sending {:?}", msg);
        let my_id = serde_json::to_string(&msg.my_id)?;

        let stream = TcpStream::connect_timeout(&msg.to, Duration::from_secs(1));

        trace!("stream status {:?}, to: {:?}", stream, &msg.to);

        let mut stream = stream?;

        // Format HTTP request
        let request = format!(
            "POST /hello HTTP/1.0\r\n\
Host: {}\r\n\
Content-Type:application/json\r\n\
Content-Length: {}\r\n\r\n
{}\r\n",
            msg.to,
            my_id.len() + 1,
            my_id
        ); //TODO: make this a lot less ugly

        trace!(
            "Sending http request:\
             {}\nEND",
            request
        );
        stream.write_all(request.as_bytes())?;

        // Make request and return response as string
        let mut resp = String::new();
        stream.read_to_string(&mut resp)?;

        trace!("{:?} replied {} END", msg.to, &resp);

        if resp.is_empty() {
            panic!("{:?} replied with empty", &resp);
        }

        if let Ok(response) = Response::new(resp.into_bytes()) {
            let mut identity: LocalIdentity = serde_json::from_str(&response.text())?;
            Ok(identity)
        } else {
            Err(HTTPClientError::HTTPParseError.into())
        }
    }
}
