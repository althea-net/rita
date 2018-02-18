use std;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;
use std::io::{Write, Read};

use minihttpse::Response;

use actix_web;
use actix::prelude::*;
use futures::Future;

use actix::registry::SystemService;

use serde_json;

use althea_types::{LocalIdentity};

#[derive(Debug, Error)]
pub enum Error {
    IOError(std::io::Error),
    DeserializationError(serde_json::Error),
    HTTPParseError,
    #[error(msg_embedded, no_from, non_std)] HTTPClientError(String),
}

pub struct HTTPClient {
    executors: SyncAddress<HTTPExecutor>
}

impl Actor for HTTPClient {
    type Context = Context<Self>;
}

impl Supervised for HTTPClient {}
impl SystemService for HTTPClient {
    fn service_started(&mut self, ctx: &mut Context<Self>) {
        info!("HTTP Client started");
    }
}
impl Default for HTTPClient {
    fn default() -> HTTPClient {
        HTTPClient{
            executors: SyncArbiter::start(3, || {HTTPExecutor{}})
        }
    }
}

pub struct HTTPExecutor;

impl Actor for HTTPExecutor {
    type Context = SyncContext<Self>;
}

pub struct Hello {
    pub my_id: LocalIdentity,
    pub to: SocketAddr
}

impl Message for Hello {
    type Result = Result<LocalIdentity, Error>;
}

impl Handler<Hello> for HTTPClient {
    type Result = ResponseFuture<LocalIdentity, Error>;
    fn handle(&mut self, msg: Hello, _: &mut Self::Context) -> Self::Result {
        Box::new(self.executors.send(msg).then(|r|{r.unwrap()}))
    }
}

impl Handler<Hello> for HTTPExecutor {
    type Result = Result<LocalIdentity, Error>;

    fn handle(&mut self, msg: Hello, _: &mut Self::Context) -> Self::Result {
        let my_id = serde_json::to_string(&msg.my_id)?;

        let mut stream = TcpStream::connect_timeout(&msg.to, Duration::from_secs(1))?;

        // Format HTTP request
        let request = format!("POST /hello HTTP/1.0\r\n\
Host: {}\r\n\
Content-Type:application/json\r\n\
Content-Length: {}\r\n\r\n
{}\r\n", msg.to, my_id.len() + 1, my_id);  //TODO: make this a lot less ugly

        trace!("Sending http request:\
        {}\nEND", request);
        stream.write(request.as_bytes())?;

        // Make request and return response as string
        let mut resp = String::new();
        stream.read_to_string(&mut resp)?;

        trace!("They replied {}", &resp);

        if let Ok(response) = Response::new(resp.into_bytes()){
            let mut identity: LocalIdentity = serde_json::from_str(&response.text())?;
            Ok(identity)
        }else{
            Err(Error::HTTPParseError)
        }
    }
}
