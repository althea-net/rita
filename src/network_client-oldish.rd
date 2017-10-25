extern crate futures;
extern crate hyper;
extern crate tokio_core;

use std::io::{self, Write};
use futures::{Future, Stream};
use hyper::Client;
use self::tokio_core::reactor::Core;


pub struct NetworkClient {
  client: hyper::Client<T: tokio_core::reactor::Core>,
}

impl NetworkClient {
  pub fn new(core: tokio_core::reactor::Core) -> NetworkClient {
    NetworkClient {
      client: Client::new(&core.handle()),
    }
  }

  pub fn post() -> String {
    let work = client.get(uri).and_then(|res| {
      println!("Response: {}", res.status());

      res
        .body()
        .for_each(|chunk| io::stdout().write_all(&chunk).map_err(From::from))
    });
    core.run(work)?;
  }
}
