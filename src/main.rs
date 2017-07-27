extern crate hyper;
extern crate futures;

// use hyper::header::ContentLength;
use hyper::server::{Http, Request, Response, Service};
use hyper::{Method, StatusCode};


use std::ascii::AsciiExt;
use futures::future::{Either, FutureResult};
// use futures::stream::Concat2;
use futures::Stream;
use futures::Future;
use hyper::Chunk;

struct Echo;

impl Service for Echo {
  type Request = Request;
  type Error = hyper::Error;
  type Future = Either<
    FutureResult<Self::Response, Self::Error>,
    Box<Future<Item = Response, Error = hyper::Error>>,
  >;
  // back to default Response
  type Response = Response;

  fn call(&self, req: Request) -> Self::Future {
    match (req.method(), req.path()) {
      (&Method::Get, "/") => {
        Either::A(futures::future::ok(
          Response::new().with_body("Try POSTing data to /echo"),
        ))
      }
      (&Method::Post, "/echo") => Either::B(Box::new(req.body().concat2().map(reverse))),
      _ => {
        Either::A(futures::future::ok(
          Response::new().with_status(StatusCode::NotFound),
        ))
      }
    }
  }
}

// impl Service for Echo {
//     // boilerplate hooking up hyper's server types
//     type Response = Response<Map<Body, fn(Chunk) -> Chunk>>;

//     // The future representing the eventual Response your call will
//     // resolve to. This can change to whatever Future you need.
//     type Future = futures::future::FutureResult<Self::Response, Self::Error>;

//     fn call(&self, req: Request) -> Self::Future {
//         let mut response = Response::new();

//         match (req.method(), req.path()) {
//             // (&Method::Get, "/") => {
//             //     response.set_body("Try POSTing data to /echo");
//             // }
//             (&Method::Post, "/echo") => {
//                 response.set_body(req.body().map(to_uppercase as _));
//             }
//             _ => {
//                 response.set_status(StatusCode::NotFound);
//             }
//         };

//         futures::future::ok(response)
//     }
// }

fn to_uppercase(chunk: Chunk) -> Chunk {
  let uppered = chunk
    .iter()
    .map(|byte| byte.to_ascii_uppercase())
    .collect::<Vec<u8>>();
  Chunk::from(uppered)
}

fn reverse(chunk: Chunk) -> Response {
  let reversed = to_uppercase(chunk)
    .iter()
    .rev()
    .cloned()
    .collect::<Vec<u8>>();
  Response::new().with_body(reversed)
}

fn main() {
  let addr = "127.0.0.1:3000".parse().unwrap();
  let server = Http::new().bind(&addr, || Ok(Echo)).unwrap();
  server.run().unwrap();
}