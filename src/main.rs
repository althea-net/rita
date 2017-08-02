#[macro_use]
extern crate jsonrpc_client_core;
extern crate jsonrpc_client_http;

use jsonrpc_client_http::HttpTransport;

struct foo {
    dang: i32,
    flop: String,
    derps: [usize; 32],
}

jsonrpc_client!(pub struct FizzBuzzClient {
    /// Returns the fizz-buzz string for the given number.
    pub fn fizz_buzz(&mut self, fo: foo) -> Result<String>;
});

fn main() {
    // let transport = HttpTransport::new("https://api.fizzbuzzexample.org/rpc/").unwrap();
    // let mut client = FizzBuzzClient::new(transport);
    // let result1 = client.fizz_buzz(3).unwrap();
    // let result2 = client.fizz_buzz(4).unwrap();
    // let result3 = client.fizz_buzz(5).unwrap();
    // // Should print "fizz 4 buzz" if the server implemented the service correctly
    // println!("{} {} {}", result1, result2, result3);
}

// extern crate jsonrpc_core;
// extern crate jsonrpc_minihttp_server;
// extern crate rocksdb;

mod types;
mod storage;
mod logic;
mod crypto;

// use jsonrpc_core::*;
// use jsonrpc_minihttp_server::{cors, ServerBuilder, DomainsValidation};
// use storage::Storage;
// use logic::Logic;
// use crypto::Crypto;
// // use rocksdb::DB;

// // fn foo () {
// //   // NB: db is automatically closed at end of lifetime
// //   let db = DB::open_default("path/for/rocksdb/storage").unwrap();
// //   db.put(b"my key", b"my value").unwrap();
// //   match db.get(b"my key") {
// //     Ok(Some(value)) => println!("retrieved value {}", value.to_utf8().unwrap()),
// //     Ok(None) => println!("value not found"),
// //     Err(e) => println!("operational problem encountered: {}", e),
// //   }
// //   db.delete(b"my key").unwrap();
// // }

// fn main() {
// 	let logic = Logic { storage: Storage::new(), crypto: Crypto::new() };
// 	let mut io = IoHandler::default();

// 	io.add_async_method("say_hello", |_params| {
// 		futures::finished(Value::String("hello".to_owned()))
// 	});

// 	io.add_async_method("propose_channel", |_params| {
// 		futures::finished(Value::String("hello".to_owned()))
// 	});

// 	let server = ServerBuilder::new(io)
// 		.cors(DomainsValidation::AllowOnly(vec![cors::AccessControlAllowOrigin::Null]))
// 		.start_http(&"127.0.0.1:3030".parse().unwrap())
// 		.expect("Unable to start RPC server");

// 	server.wait().unwrap();
// }