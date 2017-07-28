extern crate jsonrpc_core;
extern crate jsonrpc_minihttp_server;
extern crate rocksdb;

use jsonrpc_core::*;
use jsonrpc_minihttp_server::{cors, ServerBuilder, DomainsValidation};
use rocksdb::DB;

fn foo () {
  // NB: db is automatically closed at end of lifetime
  let db = DB::open_default("path/for/rocksdb/storage").unwrap();
  db.put(b"my key", b"my value").unwrap();
  match db.get(b"my key") {
    Ok(Some(value)) => println!("retrieved value {}", value.to_utf8().unwrap()),
    Ok(None) => println!("value not found"),
    Err(e) => println!("operational problem encountered: {}", e),
  }
  db.delete(b"my key").unwrap();
}

fn main() {
  foo();
	// let mut io = IoHandler::default();
	// io.add_async_method("say_hello", |_params| {
	// 	futures::finished(Value::String("hello".to_owned()))
	// });

	// let server = ServerBuilder::new(io)
	// 	.cors(DomainsValidation::AllowOnly(vec![cors::AccessControlAllowOrigin::Null]))
	// 	.start_http(&"127.0.0.1:3030".parse().unwrap())
	// 	.expect("Unable to start RPC server");

	// server.wait().unwrap();
}