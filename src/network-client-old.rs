#[macro_use]
extern crate jsonrpc_client_core;
extern crate jsonrpc_client_http;

use jsonrpc_client_http::{HttpTransport, Error};

#[macro_use]
extern crate serde_derive;

#[derive(Serialize, Deserialize, Debug)]
pub struct Foo {
  bar: String,
  dang: i32,
}

// Trait to allow swapping of functionality with test stub
pub trait NetworkApi {
  fn say_hello(&mut self, foo: Foo) -> Result<Foo, String>;
}

// Struct with swappable network client
struct Logic<T: NetworkApi> {
  network: T,
}

// Test stub struct implementing fake network client
struct FakeClient;

// Implementation of non NetworkApi methods
impl FakeClient {
  fn new() -> FakeClient {
    FakeClient {}
  }
}

impl NetworkApi for FakeClient {
  fn say_hello(&mut self, foo: Foo) -> Result<Foo, String> {
    Ok(Foo {
      bar: String::from("froop"),
      dang: foo.dang,
    })
  }
}

// Struct implementing real network client
struct RealClient<T, Q>
where
  T: std::error::Error + std::marker::Send + 'static,
  Q: jsonrpc_client_core::Transport<T>,
{
  jsonrpc_client: FizzBuzzClient<T, Q>,
}

// 3rd party network lib
jsonrpc_client!(pub struct FizzBuzzClient {
    pub fn say_hello(&mut self, foo: Foo) -> Result<Foo>;
});

// Implementation of non NetworkApi methods
impl RealClient<Error, HttpTransport> {
  fn new() -> RealClient<Error, HttpTransport> {
    let transport = HttpTransport::new("http://127.0.0.1:3030").unwrap();
    let client = FizzBuzzClient::new(transport);
    RealClient {
      jsonrpc_client: client,
    }
  }
}

// Implementation of real client
impl NetworkApi for RealClient<Error, HttpTransport> {
  fn say_hello(&mut self, foo: Foo) -> Result<Foo, String> {
    self
      .jsonrpc_client
      .say_hello(foo)
      .map_err(|e| e.to_string())
  }
}


fn main() {
  // Using fake client
  let client = FakeClient::new();
  let mut logic = Logic { network: client };
  do_it(&mut logic);

  // Using real client
  let client = RealClient::new();
  let mut logic = Logic { network: client };
  do_it(&mut logic);
}

// do_it does not know the difference between fake and real
fn do_it<T: NetworkApi>(logic: &mut Logic<T>) {
  let result1: Foo = logic
    .network
    .say_hello(Foo {
      bar: String::from("erp"),
      dang: 102,
    })
    .unwrap();
  println!("print {:?}", result1.dang);
}
