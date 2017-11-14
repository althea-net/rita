#![feature(custom_attribute)]

#[macro_use]
extern crate proc_macro;

#[macro_use]
extern crate quote;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate array_serialization_derive;

extern crate base64;
extern crate bigint;
extern crate serde;
extern crate serde_bytes;
extern crate serde_json;

fn main() {}

mod types;
// mod storage;
// mod logic;
// mod crypto;
// mod network_client;
