#![feature(custom_attribute)]

#[macro_use]
extern crate lazy_static;

/*
 *#[macro_use]
 *extern crate proc_macro;
 */

#[macro_use]
extern crate quote;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate array_serialization_derive;

#[macro_use]
extern crate derive_error;

extern crate base64;
extern crate num;
extern crate serde;
extern crate serde_bytes;
extern crate serde_json;
extern crate tiny_keccak;

fn main() {}

// mod types;
mod num256;
// mod storage;
// mod logic;
// mod crypto;
// mod network_client;
