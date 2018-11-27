#![allow(unknown_lints)]
#![warn(clippy::perf)]
#![warn(clippy::style)]
#![warn(clippy::correctness)]
#![warn(clippy::complexity)]

#[macro_use]
extern crate diesel;
#[macro_use]
extern crate serde_derive;

pub mod models;
pub mod schema;
