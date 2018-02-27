#[macro_use] extern crate log;

#[macro_use] extern crate rouille;
use rouille::{Request, Response};

#[macro_use] extern crate diesel;

use std::io::Read;

extern crate post_office_settings;
use post_office_settings::SETTING;

fn main() {
    rouille::start_server("127.0.0.1:8090", move |request| {
        router!(request,
        (GET) (/setup) => {
            let data = request.data();
            let mut data = data.unwrap();
            let mut body = String::new();
            data.read_to_string(&mut body);
            println!("{:?}", body);
            println!("Got a setup hit");
            rouille::Response::empty_404()
        },

        (POST) (/hello) => {
            rouille::Response::empty_404()
        },

        _ => {
        println!("Got an unknown hit");
        rouille::Response::empty_404()
        }
        )
    });
}
