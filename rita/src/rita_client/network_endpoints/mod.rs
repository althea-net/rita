use settings::ExitClientSettings;

use actix_web::*;

use futures::Future;

use std::boxed::Box;

use serde_json;

use bytes::Bytes;

use SETTING;

use failure::Error;

pub fn setup_exit(req: HttpRequest) -> Box<Future<Item = String, Error = Error>> {
    req.body()
        .from_err()
        .and_then(move |bytes: Bytes| {
            trace!("setup exit body: {:?}", bytes);
            let setting: ExitClientSettings = serde_json::from_slice(&bytes[..]).unwrap();

            SETTING.write().unwrap().exit_client = Some(setting);

            Ok("Setup Ok".to_string())
        })
        .responder()
}
