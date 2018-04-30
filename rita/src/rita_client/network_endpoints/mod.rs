use settings::ExitClientSettings;

use actix_web::*;

use futures::Future;

use std::boxed::Box;

use serde_json;

use bytes::Bytes;

use settings::RitaClientSettings;
use SETTING;

use failure::Error;

pub fn setup_exit(setting: Json<ExitClientSettings>) -> Result<String, Error> {
    SETTING.init_exit_client(setting.into_inner());

    Ok("Setup Ok\n".to_string())
}
