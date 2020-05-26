use crate::SETTING;
use actix_web::{HttpRequest, HttpResponse};
use failure::Error;
use settings::RitaCommonSettings;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct EthPrivateKey {
    pub eth_private_key: String,
}

pub fn get_eth_private_key(_req: HttpRequest) -> Result<HttpResponse, Error> {
    debug!("/eth_private_key GET hit");

    let mut ret = HashMap::new();

    match SETTING.get_payment().eth_private_key {
        Some(pk) => {
            ret.insert("eth_private_key".to_owned(), format!("{:x}", pk));
        }
        None => {
            let error_msg = "No eth key configured yet";
            warn!("{}", error_msg);
            ret.insert("error".to_owned(), error_msg.to_owned());
        }
    }

    Ok(HttpResponse::Ok().json(ret))
}
