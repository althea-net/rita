use actix_web_async::{HttpRequest, HttpResponse};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct EthPrivateKey {
    pub eth_private_key: String,
}

pub async fn get_eth_private_key(_req: HttpRequest) -> HttpResponse {
    debug!("/eth_private_key GET hit");

    let mut ret = HashMap::new();

    match settings::get_rita_client().payment.eth_private_key {
        Some(pk) => {
            ret.insert("eth_private_key".to_owned(), format!("{pk:x}"));
        }
        None => {
            let error_msg = "No eth key configured yet";
            warn!("{}", error_msg);
            ret.insert("error".to_owned(), error_msg.to_owned());
        }
    }

    HttpResponse::Ok().json(ret)
}
