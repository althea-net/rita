use crate::rita_common::token_bridge::get_bridge_status as get_status;
use crate::rita_common::token_bridge::BridgeStatus;
use ::actix_web::{HttpRequest, Json};

pub fn get_bridge_status(_req: HttpRequest) -> Json<BridgeStatus> {
    trace!("/token_bridge/status hit");
    Json(get_status())
}
