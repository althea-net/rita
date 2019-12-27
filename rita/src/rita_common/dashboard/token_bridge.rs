use crate::rita_common::token_bridge::BridgeStatus;
use crate::rita_common::token_bridge::GetBridgeStatus;
use crate::rita_common::token_bridge::TokenBridge;
use ::actix::registry::SystemService;
use ::actix_web::{AsyncResponder, HttpRequest, Json};
use failure::Error;
use futures01::Future;
use std::boxed::Box;

pub fn get_bridge_status(
    _req: HttpRequest,
) -> Box<dyn Future<Item = Json<BridgeStatus>, Error = Error>> {
    trace!("/token_bridge/status hit");
    TokenBridge::from_registry()
        .send(GetBridgeStatus)
        .from_err()
        .and_then(|reply| Ok(Json(reply?)))
        .responder()
}
