use crate::rita_common::usage_tracker::GetUsage;
use crate::rita_common::usage_tracker::UsageHour;
use crate::rita_common::usage_tracker::UsageTracker;
use crate::rita_common::usage_tracker::UsageType;
use ::actix::registry::SystemService;
use ::actix_web::{AsyncResponder, HttpRequest, Json};
use failure::Error;
use futures01::Future;
use std::boxed::Box;
use std::collections::VecDeque;

pub fn get_client_usage(
    _req: HttpRequest,
) -> Box<dyn Future<Item = Json<VecDeque<UsageHour>>, Error = Error>> {
    trace!("/usage/client hit");
    UsageTracker::from_registry()
        .send(GetUsage {
            kind: UsageType::Client,
        })
        .from_err()
        .and_then(|reply| Ok(Json(reply?)))
        .responder()
}

pub fn get_relay_usage(
    _req: HttpRequest,
) -> Box<dyn Future<Item = Json<VecDeque<UsageHour>>, Error = Error>> {
    trace!("/usage/relay hit");
    UsageTracker::from_registry()
        .send(GetUsage {
            kind: UsageType::Relay,
        })
        .from_err()
        .and_then(|reply| Ok(Json(reply?)))
        .responder()
}
