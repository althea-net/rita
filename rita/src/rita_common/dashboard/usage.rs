use crate::rita_common::usage_tracker::GetPayments;
use crate::rita_common::usage_tracker::PaymentHour;
use crate::rita_common::usage_tracker::UsageTracker;
use ::actix::registry::SystemService;
use ::actix_web::{AsyncResponder, HttpRequest, Json};
use failure::Error;
use futures::Future;
use std::boxed::Box;
use std::collections::VecDeque;

pub fn get_payments(
    _req: HttpRequest,
) -> Box<dyn Future<Item = Json<VecDeque<PaymentHour>>, Error = Error>> {
    trace!("/usage/relay hit");
    UsageTracker::from_registry()
        .send(GetPayments {})
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}
