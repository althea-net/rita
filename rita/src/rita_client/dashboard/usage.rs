use crate::rita_common::usage_tracker::GetUsage;
use crate::rita_common::usage_tracker::UsageHour;
use crate::rita_common::usage_tracker::UsageType;
use crate::rita_common::usage_tracker::handle_usage_data;
use ::actix_web::{HttpRequest, Json};
use std::collections::VecDeque;

pub fn get_client_usage(
    _req: HttpRequest,
) -> Json<VecDeque<UsageHour>> {
    trace!("/usage/client hit");

    Json(handle_usage_data(GetUsage {
            kind: UsageType::Client,
        })) 

}

pub fn get_relay_usage(
    _req: HttpRequest,
) -> Json<VecDeque<UsageHour>> {
    trace!("/usage/relay hit");

    Json(handle_usage_data(GetUsage {
            kind: UsageType::Relay
        })) 
}
