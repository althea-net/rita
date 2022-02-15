use actix_web_async::{HttpRequest, HttpResponse};
use rita_common::usage_tracker::get_usage_data;
use rita_common::usage_tracker::UsageType;

pub fn get_client_usage(_req: HttpRequest) -> HttpResponse {
    trace!("/usage/client hit");

    HttpResponse::Ok().json(get_usage_data(UsageType::Client))
}

pub fn get_relay_usage(_req: HttpRequest) -> HttpResponse {
    trace!("/usage/relay hit");

    HttpResponse::Ok().json(get_usage_data(UsageType::Relay))
}
