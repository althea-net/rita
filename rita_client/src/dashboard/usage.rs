use actix_web::{HttpRequest, HttpResponse};
use rita_common::usage_tracker::get_usage_data;
use rita_common::usage_tracker::structs::UsageType;

pub async fn get_client_usage(_req: HttpRequest) -> HttpResponse {
    trace!("/usage/client hit");

    HttpResponse::Ok().json(get_usage_data(UsageType::Client))
}

pub async fn get_relay_usage(_req: HttpRequest) -> HttpResponse {
    trace!("/usage/relay hit");

    HttpResponse::Ok().json(get_usage_data(UsageType::Relay))
}
